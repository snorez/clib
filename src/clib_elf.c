/*
 * TODO
 * Copyright (C) 2018  zerons
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#include "../include/clib.h"

static void dump_sechdr(elf_file *file, void *sechdr);

static int id_elf(char *buf)
{
	/*
	 * e_ident[0-3] MAGIC
	 * e_ident[4] class, 32bits or 64bits
	 * e_ident[5] 1/2 little/big endian
	 * e_ident[6] version
	 * e_ident[7] EI_OSABI,
	 * e_ident[8] EI_ABIVERSION, >linux 2.6, this is EI_PAD
	 * e_ident[9-15] EI_PAD
	 */
	if (strncmp(buf, "\x7f\x45\x4c\x46", 4) != 0)
		return -1;
	return (buf[4]-1) ? 64 : 32;
}

static void *get_sh_by_id(elf_file *ef, int idx)
{
	if (ef->elf_bits == 32) {
		Elf32_Ehdr *e = ef->elf_hdr;
		if (idx > e->e_shnum)
			return NULL;
		return ((char *)ef->elf_shdr + e->e_shentsize * idx);
	} else if (ef->elf_bits == 64) {
		Elf64_Ehdr *e = ef->elf_hdr;
		if (idx > e->e_shnum)
			return NULL;
		return ((char *)ef->elf_shdr + e->e_shentsize * idx);
	} else {
		return NULL;
	}
}

static void *get_sh_by_name(elf_file *file, const char *str)
{
	if (file->elf_bits == 32) {
		Elf32_Ehdr *e = file->elf_hdr;
		Elf32_Shdr *s;
		for (size_t i = 0; i < e->e_shnum; i++) {
			s = file->elf_shdr + e->e_shentsize * i;
			if (!memcmp(file->shstrtab+s->sh_name, str, strlen(str)+1))
				return s;
		}
		return NULL;
	} else if (file->elf_bits == 64) {
		Elf64_Ehdr *e = file->elf_hdr;
		Elf64_Shdr *s;
		for (size_t i = 0; i < e->e_shnum; i++) {
			s = file->elf_shdr + e->e_shentsize * i;
			if (!memcmp(file->shstrtab+s->sh_name, str, strlen(str)+1))
				return s;
		}
		return NULL;
	} else {
		return NULL;
	}
}

static int add_symbol(struct list_head *head, char *name, void *data)
{
	struct _elf_sym sym;
	sym.name = name;
	sym.data = data;
	return list_comm_new_append(head, &sym, sizeof(sym));
}

static int add_symbols(elf_file *file, struct list_head *head, void *shsym, char *str)
{
	int err;
	char *start;
	size_t cnt;
	char *rdata = bin_rdata(file->file);
	if (file->elf_bits == 32) {
		Elf32_Shdr *s = shsym;
		start = s->sh_offset + rdata;
		cnt = s->sh_size / s->sh_entsize;
		for (size_t i = 0; i < cnt; i++) {
			Elf32_Sym *sym = (void *)(start + s->sh_entsize * i);
			err = add_symbol(head, str + sym->st_name, sym);
			if (err == -1) {
				err_dbg(0, "add_symbol err");
				goto err_out;
			}
		}
		return 0;
	} else if (file->elf_bits == 64) {
		Elf64_Shdr *s = shsym;
		start = s->sh_offset + rdata;
		cnt = s->sh_size / s->sh_entsize;
		for (size_t i = 0; i < cnt; i++) {
			Elf64_Sym *sym = (void *)(start + s->sh_entsize * i);
			err = add_symbol(head, str + sym->st_name, sym);
			if (err == -1) {
				err_dbg(0, "add_symbol err");
				goto err_out;
			}
		}
		return 0;
	}
err_out:
	list_comm_cleanup(head, NULL);
	return -1;
}

static int parse_elf32(elf_file *file, char *buf)
{
	int err;
	file->elf_bits = 32;

	file->elf_hdr_size = sizeof(Elf32_Ehdr);
	file->elf_hdr = (Elf32_Ehdr *)malloc(file->elf_hdr_size);
	if (!file->elf_hdr) {
		err_dbg(0, "malloc err");
		return -1;
	}
	memset(file->elf_hdr, 0, file->elf_hdr_size);
	memcpy(file->elf_hdr, buf, file->elf_hdr_size);

	Elf32_Ehdr *tmp = file->elf_hdr;
	file->elf_machine = (uint16_t)tmp->e_machine;
	file->elf_text_entry = (uint64_t)tmp->e_entry;

	/* some test before getting the program header */
	if (tmp->e_ehsize != sizeof(Elf32_Ehdr))
		err_dbg(0, "elf header size abnormal");
	if (tmp->e_phoff != sizeof(Elf32_Ehdr))
		err_dbg(0, "program header offset abnormal");
	if (tmp->e_phentsize != sizeof(Elf32_Phdr))
		err_dbg(0, "program header entsize abnormal");

	file->elf_phdr_size = tmp->e_phnum * tmp->e_phentsize;
	if (!file->elf_phdr_size)
		file->elf_phdr = NULL;
	else {
		file->elf_phdr = (Elf32_Phdr *)malloc(file->elf_phdr_size);
		if (!file->elf_phdr) {
			err_dbg(0, "malloc err");
			goto err_free0;
		}
		memset(file->elf_phdr, 0, file->elf_phdr_size);
		memcpy(file->elf_phdr, buf+tmp->e_phoff, file->elf_phdr_size);
	}

	if (tmp->e_shentsize != sizeof(Elf32_Shdr))
		err_dbg(0, "section header entsize abnormal");
	file->elf_shdr_size = tmp->e_shentsize * tmp->e_shnum;
	if (!file->elf_shdr_size)
		file->elf_shdr = NULL;
	else {
		file->elf_shdr = (Elf32_Shdr *)malloc(file->elf_shdr_size);
		if (!file->elf_shdr) {
			err_dbg(0, "malloc err");
			goto err_free1;
		}
		memset(file->elf_shdr, 0, file->elf_shdr_size);
		memcpy(file->elf_shdr, buf+tmp->e_shoff, file->elf_shdr_size);
	}

	char *bin_rdata = bin_rdata(file->file);
	Elf32_Ehdr *e = file->elf_hdr;
	Elf32_Shdr *shstr, *strtab, *symtab, *dynstr, *dynsym;

	/*
	 * INFO, get shstrtab
	 * TODO, check this member if SHN_UNDEF, OR larger than or equal
	 *	SHN_LORESERVE
	 */
	if (e->e_shstrndx == SHN_UNDEF) {
		err_dbg(0, "elf has no section name string table");
		goto err_free2;
	}
	shstr = get_sh_by_id(file, e->e_shstrndx);
	file->shstrtab = shstr->sh_offset + bin_rdata;

	/*
	 * INFO, get strtab
	 */
	strtab = get_sh_by_name(file, ".strtab");
	if (!strtab) {
		err_dbg(0, "elf has no .strtab?");
		goto err_free2;
	}
	file->strtab = strtab->sh_offset + bin_rdata;

	/*
	 * INFO, get symtab
	 */
	symtab = get_sh_by_name(file, ".symtab");
	if (!symtab) {
		err_dbg(0, "elf has no .symtab?");
		goto err_free2;
	}
	err = add_symbols(file, &file->syms, symtab, file->strtab);
	if (err == -1) {
		err_dbg(0, "add_symbols err");
		goto err_free2;
	}

	/*
	 * INFO: get dynstr
	 */
	dynstr = get_sh_by_name(file, ".dynstr");
	if (!dynstr) {
		err_dbg(0, "elf has no .dynstr?");
		goto do_syms;
	}
	file->dynstr = dynstr->sh_offset + bin_rdata;

	/*
	 * INFO: get dynsym
	 */
	dynsym = get_sh_by_name(file, ".dynsym");
	if (!dynsym) {
		err_dbg(0, "elf has no .dynsym");
		goto err_free3;
	}
	err = add_symbols(file, &file->dynsyms, dynsym, file->dynstr);
	if (err == -1) {
		err_dbg(0, "add_symbols err");
		goto err_free3;
	}

do_syms:

	return 0;

err_free3:
	list_comm_cleanup(&file->syms, NULL);
err_free2:
	free(file->elf_shdr);
err_free1:
	free(file->elf_phdr);
err_free0:
	free(file->elf_hdr);
	return -1;
}

static int parse_elf64(elf_file *file, char *buf)
{
	int err = 0;
	file->elf_bits = 64;

	file->elf_hdr_size = sizeof(Elf64_Ehdr);
	file->elf_hdr = (Elf64_Ehdr *)malloc(file->elf_hdr_size);
	if (!file->elf_hdr) {
		err_dbg(0, "malloc err");
		return -1;
	}
	memset(file->elf_hdr, 0, file->elf_hdr_size);
	memcpy(file->elf_hdr, buf, file->elf_hdr_size);

	Elf64_Ehdr *tmp = file->elf_hdr;
	file->elf_machine = (uint16_t)tmp->e_machine;
	file->elf_text_entry = (uint64_t)tmp->e_entry;

	/* some test before getting the program header */
	if (tmp->e_ehsize != sizeof(Elf64_Ehdr))
		err_dbg(0, "elf header size abnormal");
	if (tmp->e_phoff != sizeof(Elf64_Ehdr))
		err_dbg(0, "program header offset abnormal");
	if (tmp->e_phentsize != sizeof(Elf64_Phdr))
		err_dbg(0, "program header entsize abnormal");

	file->elf_phdr_size = tmp->e_phnum * tmp->e_phentsize;
	if (!file->elf_phdr_size)
		file->elf_phdr = NULL;
	else {
		file->elf_phdr = (Elf64_Phdr *)malloc(file->elf_phdr_size);
		if (!file->elf_phdr) {
			err_dbg(0, "malloc err");
			goto err_free0;
		}
		memset(file->elf_phdr, 0, file->elf_phdr_size);
		memcpy(file->elf_phdr, buf+tmp->e_phoff, file->elf_phdr_size);
	}

	if (tmp->e_shentsize != sizeof(Elf64_Shdr))
		err_dbg(0, "section header entsize abnormal");
	file->elf_shdr_size = tmp->e_shentsize * tmp->e_shnum;
	if (!file->elf_shdr_size)
		file->elf_shdr = NULL;
	else {
		file->elf_shdr = (Elf64_Shdr *)malloc(file->elf_shdr_size);
		if (!file->elf_shdr) {
			err_dbg(0, "malloc err");
			goto err_free1;
		}
		memset(file->elf_shdr, 0, file->elf_shdr_size);
		memcpy(file->elf_shdr, buf+tmp->e_shoff, file->elf_shdr_size);
	}

	char *bin_rdata = bin_rdata(file->file);
	Elf64_Ehdr *e = file->elf_hdr;
	Elf64_Shdr *shstr, *strtab, *symtab, *dynstr, *dynsym;

	/*
	 * INFO, get shstrtab
	 * TODO, check this member if SHN_UNDEF, OR larger than or equal
	 *	SHN_LORESERVE
	 */
	if (e->e_shstrndx == SHN_UNDEF) {
		err_dbg(0, "elf has no section name string table");
		goto err_free2;
	}
	shstr = get_sh_by_id(file, e->e_shstrndx);
	file->shstrtab = shstr->sh_offset + bin_rdata;

	/*
	 * INFO, get strtab
	 */
	strtab = get_sh_by_name(file, ".strtab");
	if (!strtab) {
		err_dbg(0, "elf has no .strtab?");
		goto err_free2;
	}
	file->strtab = strtab->sh_offset + bin_rdata;

	/*
	 * INFO, get symtab
	 */
	symtab = get_sh_by_name(file, ".symtab");
	if (!symtab) {
		err_dbg(0, "elf has no .symtab?");
		goto err_free2;
	}
	err = add_symbols(file, &file->syms, symtab, file->strtab);
	if (err == -1) {
		err_dbg(0, "add_symbols err");
		goto err_free2;
	}

	/*
	 * INFO: get dynstr
	 */
	dynstr = get_sh_by_name(file, ".dynstr");
	if (!dynstr) {
		err_dbg(0, "elf has no .dynstr?");
		goto do_syms;
	}
	file->dynstr = dynstr->sh_offset + bin_rdata;

	/*
	 * INFO: get dynsym
	 */
	dynsym = get_sh_by_name(file, ".dynsym");
	if (!dynsym) {
		err_dbg(0, "elf has no .dynsym");
		goto err_free3;
	}
	err = add_symbols(file, &file->dynsyms, dynsym, file->dynstr);
	if (err == -1) {
		err_dbg(0, "add_symbols err");
		goto err_free3;
	}

do_syms:

	return 0;

err_free3:
	list_comm_cleanup(&file->syms, NULL);
err_free2:
	free(file->elf_shdr);
err_free1:
	free(file->elf_phdr);
err_free0:
	free(file->elf_hdr);
	return -1;
}

elf_file *elf_parse(char *path, int flag)
{
	int err;
	elf_file *ef = (elf_file *)malloc(sizeof(elf_file));
	if (!ef) {
		err = -1;
		err_dbg(0, "malloc err");
		goto ret;
	}
	memset(ef, 0, sizeof(elf_file));
	INIT_LIST_HEAD(&ef->syms);
	INIT_LIST_HEAD(&ef->dynsyms);

	ef->file = regfile_open(REGFILE_T_BIN, path, flag);
	if (!ef->file) {
		err_dbg(1, "regfile_open err");
		err = -1;
		goto free_ret;
	}

	err = regfile_readall(ef->file);
	if (err == -1) {
		err_dbg(1, "regfile_readall err");
		err = -1;
		goto free_ret2;
	}

	char *buf = bin_rdata(ef->file);
	if (!buf) {
		err_dbg(0, "file data err");
		err = -1;
		goto free_ret2;
	}

	err = id_elf(buf);
	if (err == -1) {
		err_dbg(0, "file format err");
		err = -1;
		goto free_ret2;
	}

	if (err == 32)
		err = parse_elf32(ef, buf);
	else if (err == 64)
		err = parse_elf64(ef, buf);

	if (err == -1)
		goto free_ret2;
	else
		goto ret;
free_ret2:
	regfile_close(ef->file);
free_ret:
	free(ef);
ret:
	return (err == -1) ? NULL : ef;
}

int elf_cleanup(elf_file *file)
{
	if (!file)
		return -1;
	regfile_close(file->file);
	free(file->elf_hdr);
	free(file->elf_phdr);
	free(file->elf_shdr);
	list_comm_cleanup(&file->syms, NULL);
	list_comm_cleanup(&file->dynsyms, NULL);
	free(file);
	return 0;
}

/*
 * get all elf symbols, use _elf_sym_full
 */
int elf_get_syms(char *path, struct list_head *head, uint8_t *bits)
{
	elf_file *ef = elf_parse(path, O_RDONLY);
	if (!ef) {
		err_dbg(0, "elf_parse err");
		return -1;
	}

	INIT_LIST_HEAD(head);
	*bits = ef->elf_bits;
	list_comm *tmp;
	struct _elf_sym_full *_new;
	list_for_each_entry(tmp, &ef->syms, list_head) {
		struct _elf_sym *sym = (struct _elf_sym *)tmp->data;
		_new = (struct _elf_sym_full *)malloc(sizeof(*_new));
		_new->name = malloc(strlen(sym->name)+1);
		memcpy(_new->name, sym->name, strlen(sym->name)+1);
		if (*bits == 32)
			memcpy((char *)&_new->data.sym0,
				(char *)sym->data, sizeof(Elf32_Sym));
		else if (*bits == 64)
			memcpy((char *)&_new->data.sym1,
				(char *)sym->data, sizeof(Elf64_Sym));
		else
			BUG();
		list_add_tail(&_new->sibling, head);
	}

	list_for_each_entry(tmp, &ef->dynsyms, list_head) {
		struct _elf_sym *sym = (struct _elf_sym *)tmp->data;
		_new = (struct _elf_sym_full *)malloc(sizeof(*_new));
		_new->name = malloc(strlen(sym->name)+1);
		memcpy(_new->name, sym->name, strlen(sym->name)+1);
		if (*bits == 32)
			memcpy((char *)&_new->data.sym0,
				(char *)sym->data, sizeof(Elf32_Sym));
		else if (*bits == 64)
			memcpy((char *)&_new->data.sym1,
				(char *)sym->data, sizeof(Elf64_Sym));
		else
			BUG();
		list_add_tail(&_new->sibling, head);
	}

	elf_cleanup(ef);

	return 0;
}

void elf_drop_syms(struct list_head *head)
{
	struct _elf_sym_full *tmp, *next;
	list_for_each_entry_safe(tmp, next, head, sibling) {
		list_del(&tmp->sibling);
		free(tmp->name);
		free(tmp);
	}
}

/*
 * ************************************************************************
 * dump elf infomation
 * ************************************************************************
 */
static char *x_elf_oabi(char ch)
{
	switch (ch) {
	case 0x00:
		return "System V";
		break;
	case 0x01:
		return "HP-UX";
		break;
	case 0x02:
		return "NetBSD";
		break;
	case 0x03:
		return "Linux";
		break;
	case 0x06:
		return "Solaris";
		break;
	case 0x07:
		return "AIX";
		break;
	case 0x08:
		return "IRIX";
		break;
	case 0x09:
		return "FreeBSD";
		break;
	case 0x0c:
		return "OpenBSD";
		break;
	case 0x0d:
		return "OpenVMS";
		break;
	default:
		return "Unknown";
	}
}

static char *x_elf_type(uint16_t word)
{
	switch (word) {
	case 0x1:
		return "relocatable";
		break;
	case 0x2:
		return "executable";
		break;
	case 0x3:
		return "shared";
		break;
	case 0x4:
		return "core";
		break;
	default:
		return "unknown elf type";
	}
}

static char *x_elf_machine(uint16_t word)
{
	switch (word) {
	case 0x00:
		return "No specific instruction set";
		break;
	case 0x02:
		return "SPARC";
		break;
	case 0x03:
		return "x86";
		break;
	case 0x08:
		return "MIPS";
		break;
	case 0x14:
		return "PowerPC";
		break;
	case 0x28:
		return "ARM";
		break;
	case 0x2a:
		return "SuperH";
		break;
	case 0x32:
		return "IA-64";
		break;
	case 0x3e:
		return "x86-64";
		break;
	case 0xb7:
		return "AArch64";
		break;
	default:
		return "unknown instruction set";
	}
}

static void dump_elf32_ehdr(elf_file *file)
{
	Elf32_Ehdr *ehdr = file->elf_hdr;
	if (!ehdr) {
		fprintf(stdout, "elf file header missing\n");
		return;
	}

	fprintf(stdout, "header identify:\t\t");
	dump_mem((char *)ehdr->e_ident, EI_NIDENT);
	fprintf(stdout, "program bits:\t\t\t32 bits\n");
	fprintf(stdout, "program endian:\t\t\t%s\n",(ehdr->e_ident[5]-1)?"big":"little");
	fprintf(stdout, "program os ABI:\t\t\t%s\n", x_elf_oabi(ehdr->e_ident[7]));
	fprintf(stdout, "program header padding:\t\t");
	dump_mem((char *)&ehdr->e_ident[8], 8);
	fprintf(stdout, "program type:\t\t\t%s\n", x_elf_type(ehdr->e_type));
	fprintf(stdout, "program machine:\t\t%s\n", x_elf_machine(ehdr->e_machine));
	fprintf(stdout, "program file hdr size:\t\t%04x\n", ehdr->e_ehsize);
	fprintf(stdout, "program text entry:\t\t%08x\n", ehdr->e_entry);
	fprintf(stdout, "program header off:\t\t%08x\n", ehdr->e_phoff);
	fprintf(stdout, "program header size:\t\t%04x\n", ehdr->e_phentsize);
	fprintf(stdout, "program header cnt:\t\t%04x\n", ehdr->e_phnum);
	fprintf(stdout, "section header off:\t\t%08x\n", ehdr->e_shoff);
	fprintf(stdout, "section header size:\t\t%04x\n", ehdr->e_shentsize);
	fprintf(stdout, "section header cnt:\t\t%04x\n", ehdr->e_shnum);
	fprintf(stdout, "section header idx:\t\t%04x\n", ehdr->e_shstrndx);
	fprintf(stdout, "program flags:\t\t\t%08x\n", ehdr->e_flags);
	fprintf(stdout, "\n");
}

static void dump_elf64_ehdr(elf_file *file)
{
	Elf64_Ehdr *ehdr = file->elf_hdr;
	if (!ehdr) {
		fprintf(stdout, "elf file header missing\n");
		return;
	}

	fprintf(stdout, "header identify:\t\t");
	dump_mem((char *)ehdr->e_ident, EI_NIDENT);
	fprintf(stdout, "program bits:\t\t\t64 bits\n");
	fprintf(stdout, "program endian:\t\t\t%s\n",(ehdr->e_ident[5]-1)?"big":"little");
	fprintf(stdout, "program os ABI:\t\t\t%s\n", x_elf_oabi(ehdr->e_ident[7]));
	fprintf(stdout, "program header padding:\t\t");
	dump_mem((char *)&ehdr->e_ident[8], 8);
	fprintf(stdout, "program type:\t\t\t%s\n", x_elf_type(ehdr->e_type));
	fprintf(stdout, "program machine:\t\t%s\n", x_elf_machine(ehdr->e_machine));
	fprintf(stdout, "program file hdr size:\t\t%04x\n", ehdr->e_ehsize);
#ifdef __x86_64__
	fprintf(stdout, "program text entry:\t\t%016lx\n", (uint64_t)ehdr->e_entry);
	fprintf(stdout, "program header off:\t\t%016lx\n", (uint64_t)ehdr->e_phoff);
#endif
#ifdef __i386__
	fprintf(stdout, "program text entry:\t\t%016llx\n", (uint64_t)ehdr->e_entry);
	fprintf(stdout, "program header off:\t\t%016llx\n", (uint64_t)ehdr->e_phoff);
#endif
	fprintf(stdout, "program header size:\t\t%04x\n", ehdr->e_phentsize);
	fprintf(stdout, "program header cnt:\t\t%04x\n", ehdr->e_phnum);
#ifdef __x86_64__
	fprintf(stdout, "section header off:\t\t%016lx\n", (uint64_t)ehdr->e_shoff);
#endif
#ifdef __i386__
	fprintf(stdout, "section header off:\t\t%016llx\n", (uint64_t)ehdr->e_shoff);
#endif
	fprintf(stdout, "section header size:\t\t%04x\n", ehdr->e_shentsize);
	fprintf(stdout, "section header cnt:\t\t%04x\n", ehdr->e_shnum);
	fprintf(stdout, "section header idx:\t\t%04x\n", ehdr->e_shstrndx);
	fprintf(stdout, "program flags:\t\t\t%08x\n", ehdr->e_flags);
	fprintf(stdout, "\n");
}

void dump_elf_ehdr(elf_file *file)
{
	/* this function print the elf file header */
	if (file->elf_bits == 32)
		dump_elf32_ehdr(file);
	else if (file->elf_bits == 64)
		dump_elf64_ehdr(file);
}

static void dump_elf32_phdr(elf_file *file)
{
	Elf32_Ehdr *e = file->elf_hdr;
	Elf32_Phdr *p = file->elf_phdr;
	if (!p) {
		fprintf(stdout, "file program header missing\n");
		return;
	}

	uint16_t cnt = e->e_phnum;
	while (cnt--) {
		fprintf(stdout, "entry image offset:\t\t%08x\n", (uint32_t)
		       (e->e_phoff+(char *)p-(char *)file->elf_phdr));
		fprintf(stdout, "program header type:\t\t%08x\n", p->p_type);
		fprintf(stdout, "program header offs:\t\t%08x\n", p->p_offset);
		fprintf(stdout, "program header vadd:\t\t%08x\n", p->p_vaddr);
		fprintf(stdout, "program header padd:\t\t%08x\n", p->p_paddr);
		fprintf(stdout, "program header imgsize:\t\t%08x\n", p->p_filesz);
		fprintf(stdout, "program header memsize:\t\t%08x\n", p->p_memsz);
		fprintf(stdout, "program header flag:\t\t%08x\n", p->p_flags);
		fprintf(stdout, "program header align:\t\t%08x\n", p->p_align);
		fprintf(stdout, "\n");
		p = (Elf32_Phdr *)((char *)p + e->e_phentsize);
	}
}

static void dump_elf64_phdr(elf_file *file)
{
	Elf64_Ehdr *e = file->elf_hdr;
	Elf64_Phdr *p = file->elf_phdr;
	if (!p) {
		fprintf(stdout, "file program header missing\n");
		return;
	}

	uint16_t cnt = e->e_phnum;
	while (cnt--) {
#ifdef __x86_64__
		fprintf(stdout, "entry image offset:\t\t%016lx\n", (uint64_t)
		       (e->e_phoff+(char *)p-(char *)file->elf_phdr));
#endif
#ifdef __i386__
		fprintf(stdout, "entry image offset:\t\t%016llx\n", (uint64_t)
		       (e->e_phoff+(char *)p-(char *)file->elf_phdr));
#endif
		fprintf(stdout, "program header type:\t\t%08x\n", p->p_type);
		fprintf(stdout, "program header flag:\t\t%08x\n", p->p_flags);
#ifdef __x86_64__
		fprintf(stdout, "program header offs:\t\t%016lx\n",
		       (uint64_t)p->p_offset);
		fprintf(stdout, "program header vadd:\t\t%016lx\n",
		       (uint64_t)p->p_vaddr);
		fprintf(stdout, "program header padd:\t\t%016lx\n",
		       (uint64_t)p->p_paddr);
		fprintf(stdout, "program headr imgsz:\t\t%016lx\n",
		       (uint64_t)p->p_filesz);
		fprintf(stdout, "program header memsz:\t\t%016lx\n",
		       (uint64_t)p->p_memsz);
		fprintf(stdout, "program header align:\t\t%016lx\n",
		       (uint64_t)p->p_align);
#endif
#ifdef __i386__
		fprintf(stdout, "program header offs:\t\t%016llx\n",
		       (uint64_t)p->p_offset);
		fprintf(stdout, "program header vadd:\t\t%016llx\n",
		       (uint64_t)p->p_vaddr);
		fprintf(stdout, "program header padd:\t\t%016llx\n",
		       (uint64_t)p->p_paddr);
		fprintf(stdout, "program headr imgsz:\t\t%016llx\n",
		       (uint64_t)p->p_filesz);
		fprintf(stdout, "program header memsz:\t\t%016llx\n",
		       (uint64_t)p->p_memsz);
		fprintf(stdout, "program header align:\t\t%016llx\n",
		       (uint64_t)p->p_align);
#endif
		fprintf(stdout, "\n");
		p = (Elf64_Phdr *)((char *)p + e->e_phentsize);
	}
}

void dump_elf_phdr(elf_file *file)
{
	if (file->elf_bits == 32)
		dump_elf32_phdr(file);
	else if (file->elf_bits == 64)
		dump_elf64_phdr(file);
}

static char *x_elf_shdr_type(uint32_t type)
{
	switch (type) {
	case SHT_NULL:
		return "shdr inactive, no section";
		break;
	case SHT_PROGBITS:
		return "program self defined info";
		break;
	case SHT_SYMTAB:
		return "symbol table";
		break;
	case SHT_STRTAB:
		return "string table";
		break;
	case SHT_RELA:
		return "relocatable table";
		break;
	case SHT_HASH:
		return "hash table";
		break;
	case SHT_DYNAMIC:
		return "dynamic link info";
		break;
	case SHT_NOTE:
		return "note info";
		break;
	case SHT_NOBITS:
		return "no image space use";
		break;
	case SHT_REL:
		return "relocatable table2";
		break;
	case SHT_SHLIB:
		return "reserved";
		break;
	case SHT_DYNSYM:
		return "dynamic symbols";
		break;
	case SHT_LOPROC:
		return "cpu reserved";
		break;
	case SHT_HIPROC:
		return "cpu reserved2";
		break;
	case SHT_LOUSER:
		return "user reserved";
		break;
	case SHT_HIUSER:
		return "user reserved2";
		break;
	default:
		return "unknown shdr type";
	}
}

static char *x_elf_shdr_flag(uint32_t flag)
{
	switch (flag) {
	case SHF_WRITE:
		return "writable";
		break;
	case SHF_ALLOC:
		return "allocable";
		break;
	case SHF_EXECINSTR:
		return "executable";
		break;
	case SHF_MASKPROC:
		return "cpu specific";
		break;
	case SHF_WRITE | SHF_ALLOC:
		return "writable allocable";
		break;
	case SHF_WRITE | SHF_EXECINSTR:
		return "writable executable";
		break;
	case SHF_WRITE | SHF_MASKPROC:
		return "writable cpu-specific";
		break;
	case SHF_ALLOC | SHF_EXECINSTR:
		return "allocable executable";
		break;
	case SHF_ALLOC | SHF_MASKPROC:
		return "allocable cpu-specific";
		break;
	case SHF_EXECINSTR | SHF_MASKPROC:
		return "executable cpu-specific";
		break;
	case SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR:
		return "writable allocable executable";
		break;
	case SHF_WRITE | SHF_ALLOC | SHF_MASKPROC:
		return "writable allocable cpu-specific";
		break;
	case SHF_WRITE | SHF_EXECINSTR | SHF_MASKPROC:
		return "writable executable cpu-specific";
		break;
	case SHF_ALLOC | SHF_EXECINSTR | SHF_MASKPROC:
		return "allocable executable cpu-specific";
		break;
	case SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR | SHF_MASKPROC:
		return "writable allocable executable cpu-specific";
		break;
	default:
		return "unknown shdr flag";
	}
}

static char *x_elf_shdr_type_flag(uint32_t type, uint32_t flag)
{
	if ((type == SHT_NOBITS) && (flag & (SHF_ALLOC | SHF_WRITE)))
		return ".bss";
	if ((type == SHT_PROGBITS) &&
	    (!(flag & (SHF_ALLOC | SHF_WRITE | SHF_MASKPROC | SHF_EXECINSTR))))
		return ".comment .debug .line";
	if ((type == SHT_PROGBITS) && (flag == (SHF_ALLOC | SHF_WRITE)))
		return ".data .data1";
	if ((type == SHT_DYNAMIC) && (flag == SHF_ALLOC))
		return ".dynamic";
	if ((type == SHT_STRTAB) && (flag == SHF_ALLOC))
		return ".dynstr";
	if ((type == SHT_DYNSYM) && (flag == SHF_ALLOC))
		return ".dynsym";
	if ((type == SHT_PROGBITS) && (flag == (SHF_ALLOC | SHF_EXECINSTR)))
		return ".init .text .fini";
	if ((type == SHT_HASH) && (flag == SHF_ALLOC))
		return ".hash";
	if ((type == SHT_PROGBITS) && (flag == SHF_ALLOC))
		return ".rodata .rodata1";
	if ((type == SHT_SYMTAB))
		return ".symtab";
	if ((type == SHT_STRTAB))
		return ".shstrtab .strtab";
	if ((type == SHT_REL) || (type == SHT_RELA))
		return ".relname .relaname";
	if ((type == SHT_NOTE) &&
	    (!(flag & (SHF_ALLOC | SHF_WRITE | SHF_MASKPROC | SHF_EXECINSTR))))
		return ".note";
	if (type == SHT_PROGBITS)
		return ".got .interp .plt";
	return "maybe .got .interp .plt";
}

static void dump_sechdr(elf_file *file, void *sechdr)
{
	if (file->elf_bits == 32) {
		Elf32_Ehdr *e = file->elf_hdr;
		Elf32_Shdr *s = sechdr;
		fprintf(stdout, "entry image offset:\t\t%08x\n", (uint32_t)
		       (e->e_shoff+(char *)s-(char *)file->elf_shdr));
		fprintf(stdout, "section header name:\t\t%08x\n", s->sh_name);
		fprintf(stdout, "section header type:\t\t%08x\n", s->sh_type);
		fprintf(stdout, "type means:\t\t\t%s\n",x_elf_shdr_type(s->sh_type));
		fprintf(stdout, "section header flag:\t\t%08x\n", s->sh_flags);
		fprintf(stdout, "flag means:\t\t\t%s\n",
					x_elf_shdr_flag(s->sh_flags));
		fprintf(stdout, "type&flag means:\t\t%s\n",
		       x_elf_shdr_type_flag(s->sh_type, s->sh_flags));
		fprintf(stdout, "section header mem_addr:\t%08x\n", s->sh_addr);
		fprintf(stdout, "section header img_offs:\t%08x\n", s->sh_offset);
		fprintf(stdout, "section header sec_size:\t%08x\n", s->sh_size);
		fprintf(stdout, "section header link:\t\t%08x\n", s->sh_link);
		fprintf(stdout, "section header info:\t\t%08x\n", s->sh_info);
		fprintf(stdout, "section header align:\t\t%08x\n", s->sh_addralign);
		fprintf(stdout, "section header entsize:\t\t%08x\n", s->sh_entsize);
		fprintf(stdout, "\n");
		return;
	} else if (file->elf_bits == 64) {
		Elf64_Ehdr *e = file->elf_hdr;
		Elf64_Shdr *s = sechdr;
#ifdef __x86_64__
		fprintf(stdout, "entry image offset:\t\t%016lx\n", (uint64_t)
		       (e->e_shoff+(char *)s-(char *)file->elf_shdr));
#endif
#ifdef __i386__
		fprintf(stdout, "entry image offset:\t\t%016llx\n", (uint64_t)
		       (e->e_shoff+(char *)s-(char *)file->elf_shdr));
#endif
		fprintf(stdout, "section header name:\t\t%08x\n", s->sh_name);
		fprintf(stdout, "section header type:\t\t%08x\n", s->sh_type);
		fprintf(stdout, "type means:\t\t\t%s\n",x_elf_shdr_type(s->sh_type));
#ifdef __x86_64__
		fprintf(stdout, "section header flag:\t\t%016lx\n",
		       (uint64_t)s->sh_flags);
#endif
#ifdef __i386__
		fprintf(stdout, "section header flag:\t\t%016llx\n",
		       (uint64_t)s->sh_flags);
#endif
		fprintf(stdout, "flag means:\t\t\t%s\n",
				x_elf_shdr_flag(s->sh_flags));
		fprintf(stdout, "type&flag means:\t\t%s\n",
		       x_elf_shdr_type_flag(s->sh_type, s->sh_flags));
#ifdef __x86_64__
		fprintf(stdout, "section header mem_addr:\t%016lx\n",
		       (uint64_t)s->sh_addr);
		fprintf(stdout, "section header img_offs:\t%016lx\n",
		       (uint64_t)s->sh_offset);
		fprintf(stdout, "section header sec_size:\t%016lx\n",
		       (uint64_t)s->sh_size);
#endif
#ifdef __i386__
		fprintf(stdout, "section header mem_addr:\t%016llx\n",
		       (uint64_t)s->sh_addr);
		fprintf(stdout, "section header img_offs:\t%016llx\n",
		       (uint64_t)s->sh_offset);
		fprintf(stdout, "section header sec_size:\t%016llx\n",
		       (uint64_t)s->sh_size);
#endif
		fprintf(stdout, "section header link:\t\t%08x\n", s->sh_link);
		fprintf(stdout, "section header info:\t\t%08x\n", s->sh_info);
#ifdef __x86_64__
		fprintf(stdout, "section header align:\t\t%016lx\n",
		       (uint64_t)s->sh_addralign);
		fprintf(stdout, "section header entsize:\t\t%016lx\n",
		       (uint64_t)s->sh_entsize);
#endif
#ifdef __i386__
		fprintf(stdout, "section header align:\t\t%016llx\n",
		       (uint64_t)s->sh_addralign);
		fprintf(stdout, "section header entsize:\t\t%016llx\n",
		       (uint64_t)s->sh_entsize);
#endif
		fprintf(stdout, "\n");
		return;
	} else {
		return;
	}
}

static void dump_elf32_shdr(elf_file *file)
{
	Elf32_Ehdr *e = file->elf_hdr;
	Elf32_Shdr *s = file->elf_shdr;
	if (!s) {
		fprintf(stdout, "elf section header missing\n");
		return;
	}

	uint16_t cnt = e->e_shnum;
	while (cnt--) {
		dump_sechdr(file, s);
#if 0
		fprintf(stdout, "entry image offset:\t\t%08x\n", (uint32_t)
		       (e->e_shoff+(char *)s-(char *)file->elf_shdr));
		fprintf(stdout, "section header name:\t\t%08x\n", s->sh_name);
		fprintf(stdout, "section header type:\t\t%08x\n", s->sh_type);
		fprintf(stdout, "type means:\t\t\t%s\n",x_elf_shdr_type(s->sh_type));
		fprintf(stdout, "section header flag:\t\t%08x\n", s->sh_flags);
		fprintf(stdout, "flag means:\t\t\t%s\n",
				x_elf_shdr_flag(s->sh_flags));
		fprintf(stdout, "type&flag means:\t\t%s\n",
		       x_elf_shdr_type_flag(s->sh_type, s->sh_flags));
		fprintf(stdout, "section header mem_addr:\t%08x\n", s->sh_addr);
		fprintf(stdout, "section header img_offs:\t%08x\n", s->sh_offset);
		fprintf(stdout, "section header sec_size:\t%08x\n", s->sh_size);
		fprintf(stdout, "section header link:\t\t%08x\n", s->sh_link);
		fprintf(stdout, "section header info:\t\t%08x\n", s->sh_info);
		fprintf(stdout, "section header align:\t\t%08x\n", s->sh_addralign);
		fprintf(stdout, "section header entsize:\t\t%08x\n", s->sh_entsize);
		fprintf(stdout, "\n");
#endif
		s = (Elf32_Shdr *)((char *)s + e->e_shentsize);
	}
}

static void dump_elf64_shdr(elf_file *file)
{
	Elf64_Ehdr *e = file->elf_hdr;
	Elf64_Shdr *s = file->elf_shdr;
	if (!s) {
		fprintf(stdout, "elf section header missing\n");
		return;
	}

	uint16_t cnt = e->e_shnum;
	while (cnt--) {
		dump_sechdr(file, s);
#if 0
#ifdef __x86_64__
		fprintf(stdout, "entry image offset:\t\t%016lx\n", (uint64_t)
		       (e->e_shoff+(char *)s-(char *)file->elf_shdr));
#endif
#ifdef __i386__
		fprintf(stdout, "entry image offset:\t\t%016llx\n", (uint64_t)
		       (e->e_shoff+(char *)s-(char *)file->elf_shdr));
#endif
		fprintf(stdout, "section header name:\t\t%08x\n", s->sh_name);
		fprintf(stdout, "section header type:\t\t%08x\n", s->sh_type);
		fprintf(stdout, "type means:\t\t\t%s\n",x_elf_shdr_type(s->sh_type));
#ifdef __x86_64__
		fprintf(stdout, "section header flag:\t\t%016lx\n",
		       (uint64_t)s->sh_flags);
#endif
#ifdef __i386__
		fprintf(stdout, "section header flag:\t\t%016llx\n",
		       (uint64_t)s->sh_flags);
#endif
		fprintf(stdout, "flag means:\t\t\t%s\n",
				x_elf_shdr_flag(s->sh_flags));
		fprintf(stdout, "type&flag means:\t\t%s\n",
		       x_elf_shdr_type_flag(s->sh_type, s->sh_flags));
#ifdef __x86_64__
		fprintf(stdout, "section header mem_addr:\t%016lx\n",
		       (uint64_t)s->sh_addr);
		fprintf(stdout, "section header img_offs:\t%016lx\n",
		       (uint64_t)s->sh_offset);
		fprintf(stdout, "section header sec_size:\t%016lx\n",
		       (uint64_t)s->sh_size);
#endif
#ifdef __i386__
		fprintf(stdout, "section header mem_addr:\t%016llx\n",
		       (uint64_t)s->sh_addr);
		fprintf(stdout, "section header img_offs:\t%016llx\n",
		       (uint64_t)s->sh_offset);
		fprintf(stdout, "section header sec_size:\t%016llx\n",
		       (uint64_t)s->sh_size);
#endif
		fprintf(stdout, "section header link:\t\t%08x\n", s->sh_link);
		fprintf(stdout, "section header info:\t\t%08x\n", s->sh_info);
#ifdef __x86_64__
		fprintf(stdout, "section header align:\t\t%016lx\n",
		       (uint64_t)s->sh_addralign);
		fprintf(stdout, "section header entsize:\t\t%016lx\n",
		       (uint64_t)s->sh_entsize);
#endif
#ifdef __i386__
		fprintf(stdout, "section header align:\t\t%016llx\n",
		       (uint64_t)s->sh_addralign);
		fprintf(stdout, "section header entsize:\t\t%016llx\n",
		       (uint64_t)s->sh_entsize);
#endif
		fprintf(stdout, "\n");
#endif
		s = (Elf64_Shdr *)((char *)s + e->e_shentsize);
	}
}

void dump_elf_shdr(elf_file *file)
{
	if (file->elf_bits == 32)
		dump_elf32_shdr(file);
	else if (file->elf_bits == 64)
		dump_elf64_shdr(file);
}

void dump_elf_shstr(elf_file *file)
{
	fprintf(stdout, ".shstrtab:\n");
	char *start = file->shstrtab;
	if (!start || *start) {
		fprintf(stdout, "no shstrtab OR not start with nul byte\n\n");
		return;
	}

	start++;
	while (1) {
		if (!*start)
			break;
		fprintf(stdout, "%s\n", start);
		start += strlen(start) + 1;
	}
	fprintf(stdout, "\n");
}
void dump_elf_strtab(elf_file *file)
{
	fprintf(stdout, ".strtab:\n");
	char *start = file->strtab;
	if (!start || *start) {
		fprintf(stdout, "no strtab OR not start with nul byte\n\n");
		return;
	}

	start++;
	while (1) {
		if (!*start)
			break;
		fprintf(stdout, "%s\n", start);
		start += strlen(start) + 1;
	}
	fprintf(stdout, "\n");
}
void dump_elf_dynstr(elf_file *file)
{
	fprintf(stdout, ".dynstr:\n");
	char *start = file->dynstr;
	if (!start || *start) {
		fprintf(stdout, "no dynstr OR not start with nul byte\n\n");
		return;
	}

	start++;
	while (1) {
		if (!*start)
			break;
		fprintf(stdout, "%s\n", start);
		start += strlen(start) + 1;
	}
	fprintf(stdout, "\n");
}

static void dump_syms32(Elf32_Sym *sym)
{
	fprintf(stdout, "Sym info\n");
	fprintf(stdout, "st_name: 0x%08x\n", sym->st_name);
	fprintf(stdout, "st_value: 0x%08x\n", sym->st_value);
	fprintf(stdout, "st_size: 0x%08x\n", sym->st_size);
	fprintf(stdout, "st_info: 0x%08x\n", sym->st_info);
	fprintf(stdout, "st_other: 0x%08x\n", sym->st_other);
	fprintf(stdout, "st_shndx: 0x%08x\n", sym->st_shndx);
	fprintf(stdout, "\n");
}
static void dump_syms64(Elf64_Sym *sym)
{
	fprintf(stdout, "Sym info\n");
	fprintf(stdout, "st_name: 0x%08x\n", sym->st_name);
	fprintf(stdout, "st_info: 0x%08x\n", sym->st_info);
	fprintf(stdout, "st_other: 0x%08x\n", sym->st_other);
	fprintf(stdout, "st_shndx: 0x%08x\n", sym->st_shndx);
#ifdef __x86_64__
	fprintf(stdout, "st_value: 0x%016lx\n", sym->st_value);
	fprintf(stdout, "st_size: 0x%016lx\n", sym->st_size);
#endif
#ifdef __i386__
	fprintf(stdout, "st_value: 0x%016llx\n", sym->st_value);
	fprintf(stdout, "st_size: 0x%016llx\n", sym->st_size);
#endif
	fprintf(stdout, "\n");
}
void dump_elf_sym(elf_file *file)
{
	struct _elf_sym *es;
	list_comm *n;
	list_for_each_entry(n, &file->syms, list_head) {
		es = (void *)n->data;
		if (file->elf_bits == 32) {
			Elf32_Sym *sym = es->data;
			fprintf(stdout, "%s\n", es->name);
			dump_syms32(sym);
		} else if (file->elf_bits == 64) {
			Elf64_Sym *sym = es->data;
			fprintf(stdout, "%s\n", es->name);
			dump_syms64(sym);
		} else {
			continue;
		}
	}
}
void dump_elf_dynsym(elf_file *file)
{
	struct _elf_sym *es;
	list_comm *n;
	list_for_each_entry(n, &file->dynsyms, list_head) {
		es = (void *)n->data;
		if (file->elf_bits == 32) {
			Elf32_Sym *sym = es->data;
			fprintf(stdout, "%s\n", es->name);
			dump_syms32(sym);
		} else if (file->elf_bits == 64) {
			Elf64_Sym *sym = es->data;
			fprintf(stdout, "%s\n", es->name);
			dump_syms64(sym);
		} else {
			continue;
		}
	}
}

#ifdef USELIB
/*
 * use sys_uselib to load elf library at specific address
 * check SYSCALL_DEFINE1(uselib, ...)
 * an example: https://github.com/ganboing/ski-uselib/blob/master/mklib.c
 * TODO: sys_uselib return function not implement
 */
int elf_uselib(char *libname, unsigned long load_addr)
{
	/*
	 * TODO:
	 *	(MAY NOT need)check libname whether an elf library or not
	 *	modify elf header, section header
	 *	call sys_uselib
	 */
	int err = 0;
	elf_file *ef = elf_parse(libname, O_RDWR);
	if (!ef) {
		err_dbg(0, "elf_pars err");
		return -1;
	}

	long subval = 0;
#ifdef __x86_64__
	Elf64_Ehdr *eh = ef->elf_hdr;
	if (!eh->e_phnum) {
		err_dbg(0, "%s has no program headers");
		elf_cleanup(ef);
		return -1;
	}
	uint16_t cnt = eh->e_phnum;
	Elf64_Phdr *p = ef->elf_phdr;
	subval = load_addr - p->p_vaddr;
	while (cnt--) {
		if (p->p_type != PT_LOAD)
			goto next_loop;
		if (!(p->p_flags & PF_X))
			goto next_loop;
		p->p_vaddr = subval + p->p_vaddr;
next_loop:
		p = (Elf64_Phdr *)((void *)p + eh->e_phentsize);
	}

	err = lseek(ef->file->fd, eh->e_phoff, SEEK_SET);
	if (err < 0) {
		err_dbg(1, "lseek err");
		elf_cleanup(ef);
		return -1;
	}
	err = write(ef->file->fd, ef->elf_phdr, ef->elf_phdr_size);
	if (err < 0) {
		err_dbg(0, "write err");
		elf_cleanup(ef);
		return -1;
	}
	elf_cleanup(ef);
#elif defined(__i386__)
	Elf32_Ehdr *eh = ef->elf_hdr;
	if (!eh->e_phnum) {
		err_dbg(0, "%s has no program headers");
		elf_cleanup(ef);
		return -1;
	}
	uint16_t cnt = eh->e_phnum;
	Elf32_Phdr *p = ef->elf_phdr;
	subval = load_addr - p->p_vaddr;
	while (cnt--) {
		if (p->p_type != PT_LOAD)
			goto next_loop;
		if (!(p->p_flags & PF_X))
			goto next_loop;
		p->p_vaddr = subval + p->p_vaddr;
next_loop:
		p = (Elf32_Phdr *)((void *)p + eh->e_phentsize);
	}

	err = lseek(ef->file->fd, eh->e_phoff, SEEK_SET);
	if (err < 0) {
		err_dbg(0, "lseek err");
		elf_cleanup(ef);
		return -1;
	}
	err = write(ef->file->fd, ef->elf_phdr, ef->elf_phdr_size);
	if (err < 0) {
		err_dbg(0, "write err");
		elf_cleanup(ef);
		return -1;
	}
	elf_cleanup(ef);
#else
	err_msg("file format not recognized");
	return -1;
#endif

	err = syscall(__NR_uselib, libname);
	if (err == -1) {
		err_dbg(1, "uselib err");
		return -1;
	}
	return 0;
}
#endif
