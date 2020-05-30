/*
 * Maybe we should use libelf(elfutils) instead
 *
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

static int elf_check_magic(char *buf)
{
	if ((buf[EI_MAG0] == 0x7f) &&
		(buf[EI_MAG1] == 0x45) &&
		(buf[EI_MAG2] == 0x4c) &&
		(buf[EI_MAG3] == 0x46))
		return 1;
	return 0;
}

static int elf_check_endian(char *buf)
{
	char c = buf[EI_DATA];
	if (c == ELFDATA2LSB)
		return 1;
	err_dbg(0, "EI_DATA endian not implemented.");
	return 0;
}

static int elf_check_osabi(char *buf)
{
	char c = buf[EI_OSABI];

	switch (c) {
	case ELFOSABI_LINUX:
	case ELFOSABI_SYSV:
	case ELFOSABI_NETBSD:
	case ELFOSABI_SOLARIS:
	case ELFOSABI_FREEBSD:
		return 1;
	default:
		err_dbg(0, "EI_OSABI not implemented.");
		return 0;
	}
}

static int elf_check_machine(char *buf)
{
	int offset = 0x12;
	uint16_t machine = *(uint16_t *)&buf[offset];

	switch (machine) {
	case EM_386:
	case EM_860:
	case EM_X86_64:
		return 1;
	default:
		err_dbg(0, "e_machine not implemented.");
		return 0;
	}
}

static int elf_valid(char *buf)
{
	int rv = 0;

	rv = elf_check_magic(buf);
	if (!rv)
		return rv;

	rv = elf_check_endian(buf);
	if (!rv)
		return rv;

	rv = elf_check_osabi(buf);
	if (!rv)
		return rv;

	rv = elf_check_machine(buf);
	if (!rv)
		return rv;

	return rv;
}

static int add_symbol(struct list_head *head, char *name, void *data)
{
	struct _elf_sym sym;
	sym.name = name;
	sym.data = data;
	return list_comm_new_append(head, &sym, sizeof(sym));
}

static int add_symbols(elf_file *ef, struct list_head *head,
			void *shsym, char *str)
{
	int err;
	char *start;
	size_t cnt;
	char *rdata = bin_rdata(ef->file);
	switch (ef->elf_bits) {
	case 32:
	{
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
	}
	case 64:
	{
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
	default:
		return 0;
	}

err_out:
	list_comm_cleanup(head, NULL);
	return -1;
}

static int parse_elf32(elf_file *ef, char *buf)
{
	int err;

	Elf32_Ehdr *eh = (Elf32_Ehdr *)buf;
	ef->elf_hdr = eh;
	ef->elf_hdr_size = eh->e_ehsize;

	ef->elf_text_entry = (uint64_t)eh->e_entry;

	ef->elf_phdr_size = eh->e_phnum * eh->e_phentsize;
	if (!ef->elf_phdr_size)
		ef->elf_phdr = NULL;
	else
		ef->elf_phdr = buf + eh->e_phoff;

	ef->elf_shdr_size = eh->e_shentsize * eh->e_shnum;
	if (!ef->elf_shdr_size)
		ef->elf_shdr = NULL;
	else
		ef->elf_shdr = buf + eh->e_shoff;

	Elf32_Shdr *shstr, *strtab, *symtab, *dynstr, *dynsym;

	/*
	 * INFO, get shstrtab
	 * TODO, check this member if SHN_UNDEF, OR larger than or equal
	 *	SHN_LORESERVE
	 */
	if (eh->e_shstrndx == SHN_UNDEF) {
		err_dbg(0, "elf has no section name string table");
		return -1;
	}
	shstr = get_sh_by_id(ef, eh->e_shstrndx);
	ef->shstrtab = shstr->sh_offset + buf;

	/*
	 * INFO, get strtab
	 */
	strtab = get_sh_by_name(ef, ".strtab");
	if (!strtab) {
		err_dbg(0, "elf has no .strtab?");
	} else {
		ef->strtab = strtab->sh_offset + buf;

		/*
		 * INFO, get symtab
		 */
		symtab = get_sh_by_name(ef, ".symtab");
		if (!symtab) {
			err_dbg(0, "elf has no .symtab?");
			return -1;
		}
		err = add_symbols(ef, &ef->syms, symtab, ef->strtab);
		if (err == -1) {
			err_dbg(0, "add_symbols err");
			return -1;
		}
	}

	/*
	 * INFO: get dynstr
	 */
	dynstr = get_sh_by_name(ef, ".dynstr");
	if (!dynstr) {
		err_dbg(0, "elf has no .dynstr?");
	} else {
		ef->dynstr = dynstr->sh_offset + buf;

		/*
		 * INFO: get dynsym
		 */
		dynsym = get_sh_by_name(ef, ".dynsym");
		if (!dynsym) {
			err_dbg(0, "elf has no .dynsym");
			goto err_free3;
		}
		err = add_symbols(ef, &ef->dynsyms, dynsym, ef->dynstr);
		if (err == -1) {
			err_dbg(0, "add_symbols err");
			goto err_free3;
		}
	}

	return 0;

err_free3:
	list_comm_cleanup(&ef->syms, NULL);
	return -1;
}

static int parse_elf64(elf_file *ef, char *buf)
{
	int err = 0;

	Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
	ef->elf_hdr = eh;
	ef->elf_hdr_size = eh->e_ehsize;

	ef->elf_text_entry = (uint64_t)eh->e_entry;

	ef->elf_phdr_size = eh->e_phnum * eh->e_phentsize;
	if (!ef->elf_phdr_size)
		ef->elf_phdr = NULL;
	else
		ef->elf_phdr = buf + eh->e_phoff;

	ef->elf_shdr_size = eh->e_shentsize * eh->e_shnum;
	if (!ef->elf_shdr_size)
		ef->elf_shdr = NULL;
	else
		ef->elf_shdr = buf + eh->e_shoff;

	Elf64_Shdr *shstr, *strtab, *symtab, *dynstr, *dynsym;

	/*
	 * INFO, get shstrtab
	 * TODO, check this member if SHN_UNDEF, OR larger than or equal
	 *	SHN_LORESERVE
	 */
	if (eh->e_shstrndx == SHN_UNDEF) {
		err_dbg(0, "elf has no section name string table");
		return -1;
	}
	shstr = get_sh_by_id(ef, eh->e_shstrndx);
	ef->shstrtab = shstr->sh_offset + buf;

	/*
	 * INFO, get strtab
	 */
	strtab = get_sh_by_name(ef, ".strtab");
	if (!strtab) {
		err_dbg(0, "elf has no .strtab?");
	} else {
		ef->strtab = strtab->sh_offset + buf;

		/*
		 * INFO, get symtab
		 */
		symtab = get_sh_by_name(ef, ".symtab");
		if (!symtab) {
			err_dbg(0, "elf has no .symtab?");
			return -1;
		}
		err = add_symbols(ef, &ef->syms, symtab, ef->strtab);
		if (err == -1) {
			err_dbg(0, "add_symbols err");
			return -1;
		}
	}

	/*
	 * INFO: get dynstr
	 */
	dynstr = get_sh_by_name(ef, ".dynstr");
	if (!dynstr) {
		err_dbg(0, "elf has no .dynstr?");
	} else {
		ef->dynstr = dynstr->sh_offset + buf;

		/*
		 * INFO: get dynsym
		 */
		dynsym = get_sh_by_name(ef, ".dynsym");
		if (!dynsym) {
			err_dbg(0, "elf has no .dynsym");
			goto err_free3;
		}
		err = add_symbols(ef, &ef->dynsyms, dynsym, ef->dynstr);
		if (err == -1) {
			err_dbg(0, "add_symbols err");
			goto err_free3;
		}
	}

	return 0;

err_free3:
	list_comm_cleanup(&ef->syms, NULL);
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
	if (!elf_valid(buf)) {
		err_dbg(0, "elf_valid() check failed");
		err = -1;
		goto free_ret2;
	}

	ef->elf_bits = elf_bits(buf);
	if (ef->elf_bits == 32)
		err = parse_elf32(ef, buf);
	else if (ef->elf_bits == 64)
		err = parse_elf64(ef, buf);

	if (!err)
		goto ret;
free_ret2:
	regfile_close(ef->file);
free_ret:
	free(ef);
ret:
	return (err == -1) ? NULL : ef;
}

elf_file *elf_parse_data(void *ctx)
{
	int err;
	if (!elf_valid(ctx)) {
		err_dbg(0, "elf_valid() check failed");
		err = -1;
		goto ret;
	}

	elf_file *ef = (elf_file *)malloc(sizeof(elf_file));
	if (!ef) {
		err = -1;
		err_dbg(0, "malloc err");
		goto ret;
	}
	memset(ef, 0, sizeof(elf_file));
	INIT_LIST_HEAD(&ef->syms);
	INIT_LIST_HEAD(&ef->dynsyms);

	ef->file = regfile_open_fake(REGFILE_T_BIN);
	if (!ef->file) {
		err_dbg(1, "regfile_open err");
		err = -1;
		goto free_elf;
	}
	bin_rdata(ef->file) = ctx;

	char *buf = (char *)ctx;
	ef->elf_bits = elf_bits(buf);
	if (ef->elf_bits == 32)
		err = parse_elf32(ef, buf);
	else if (ef->elf_bits == 64)
		err = parse_elf64(ef, buf);

	if (!err)
		goto ret;

	regfile_close(ef->file);
free_elf:
	free(ef);
ret:
	return (err == -1) ? NULL : ef;
}

int elf_cleanup(elf_file *file)
{
	if (!file)
		return -1;
	regfile_close(file->file);
	list_comm_cleanup(&file->syms, NULL);
	list_comm_cleanup(&file->dynsyms, NULL);
	free(file);
	return 0;
}

/*
 * get all elf symbols, use _elf_sym_full
 */
int elf_get_syms(elf_file *ef, struct list_head *head)
{
	INIT_LIST_HEAD(head);
	list_comm *tmp;
	struct _elf_sym_full *_new;
	list_for_each_entry(tmp, &ef->syms, list_head) {
		struct _elf_sym *sym = (struct _elf_sym *)tmp->data;
		_new = (struct _elf_sym_full *)malloc(sizeof(*_new));
		_new->name = malloc(strlen(sym->name)+1);
		memcpy(_new->name, sym->name, strlen(sym->name)+1);
		if (ef->elf_bits == 32)
			memcpy((char *)&_new->data.sym0,
				(char *)sym->data, sizeof(Elf32_Sym));
		else if (ef->elf_bits == 64)
			memcpy((char *)&_new->data.sym1,
				(char *)sym->data, sizeof(Elf64_Sym));
		else {
			err_dbg(0, "Not support: %d\n", ef->elf_bits);
			return -1;
		}
		list_add_tail(&_new->sibling, head);
	}

	list_for_each_entry(tmp, &ef->dynsyms, list_head) {
		struct _elf_sym *sym = (struct _elf_sym *)tmp->data;
		_new = (struct _elf_sym_full *)malloc(sizeof(*_new));
		_new->name = malloc(strlen(sym->name)+1);
		memcpy(_new->name, sym->name, strlen(sym->name)+1);
		if (ef->elf_bits == 32)
			memcpy((char *)&_new->data.sym0,
				(char *)sym->data, sizeof(Elf32_Sym));
		else if (ef->elf_bits == 64)
			memcpy((char *)&_new->data.sym1,
				(char *)sym->data, sizeof(Elf64_Sym));
		else {
			err_dbg(0, "Not support: %d\n", ef->elf_bits);
			return -1;
		}
		list_add_tail(&_new->sibling, head);
	}

	return 0;
}

int elf_get_syms_path(char *path, struct list_head *head, uint8_t *bits)
{
	int err = 0;
	elf_file *ef = elf_parse(path, O_RDONLY);
	if (!ef) {
		err_dbg(0, "elf_parse err");
		return -1;
	}

	err = elf_get_syms(ef, head);
	if (err == -1) {
		err_dbg(0, "elf_get_syms err");
	}

	*bits = ef->elf_bits;
	elf_cleanup(ef);
	return err;
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

void get_sym_detail(elf_file *ef, struct _elf_sym_full *sym)
{
	int type = elf_type(ef);
	char *buf = bin_rdata(ef->file);

	sym->bind = sym_bind(ef, sym);
	sym->type = sym_type(ef, sym);
	sym->size = sym_size(ef, sym);

	switch (type) {
	case ET_REL:
	{
		switch (ef->elf_bits) {
		case 32:
		{
			Elf32_Sym s = sym->data.sym0;
			if (s.st_shndx == SHN_COMMON)
				break;
			Elf32_Shdr *shdr = get_sh_by_id(ef, s.st_shndx);
			if (!shdr)
				break;
			void *taddr = shdr->sh_offset + buf;
			sym->load_addr = taddr + s.st_value;
			break;
		}
		case 64:
		{
			Elf64_Sym s = sym->data.sym1;
			if (s.st_shndx == SHN_COMMON)
				break;
			Elf64_Shdr *shdr = get_sh_by_id(ef, s.st_shndx);
			if (!shdr)
				break;
			void *taddr = shdr->sh_offset + buf;
			sym->load_addr = taddr + s.st_value;
			break;
		}
		default:
			break;
		}
		break;
	}
	case ET_EXEC:
	case ET_DYN:
	{
		switch (ef->elf_bits) {
		case 32:
		{
			Elf32_Sym s = sym->data.sym0;
			if (s.st_shndx == SHN_UNDEF)
				break;
			sym->load_addr = buf + s.st_value;
			break;
		}
		case 64:
		{
			Elf64_Sym s = sym->data.sym1;
			if (s.st_shndx == SHN_UNDEF)
				break;
			sym->load_addr = buf + s.st_value;
			break;
		}
		default:
			break;
		}
		break;
	}
	default:
	{
		break;
	}
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

/*
 * ************************************************************************
 * The following functions use libelf library
 * check https://www.zybuluo.com/devilogic/note/139554 for interfaces
 * ************************************************************************
 */
