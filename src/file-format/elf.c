#include "../../include/elf.h"

static int do_elf_id(char *buf)
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

static int do_elf_file32(elf_file *file, char *buf)
{
	file->elf_bits = 32;

	file->elf_hdr_size = sizeof(Elf32_Ehdr);
	file->elf_hdr = (Elf32_Ehdr *)malloc(file->elf_hdr_size);
	if (!file->elf_hdr)
		return err_ret(0, -1, err_fmt("malloc err"));
	memset(file->elf_hdr, 0, file->elf_hdr_size);
	memcpy(file->elf_hdr, buf, file->elf_hdr_size);

	Elf32_Ehdr *tmp = file->elf_hdr;
	file->elf_machine = (uint16_t)tmp->e_machine;
	file->elf_text_entry = (uint64_t)tmp->e_entry;

	/* some test before getting the program header */
	if (tmp->e_ehsize != sizeof(Elf32_Ehdr))
		err_dbg(0, err_fmt("elf header size abnormal"));
	if (tmp->e_phoff != sizeof(Elf32_Ehdr))
		err_dbg(0, err_fmt("program header offset abnormal"));
	if (tmp->e_phentsize != sizeof(Elf32_Phdr))
		err_dbg(0, err_fmt("program header entsize abnormal"));

	file->elf_phdr_size = tmp->e_phnum * tmp->e_phentsize;
	if (!file->elf_phdr_size)
		file->elf_phdr = NULL;
	else {
		file->elf_phdr = (Elf32_Phdr *)malloc(file->elf_phdr_size);
		if (!file->elf_phdr) {
			free(file->elf_hdr);
			err_dbg(0, err_fmt("malloc err"));
			return -1;
		}
		memset(file->elf_phdr, 0, file->elf_phdr_size);
		memcpy(file->elf_phdr, buf+tmp->e_phoff, file->elf_phdr_size);
	}

	if (tmp->e_shentsize != sizeof(Elf32_Shdr))
		err_dbg(0, err_fmt("section header entsize abnormal"));
	file->elf_shdr_size = tmp->e_shentsize * tmp->e_shnum;
	if (!file->elf_shdr_size)
		file->elf_shdr = NULL;
	else {
		file->elf_shdr = (Elf32_Shdr *)malloc(file->elf_shdr_size);
		if (!file->elf_shdr) {
			free(file->elf_hdr);
			free(file->elf_phdr);
			err_dbg(0, err_fmt("malloc err"));
			return -1;
		}
		memset(file->elf_shdr, 0, file->elf_shdr_size);
		memcpy(file->elf_shdr, buf+tmp->e_shoff, file->elf_shdr_size);
	}
	return 0;
}

static int do_elf_file64(elf_file *file, char *buf)
{
	file->elf_bits = 64;

	file->elf_hdr_size = sizeof(Elf64_Ehdr);
	file->elf_hdr = (Elf64_Ehdr *)malloc(file->elf_hdr_size);
	if (!file->elf_hdr)
		return err_ret(0, -1, err_fmt("malloc err"));
	memset(file->elf_hdr, 0, file->elf_hdr_size);
	memcpy(file->elf_hdr, buf, file->elf_hdr_size);

	Elf64_Ehdr *tmp = file->elf_hdr;
	file->elf_machine = (uint16_t)tmp->e_machine;
	file->elf_text_entry = (uint64_t)tmp->e_entry;

	/* some test before getting the program header */
	if (tmp->e_ehsize != sizeof(Elf64_Ehdr))
		err_dbg(0, err_fmt("elf header size abnormal"));
	if (tmp->e_phoff != sizeof(Elf64_Ehdr))
		err_dbg(0, err_fmt("program header offset abnormal"));
	if (tmp->e_phentsize != sizeof(Elf64_Phdr))
		err_dbg(0, err_fmt("program header entsize abnormal"));

	file->elf_phdr_size = tmp->e_phnum * tmp->e_phentsize;
	if (!file->elf_phdr_size)
		file->elf_phdr = NULL;
	else {
		file->elf_phdr = (Elf64_Phdr *)malloc(file->elf_phdr_size);
		if (!file->elf_phdr) {
			free(file->elf_hdr);
			err_dbg(0, err_fmt("malloc err"));
			return -1;
		}
		memset(file->elf_phdr, 0, file->elf_phdr_size);
		memcpy(file->elf_phdr, buf+tmp->e_phoff, file->elf_phdr_size);
	}

	if (tmp->e_shentsize != sizeof(Elf64_Shdr))
		err_dbg(0, err_fmt("section header entsize abnormal"));
	file->elf_shdr_size = tmp->e_shentsize * tmp->e_shnum;
	if (!file->elf_shdr_size)
		file->elf_shdr = NULL;
	else {
		file->elf_shdr = (Elf64_Shdr *)malloc(file->elf_shdr_size);
		if (!file->elf_shdr) {
			free(file->elf_hdr);
			free(file->elf_phdr);
			err_dbg(0, err_fmt("malloc err"));
			return -1;
		}
		memset(file->elf_shdr, 0, file->elf_shdr_size);
		memcpy(file->elf_shdr, buf+tmp->e_shoff, file->elf_shdr_size);
	}
	return 0;
}

elf_file *do_elf_file(char *path)
{
	int err;
	elf_file *ef = (elf_file *)malloc(sizeof(elf_file));
	if (!ef) {
		err = -1;
		err_dbg(0, err_fmt("malloc err"));
		goto ret;
	}
	memset(ef, 0, sizeof(elf_file));

	ef->file = text_open(path, O_RDONLY);
	if (!ef->file) {
		err_dbg(1, err_fmt("text_open err"));
		err = -1;
		goto free_ret;
	}

	err = text_readall(ef->file);
	if (err == -1) {
		err_dbg(1, err_fmt("text_readall err"));
		err = -1;
		goto free_ret2;
	}

	list_comm *rhead = (list_comm *)ef->file->file.rdata;
	list_comm *tmp = (list_comm *)(rhead->list_head.next);
	line_struct *tmp_buf = (line_struct *)tmp->extra;
	char *buf = tmp_buf->str;
	if (!buf) {
		err_dbg(0, err_fmt("file data err"));
		err = -1;
		goto free_ret2;
	}

	err = do_elf_id(buf);
	if (err == -1) {
		err_dbg(0, err_fmt("file format err"));
		err = -1;
		goto free_ret2;
	}

	if (err == 32)
		err = do_elf_file32(ef, buf);
	else if (err == 64)
		err = do_elf_file64(ef, buf);

	if (err == -1)
		goto free_ret2;
	else
		goto ret;
free_ret2:
	text_close(ef->file);
free_ret:
	free(ef);
ret:
	return (err == -1) ? NULL : ef;
}

int done_elf_file(elf_file *file)
{
	if (!file)
		return -1;
	text_close(file->file);
	free(file->elf_hdr);
	free(file->elf_phdr);
	free(file->elf_shdr);
	return 0;
}

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

static void dump_elf_ehdr32(elf_file *file)
{
	Elf32_Ehdr *ehdr = file->elf_hdr;
	if (!ehdr) {
		printf("elf file header missing\n");
		return;
	}

	printf("header identify:\t\t");
	dump_mem((char *)ehdr->e_ident, EI_NIDENT);
	printf("program bits:\t\t\t32 bits\n");
	printf("program endian:\t\t\t%s\n",(ehdr->e_ident[5]-1)?"big":"little");
	printf("program os ABI:\t\t\t%s\n", x_elf_oabi(ehdr->e_ident[7]));
	printf("program header padding:\t\t");
	dump_mem((char *)&ehdr->e_ident[8], 8);
	printf("program type:\t\t\t%s\n", x_elf_type(ehdr->e_type));
	printf("program machine:\t\t%s\n", x_elf_machine(ehdr->e_machine));
	printf("program file hdr size:\t\t%04x\n", ehdr->e_ehsize);
	printf("program text entry:\t\t%08x\n", ehdr->e_entry);
	printf("program header off:\t\t%08x\n", ehdr->e_phoff);
	printf("program header size:\t\t%04x\n", ehdr->e_phentsize);
	printf("program header cnt:\t\t%04x\n", ehdr->e_phnum);
	printf("section header off:\t\t%08x\n", ehdr->e_shoff);
	printf("section header size:\t\t%04x\n", ehdr->e_shentsize);
	printf("section header cnt:\t\t%04x\n", ehdr->e_shnum);
	printf("section header idx:\t\t%04x\n", ehdr->e_shstrndx);
	printf("program flags:\t\t\t%08x\n", ehdr->e_flags);
	printf("\n");
}

static void dump_elf_ehdr64(elf_file *file)
{
	Elf64_Ehdr *ehdr = file->elf_hdr;
	if (!ehdr) {
		printf("elf file header missing\n");
		return;
	}

	printf("header identify:\t\t");
	dump_mem((char *)ehdr->e_ident, EI_NIDENT);
	printf("program bits:\t\t\t64 bits\n");
	printf("program endian:\t\t\t%s\n",(ehdr->e_ident[5]-1)?"big":"little");
	printf("program os ABI:\t\t\t%s\n", x_elf_oabi(ehdr->e_ident[7]));
	printf("program header padding:\t\t");
	dump_mem((char *)&ehdr->e_ident[8], 8);
	printf("program type:\t\t\t%s\n", x_elf_type(ehdr->e_type));
	printf("program machine:\t\t%s\n", x_elf_machine(ehdr->e_machine));
	printf("program file hdr size:\t\t%04x\n", ehdr->e_ehsize);
#ifdef __x86_64__
	printf("program text entry:\t\t%016lx\n", (uint64_t)ehdr->e_entry);
	printf("program header off:\t\t%016lx\n", (uint64_t)ehdr->e_phoff);
#endif
#ifdef __i386__
	printf("program text entry:\t\t%016llx\n", (uint64_t)ehdr->e_entry);
	printf("program header off:\t\t%016llx\n", (uint64_t)ehdr->e_phoff);
#endif
	printf("program header size:\t\t%04x\n", ehdr->e_phentsize);
	printf("program header cnt:\t\t%04x\n", ehdr->e_phnum);
#ifdef __x86_64__
	printf("section header off:\t\t%016lx\n", (uint64_t)ehdr->e_shoff);
#endif
#ifdef __i386__
	printf("section header off:\t\t%016llx\n", (uint64_t)ehdr->e_shoff);
#endif
	printf("section header size:\t\t%04x\n", ehdr->e_shentsize);
	printf("section header cnt:\t\t%04x\n", ehdr->e_shnum);
	printf("section header idx:\t\t%04x\n", ehdr->e_shstrndx);
	printf("program flags:\t\t\t%08x\n", ehdr->e_flags);
	printf("\n");
}

void dump_elf_ehdr(elf_file *file)
{
	/* this function print the elf file header */
	if (file->elf_bits == 32)
		dump_elf_ehdr32(file);
	else if (file->elf_bits == 64)
		dump_elf_ehdr64(file);
}

static void dump_elf_phdr32(elf_file *file)
{
	Elf32_Ehdr *e = file->elf_hdr;
	Elf32_Phdr *p = file->elf_phdr;
	if (!p) {
		printf("file program header missing\n");
		return;
	}

	uint16_t cnt = e->e_phnum;
	while (cnt--) {
		printf("entry image offset:\t\t%08x\n", (uint32_t)
		       (e->e_phoff+(char *)p-(char *)file->elf_phdr));
		printf("program header type:\t\t%08x\n", p->p_type);
		printf("program header offs:\t\t%08x\n", p->p_offset);
		printf("program header vadd:\t\t%08x\n", p->p_vaddr);
		printf("program header padd:\t\t%08x\n", p->p_paddr);
		printf("program header imgsize:\t\t%08x\n", p->p_filesz);
		printf("program header memsize:\t\t%08x\n", p->p_memsz);
		printf("program header flag:\t\t%08x\n", p->p_flags);
		printf("program header align:\t\t%08x\n", p->p_align);
		printf("\n");
		p = (Elf32_Phdr *)((char *)p + e->e_phentsize);
	}
}

static void dump_elf_phdr64(elf_file *file)
{
	Elf64_Ehdr *e = file->elf_hdr;
	Elf64_Phdr *p = file->elf_phdr;
	if (!p) {
		printf("file program header missing\n");
		return;
	}

	uint16_t cnt = e->e_phnum;
	while (cnt--) {
#ifdef __x86_64__
		printf("entry image offset:\t\t%016lx\n", (uint64_t)
		       (e->e_phoff+(char *)p-(char *)file->elf_phdr));
#endif
#ifdef __i386__
		printf("entry image offset:\t\t%016llx\n", (uint64_t)
		       (e->e_phoff+(char *)p-(char *)file->elf_phdr));
#endif
		printf("program header type:\t\t%08x\n", p->p_type);
		printf("program header flag:\t\t%08x\n", p->p_flags);
#ifdef __x86_64__
		printf("program header offs:\t\t%016lx\n",
		       (uint64_t)p->p_offset);
		printf("program header vadd:\t\t%016lx\n",
		       (uint64_t)p->p_vaddr);
		printf("program header padd:\t\t%016lx\n",
		       (uint64_t)p->p_paddr);
		printf("program headr imgsz:\t\t%016lx\n",
		       (uint64_t)p->p_filesz);
		printf("program header memsz:\t\t%016lx\n",
		       (uint64_t)p->p_memsz);
		printf("program header align:\t\t%016lx\n",
		       (uint64_t)p->p_align);
#endif
#ifdef __i386__
		printf("program header offs:\t\t%016llx\n",
		       (uint64_t)p->p_offset);
		printf("program header vadd:\t\t%016llx\n",
		       (uint64_t)p->p_vaddr);
		printf("program header padd:\t\t%016llx\n",
		       (uint64_t)p->p_paddr);
		printf("program headr imgsz:\t\t%016llx\n",
		       (uint64_t)p->p_filesz);
		printf("program header memsz:\t\t%016llx\n",
		       (uint64_t)p->p_memsz);
		printf("program header align:\t\t%016llx\n",
		       (uint64_t)p->p_align);
#endif
		printf("\n");
		p = (Elf64_Phdr *)((char *)p + e->e_phentsize);
	}
}

void dump_elf_phdr(elf_file *file)
{
	if (file->elf_bits == 32)
		dump_elf_phdr32(file);
	else if (file->elf_bits == 64)
		dump_elf_phdr64(file);
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

static void dump_elf_shdr32(elf_file *file)
{
	Elf32_Ehdr *e = file->elf_hdr;
	Elf32_Shdr *s = file->elf_shdr;
	if (!s) {
		printf("elf section header missing\n");
		return;
	}

	uint16_t cnt = e->e_shnum;
	while (cnt--) {
		printf("entry image offset:\t\t%08x\n", (uint32_t)
		       (e->e_shoff+(char *)s-(char *)file->elf_shdr));
		printf("section header name:\t\t%08x\n", s->sh_name);
		printf("section header type:\t\t%08x\n", s->sh_type);
		printf("type means:\t\t\t%s\n", x_elf_shdr_type(s->sh_type));
		printf("section header flag:\t\t%08x\n", s->sh_flags);
		printf("flag means:\t\t\t%s\n", x_elf_shdr_flag(s->sh_flags));
		printf("type&flag means:\t\t%s\n",
		       x_elf_shdr_type_flag(s->sh_type, s->sh_flags));
		printf("section header mem_addr:\t%08x\n", s->sh_addr);
		printf("section header img_offs:\t%08x\n", s->sh_offset);
		printf("section header sec_size:\t%08x\n", s->sh_size);
		printf("section header link:\t\t%08x\n", s->sh_link);
		printf("section header info:\t\t%08x\n", s->sh_info);
		printf("section header align:\t\t%08x\n", s->sh_addralign);
		printf("section header entsize:\t\t%08x\n", s->sh_entsize);
		printf("\n");
		s = (Elf32_Shdr *)((char *)s + e->e_shentsize);
	}
}

static void dump_elf_shdr64(elf_file *file)
{
	Elf64_Ehdr *e = file->elf_hdr;
	Elf64_Shdr *s = file->elf_shdr;
	if (!s) {
		printf("elf section header missing\n");
		return;
	}

	uint16_t cnt = e->e_shnum;
	while (cnt--) {
		if ((e->e_shnum - cnt - 1) == e->e_shstrndx)
			printf("entry is String Table\n");
#ifdef __x86_64__
		printf("entry image offset:\t\t%016lx\n", (uint64_t)
		       (e->e_shoff+(char *)s-(char *)file->elf_shdr));
#endif
#ifdef __i386__
		printf("entry image offset:\t\t%016llx\n", (uint64_t)
		       (e->e_shoff+(char *)s-(char *)file->elf_shdr));
#endif
		printf("section header name:\t\t%08x\n", s->sh_name);
		printf("section header type:\t\t%08x\n", s->sh_type);
		printf("type means:\t\t\t%s\n", x_elf_shdr_type(s->sh_type));
#ifdef __x86_64__
		printf("section header flag:\t\t%016lx\n",
		       (uint64_t)s->sh_flags);
#endif
#ifdef __i386__
		printf("section header flag:\t\t%016llx\n",
		       (uint64_t)s->sh_flags);
#endif
		printf("flag means:\t\t\t%s\n", x_elf_shdr_flag(s->sh_flags));
		printf("type&flag means:\t\t%s\n",
		       x_elf_shdr_type_flag(s->sh_type, s->sh_flags));
#ifdef __x86_64__
		printf("section header mem_addr:\t%016lx\n",
		       (uint64_t)s->sh_addr);
		printf("section header img_offs:\t%016lx\n",
		       (uint64_t)s->sh_offset);
		printf("section header sec_size:\t%016lx\n",
		       (uint64_t)s->sh_size);
#endif
#ifdef __i386__
		printf("section header mem_addr:\t%016llx\n",
		       (uint64_t)s->sh_addr);
		printf("section header img_offs:\t%016llx\n",
		       (uint64_t)s->sh_offset);
		printf("section header sec_size:\t%016llx\n",
		       (uint64_t)s->sh_size);
#endif
		printf("section header link:\t\t%08x\n", s->sh_link);
		printf("section header info:\t\t%08x\n", s->sh_info);
#ifdef __x86_64__
		printf("section header align:\t\t%016lx\n",
		       (uint64_t)s->sh_addralign);
		printf("section header entsize:\t\t%016lx\n",
		       (uint64_t)s->sh_entsize);
#endif
#ifdef __i386__
		printf("section header align:\t\t%016llx\n",
		       (uint64_t)s->sh_addralign);
		printf("section header entsize:\t\t%016llx\n",
		       (uint64_t)s->sh_entsize);
#endif
		printf("\n");
		s = (Elf64_Shdr *)((char *)s + e->e_shentsize);
	}
}

void dump_elf_shdr(elf_file *file)
{
	if (file->elf_bits == 32)
		dump_elf_shdr32(file);
	else if (file->elf_bits == 64)
		dump_elf_shdr64(file);
}
