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
#ifndef ELF_H_DAGNAQG6
#define ELF_H_DAGNAQG6

#include "../include/clib_utils.h"
#include "../include/clib_eh.h"
#include "../include/clib_buf.h"
#include "../include/clib_list.h"
#include "../include/clib_file.h"
#include <elf.h>
#include <syscall.h>

DECL_BEGIN

struct _elf_sym {
	char		*name;
	void		*data;		/* Elf32_Sym / Elf64_Sym */
};

struct _elf_sym_full {
	struct list_head	sibling;
	char			*name;
	union {
		Elf32_Sym	sym0;
		Elf64_Sym	sym1;
	} data;

	void			*load_addr;
	char			bind;
	char			type;
};

typedef struct _elf_file {
	regfile		*file;
	uint64_t	elf_text_entry;

	void		*elf_hdr;
	void		*elf_phdr;
	void		*elf_shdr;
	void		*shstrtab;
	void		*strtab;		/* for strtab */
	void		*dynstr;

	struct list_head syms;		/* struct _elf_sym nodes */
	struct list_head dynsyms;		/* struct _elf_sym nodes */

	uint32_t	elf_hdr_size;
	uint32_t	elf_phdr_size;
	uint32_t	elf_shdr_size;

	uint8_t		elf_bits;
} elf_file;

static inline int elf_bits(char *buf)
{
	return (buf[EI_CLASS]-1) ? 64 : 32;
}

static inline int elf_type(elf_file *ef)
{
	switch (ef->elf_bits) {
	case 32:
	{
		Elf32_Ehdr *eh = (Elf32_Ehdr *)ef->elf_hdr;
		return eh->e_type;
	}
	case 64:
	{
		Elf64_Ehdr *eh = (Elf64_Ehdr *)ef->elf_hdr;
		return eh->e_type;
	}
	default:
	{
		return ET_NONE;
	}
	}
}

static inline void *get_sh_by_id(elf_file *ef, int idx)
{
	switch (ef->elf_bits) {
	case 32:
	{
		Elf32_Ehdr *e = (Elf32_Ehdr *)ef->elf_hdr;
		if (idx > e->e_shnum)
			return NULL;
		return ((char *)ef->elf_shdr + e->e_shentsize * idx);
	}
	case 64:
	{
		Elf64_Ehdr *e = (Elf64_Ehdr *)ef->elf_hdr;
		if (idx > e->e_shnum)
			return NULL;
		return ((char *)ef->elf_shdr + e->e_shentsize * idx);
	}
	default:
	{
		return NULL;
	}
	}
}

static inline void *get_sh_by_name(elf_file *ef, const char *str)
{
	switch (ef->elf_bits) {
	case 32:
	{
		Elf32_Ehdr *e = (Elf32_Ehdr *)ef->elf_hdr;
		Elf32_Shdr *s;
		for (size_t i = 0; i < e->e_shnum; i++) {
			s = (Elf32_Shdr *)((long)ef->elf_shdr +
						e->e_shentsize * i);
			if (!memcmp((void *)((long)ef->shstrtab + s->sh_name),
						str, strlen(str)+1))
				return s;
		}
		return NULL;
	}
	case 64:
	{
		Elf64_Ehdr *e = (Elf64_Ehdr *)ef->elf_hdr;
		Elf64_Shdr *s;
		for (size_t i = 0; i < e->e_shnum; i++) {
			s = (Elf64_Shdr *)((long)ef->elf_shdr +
						e->e_shentsize * i);
			if (!memcmp((void *)((long)ef->shstrtab + s->sh_name),
						str, strlen(str)+1))
				return s;
		}
		return NULL;
	}
	default:
	{
		return NULL;
	}
	}
}

static inline int sym_bind(elf_file *ef, struct _elf_sym_full *sym)
{
	switch (ef->elf_bits) {
	case 32:
	{
		Elf32_Sym s = sym->data.sym0;
		return ELF32_ST_BIND(s.st_info);
	}
	case 64:
	{
		Elf64_Sym s = sym->data.sym1;
		return ELF64_ST_BIND(s.st_info);
	}
	default:
	{
		return STB_LOCAL;
	}
	}
}

static inline int sym_type(elf_file *ef, struct _elf_sym_full *sym)
{
	switch (ef->elf_bits) {
	case 32:
	{
		Elf32_Sym s = sym->data.sym0;
		return ELF32_ST_TYPE(s.st_info);
	}
	case 64:
	{
		Elf64_Sym s = sym->data.sym1;
		return ELF64_ST_TYPE(s.st_info);
	}
	default:
	{
		return STT_NOTYPE;
	}
	}
}

extern elf_file *elf_parse(char *path, int flag);
extern elf_file *elf_parse_data(void *ctx);
extern int elf_cleanup(elf_file *);

extern void dump_elf_ehdr(elf_file *);
extern void dump_elf_phdr(elf_file *);
extern void dump_elf_shdr(elf_file *);

extern void dump_elf_shstr(elf_file *);
extern void dump_elf_strtab(elf_file *);
extern void dump_elf_dynstr(elf_file *);

extern void dump_elf_sym(elf_file *);
extern void dump_elf_dynsym(elf_file *);

extern int elf_get_syms(elf_file *ef, struct list_head *head);
extern int elf_get_syms_path(char *path, struct list_head *head, uint8_t *bits);
extern void elf_drop_syms(struct list_head *head);

extern void get_sym_detail(elf_file *ef, struct _elf_sym_full *sym);

#ifdef USELIB
extern int elf_uselib(char *libname, unsigned long load_addr);
#endif

DECL_END

#endif /* end of include guard: ELF_H_DAGNAQG6 */
