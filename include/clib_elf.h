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
#include "../include/clib_error.h"
#include "../include/clib_string.h"
#include "../include/clib_list.h"
#include "../include/clib_file.h"
#include <elf.h>
#include <syscall.h>

DECL_BEGIN

struct _elf_sym {
	char		*name;
	void		*data;		/* Elf32_sym / Elf64_sym */
};

struct _elf_sym_full {
	struct list_head	sibling;
	char			*name;
	union {
		Elf32_Sym	sym0;
		Elf64_Sym	sym1;
	} data;

	void			*load_addr;
};

typedef struct _elf_file {
	regfile		*file;
	uint8_t		elf_bits;
	uint16_t	elf_machine;
	uint64_t	elf_text_entry;
	void		*elf_hdr;
	uint32_t	elf_hdr_size;
	void		*elf_phdr;
	uint32_t	elf_phdr_size;
	void		*elf_shdr;
	uint32_t	elf_shdr_size;

	void		*shstrtab;
	void		*strtab;		/* for strtab */
	list_comm	syms;			/* struct _elf_sym nodes */
	void		*dynstr;
	list_comm	dynsyms;		/* struct _elf_sym nodes */
} elf_file;

extern elf_file *elf_parse(char *path, int flag);
extern int elf_cleanup(elf_file *);

extern void dump_elf_ehdr(elf_file *);
extern void dump_elf_phdr(elf_file *);
extern void dump_elf_shdr(elf_file *);

extern void dump_elf_shstr(elf_file *);
extern void dump_elf_strtab(elf_file *);
extern void dump_elf_dynstr(elf_file *);

extern void dump_elf_sym(elf_file *);
extern void dump_elf_dynsym(elf_file *);

extern int elf_get_syms(char *path, struct list_head *head, uint8_t *bits);
extern void elf_drop_syms(struct list_head *head);

#ifdef USELIB
extern int elf_uselib(char *libname, unsigned long load_addr);
#endif

DECL_END

#endif /* end of include guard: ELF_H_DAGNAQG6 */
