#ifndef ELF_H_DAGNAQG6
#define ELF_H_DAGNAQG6

#ifdef __cplusplus
extern "C" {
#endif

#include "../include/clib_error.h"
#include "../include/clib_string.h"
#include "../include/clib_list.h"
#include "../include/clib_file.h"
#include <elf.h>

struct _elf_sym {
	char		*name;
	void		*data;		/* Elf32_sym / Elf64_sym */
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

extern elf_file *elf_parse(char *);
extern int elf_cleanup(elf_file *);

extern void dump_elf_ehdr(elf_file *);
extern void dump_elf_phdr(elf_file *);
extern void dump_elf_shdr(elf_file *);

extern void dump_elf_shstr(elf_file *);
extern void dump_elf_strtab(elf_file *);
extern void dump_elf_dynstr(elf_file *);

extern void dump_elf_sym(elf_file *);
extern void dump_elf_dynsym(elf_file *);

#ifdef __cplusplus
}
#endif

#endif /* end of include guard: ELF_H_DAGNAQG6 */
