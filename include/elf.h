#ifndef __ELF_H__
#define __ELF_H__

#include "../include/error.h"
#include "../include/string.h"
#include "../include/list.h"
#include "../include/file.h"
#include <elf.h>

typedef struct _elf_file {
	reg_file *file;
	uint8_t elf_bits;
	uint16_t elf_machine;
	uint64_t elf_text_entry;
	void *elf_hdr;
	uint32_t elf_hdr_size;
	void *elf_phdr;
	uint32_t elf_phdr_size;
	void *elf_shdr;
	uint32_t elf_shdr_size;
} elf_file;

extern elf_file *do_elf_file(char *);
extern int done_elf_file(elf_file *);
extern void dump_elf_ehdr(elf_file *);
extern void dump_elf_phdr(elf_file *);
extern void dump_elf_shdr(elf_file *);

#endif
