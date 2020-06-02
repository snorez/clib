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
#ifndef DISAS_H_QWXBDHCJ
#define DISAS_H_QWXBDHCJ

#include "../include/clib_utils.h"
#ifdef HAS_CAPSTONE
#include <capstone/capstone.h>
#include <capstone/x86.h>
#endif
#include <stdint.h>

DECL_BEGIN

#define		X86_X64_OPCODE_MAXLEN		15

extern int disas_next(int arch, int mode, void *addr, char *buf, size_t bufsz,
			unsigned int *opcid);
extern int disas_single(int arch, int mode, void *addr);

DECL_END

#endif /* end of include guard: DISAS_H_QWXBDHCJ */
