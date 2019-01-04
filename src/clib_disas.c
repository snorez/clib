/*
 * this file needed by dbg.c
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

int disas_single(int arch, int mode, void *addr)
{
#ifdef HAS_CAPSTONE
	csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(arch, mode, &handle) != CS_ERR_OK)
		return -1;
	count = cs_disasm(handle, addr, X86_X64_OPCODE_MAXLEN,
			  (unsigned long)addr, 1, &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			fprintf(stderr, "%s\t%s\n", insn[j].mnemonic,
				insn[j].op_str);
		}
		cs_free(insn, count);
		cs_close(&handle);
		return 0;
	} else {
		fprintf(stderr, "\n");
		cs_close(&handle);
		return -1;
	}
#else
	return 0;
#endif
}
