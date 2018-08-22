/* this file needed by dbg.c */
#include "../include/clib_disas.h"

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
			fprintf(stdout, "%s\t%s\n", insn[j].mnemonic,
				insn[j].op_str);
		}
		cs_free(insn, count);
		cs_close(&handle);
		return 0;
	} else {
		cs_close(&handle);
		return -1;
	}
#else
	return 0;
#endif
}
