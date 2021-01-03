#ifndef CLIB_SME_H_B1KNANYT
#define CLIB_SME_H_B1KNANYT

#include <sys/mman.h>
#include "../include/clib.h"

DECL_BEGIN

enum clib_sme_error {
	CLIB_SME_EINVALID = -1,
	CLIB_SME_EOK,

	/* the position to access is not requested */
	CLIB_SME_ENOTPRESENT,
	/* read some data not initialised */
	CLIB_SME_ENOTINIT,
	/* out-of-bound read/write */
	CLIB_SME_EOOB,
};

struct clib_sme_summary {
	struct slist_head	data_head;

	u64			sme_start;
	u64			sme_size;
	u64			sme_used;
};

struct clib_sme_data {
	struct slist_head	sibling;
	u64			data_start;
	u64			data_bytes;

	char			*shadow;
};

C_SYM void clib_sme_cleanup(struct clib_sme_summary *summary);
C_SYM struct clib_sme_summary *clib_sme_init(u64 start, u64 size);

DECL_END

#endif /* end of include guard: CLIB_SME_H_B1KNANYT */
