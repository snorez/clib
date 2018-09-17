#ifndef CRYPT_H_MS9YVIBE
#define CRYPT_H_MS9YVIBE

#include "../include/clib_utils.h"
#include "../include/clib_error.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

DECL_BEGIN

/* base64 */
char *base64_enc(const char *data, int len);
char *base64_dec(const char *data, int len);

DECL_END

#endif /* end of include guard: CRYPT_H_MS9YVIBE */
