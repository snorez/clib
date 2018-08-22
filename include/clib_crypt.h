#ifndef CRYPT_H_MS9YVIBE
#define CRYPT_H_MS9YVIBE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../include/clib_error.h"

/* base64 */
char *base64_enc(const char *data, int len);
char *base64_dec(const char *data, int len);

#ifdef __cplusplus
}
#endif

#endif /* end of include guard: CRYPT_H_MS9YVIBE */
