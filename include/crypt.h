#ifndef __CRYPT_H__
#define __CRYPT_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../include/error.h"

/* base64 */
char *base64_enc(const char *data, int len);
char *base64_dec(const char *data, int len);

#endif
