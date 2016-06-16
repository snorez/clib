#ifndef __CRYPTO_H__
#define __CRYPTO_H__

/* base64 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../include/error.h"

char *base64_encode(const char *data, int len);
char *base64_decode(const char *data, int len);

#endif
