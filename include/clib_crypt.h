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
