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
#include <string.h>

void *__memcpy_old(void *, const void *, size_t);

#ifndef __x86_64__
asm(".symver memcpy, memcpy@GLIBC_2.0");
#else
asm(".symver memcpy, memcpy@GLIBC_2.2.5");
#endif

void *__wrap_memcpy(void *dest, const void *src, size_t n)
{
	return memcpy(dest, src, n);
}
