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
#ifndef STRING_H_CMNRJ3FM
#define STRING_H_CMNRJ3FM

#include "../include/clib_utils.h"
#include "../include/clib_error.h"
#include "../include/clib_list.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <sys/time.h>
#include <errno.h>
#include <ctype.h>
#include <strings.h>

DECL_BEGIN

typedef struct _buf_struct {
	void *buf;
	size_t buf_len;
} buf_struct;

typedef struct _str_struct {
	char *str;
	size_t str_len;		/* the real data length, exclude the nul byte */
} str_struct;

extern long s_random(void);
extern char *random_str_nr_en_fau(size_t);
extern char *random_str_fau(size_t);
extern char *mul_str_fau(const char *, size_t);
extern char *insert_str_fau(const char *str1, const char *str2, size_t pos);
extern char *add_str_fau(const char *str1, const char *str2);
extern char *del_str_once_fau(const char *longer, const char *shorter);
extern char *del_str_all_fau(const char *longer, const char *shorter);
extern char *replace_str_once_fau(const char *str, const char *old_sub,
				  const char *new_sub);
extern char *replace_str_all_fau(const char *str, const char *old_sub,
				 const char *new_sub);
extern void dump_mem(const char *addr, size_t len);
extern char *pattern_in_str(const char *str, const char *pattern, size_t *len);
extern void del_str_extra_space(char *str);
extern int is_empty_line(char *line);
extern int get_next_word(char **pos, uint32_t *len);
extern int get_next_word_until(char **pos, uint32_t *len, char *chs);
extern int get_context_in_quote(char **pos, uint32_t *len);
extern int list_comm_str_struct_new(list_comm *head, char *str,
				      uint32_t len);
extern void list_comm_str_struct_make_empty(list_comm *head);
extern int list_comm_str_struct_merge(list_comm *prev,
					    list_comm *next);
extern void list_comm_str_struct_print(list_comm *head);
extern int get_dict_key_value(list_comm *head, char *str, char *sep);
extern int str_split(list_comm *head, const char *str, const char *key);

DECL_END

#endif /* end of include guard: STRING_H_CMNRJ3FM */
