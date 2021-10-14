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
#include "../include/clib_eh.h"
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

typedef struct {
	char	*buf;
	size_t	buf_len;
} buf_struct;

extern int buf_printable(char *buf, size_t len);
extern uint64_t s_rand64(void);
extern uint32_t s_rand32(void);
extern char *random_str_nr_en(size_t);
extern char *random_str(size_t);
extern char *mul_str(const char *, size_t);
extern char *insert_str(const char *str1, const char *str2, size_t pos);
extern char *add_str(const char *str1, const char *str2);
extern char *del_str_once(const char *longer, const char *shorter);
extern char *del_str_all(const char *longer, const char *shorter);
extern char *replace_str_once(const char *str,const char *old_sub,const char *new_sub);
extern char *replace_str_all(const char *str,const char *old_sub,const char *new_sub);
extern void dump_mem(const char *addr, size_t len);
extern char *pattern_in_str(const char *str, const char *pattern, size_t *len);
extern void del_str_extra_space(char *str);
extern int is_empty_line(char *line);
extern void get_next_word(char **pos, size_t *len);
extern void get_next_word_until(char **pos, size_t *len, char *chs);
extern char *get_matched_pair(char *start);
extern void get_context_in_quote(char **pos, size_t *len);

extern buf_struct *buf_struct_alloc(void);
extern void buf_struct_free(buf_struct *bs);
extern int buf_struct_init(buf_struct *_new, char *buf, size_t len);
extern int buf_struct_new_append(struct list_head *head, char *str, size_t len);
extern void buf_struct_list_cleanup(struct list_head *head);
extern int buf_struct_merge(buf_struct *prev, buf_struct *next);
extern int buf_struct_print(void *data);
extern int get_dict_key_value(struct list_head *head, char *str, char *sep);
extern int str_split(struct list_head *head, const char *str, const char *key);
extern void str_and(char *src0, char *src1);

DECL_END

#endif /* end of include guard: STRING_H_CMNRJ3FM */
