/*
 * this file comes from github, gather all the info from different repo
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
#include "../include/clib.h"

/*
 * base64
 */
static char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
			"0123456789+/=";

static char find_pos(char ch)
{
	char *ptr = (char *)strrchr(base64, ch);
	return (ptr - base64);
}

char *base64_enc(const char *data, int data_len)
{
	int prepare = 0;
	int ret_len;
	int temp = 0;
	char *ret = NULL;
	char *f = NULL;
	int tmp = 0;
	char changed[4];
	int i = 0;

	ret_len = data_len / 3;
	temp = data_len % 3;
	if (temp > 0)
		ret_len += 1;

	ret_len = ret_len * 4 + 1;
	ret = (char *)malloc(ret_len);

	if (ret == NULL) {
		err_dbg(0, "malloc err");
		return NULL;
	}

	memset(ret, 0, ret_len);
	f = ret;
	while (tmp < data_len) {
		temp = 0;
		prepare = 0;
		memset(changed, '\0', 4);
		while (temp < 3) {
			if (tmp >= data_len)
				break;
			prepare = ((prepare << 8) | (data[tmp] & 0xFF));
			tmp++;
			temp++;
		}
		prepare = (prepare << ((3 - temp) * 8));
		for (i = 0; i < 4; i++) {
			if (temp < i)
				changed[i] = 0x40;
			else
				changed[i] = (prepare >> ((3 - i) * 6)) & 0x3F;
			*f = *(base64 + changed[i]);
			f++;
		}
	}
	*f = '\0';

	return ret;
}

char *base64_dec(const char *data, int data_len)
{
	int ret_len = (data_len / 4) * 3;
	int equal_count = 0;
	char *ret = NULL;
	char *f = NULL;
	int tmp = 0;
	int temp = 0;
	char need[4];
	int prepare = 0;
	int i = 0;

	if (*(data + data_len - 1) == '=')
		equal_count += 1;
	if (*(data + data_len - 2) == '=')
		equal_count += 1;
	if (*(data + data_len - 3) == '=')
		equal_count += 1;

	switch (equal_count) {
	case 0:
		ret_len += 4;
		break;
	case 1:
		ret_len += 4;
		break;
	case 2:
		ret_len += 3;
		break;
	case 3:
		ret_len += 2;
		break;
	}

	ret = (char *)malloc(ret_len);
	if (ret == NULL) {
		err_dbg(0, "malloc err");
		return NULL;
	}
	memset(ret, 0, ret_len);
	f = ret;
	while (tmp < (data_len - equal_count)) {
		temp = 0;
		prepare = 0;
		memset(need, 0, 4);
		while (temp < 4) {
			if (tmp >= (data_len - equal_count))
				break;
			prepare = (prepare << 6) | (find_pos(data[tmp]));
			temp++;
			tmp++;
		}
		prepare = prepare << ((4 - temp) * 6);
		for (i = 0; i < 3; i++) {
			if (i == temp)
				break;
			*f = (char)((prepare >> ((2 - i) * 8)) & 0xFF);
			f++;
		}
	}
	*f = '\0';
	return ret;
}
