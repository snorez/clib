#include "../include/sil.h"

static int del_comment(struct sil_inst *inst)
{
	char *b = inst->infile_content;
	while (*b) {
		if ((*b == '\'') || (*b == '"')) {
			char *match_ch;
			match_ch = get_matched_pair(b);
			if (!match_ch) {
				SIL_LOG(inst, 0, "get_matched_pair err");
				return -1;
			}

			b = match_ch + 1;
		} else if (*b == '#') {
			/* XXX: clear the content after this # till newline */
			char *newline;
			size_t clear_len = 0;

			newline = strchr(b, '\n');
			if (newline) {
				clear_len = newline - b;
			} else {
				clear_len = strlen(b);
			}

			memset(b, ' ', clear_len);

			b = b + clear_len;
		} else {
			b++;
		}
	}
	return 0;
}

static int do_tokenize(struct sil_inst *inst)
{
	char *b = inst->infile_content;
	int line_nr = 0;
	int col_nr = 0;
	char token_tmp[128];

	while (*b) {
		struct sil_token *token = NULL;
		size_t token_len = 0;

		switch (*b) {
		case '\'':
		case '"':
		{
			char *match_ch;
			char *newline;
			match_ch = get_matched_pair(b);
			if (!match_ch) {
				SIL_LOG(inst, 0, "get_matched_pair err");
				return -1;
			}

			token_len = match_ch + 1 - b;
			if (token_len >= sizeof(token_tmp)) {
				SIL_LOG(inst, 0, "token too long at %d %d",
					line_nr, col_nr);
			}

			memset(token_tmp, 0, sizeof(token_tmp));
			memcpy(token_tmp, b, token_len);

			token = sil_token_new(inst, token_tmp, line_nr, col_nr);
			if (!token) {
				SIL_LOG(inst, 0, "sil_token_new err");
				return -1;
			}

			sil_token_insert(inst, token);

			b = b + token_len;

			newline = token_tmp;
			while (1) {
				char *tmp = newline;

				newline = strchr(newline, '\n');
				if (newline) {
					line_nr++;
					col_nr = 0;
					newline++;
				} else {
					col_nr = strlen(tmp);
					break;
				}
			}
			break;
		}
		case '(':
		case ')':
		case '{':
		case '}':
		case ';':
		case ',':
		case '!':
		{
			memset(token_tmp, 0, sizeof(token_tmp));
			memcpy(token_tmp, b, 1);

			token = sil_token_new(inst, token_tmp, line_nr, col_nr);
			if (!token) {
				SIL_LOG(inst, 0, "sil_token_new err");
				return -1;
			}

			sil_token_insert(inst, token);

			b++;
			col_nr++;
			break;
		}
		case '&':
		case '|':
		{
			if (*(b + 1) != *b) {
				SIL_LOG(inst, 0, "Syntax error: %d %d, %c",
					line_nr, col_nr, *b);
				return -1;
			}

			token_len = 2;
			memset(token_tmp, 0, sizeof(token_tmp));
			memcpy(token_tmp, b, token_len);

			token = sil_token_new(inst, token_tmp, line_nr, col_nr);
			if (!token) {
				SIL_LOG(inst, 0, "sil_token_new err");
				return -1;
			}

			sil_token_insert(inst, token);

			b += token_len;
			col_nr += token_len;
			break;
		}
		case '=':
		case '<':
		case '>':
		{
			token_len = 1;

			if (*(b+1) == '=')
				token_len = 2;

			memset(token_tmp, 0, sizeof(token_tmp));
			memcpy(token_tmp, b, token_len);

			token = sil_token_new(inst, token_tmp, line_nr, col_nr);
			if (!token) {
				SIL_LOG(inst, 0, "sil_token_new err");
				return -1;
			}

			sil_token_insert(inst, token);

			b += token_len;
			col_nr += token_len;
			break;
		}
		case '0':
		{
			if ((isspace(*(b+1))) || (*(b+1) == ',') ||
			    (*(b+1) == ';') || (*(b+1) == ')')) {
				token_len = 1;

				memset(token_tmp, 0, sizeof(token_tmp));
				memcpy(token_tmp, b, token_len);

				token = sil_token_new(inst, token_tmp, line_nr, col_nr);
				if (!token) {
					SIL_LOG(inst, 0, "sil_token_new err");
					return -1;
				}

				sil_token_insert(inst, token);

				b += token_len;
				col_nr += token_len;

				break;
			}

			if ((*(b+1) != 'x') && (*(b+1) != 'X')) {
				SIL_LOG(inst, 0, "Syntax error: %d %d, %c",
					line_nr, col_nr, *b);
				return -1;
			}

			char *e = b + 2;
			while (1) {
				char c = *e;
				if (((c >= 0x30) && (c <= 0x39)) ||
				    ((c >= 0x41) && (c <= 0x46)) ||
				    ((c >= 0x61) && (c <= 0x66))) {
					e++;
				} else {
					break;
				}
			}

			token_len = e - b;

			memset(token_tmp, 0, sizeof(token_tmp));
			memcpy(token_tmp, b, token_len);

			token = sil_token_new(inst, token_tmp, line_nr, col_nr);
			if (!token) {
				SIL_LOG(inst, 0, "sil_token_new err");
				return -1;
			}

			sil_token_insert(inst, token);

			b += token_len;
			col_nr += token_len;

			break;
		}
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		{
			char *e = b + 1;
			while (1) {
				char c = *e;
				if (isdigit(c)) {
					e++;
				} else {
					break;
				}
			}

			token_len = e - b;

			memset(token_tmp, 0, sizeof(token_tmp));
			memcpy(token_tmp, b, token_len);

			token = sil_token_new(inst, token_tmp, line_nr, col_nr);
			if (!token) {
				SIL_LOG(inst, 0, "sil_token_new err");
				return -1;
			}

			sil_token_insert(inst, token);

			b += token_len;
			col_nr += token_len;

			break;
		}
		default:
		{
			if (isspace(*b)) {
				if (*b == '\n') {
					line_nr++;
					col_nr = 0;
				} else {
					col_nr++;
				}
				b++;
			} else if ((!isalpha(*b)) && (*b != '_')) {
				SIL_LOG(inst, 0, "Syntax error: %d %d, %c",
					line_nr, col_nr, *b);
				return -1;
			} else {
				char *e = b + 1;
				while (1) {
					if (*e == '_') {
						e++;
					} else if (isdigit(*e)) {
						e++;
					} else if (isalpha(*e)) {
						e++;
					} else {
						break;
					}
				}

				token_len = e - b;
				memset(token_tmp, 0, sizeof(token_tmp));
				memcpy(token_tmp, b, token_len);

				token = sil_token_new(inst, token_tmp, line_nr, col_nr);
				if (!token) {
					SIL_LOG(inst, 0, "sil_token_new err");
					return -1;
				}

				sil_token_insert(inst, token);

				b += token_len;
				col_nr += token_len;
			}
			break;
		}
		}
	}
	return 0;
}

static int sil_tokenize(struct sil *sil, struct sil_inst *inst)
{
	int err;

	err = del_comment(inst);
	if (err == -1) {
		SIL_LOG(inst, 0, "del_comment err");
		return -1;
	}

	err = do_tokenize(inst);
	if (err == -1) {
		SIL_LOG(inst, 0, "do_tokenize err");
		return -1;
	}

	return err;
}
