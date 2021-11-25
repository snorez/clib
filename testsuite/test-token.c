#include "testsuite.h"

static const char *infile = "./test-token.sil";
static const char *_logfile = "./test-token.sil.log";
static const char *debugfile = "./test-token.sil.debug";

void test_token(void)
{
	int err;

	struct sil *sil;
	sil = sil_new(NULL, NULL, 0, NULL, 0, NULL, NULL, NULL);

	err = sil_run_script(sil, infile, _logfile, debugfile);
	if (err == -1) {
		err_msg("sil_run_script err");
		return;
	}

	sil_destroy(sil);

	return;
}
