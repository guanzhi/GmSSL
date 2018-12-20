/* ====================================================================
 * Copyright (c) 2014 - 2018 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <openssl/opensslconf.h>
#ifdef OPENSSL_NO_OTP
NON_EMPTY_TRANSLATION_UNIT
#else

# include <ctype.h>
# include <stdio.h>
# include <string.h>
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/evp.h>
# include <openssl/otp.h>
# include "apps.h"

typedef enum OPTION_choice {
	OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
	OPT_IN, OPT_OUT, OPT_SETUP, OPT_GENKEY
} OPTION_CHOICE;

OPTIONS otp_options[] = {
	{"help", OPT_HELP, '-', "Display this summary"},
	{"in", OPT_IN, '<', "Input seed file - default stdin"},
	{"out", OPT_OUT, '>', "Output seed file - default stdout"},
	{"setup", OPT_SETUP, '-', "Generate seed"},
	{"genkey", OPT_GENKEY, '-', "Generate one-time password"},
	{NULL}
};

int otp_main(int argc, char **argv)
{
	int ret = 1;
	BIO *bio = NULL;
	char *infile = NULL, *outfile = NULL, *prog;
	OPTION_CHOICE o;
	int setup = 0, genkey = 0;
	unsigned char key[32];

	prog = opt_init(argc, argv, otp_options);
	while ((o = opt_next()) != OPT_EOF) {
		switch (o) {
		case OPT_EOF:
		case OPT_ERR:
opthelp:
			BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
			goto end;
		case OPT_HELP:
			opt_help(otp_options);
			ret = 0;
			goto end;
		case OPT_IN:
			infile = opt_arg();
			break;
		case OPT_OUT:
			outfile = opt_arg();
			break;
		case OPT_SETUP:
			setup = 1;
			break;
		case OPT_GENKEY:
			genkey = 1;
			break;
		}
	}
	argc = opt_num_rest();
	if (argc != 0)
		goto opthelp;

	if (!(setup ^ genkey))
		goto opthelp;

	if (setup) {
		unsigned char key[32];

		if (!RAND_bytes(key, sizeof(key))) {
			ERR_print_errors(bio_err);
			goto end;
		}

		bio = bio_open_default(outfile, 'w', FORMAT_BINARY);
		if (!bio)
			goto end;

		if (BIO_write(bio, key, sizeof(key)) != sizeof(key)) {
			goto end;
		}

		BIO_printf(bio_err, "generate OTP seed in '%s'\n", outfile);

	} else if (genkey) {

		OTP_PARAMS params;
		unsigned char event[] = "gmssl otp event default";
		unsigned int otp;

		params.type = NID_sm3;
		params.te = 1;
		params.option = NULL;
		params.option_size = 0;
		params.otp_digits = 6;

		bio = bio_open_default(infile, 'r', FORMAT_BINARY);
		if (!bio)
			goto end;

		if (BIO_read(bio, key, sizeof(key)) != sizeof(key)) {
			ERR_print_errors(bio_err);
			goto end;
		}

		if (!OTP_generate(&params, event, sizeof(event), &otp, key, sizeof(key))) {
			ERR_print_errors(bio_err);
			goto end;
		}

		printf("%06u\n", otp);
		ret = 0;
	}

end:
	BIO_free(bio);
	OPENSSL_cleanse(key, sizeof(key));
	return ret;
}

#endif
