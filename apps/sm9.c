/* ====================================================================
 * Copyright (c) 2014 - 2017 The GmSSL Project.  All rights reserved.
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
#ifdef OPENSSL_NO_SM9
NON_EMPTY_TRANSLATION_UNIT
#else

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/evp.h>
# include <openssl/pem.h>
# include <openssl/sm9.h>
# include "apps.h"

typedef enum OPTION_choice {
	OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
	OPT_IN, OPT_OUT, OPT_INFORM, OPT_OUTFORM,
	OPT_PASSIN, OPT_PASSOUT, OPT_TEXT, OPT_NOOUT
} OPTION_CHOICE;

OPTIONS sm9_options[] = {
	{"help", OPT_HELP, '-', "Display this summary"},
	{"in", OPT_IN, 's', "Input key"},
	{"out", OPT_OUT, '>', "Output file"},
	{"inform", OPT_INFORM, 'f', "Input format (DER or PEM)"},
	{"outform", OPT_OUTFORM, 'F', "Output format (DER or PEM)"},
	{"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
	{"passout", OPT_PASSOUT, 's', "Output file pass phrase source"},
	{"text", OPT_TEXT, '-', "Output in plaintext as well"},
	{"noout", OPT_NOOUT, '-', "Don't output the key"},
	{NULL}
};

int sm9_main(int argc, char **argv)
{
	int ret = 1;
	SM9_KEY *key = NULL;
	BIO *in = NULL, *out = NULL;
	char *infile = NULL, *outfile = NULL, *prog;
	char *passin = NULL, *passout = NULL;
	char *passinarg = NULL, *passoutarg = NULL;
	OPTION_CHOICE o;
	int informat = FORMAT_PEM, outformat = FORMAT_PEM;
	int text = 0, noout = 0;

	prog = opt_init(argc, argv, sm9_options);
	while ((o = opt_next()) != OPT_EOF) {
		switch (o) {
		case OPT_EOF:
		case OPT_ERR:
opthelp:
			BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
			goto end;
		case OPT_HELP:
			opt_help(sm9_options);
			ret = 0;
			goto end;
		case OPT_IN:
			infile = opt_arg();
			break;
		case OPT_OUT:
			outfile = opt_arg();
			break;
		case OPT_INFORM:
			if (!opt_format(opt_arg(), OPT_FMT_ANY, &informat))
				goto opthelp;
			break;
		case OPT_OUTFORM:
			if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
				goto opthelp;
			break;
		case OPT_PASSIN:
			passinarg = opt_arg();
			break;
		case OPT_PASSOUT:
			passoutarg = opt_arg();
			break;
		case OPT_TEXT:
			text = 1;
			break;
		case OPT_NOOUT:
			noout = 1;
			break;
		}
	}
	argc = opt_num_rest();
	if (argc != 0)
		goto opthelp;

	if (!app_passwd(passinarg, passoutarg, &passin, &passout)) {
		BIO_printf(bio_err, "Error getting passwords\n");
		goto end;
	}

	if (informat != FORMAT_ENGINE) {
		if (!(in = bio_open_default(infile, 'r', informat)))
			goto end;
	}

	BIO_printf(bio_err, "read SM9 key\n");
	if (informat == FORMAT_ASN1) {
		if (!(key = d2i_SM9PrivateKey_bio(in, NULL))) {
			BIO_printf(bio_err, "unable to load Key\n");
			ERR_print_errors(bio_err);
			goto end;
		}
	} else if (informat == FORMAT_PEM) {
		if (!(key = PEM_read_bio_SM9PrivateKey(in, NULL, NULL, passin))) {
			BIO_printf(bio_err, "unable to load Key\n");
			ERR_print_errors(bio_err);
			goto end;
		}
	} else {
		BIO_printf(bio_err, "supported key format\n");
		goto end;
	}

	if (!(out = bio_open_owner(outfile, outformat, 1))) {
		goto end;
	}

	if (!noout) {
		BIO_printf(bio_err, "writing SM9 key\n");
		if (outformat == FORMAT_ASN1) {
			if (!i2d_SM9PrivateKey_bio(out, key)) {
				BIO_printf(bio_err, "unable to write private key\n");
				ERR_print_errors(bio_err);
				goto end;
			}
		} else if (outformat == FORMAT_PEM) {
			if (!PEM_write_bio_SM9PrivateKey(out, key, EVP_sms4_cbc(), NULL, 0, NULL, passout)) {
				BIO_printf(bio_err, "unable to write private key\n");
				ERR_print_errors(bio_err);
				goto end;
			}
		} else {
			BIO_printf(bio_err, "unsupported key format\n");
			goto end;
		}
	}

	/* sm9 api does not support public key print, do it with evp api */
	if (text) {
		if (!SM9_KEY_print(out, key, 0)) {
			perror(outfile);
			ERR_print_errors(bio_err);
			goto end;
		}
	}

	ret = 0;

end:
	SM9_KEY_free(key);
	BIO_free(in);
	BIO_free_all(out);
	OPENSSL_free(passin);
	OPENSSL_free(passout);
	return ret;
}
#endif
