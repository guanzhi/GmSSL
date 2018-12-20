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
#ifdef OPENSSL_NO_FPE
NON_EMPTY_TRANSLATION_UNIT
#else

# include <ctype.h>
# include <stdio.h>
# include <string.h>
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/evp.h>
# include <openssl/ffx.h>
# include "apps.h"

typedef enum OPTION_choice {
	OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
	OPT_LIST,
	OPT_E, OPT_D,
	OPT_CIPHER, OPT_UPPER_K, OPT_TWEAK,
	OPT_ENGINE, OPT_CONFIG
} OPTION_CHOICE;

OPTIONS fpe_options[] = {
	{"help", OPT_HELP, '-', "Display this summary"},
	{"ciphers", OPT_LIST, '-', "List ciphers"},
	{"e", OPT_E, '-', "Encrypt"},
	{"d", OPT_D, '-', "Decrypt"},
	{"K", OPT_UPPER_K, 's', "Raw key, in hex"},
	{"tweak", OPT_TWEAK, 's', "Tweak string"},
	{"", OPT_CIPHER, '-', "Any supported cipher"},
#ifndef OPENSSL_NO_ENGINE
	{"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
	{"config", OPT_CONFIG, 's', "A config file"},
#endif
	{NULL}
};

static void show_ciphers(const OBJ_NAME *name, void *bio_);
static int set_hex(char *in, unsigned char *out, int size);

int fpe_main(int argc, char **argv)
{
	int ret = 1;
	BIO *in = NULL, *out = NULL;
	char *prog;
	OPTION_CHOICE o;
	int enc = 1;
	unsigned char key[32] = {0};
	char *hkey = NULL, *tweak = NULL;
	const EVP_CIPHER *cipher = NULL;
	CONF *conf = NULL;
	char *configfile = default_config_file;
	ENGINE *e = NULL;
	char inbuf[32] = {0};
	char outbuf[32] = {0};
	FFX_CTX *ctx = NULL;


	prog = opt_init(argc, argv, fpe_options);
	while ((o = opt_next()) != OPT_EOF) {
		switch (o) {
		case OPT_EOF:
		case OPT_ERR:
help:
			BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
			goto end;
		case OPT_HELP:
			opt_help(fpe_options);
			ret = 0;
			goto end;
		case OPT_LIST:
			BIO_printf(bio_err, "Supported ciphers:\n");
			OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_CIPHER_METH,
				show_ciphers, bio_err);
			BIO_printf(bio_err, "\n");
			goto end;
		case OPT_E:
			enc = 1;
			break;
		case OPT_D:
			enc = 0;
			break;
		case OPT_UPPER_K:
			hkey = opt_arg();
			break;
		case OPT_TWEAK:
			tweak = opt_arg();
			break;
		case OPT_CIPHER:
			if (!opt_cipher(opt_unknown(), &cipher))
				goto help;
			break;
		case OPT_ENGINE:
			e = setup_engine(opt_arg(), 0);
			break;
		case OPT_CONFIG:
			configfile = opt_arg();
			break;
		}
	}
	argc = opt_num_rest();
	if (argc != 0)
		goto help;

	in = BIO_new_fp(stdin, BIO_NOCLOSE);
	out = BIO_new_fp(stdout, BIO_NOCLOSE);

	/* engine */
	if (e)
		BIO_printf(bio_err, "Using configuration from %s\n", configfile);

	if ((conf = app_load_config(configfile)) == NULL)
		goto end;
	if (configfile != default_config_file && !app_load_modules(conf))
		goto end;

	/* get cipher */
	if (EVP_CIPHER_mode(cipher) != EVP_CIPH_ECB_MODE) {
		BIO_printf(bio_err, "%s: Only block cipher with ECB mode is supported\n", prog);
		goto end;
	}

	/* get key */
	if (!hkey) {
		BIO_printf(bio_err, "%s: no key given\n", prog);
		goto end;
	}
	if (!set_hex(hkey, key, EVP_CIPHER_key_length(cipher))) {
		BIO_printf(bio_err, "%s: invalid hex key value\n", prog);
		goto end;
	}

	/* get tweak */
	if (!tweak) {
		BIO_printf(bio_err, "%s: `-tweak` required\n", prog);
		goto end;
	}
	if (strlen(tweak) < FFX_MIN_TWEAKLEN || strlen(tweak) > FFX_MAX_TWEAKLEN) {
		BIO_printf(bio_err, "%s: invalid tweak length, should be %d to %d\n",
			prog, FFX_MIN_TWEAKLEN, FFX_MAX_TWEAKLEN);
		goto end;
	}

	/* get input digits */
	if (BIO_read(in, inbuf, sizeof(inbuf) - 1) <= 0) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (strlen(inbuf) < FFX_MIN_DIGITS || strlen(inbuf) > FFX_MAX_DIGITS) {
		BIO_printf(bio_err, "%s: invalid digits length, should be %d to %d\n",
			prog, FFX_MIN_DIGITS, FFX_MAX_DIGITS);
		goto end;
	}

	/* encrypt/decrypt */
	if (!(ctx = FFX_CTX_new())
		|| !FFX_init(ctx, cipher, key, 0)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (enc) {
		if (!FFX_encrypt(ctx, inbuf, outbuf, strlen(inbuf),
			(unsigned char *)tweak, strlen(tweak))) {
			ERR_print_errors(bio_err);
			goto end;
		}
	} else {
		if (!FFX_decrypt(ctx, inbuf, outbuf, strlen(inbuf),
			(unsigned char *)tweak, strlen(tweak))) {
			ERR_print_errors(bio_err);
			goto end;
		}
	}

	if (BIO_write(out, outbuf, strlen(outbuf)) != strlen(outbuf)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	BIO_puts(out, "\n");

	ret = 0;

end:
	BIO_free(in);
	BIO_free(out);
	OPENSSL_cleanse(key, sizeof(key));
	if (enc)
		OPENSSL_cleanse(inbuf, sizeof(inbuf));
	FFX_CTX_free(ctx);
	return ret;
}

static void show_ciphers(const OBJ_NAME *name, void *bio_)
{
    BIO *bio = bio_;
    static int n;

    if (!islower((unsigned char)*name->name))
        return;

    BIO_printf(bio, "-%-25s", name->name);
    if (++n == 3) {
        BIO_printf(bio, "\n");
        n = 0;
    } else
        BIO_printf(bio, " ");
}

static int set_hex(char *in, unsigned char *out, int size)
{
    int i, n;
    unsigned char j;

    n = strlen(in);
    if (n > (size * 2)) {
        BIO_printf(bio_err, "hex string is too long\n");
        return (0);
    }
    memset(out, 0, size);
    for (i = 0; i < n; i++) {
        j = (unsigned char)*in;
        *(in++) = '\0';
        if (j == 0)
            break;
        if (!isxdigit(j)) {
            BIO_printf(bio_err, "non-hex digit\n");
            return (0);
        }
        j = (unsigned char)OPENSSL_hexchar2int(j);
        if (i & 1)
            out[i / 2] |= j;
        else
            out[i / 2] = (j << 4);
    }
    return (1);
}
#endif
