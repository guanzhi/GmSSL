/* ====================================================================
 * Copyright (c) 2014 - 2019 The GmSSL Project.  All rights reserved.
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
#ifdef OPENSSL_NO_PAILLIER
NON_EMPTY_TRANSLATION_UNIT
#else

# include <ctype.h>
# include <stdio.h>
# include <string.h>
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/evp.h>
# include <openssl/paillier.h>
# include "apps.h"

#define KEY_NONE        0
#define KEY_PRIVKEY     1
#define KEY_PUBKEY      2
#define KEY_CERT        3

typedef enum OPTION_choice {
	OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
	OPT_IN, OPT_OUT, OPT_ADD, OPT_SCALAR_MUL,
	OPT_PUBIN, OPT_INKEY, OPT_KEYFORM, OPT_PASSIN,
} OPTION_CHOICE;

OPTIONS paiutl_options[] = {
	{"help", OPT_HELP, '-', "Display this summary"},
	{"in", OPT_IN, '<', "Input file - default stdin"},
	{"out", OPT_OUT, '>', "Output file - default stdout"},
	{"add", OPT_ADD, '-', "Add ciphertexts"},
	{"scalar_mul", OPT_SCALAR_MUL, 's', "Scalar multiply"},
	{"pubin", OPT_PUBIN, '-', "Input is a public key"},
	{"inkey", OPT_INKEY, 's', "Input private key file"},
	{"keyform", OPT_KEYFORM, 'E', "Private key format - default PEM"},
	{"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
	{NULL}
};

int paiutl_main(int argc, char **argv)
{
	int ret = 1;
	OPTION_CHOICE o;
	char *prog;
	char *infile = NULL;
	char *outfile = NULL;
	BIO *in = NULL;
	BIO *out = NULL;
	int op = PAILLIER_OP_UNDEF;
	int scalar = 1;
	char *keyfile = NULL;
	int key_type = KEY_PRIVKEY;
	int keyform = FORMAT_PEM;
	char *passinarg = NULL;
	char *passin = NULL;
	EVP_PKEY *pkey = NULL;
	PAILLIER *key;
	ASN1_INTEGER *ai = NULL;
	BIGNUM *a = NULL;
	BIGNUM *r = NULL;

	prog = opt_init(argc, argv, paiutl_options);
	while ((o = opt_next()) != OPT_EOF) {
		switch (o) {
		case OPT_EOF:
		case OPT_ERR:
opthelp:
			BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
			goto end;
		case OPT_HELP:
			opt_help(paiutl_options);
			ret = 0;
			goto end;
		case OPT_IN:
			infile = opt_arg();
			break;
		case OPT_OUT:
			outfile = opt_arg();
			break;
		case OPT_ADD:
			op = PAILLIER_OP_ADD;
			break;
		case OPT_SCALAR_MUL:
			op = PAILLIER_OP_SCALAR_MUL;
			scalar = atoi(opt_arg());
			break;
		case OPT_INKEY:
			keyfile = opt_arg();
			break;
		case OPT_PUBIN:
			key_type = KEY_PUBKEY;
			break;
		case OPT_KEYFORM:
			if (!opt_format(opt_arg(), OPT_FMT_PDE, &keyform))
				goto opthelp;
			break;
		case OPT_PASSIN:
			passinarg = opt_arg();
			break;
		}
	}
	argc = opt_num_rest();
	if (argc != 0)
		goto opthelp;

	app_RAND_load_file(NULL, 0);

	if (!(in = bio_open_default(infile, 'r', FORMAT_BINARY))) {
		BIO_printf(bio_err, "Error reading input file\n");
		goto end;
	}

	if (!(out = bio_open_default(outfile, 'w', FORMAT_BINARY))) {
		BIO_printf(bio_err, "Error writting output file\n");
		goto end;
	}

	if (key_type == KEY_PRIVKEY) {
		if (!app_passwd(passinarg, NULL, &passin, NULL)) {
			BIO_printf(bio_err, "Error getting password\n");
			goto end;
		}
		if (!(pkey = load_key(keyfile, keyform, 0, passin, NULL, "Private Key"))) {
			BIO_printf(bio_err, "Error reading private key\n");
			goto end;
		}
	} else {
		if (!(pkey = load_pubkey(keyfile, keyform, 0, NULL, NULL, "Public Key"))) {
			BIO_printf(bio_err, "Error reading public key\n");
			goto end;
		}
	}

	if (!(key = EVP_PKEY_get0_PAILLIER(pkey))) {
		BIO_printf(bio_err, "Error key type\n");
		goto end;
	}

	/* get the first oprand */
	if (!(ai = ASN1_item_d2i_bio(ASN1_ITEM_rptr(ASN1_INTEGER), in, NULL))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!(r = ASN1_INTEGER_to_BN(ai, NULL))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!(a = BN_new())) {
		goto end;
	}


	if (op == PAILLIER_OP_ADD) {

		/* add the second oprand */
		if (!ASN1_item_d2i_bio(ASN1_ITEM_rptr(ASN1_INTEGER), in, &ai)) {
			ERR_print_errors(bio_err);
			goto end;
		}
		if (!ASN1_INTEGER_to_BN(ai, a)) {
			ERR_print_errors(bio_err);
			goto end;
		}
		if (!PAILLIER_ciphertext_add(r, r, a, key)) {
			ERR_print_errors(bio_err);
			goto end;
		}

		/* (optional) continue */
		while (ASN1_item_d2i_bio(ASN1_ITEM_rptr(ASN1_INTEGER), in, &ai)) {
			if (!ASN1_INTEGER_to_BN(ai, a)) {
				ERR_print_errors(bio_err);
				goto end;
			}
			if (!PAILLIER_ciphertext_add(r, r, a, key)) {
				ERR_print_errors(bio_err);
				goto end;
			}
		}

		/* output sum */
		if (!BN_to_ASN1_INTEGER(r, ai)
			|| !ASN1_item_i2d_bio(ASN1_ITEM_rptr(ASN1_INTEGER), out, ai)) {
			ERR_print_errors(bio_err);
			goto end;
		}

	} else if (op == PAILLIER_OP_SCALAR_MUL) {

		/* scalar mul the first ciphertext */
		if (!BN_set_word(a, scalar)) {
			ERR_print_errors(bio_err);
			goto end;
		}
		if (!PAILLIER_ciphertext_scalar_mul(r, a, r, key)) {
			ERR_print_errors(bio_err);
			goto end;
		}
		if (!BN_to_ASN1_INTEGER(r, ai)
			|| !ASN1_item_i2d_bio(ASN1_ITEM_rptr(ASN1_INTEGER), out, ai)) {
			ERR_print_errors(bio_err);
			goto end;
		}

		/* (optional) do more, do not decrypt the output with `pkeyutl` */
		while (ASN1_item_d2i_bio(ASN1_ITEM_rptr(ASN1_INTEGER), in, &ai)) {
			if (!ASN1_INTEGER_to_BN(ai, r)
				|| !PAILLIER_ciphertext_scalar_mul(r, r, a, key)
				|| !BN_to_ASN1_INTEGER(r, ai)
				|| !ASN1_item_i2d_bio(ASN1_ITEM_rptr(ASN1_INTEGER), out, ai)) {
				ERR_print_errors(bio_err);
				goto end;
			}
		}
	} else {
		BIO_printf(bio_err, "No operation assigned\n");
		goto end;
	}

	ret = 0;

end:
	OPENSSL_free(passin);
	ASN1_INTEGER_free(ai);
	BN_free(a);
	BN_free(r);
	return ret;
}
#endif
