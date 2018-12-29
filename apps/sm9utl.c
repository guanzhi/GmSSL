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
#ifdef OPENSSL_NO_SM9
NON_EMPTY_TRANSLATION_UNIT
#else

# include <ctype.h>
# include <stdio.h>
# include <string.h>
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/evp.h>
# include <openssl/sm9.h>
# include "../crypto/sm9/sm9_lcl.h"
# include "apps.h"

typedef enum OPTION_choice {
	OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
	OPT_IN, OPT_OUT, OPT_SIGFILE,
	OPT_SIGN, OPT_VERIFY, OPT_ENCRYPT, OPT_DECRYPT,
	OPT_MD, OPT_SCHEME,
	OPT_PARAMFILE, OPT_ID, OPT_INKEY, OPT_PASSIN,
	OPT_KEYFORM, OPT_PARAMFORM
} OPTION_CHOICE;

OPTIONS sm9utl_options[] = {
	{"help", OPT_HELP, '-', "Display this summary"},
	{"in", OPT_IN, '<', "Input file - default stdin"},
	{"out", OPT_OUT, '>', "Output file - default stdout"},
	{"sigfile", OPT_SIGFILE, '<', "Signature file (verify operation only)"},
	{"sign", OPT_SIGN, '-', "Sign input data with private key and public parameters"},
	{"verify", OPT_VERIFY, '-', "Verify with signer's ID and public parameters"},
	{"encrypt", OPT_ENCRYPT, '-', "Encrypt input data with recipient's ID"},
	{"decrypt", OPT_DECRYPT, '-', "Decrypt input data with private key"},
	{"md", OPT_MD, 's', "Digest algorithm for signing or verification"},
	{"scheme", OPT_SCHEME, 's', "Encryption scheme"},
	{"paramfile", OPT_PARAMFILE, 's', "Public parameters file"},
	{"id", OPT_ID, 's', "Recipient's or signer's ID"},
	{"inkey", OPT_INKEY, 's', "Private key for signing or decryption"},
	{"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
	{"keyform", OPT_KEYFORM, 'E', "Private key format - default PEM"},
	{"paramform", OPT_PARAMFORM, 'E', "Public parameters format - default PEM"},
	{NULL}
};

static int sm9_sign(const EVP_MD *md, BIO *in, BIO *out,
	SM9_KEY *key, const char *prog)
{
	int ret = 0;
	EVP_MD_CTX *md_ctx = NULL;
	SM9Signature *sig = NULL;
	unsigned char buf[1024];
	int len;

	if (!(md_ctx = EVP_MD_CTX_new())
		|| !SM9_SignInit(md_ctx, md, NULL)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	while ((len = BIO_read(in, buf, sizeof(buf))) > 0) {
		if (!SM9_SignUpdate(md_ctx, buf, len)) {
			ERR_print_errors(bio_err);
			goto end;
		}
	}
	if (!(sig = SM9_SignFinal(md_ctx, key))) {
		ERR_print_errors(bio_err);
		goto end;
}
	if (i2d_SM9Signature_bio(out, sig) <= 0) {
		ERR_print_errors(bio_err);
		goto end;
	}

	ret = 1;

end:
	EVP_MD_CTX_free(md_ctx);
	SM9Signature_free(sig);
	return ret;
}

static int sm9_verify(const EVP_MD *md, BIO *in, BIO *out, const char *sigfile,
	SM9_MASTER_KEY *param, const char *id, const char *prog)
{
	int ret = 0;
	BIO *sig_bio = NULL;
	SM9_KEY *key = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	SM9Signature *sig = NULL;
	unsigned char buf[1024];
	int len;

	if (!sigfile) {
		BIO_printf(bio_err, "%s: `-sigfile` required for verification\n", prog);
		return 0;
	}
	if (!(sig_bio = BIO_new_file(sigfile, "rb"))
		|| !(sig = d2i_SM9Signature_bio(sig_bio, NULL))) {
		ERR_print_errors(bio_err);
		goto end;
	}

	if (!param || !id) {
		BIO_printf(bio_err, "%s: param and id required\n", prog);
		goto end;
	}
	if (!(key = SM9_extract_public_key(param, id, strlen(id)))) {
		ERR_print_errors(bio_err);
		goto end;
	}

	if (!(md_ctx = EVP_MD_CTX_new())
		|| !SM9_VerifyInit(md_ctx, md, NULL)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	while ((len = BIO_read(in, buf, sizeof(buf))) > 0) {
		if (!SM9_VerifyUpdate(md_ctx, buf, len)) {
			ERR_print_errors(bio_err);
			goto end;
		}
	}
	if ((ret = SM9_VerifyFinal(md_ctx, sig, key)) != 1) {
		ERR_print_errors(bio_err);
	}
	BIO_printf(out, "Signature Verified %s\n", ret ? "Successfully" : "Failure");

end:
	BIO_free(sig_bio);
	SM9_KEY_free(key);
	EVP_MD_CTX_free(md_ctx);
	SM9Signature_free(sig);
	return ret;
}

static int sm9_encrypt(int scheme, BIO *in, BIO *out,
	SM9_MASTER_KEY *param, const char *id, const char *prog)
{
	int ret = 0;
	unsigned char *inbuf = NULL;
	unsigned char *outbuf = NULL;
	int inlen;
	size_t outlen;

	if (!param || !id) {
		BIO_printf(bio_err, "%s: param and id required\n", prog);
		return 0;
	}

	if (!(inlen = bio_to_mem(&inbuf, SM9_MAX_PLAINTEXT_LENGTH, in))) {
		BIO_printf(bio_err, "%s: error reading input\n", prog);
		return 0;
	}

	if (!SM9_encrypt(scheme, inbuf, inlen, NULL, &outlen, param, id, strlen(id))
		|| !(outbuf = OPENSSL_malloc(outlen))
		|| !SM9_encrypt(scheme, inbuf, inlen, outbuf, &outlen,
			param, id, strlen(id))
		|| BIO_write(out, outbuf, outlen) != outlen) {
		ERR_print_errors(bio_err);
		goto end;
	}

	ret = 1;

end:
	OPENSSL_free(inbuf);
	OPENSSL_free(outbuf);
	return ret;
}

static int sm9_decrypt(int scheme, BIO *in, BIO *out, SM9_KEY *key, char *prog)
{
	int ret = 0;
	unsigned char *inbuf = NULL;
	unsigned char *outbuf = NULL;
	int inlen;
	size_t outlen;

	if (!key) {
		BIO_printf(bio_err, "%s: private key required\n", prog);
		goto end;
	}

	if (!(inlen = bio_to_mem(&inbuf, SM9_MAX_CIPHERTEXT_LENGTH, in))) {
		BIO_printf(bio_err, "%s: error reading input\n", prog);
		goto end;
	}

	if (!SM9_decrypt(scheme, inbuf, inlen, NULL, &outlen, key)
		|| !(outbuf = OPENSSL_malloc(outlen))
		|| !SM9_decrypt(scheme, inbuf, inlen, outbuf, &outlen, key)
		|| BIO_write(out, outbuf, outlen) != outlen) {
		ERR_print_errors(bio_err);
		goto end;
	}

	ret = 1;

end:
	OPENSSL_free(inbuf);
	OPENSSL_free(outbuf);
	return ret;
}

int sm9utl_main(int argc, char **argv)
{
	int ret = 1;
	OPTION_CHOICE o;
	char *prog;
	char *infile = NULL;
	char *outfile = NULL;
	char *sigfile = NULL;
	BIO *in = NULL;
	BIO *out = NULL;
	int op = EVP_PKEY_OP_UNDEFINED;
	char *paramfile = NULL;
	char *id = NULL;
	char *keyfile = NULL;
	char *passinarg = NULL;
	int keyform = FORMAT_PEM;
	int paramform = FORMAT_PEM;
	char *dgst = NULL;
	char *scheme = NULL;
	const EVP_MD *md = EVP_sm3();
	int enc_scheme = NID_sm9encrypt_with_sm3_xor;
	char *passin = NULL;

	EVP_PKEY *pkey = NULL;
	SM9_MASTER_KEY *param;
	SM9_KEY *key;

	prog = opt_init(argc, argv, sm9utl_options);
	while ((o = opt_next()) != OPT_EOF) {
		switch (o) {
		case OPT_EOF:
		case OPT_ERR:
opthelp:
			BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
			goto end;
		case OPT_HELP:
			opt_help(sm9utl_options);
			ret = 0;
			goto end;
		case OPT_IN:
			infile = opt_arg();
			break;
		case OPT_OUT:
			outfile = opt_arg();
			break;
		case OPT_SIGFILE:
			sigfile = opt_arg();
			break;
		case OPT_SIGN:
			op = EVP_PKEY_OP_SIGN;
			break;
		case OPT_VERIFY:
			op = EVP_PKEY_OP_VERIFY;
			break;
		case OPT_ENCRYPT:
			op = EVP_PKEY_OP_ENCRYPT;
			break;
		case OPT_DECRYPT:
			op = EVP_PKEY_OP_DECRYPT;
			break;
		case OPT_MD:
			dgst = opt_arg();
			break;
		case OPT_SCHEME:
			scheme = opt_arg();
			break;
		case OPT_PARAMFILE:
			paramfile = opt_arg();
			break;
		case OPT_ID:
			id = opt_arg();
			break;
		case OPT_INKEY:
			keyfile = opt_arg();
			break;
		case OPT_PASSIN:
			passinarg = opt_arg();
			break;
		case OPT_KEYFORM:
			if (!opt_format(opt_arg(), OPT_FMT_PDE, &keyform))
				goto opthelp;
			break;
		case OPT_PARAMFORM:
			if (!opt_format(opt_arg(), OPT_FMT_PDE, &paramform))
				goto opthelp;
			break;
		}
	}
	argc = opt_num_rest();
	if (argc != 0)
		goto opthelp;

	app_RAND_load_file(NULL, 0);


	if (op == EVP_PKEY_OP_SIGN || op == EVP_PKEY_OP_DECRYPT) {

		if (!keyfile) {
			BIO_printf(bio_err, "Private key required\n");
			goto end;
		}

		if (paramfile || id) {
			BIO_printf(bio_err, "Parameters and ID not required\n");
			goto end;
		}

		if (!app_passwd(passinarg, NULL, &passin, NULL)) {
			BIO_printf(bio_err, "Error getting password\n");
			goto end;
		}

		if (keyfile) {
			pkey = load_key(keyfile, keyform, 0, passin, NULL, "Private Key");
			if (!(key = EVP_PKEY_get0_SM9(pkey))) {
				ERR_print_errors(bio_err);
				goto end;
			}
		}

		if (op == EVP_PKEY_OP_SIGN)
			return sm9_sign(md, in, out, key, prog);
		else
			return sm9_decrypt(enc_scheme, in, out, key, prog);

	} else if (op == EVP_PKEY_OP_VERIFY || op == EVP_PKEY_OP_ENCRYPT) {

		if (!paramfile || !id) {
			BIO_printf(bio_err, "Parameters and ID required\n");
			goto end;
		}

		if (keyfile) {
			BIO_printf(bio_err, "Private key not required\n");
			goto end;
		}

		pkey = load_pubkey(keyfile, keyform,  0, NULL, NULL, "Public Key");
		if (!(param = EVP_PKEY_get0_SM9_MASTER(pkey))) {
			ERR_print_errors(bio_err);
			goto end;
		}

		if (op == EVP_PKEY_OP_VERIFY) {
			if (!sigfile) {
				BIO_printf(bio_err, "Signature file required\n");
				goto end;
			}
			return sm9_verify(md, in, out, sigfile, param, id, prog);
		} else {
			return sm9_encrypt(enc_scheme, in, out, param, id, prog);
		}

	} else {
		BIO_printf(bio_err, "%s: operation not assigned\n", prog);
		goto end;
	}


end:
	OPENSSL_free(passin);
	return ret;
}
#endif
