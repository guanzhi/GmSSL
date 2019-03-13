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
#ifdef OPENSSL_NO_SM2
NON_EMPTY_TRANSLATION_UNIT
#else

# include <ctype.h>
# include <stdio.h>
# include <string.h>
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/evp.h>
# include <openssl/sm2.h>
# include "../crypto/sm2/sm2_lcl.h"
# include "apps.h"


# define OP_UNDEF	0
# define OP_DGST	1
# define OP_SIGN	2
# define OP_VERIFY	3
# define OP_ENCRYPT	4
# define OP_DECRYPT	5

# define KEY_NONE	0
# define KEY_PRIVKEY	1
# define KEY_PUBKEY	2
# define KEY_CERT	3

typedef enum OPTION_choice {
	OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
	OPT_IN,
	OPT_OUT,
	OPT_DGST,
	OPT_SIGN,
	OPT_VERIFY,
	OPT_ENCRYPT,
	OPT_DECRYPT,
	OPT_ID,
	OPT_SIGFILE,
	OPT_INKEY,
	OPT_PUBIN,
	OPT_CERTIN,
	OPT_PASSIN,
	OPT_KEYFORM,
	OPT_MD,
	OPT_ENGINE,
	OPT_ENGINE_IMPL,
	OPT_CONFIG
} OPTION_CHOICE;

OPTIONS sm2utl_options[] = {
	{"help", OPT_HELP, '-', "Display this summary"},
	{"in", OPT_IN, '<', "Input file - default stdin"},
	{"out", OPT_OUT, '>', "Output file - default stdout"},
	{"dgst", OPT_DGST, '-', "Generate input data digest with Z value"},
	{"sign", OPT_SIGN, '-', "Sign input data with private key and public parameters"},
	{"verify", OPT_VERIFY, '-', "Verify with signer's ID and public parameters"},
	{"encrypt", OPT_ENCRYPT, '-', "Encrypt input data with recipient's ID"},
	{"decrypt", OPT_DECRYPT, '-', "Decrypt input data with private key"},
	{"id", OPT_ID, 's', "Identity for Z value"},
	{"sigfile", OPT_SIGFILE, '<', "Signature file (verify operation only)"},
	{"inkey", OPT_INKEY, 's', "Private key for signing or decryption"},
	{"pubin", OPT_PUBIN, '-', "Input is a public key"},
	{"certin", OPT_CERTIN, '-', "Input is a cert with a public key"},
	{"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
	{"keyform", OPT_KEYFORM, 'E', "Private key format - default PEM"},
	{"", OPT_MD, '-', "Any supported digest"},
# ifndef OPENSSL_NO_ENGINE
	{"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
	{"engine_impl", OPT_ENGINE_IMPL, '-', "Also use engine given by -engine for crypto operations"},
	{"config", OPT_CONFIG, 's', "A config file"},
# endif
	{NULL}
};

static int sm2utl_sign(const EVP_MD *md, BIO *in, BIO *out, const char *id,
	ENGINE *e, EC_KEY *key, int sign);
static int sm2utl_verify(const EVP_MD *md, BIO *in, BIO *out, BIO *sig,
	const char *id, ENGINE *e, EC_KEY *ec_key);
static int sm2utl_encrypt(const EVP_MD *md, BIO *in, BIO *out, EC_KEY *ec_key);
static int sm2utl_decrypt(const EVP_MD *md, BIO *in, BIO *out, EC_KEY *ec_key);

int sm2utl_main(int argc, char **argv)
{
	int ret = 1;
	OPTION_CHOICE o;
	char *prog;
	char *infile = NULL, *outfile = NULL, *sigfile = NULL;
	BIO *in = NULL, *out = NULL, *sig = NULL;
	int op = OP_UNDEF;
	char *id = NULL;
	char *keyfile = NULL;
	int key_type = KEY_PRIVKEY;
	char *passinarg = NULL;
	char *passin = NULL;
	int keyform = FORMAT_PEM;
	const EVP_MD *md = EVP_sm3(), *m;
# ifndef OPENSSL_NO_ENGINE
	ENGINE *e = NULL;
	CONF *conf = NULL;
	char *configfile = default_config_file;
# endif
	int engine_impl = 0;
	EVP_PKEY *pkey = NULL;
	EC_KEY *ec_key;

	prog = opt_init(argc, argv, sm2utl_options);
	while ((o = opt_next()) != OPT_EOF) {
		switch (o) {
		case OPT_EOF:
		case OPT_ERR:
opthelp:
			BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
			goto end;
		case OPT_HELP:
			opt_help(sm2utl_options);
			ret = 0;
			goto end;
		case OPT_IN:
			infile = opt_arg();
			break;
		case OPT_OUT:
			outfile = opt_arg();
			break;
		case OPT_DGST:
			op = OP_DGST;
			break;
		case OPT_SIGN:
			op = OP_SIGN;
			break;
		case OPT_VERIFY:
			op = OP_VERIFY;
			break;
		case OPT_ENCRYPT:
			op = OP_ENCRYPT;
			break;
		case OPT_DECRYPT:
			op = OP_DECRYPT;
			break;
		case OPT_ID:
			id = opt_arg();
			break;
		case OPT_SIGFILE:
			sigfile = opt_arg();
			break;
		case OPT_INKEY:
			keyfile = opt_arg();
			break;
		case OPT_PUBIN:
			key_type = KEY_PUBKEY;
			break;
		case OPT_CERTIN:
			key_type = KEY_CERT;
			break;
		case OPT_PASSIN:
			passinarg = opt_arg();
			break;
		case OPT_KEYFORM:
			if (!opt_format(opt_arg(), OPT_FMT_PDE, &keyform))
				goto opthelp;
			break;
		case OPT_ENGINE:
			e = setup_engine(opt_arg(), 0);
			break;
		case OPT_ENGINE_IMPL:
			engine_impl = 1;
			break;
		case OPT_CONFIG:
			configfile = opt_arg();
			break;
		case OPT_MD:
			if (!opt_md(opt_unknown(), &m))
				goto opthelp;
			md = m;
			break;
		}
	}
	argc = opt_num_rest();
	if (argc != 0)
		goto opthelp;

# ifndef OPENSSL_NO_ENGINE
	if (e)
		BIO_printf(bio_err, "Using configuration from %s\n", configfile);

	if ((conf = app_load_config(configfile)) == NULL)
		goto end;
	if (configfile != default_config_file && !app_load_modules(conf))
		goto end;
# endif

	in = bio_open_default(infile, 'r', FORMAT_BINARY);
	if (!in)
		goto end;

	out = bio_open_default(outfile, 'w', FORMAT_BINARY);
	if (!out)
		goto end;

	if (sigfile) {
		sig = BIO_new_file(sigfile, "rb");
		if (!sig) {
			BIO_printf(bio_err, "Can't open signature file %s\n", sigfile);
			goto end;
		}
	}

	app_RAND_load_file(NULL, 0);

	switch (key_type) {
	case KEY_PRIVKEY:
		if (!(pkey = load_key(keyfile, keyform, 0, passin, e, "Private Key"))) {
			ERR_print_errors(bio_err);
			goto end;
		}
		break;

	case KEY_PUBKEY:
		if (!(pkey = load_pubkey(keyfile, keyform, 0, NULL, e, "Public Key"))) {
			ERR_print_errors(bio_err);
			goto end;
		}
		break;

	case KEY_CERT:
		{
			X509 *x = load_cert(keyfile, keyform, "Certificate");
			if (x) {
				pkey = X509_get_pubkey(x);
				X509_free(x);
			}
		}
		break;
	}

	if (!(ec_key = EVP_PKEY_get0_EC_KEY(pkey))
		|| !EC_KEY_is_sm2p256v1(ec_key)) {
		BIO_printf(bio_err, "Invalid key type\n");
		goto end;
	}

	switch (op) {
	case OP_DGST:
	case OP_SIGN:
	case OP_VERIFY:
		if (!id) {
			BIO_printf(bio_err, "Option '-id' required\n");
			goto end;
		}
		break;
	}

	switch (op) {
	case OP_DGST:
		return sm2utl_sign(md, in, out, id, e, ec_key, 0);
	case OP_SIGN:
		return sm2utl_sign(md, in, out, id, e, ec_key, 1);
	case OP_VERIFY:
		return sm2utl_verify(md, in, out, sig, id, e, ec_key);
	case OP_ENCRYPT:
		return sm2utl_encrypt(md, in, out, ec_key);
	case OP_DECRYPT:
		return sm2utl_decrypt(md, in, out, ec_key);
	default:
		BIO_printf(bio_err, "Cryptographic operation not specified\n");
		goto end;
	}


end:
	BIO_free(in);
	BIO_free(out);
	BIO_free(sig);
	OPENSSL_free(passin);
	return ret;
}
static int sm2utl_sign(const EVP_MD *md, BIO *in, BIO *out, const char *id,
	ENGINE *e, EC_KEY *ec_key, int sign)
{
	int ret = 0;
	EVP_MD_CTX *md_ctx = NULL;
	ECDSA_SIG *sig = NULL;
	unsigned char buf[1024];
	size_t siz = sizeof(buf);
	unsigned int ulen = sizeof(buf);
	int len;

	if (!(md_ctx = EVP_MD_CTX_new())
		|| !EVP_DigestInit_ex(md_ctx, md, e)
		|| !SM2_compute_id_digest(md, id, strlen(id), buf, &siz, ec_key)
		|| !EVP_DigestUpdate(md_ctx, buf, siz)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	while ((len = BIO_read(in, buf, sizeof(buf))) > 0) {
		if (!EVP_DigestUpdate(md_ctx, buf, len)) {
			ERR_print_errors(bio_err);
			goto end;
		}
	}
	if (!EVP_DigestFinal_ex(md_ctx, buf, &ulen)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	len = (int)ulen;

	if (sign) {
		unsigned char *p = buf;
		if (!(sig = SM2_do_sign(buf, len, ec_key))
			|| (len = i2d_ECDSA_SIG(sig, &p)) <= 0) {
			ERR_print_errors(bio_err);
			goto end;
		}
	}
	if (BIO_write(out, buf, len) != len) {
		ERR_print_errors(bio_err);
		goto end;
	}

	ret = 1;
end:
	EVP_MD_CTX_free(md_ctx);
	ECDSA_SIG_free(sig);
	return ret;
}

static int sm2utl_verify(const EVP_MD *md, BIO *in, BIO *out, BIO *sig,
	const char *id, ENGINE *e, EC_KEY *ec_key)
{
	int ret = 0;
	EVP_MD_CTX *md_ctx = NULL;
	unsigned char *sigbuf = NULL;
	unsigned char buf[1024];
	size_t siz = sizeof(buf);
	unsigned int ulen = sizeof(buf);
	int siglen, len;

	siglen = bio_to_mem(&sigbuf, 256, sig);
	if (siglen < 0) {
		BIO_printf(bio_err, "Error reading signature data\n");
		goto end;
	}

	if (!(md_ctx = EVP_MD_CTX_new())
		|| !EVP_DigestInit_ex(md_ctx, md, e)
		|| !SM2_compute_id_digest(md, id, strlen(id), buf, &siz, ec_key)
		|| !EVP_DigestUpdate(md_ctx, buf, siz)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	while ((len = BIO_read(in, buf, sizeof(buf))) > 0) {
		if (!EVP_DigestUpdate(md_ctx, buf, len)) {
			ERR_print_errors(bio_err);
			goto end;
		}
	}
	siz = sizeof(buf);
	if (!EVP_DigestFinal_ex(md_ctx, buf, &ulen)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	/* SM2_verify() can check no suffix on signature */
	ret = SM2_verify(NID_undef, buf, ulen, sigbuf, siglen, ec_key);
	if (ret == 1) {
		BIO_puts(out, "Signature Verification Successful\n");
	} else {
		BIO_puts(out, "Signature Verification Failure\n");
		ret = 0;
	}

end:
	OPENSSL_free(sigbuf);
	EVP_MD_CTX_free(md_ctx);
	return ret;
}

static int sm2utl_encrypt(const EVP_MD *md, BIO *in, BIO *out, EC_KEY *ec_key)
{
	int ret = 0;
	SM2CiphertextValue *cval = NULL;
	unsigned char *buf = NULL;
	int len;

	if (!(len = bio_to_mem(&buf, SM2_MAX_PLAINTEXT_LENGTH, in))) {
		ERR_print_errors(bio_err);
		BIO_printf(bio_err, "Error reading plaintext\n");
		goto end;
	}
	if (!(cval = SM2_do_encrypt(md, buf, len, ec_key))
		|| i2d_SM2CiphertextValue_bio(out, cval) <= 0) {
		ERR_print_errors(bio_err);
		goto end;
	}

	ret = 1;

end:
	OPENSSL_free(buf);
	SM2CiphertextValue_free(cval);
	return ret;
}

static int sm2utl_decrypt(const EVP_MD *md, BIO *in, BIO *out, EC_KEY *ec_key)
{
	int ret = 0;
	SM2CiphertextValue *cval = NULL;
	unsigned char *buf = NULL;
	size_t siz;

	if (!(cval = d2i_SM2CiphertextValue_bio(in, NULL))
		|| !SM2_do_decrypt(md, cval, NULL, &siz, ec_key)
		|| !(buf = OPENSSL_malloc(siz))
		|| !SM2_do_decrypt(md, cval, buf, &siz, ec_key)
		|| BIO_write(out, buf, siz) != siz) {
		ERR_print_errors(bio_err);
		goto end;
	}
	ret = 1;

end:
	SM2CiphertextValue_free(cval);
	OPENSSL_free(buf);
	return ret;
}
#endif
