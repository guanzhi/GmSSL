#include <stdio.h>
#include "cryptlib.h"

#ifndef OPENSSL_NO_GMSSL

#include <openssl/evp.h>
#include "evp_locl.h"
#include <openssl/objects.h>
#include <openssl/zuc.h>


static int zuc_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
	const unsigned char *iv, int enc)
{
	ZUC_set_key((ZUC_KEY *)&ctx->cipher_data, key, iv);
	return 1;
}

static int zuc_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t inlen)
{
	ZUC_encrypt((ZUC_KEY *)&ctx->cipher_data, inlen, in, out);
	return 1;
}


/*
 * FIXME:
 * evp_enc.c assert block_size in {1, 8, 16}, 4 not ok!
 */
static const EVP_CIPHER zuc_cipher = {
	NID_zuc, /* nid */
	4, /* block_size */
	16, /* key_len */
	16, /* iv_len */
	0, /* flags */
	zuc_init, /* init() */
	zuc_do_cipher, /* do_cipher() */
	NULL, /* cleanup() */
	sizeof(ZUC_KEY), /* ctx_size */
	NULL, /* set_asn1_parameters() */
	NULL, /* get_asn1_parameters() */
	NULL, /* ctrl() */
	NULL /* app_data */
};

const EVP_CIPHER *EVP_zuc(void)
{
	return &zuc_cipher;
}

#endif

