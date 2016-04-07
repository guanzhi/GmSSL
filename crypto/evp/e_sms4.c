/* crypto/evp/e_sms4.c */
#include <stdio.h>
#include "cryptlib.h"

#ifndef OPENSSL_NO_SMS4
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "evp_locl.h"
#include <openssl/sms4.h>


#define SMS4_IV_LENGTH	SMS4_BLOCK_SIZE

typedef struct {
	sms4_key_t ks;
} EVP_SMS4_KEY;

static int sms4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
	const unsigned char *iv, int enc)
{
	if (!enc) {
		if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_OFB_MODE)
			enc = 1;
		else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CFB_MODE)
			enc = 1;  //encrypt key == decrypt key
	}

	if (enc)
                sms4_set_encrypt_key(ctx->cipher_data, key);
	else	sms4_set_decrypt_key(ctx->cipher_data, key);


	return 1;
}

IMPLEMENT_BLOCK_CIPHER(sms4, ks, sms4, EVP_SMS4_KEY, NID_sms4,
	SMS4_BLOCK_SIZE, SMS4_KEY_LENGTH, SMS4_IV_LENGTH, 128, 0,
	sms4_init_key, NULL, NULL, NULL, NULL)

#if 0
static int sms4_ctr_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
	const unsigned char *in, size_t inlen)
{

	unsigned int num = ctx->num;
	EVP_SMS4_KEY *sms4 = (EVP_SMS4_KEY *)ctx->cipher_data;

	CRYPTO_ctr128_encrypt_ctr32(in, out, inlen, &sms4->ks, ctx->iv, ctx->buf,
		&num, sms4_ctr_encrypt);

	ctx->num = (size_t)num;
	return 1;
}

const EVP_CIPHER sms4_ctr = {
	NID_sms4_ctr,
	SMS4_BLOCK_SIZE,
	SMS4_KEY_LENGTH,
	SMS4_IV_LENGTH,
	0,
	sms4_init_key,
	sms4_ctr_cipher,
	NULL, /* cleanup() */
	sizeof(EVP_SMS4_CTX),
	NULL, /* set_asn1_parameters() */
	NULL, /* get_asn1_parameters() */
	NULL, /* ctrl() */
	NULL  /* app_data */
};

const EVP_CIPHER *EVP_sms4_ctr(void)
{
	return &sms4_ctr;
}

static int sms4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
	const unsigned char *iv, int enc)
{

	int mode;

	mode = ctx->cipher->flags & EVP_CIPH_MODE;
	if ((mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE) && !enc) {
		ret = sms4_set_decrypt_key(key, ctx->key_len * 8, ctx->cipher_data);
		sms4->block = (block128_f)sms4_decrypt;
		sms4->stream.cbc = (mode == EVP_CIPH_CBC_MODE ?
			(cbc128_f)sms4_cbc_encrypt : NULL);
	} else {
		ret = sms4_set_encrypt_key(key, ctx->key_len * 8, ctx->cipher_data);
		sms4->block = (block128_f)sms4_encrypt;
	
		if (mode == EVP_CIPH_CBC_MODE) {
			sms4->stream.cbc = (cbc128_f)sms4_cbc_encrypt;
		} else if (mode == EVP_CIPH_CTR_MODE) {
			sms4->stream.ctr = (ctr128_f)sms4_ctr32_encrypt_blocks;
		} else {
			sms4->stream.cbc = NULL;
		}
	}

	if (ret < 0) {
		return 0;
	}

	return 1;
}




typedef struct {
	sms4_key_t ks;
	int key_is_inited;
	int iv_is_inited;
	GCM128_CONTEXT gcm;
	unsigned char *iv;
	int ivlen;
	int taglen;
	int iv_gen;
	ctr128_f ctr;
} EVP_SMS4_GCM_CTX;





static int sms4_gcm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{

	switch (type) {
	case EVP_CTRL_INIT:


	case EVP_CTRL_GCM_SET_IVLEN:
	case EVP_CTRL_GCM_SET_TAG:
	case EVP_CTRL_GCM_GET_TAG:
	case EVP_CTRL_GCM_SET_IV_FIXED:
	case EVP_CTRL_GCM_IV_GEN:
	case EVP_CTRL_GCM_SET_IV_INV:
	case EVP_CTRL_COPY:
	default:
		return -1;
	}	


}






typedef struct {
	union {
		double align;
		sms4_key_t ks;
	} ks;
	unsigned char *iv;
} EVP_SMS4_WRAP_CTX;


static int sms4_wrap_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
	const unsigned char *iv, int enc)
{
	return -1;
}

static int sms4_wrap_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t inlen)
{
	return -1;
}


#define WRAP_FLAGS      (EVP_CIPH_WRAP_MODE \
                | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
                | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_DEFAULT_ASN1)



 const EVP_CIPHER sms4_wrap = {
	NID_sms4_wrap,
	SMS4_WRAP_BLOCK_SIZE,
	SMS4_KEY_LENGTH,
	SMS4_WRAP_IV_LENGTH,
	WRAP_FLAGS,
	sms4_wrap_init_key,
	sms4_wrap_do_cipher,
	NULL, /* cleanup() */
	sizeof(EVP_SMS4_WRAP_CTX),
	NULL, /* set_asn1_parameters() */
	NULL, /* get_asn1_parameters() */
	NULL, /* ctrl() */
	NULL  /* app_data */
};	

const EVP_CIPHER *EVP_sms4_wrap(void)
{
	return &sms4_wrap;
}

#endif

#endif
