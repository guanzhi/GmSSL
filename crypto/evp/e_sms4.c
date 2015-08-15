/* crypto/evp/e_sms4.c */
#include <stdio.h>
#include "cryptlib.h"

#ifndef OPENSSL_NO_SMS4
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "evp_locl.h"
#include <openssl/sms4.h>

static int sms4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
			 const unsigned char *iv,int enc);

typedef struct
	{
	sms4_key_t ks;
	} EVP_SMS4_KEY;


IMPLEMENT_BLOCK_CIPHER(sms4, ks, sms4, EVP_SMS4_KEY, NID_sms4,
		       16, 16, 16, 128, 0, sms4_init_key, 0, 0, 0, 0)

static int sms4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
			 const unsigned char *iv, int enc)
	{
	if(!enc) {
		if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_OFB_MODE) enc = 1;
		else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CFB_MODE) enc = 1;  //encrypt key == decrypt key
	}
	if (enc)
                sms4_set_encrypt_key(ctx->cipher_data, key);
	else            //ecb, cbc
		sms4_set_decrypt_key(ctx->cipher_data, key);
	return 1;
	}

#endif
