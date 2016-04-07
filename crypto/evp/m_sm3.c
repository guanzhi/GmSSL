#include <stdio.h>
#include "cryptlib.h"

#ifndef OPENSSL_NO_SM3

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/sm3.h>


static int init(EVP_MD_CTX *ctx)
{
	return sm3_init(ctx->md_data);
}

static int update(EVP_MD_CTX *ctx, const void *in, size_t inlen)
{
	return sm3_update(ctx->md_data, in, inlen);
}

static int final(EVP_MD_CTX *ctx, unsigned char *md)
{
	return sm3_final(ctx->md_data, md);
}

static const EVP_MD sm3_md = {
        NID_sm3,
        NID_sm2sign_with_sm3,
        SM3_DIGEST_LENGTH,
        0,
        init,
        update,
        final,
        NULL,
        NULL,
        EVP_PKEY_RSA_method,
        SM3_BLOCK_SIZE,
        sizeof(EVP_MD *) + sizeof(sm3_ctx_t),
};

const EVP_MD *EVP_sm3(void)
{
        return &sm3_md;
}

#endif
