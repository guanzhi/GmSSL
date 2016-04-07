



#include <stdio.h>



struct CBCMAC_CTX_st {
	EVP_CIPHER_CTX cipher_ctx;
	unsigned char block[EVP_MAX_BLOCK_LENGTH];
	unsigned char tmp_block[EVP_MAX_BLOCK_LENGTH];	
};


CBCMAC *CBCMAC_CTX_new(void)
{
	CBCMAC_CTX *ret;

	if (!(ret = OPENSSL_malloc(*ret))) {
		return NULL;
	}

	EVP_CIPHER_CTX_init(&ret->cipher_ctx);

	return ret;
}

void CBCMAC_CTX_cleanup(CBCMAC_CTX *ctx)
{
	EVP_CIPHER_CTX_cleanup(&ctx->cipher_ctx);
	OPENSSL_cleanse(ctx->block, EVP_MAX_BLOCK_LENGTH);
	OPENSSL_cleanse(ctx->tmp_block, EVP_MAX_BLOCK_LENGTH);
}

EVP_CIPHER_CTX *CBCMAC_CTX_get0_cipher_ctx(CBCMAC_CTX *ctx)
{
	return &ctx->cipher_ctx;
}

void CBCMAC_CTX_free(CBCMAC_CTX *ctx)
{
	if (ctx) {
		CBCMAC_CTX_cleanup(ctx);
		OPENSSL_free(ctx);
	}
}

int CBCMAC_CTX_copy(CBCMAC_CTX *to, const CBCMAC_CTX *from)
{
	return 0;
}

int CBCMAC_Init(CBCMAC_CTX *ctx, const void *key, size_t keylen,
	const EVP_CIPHER *cipher, ENGINE *impl)
{
}

int CBCMAC_Update(CBCMAC_CTX *ctx, const void *data, size_t datalen)
{
}

int CBCMAC_Final(CBCMAC_CTX *ctx, unsigned char *out, size_t *outlen)
{
}

int CBCMAC_resume(CBCMAC_CTX *ctx)
{
}

