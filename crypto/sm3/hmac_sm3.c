#include <string.h>
#include <assert.h>
#include "hmac_sm3.h"

/**
 * HMAC_k(m) = H((k ^ opad), H((k ^ ipad), m))
 * pseudo-code:
 * function hmac(key, message)
 *	opad = [0x5c * blocksize]
 *	ipad = [0x36 * blocksize]
 *	if (length(key) > blocksize) then
 *		key = hash(key)
 *	end if
 *	for i from 0 to length(key) - 1 step 1
 *		ipad[i] = ipad[i] XOR key[i]
 *		opad[i] = opad[i] XOR key[i]
 *	end for
 *	return hash(opad || hash(ipad || message))
 * end function
 */


#define IPAD	0x36
#define OPAD	0x5C



void hmac_sm3_init(hmac_sm3_ctx_t *ctx, const unsigned char *key, size_t key_len)
{
	int i;
	unsigned char ipad[SM3_DIGEST_LENGTH];

	if (key_len <= SM3_BLOCK_SIZE) {
		memcpy(ctx->key, key, key_len);
		memset(ctx->key + key_len, 0, SM3_BLOCK_SIZE - key_len);
	} else {
		sm3_init(&ctx->sm3_ctx);
		sm3_update(&ctx->sm3_ctx, key, key_len);
		sm3_final(&ctx->sm3_ctx, ctx->key);
		memset(ctx->key + SM3_DIGEST_LENGTH, 0,
			SM3_BLOCK_SIZE - SM3_DIGEST_LENGTH);
	}
	for (i = 0; i < SM3_BLOCK_SIZE; i++) {
		ctx->key[i] ^= IPAD;
	}
	
	sm3_init(&ctx->sm3_ctx);
	sm3_update(&ctx->sm3_ctx, ctx->key, SM3_BLOCK_SIZE);		
}

void hmac_sm3_update(hmac_sm3_ctx_t *ctx, const unsigned char *data, size_t data_len)
{
	sm3_update(&ctx->sm3_ctx, data, data_len);
}

void hmac_sm3_final(hmac_sm3_ctx_t *ctx, unsigned char mac[HMAC_SM3_MAC_SIZE])
{
	int i;
	for (i = 0; i < SM3_BLOCK_SIZE; i++) {
		ctx->key[i] ^= (IPAD ^ OPAD);
	}	
	sm3_final(&ctx->sm3_ctx, mac);
	sm3_init(&ctx->sm3_ctx);
	sm3_update(&ctx->sm3_ctx, ctx->key, SM3_BLOCK_SIZE);
	sm3_update(&ctx->sm3_ctx, mac, SM3_DIGEST_LENGTH);
	sm3_final(&ctx->sm3_ctx, mac);
}

void hmac_sm3(const unsigned char *data, size_t data_len,
	const unsigned char *key, size_t key_len, unsigned char mac[HMAC_SM3_MAC_SIZE])
{
	hmac_sm3_ctx_t ctx;
	
	hmac_sm3_init(&ctx, key, key_len);
	hmac_sm3_update(&ctx, data, data_len);
	hmac_sm3_final(&ctx, mac);

	memset(&ctx, 0, sizeof(hmac_sm3_ctx_t));
}

