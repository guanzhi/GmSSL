#ifndef LIBSM3_HMAC_SM3_H
#define LIBSM3_HMAC_SM3_H

#include "sm3.h"

#define HMAC_SM3_MAC_SIZE  SM3_DIGEST_LENGTH

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	sm3_ctx_t sm3_ctx;
	unsigned char key[SM3_DIGEST_LENGTH];
} hmac_sm3_ctx_t;


void hmac_sm3_init(hmac_sm3_ctx_t *ctx, const unsigned char *key, size_t key_len);
void hmac_sm3_update(hmac_sm3_ctx_t *ctx, const unsigned char *data, size_t data_len);
void hmac_sm3_final(hmac_sm3_ctx_t *ctx, unsigned char mac[HMAC_SM3_MAC_SIZE]);
void hmac_sm3(const unsigned char *data, size_t data_len,
	const unsigned char *key, size_t key_len, unsigned char mac[HMAC_SM3_MAC_SIZE]);

#ifdef __cplusplus
}
#endif
#endif

