#ifndef LIBSM_SMS4_H
#define LIBSM_SMS4_H

#define SMS4_KEY_LENGTH		16
#define SMS4_BLOCK_SIZE		16
#define SMS4_NUM_ROUNDS		32

#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include "openssl/modes.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint32_t rk[SMS4_NUM_ROUNDS];
} sms4_key_t;

void sms4_set_encrypt_key(sms4_key_t *key, const unsigned char *user_key);
void sms4_set_decrypt_key(sms4_key_t *key, const unsigned char *user_key);
void sms4_encrypt(const unsigned char *in, unsigned char *out, sms4_key_t *key);
void sms4_cbc_encrypt(const unsigned char *in, unsigned char *out,
                              size_t len, const sms4_key_t *key,
                      unsigned char *ivec, int encrypt);
void sms4_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                                 size_t length, const sms4_key_t *key,
                         unsigned char *ivec, int *num, int encrypt);
void sms4_ofb128_encrypt(const unsigned char *in, unsigned char *out,
                                 size_t length, const sms4_key_t *key,
                                 unsigned char ivec[SMS4_BLOCK_SIZE],
                                 unsigned int *num);
void sms4_ecb_encrypt(const unsigned char *in, unsigned char *out, const sms4_key_t *key, int encrypt);
#define sms4_decrypt(in,out,key)  sms4_encrypt(in,out,key)
#ifdef __cplusplus
}
#endif
#endif

