#ifndef LIBSM_SMS4_EDE_H
#define LIBSM_SMS4_EDE_H

#define SMS4_EDE_KEY_LENGTH	32

#include "sms4.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	sms4_key_t k1;
	sms4_key_t k2;	
} sms4_ede_key_t;

void sms4_ede_set_encrypt_key(sms4_ede_key_t *key, const unsigned char *user_key);
void sms4_ede_set_decrypt_key(sms4_ede_key_t *key, const unsigned char *user_key);
void sms4_ede_encrypt(sms4_ede_key_t *key, const unsigned char *in, unsigned char *out);
void sms4_ede_encrypt_8blocks(sms4_ede_key_t *key, const unsigned char *in, unsigned char *out);
void sms4_ede_encrypt_16blocks(sms4_ede_key_t *key, const unsigned char *in, unsigned char *out);
void sms4_ede_decrypt(sms4_ede_key_t *key, const unsigned char *in, unsigned char *out);
void sms4_ede_decrypt_8blocks(sms4_ede_key_t *key, const unsigned char *in, unsigned char *out);
void sms4_ede_decrypt_16blocks(sms4_ede_key_t *key, const unsigned char *in, unsigned char *out);

#ifdef __cplusplus
}
#endif
#endif

