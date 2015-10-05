#ifndef HEADER_SM2_ENC_H
#define HEADER_SM2_ENC_H

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct sm2_ciphertext_value_st {
	EC_POINT *ephem_point;
	unsigned char *ciphertext;
	size_t ciphertext_size;
	unsigned char mactag[EVP_MAX_MD_SIZE];
	size_t mactag_size;
} SM2_CIPHERTEXT_VALUE;


SM2_CIPHERTEXT_VALUE *SM2_do_encrypt(
	const EVP_MD *kdf_md, const EVP_MD *mac_md,
	const void *in, size_t inlen, const EC_KEY *pub_key);

int SM2_do_decrypt(const SM2_CIPHERTEXT_VALUE *cv,
	const EVP_MD *kdf_md, const EVP_MD *mac_md,
	unsigned char *out, size_t *outlen, EC_KEY *pri_key);

void SM2_CIPHERTEXT_VALUE_free(SM2_CIPHERTEXT_VALUE *cv);


void ERR_load_SM2_strings(void);

/* Error codes for the ECIES functions. */

/* Function codes. */
#define SM2_F_SM2_DO_ENCRYPT			100
#define SM2_F_SM2_DO_DECRYPT			101
#define SM2_F_SM2_CIPHERTEXT_VALUE_FREE	102

/* Reason codes. */
#define SM2_R_BAD_DATA				100
#define SM2_R_UNKNOWN_CIPHER_TYPE		101
#define SM2_R_ENCRYPT_FAILED			102
#define SM2_R_DECRYPT_FAILED			103
#define SM2_R_UNKNOWN_MAC_TYPE			104
#define SM2_R_GEN_MAC_FAILED			105
#define SM2_R_VERIFY_MAC_FAILED			106
#define SM2_R_ECDH_FAILED			107
#define SM2_R_BUFFER_TOO_SMALL			108

#ifdef __cplusplus
}
#endif
#endif

