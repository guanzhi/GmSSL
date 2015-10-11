#ifndef HEADER_SM2_H
#define HEADER_SM2_H

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SM2_DEFAULT_POINT_CONVERSION_FORM 0


typedef struct sm2_ciphertext_value_st {
	EC_POINT *ephem_point;
	unsigned char *ciphertext;
	size_t ciphertext_size;
	unsigned char mactag[EVP_MAX_MD_SIZE];
	unsigned int mactag_size;
} SM2_CIPHERTEXT_VALUE;


int SM2_compute_za(unsigned char *za, const EVP_MD *md,
	const void *id, size_t idlen, EC_KEY *ec_key);

int SM2_compute_digest(unsigned char *dgst, unsigned int *dgstlen,
	const EVP_MD *za_md, const void *id, size_t idlen, EC_KEY *ec_key,
	const EVP_MD *msg_md, const void *msg, size_t msglen);

int SM2_CIPHERTEXT_VALUE_size(const EC_GROUP *ec_group,
	point_conversion_form_t point_form, size_t mlen,
	const EVP_MD *mac_md);

void SM2_CIPHERTEXT_VALUE_free(SM2_CIPHERTEXT_VALUE *cv);

int SM2_CIPHERTEXT_VALUE_encode(const SM2_CIPHERTEXT_VALUE *cv,
	const EC_GROUP *ec_group, point_conversion_form_t point_form,
	unsigned char *buf, size_t *buflen);

SM2_CIPHERTEXT_VALUE *SM2_CIPHERTEXT_VALUE_decode(const EC_GROUP *ec_group,
	point_conversion_form_t point_form, const EVP_MD *mac_md,
	const unsigned char *buf, size_t buflen);

int SM2_CIPHERTEXT_VALUE_print(BIO *out, const SM2_CIPHERTEXT_VALUE *cv,
	int indent, unsigned long flags);

SM2_CIPHERTEXT_VALUE *SM2_do_encrypt(const EVP_MD *kdf_md, const EVP_MD *mac_md,
	const unsigned char *in, size_t inlen, EC_KEY *ec_key);

int SM2_do_decrypt(const EVP_MD *kdf_md, const EVP_MD *mac_md,
	const SM2_CIPHERTEXT_VALUE *cv, unsigned char *out, size_t *outlen,
	EC_KEY *ec_key);

int SM2_encrypt(const EVP_MD *kdf_md, const EVP_MD *mac_md,
	point_conversion_form_t point_form, unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen, EC_KEY *ec_key);

int SM2_decrypt(const EVP_MD *kdf_md, const EVP_MD *mac_md,
	point_conversion_form_t point_form, const unsigned char *in,
	size_t inlen, unsigned char *out, size_t *outlen, EC_KEY *ec_key);

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

