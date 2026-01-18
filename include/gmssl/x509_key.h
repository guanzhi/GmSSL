/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_X509_KEY_H
#define GMSSL_X509_KEY_H


#include <time.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmssl/oid.h>
#include <gmssl/asn1.h>
#include <gmssl/sm2.h>
#include <gmssl/lms.h>
#include <gmssl/xmss.h>
#include <gmssl/sphincs.h>


#ifdef __cplusplus
extern "C" {
#endif


/*
   Supported public key type OIDs
	* OID_ec_public_key
	* OID_rsa_encryption
	* OID_lms_hashsig
	* OID_hss_lms_hashsig
	* OID_xmss_hashsig
	* OID_xmssmt_hashsig
	* OID_sphincs_hashsig


*/
typedef struct {
	int algor;
	int algor_param;
	union {
		SM2_KEY sm2_key;
		LMS_KEY lms_key;
		HSS_KEY hss_key;
		XMSS_KEY xmss_key;
		XMSSMT_KEY xmssmt_key;
		SPHINCS_KEY sphincs_key;
	} u;
} X509_KEY;

int x509_key_generate(X509_KEY *key, int algor, int algor_param);

int x509_key_set_sm2_key(X509_KEY *x509_key, SM2_KEY *sm2_key);
int x509_key_set_lms_key(X509_KEY *x509_key, LMS_KEY *lms_key);
int x509_key_set_hss_key(X509_KEY *x509_key, HSS_KEY *hss_key);
int x509_key_set_xmss_key(X509_KEY *x509_key, XMSS_KEY *xmss_key);
int x509_key_set_xmssmt_key(X509_KEY *x509_key, XMSSMT_KEY *xmssmt_key);
int x509_key_set_sphincs_key(X509_KEY *x509_key, SPHINCS_KEY *sphincs_key);

int x509_public_key_digest(const X509_KEY *key, uint8_t dgst[32]);

/*
SubjectPublicKeyInfo  ::=  SEQUENCE  {
	algorithm            AlgorithmIdentifier,
	subjectPublicKey     BIT STRING  }

algorithm.algorithm = OID_ec_public_key;
algorithm.parameters = OID_sm2;
subjectPublicKey = ECPoint
*/
int x509_public_key_info_to_der(const X509_KEY *key, uint8_t **out, size_t *outlen);
int x509_public_key_info_from_der(X509_KEY *key, const uint8_t **in, size_t *inlen);
int x509_public_key_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);
int x509_private_key_print(FILE *fp, int fmt, int ind, const char *label, const X509_KEY *key);
int x509_public_key_print(FILE *fp, int fmt, int ind, const char *label, const X509_KEY *key);
int x509_private_key_from_file(X509_KEY *key, int algor, const char *pass, FILE *fp);


typedef union {
	SM2_POINT sm2;
	HSS_PUBLIC_KEY hss;
	XMSS_PUBLIC_KEY xmss;
	XMSSMT_PUBLIC_KEY xmssmt;
} X509_PUBLIC_KEY;

#define X509_PUBLIC_KEY_MAX_SIZE sizeof(X509_PUBLIC_KEY)

typedef union {
	uint8_t sm2_sig[SM2_MAX_SIGNATURE_SIZE];
	HSS_SIGNATURE hss_sig;
	XMSS_SIGNATURE xmss_sig;
	XMSSMT_SIGNATURE xmssmt_sig;
} X509_SIGNATURE;

#define X509_SIGNATURE_MAX_SIZE	sizeof(X509_SIGNATURE)

typedef struct {
	union {
		SM2_SIGN_CTX sm2_sign_ctx;
		SM2_VERIFY_CTX sm2_verify_ctx;
		HSS_SIGN_CTX hss_sign_ctx;
		XMSS_SIGN_CTX xmss_sign_ctx;
		XMSSMT_SIGN_CTX xmssmt_sign_ctx;
	} u;
	int sign_algor;
	uint8_t sig[X509_SIGNATURE_MAX_SIZE];
	size_t siglen;
} X509_SIGN_CTX;


int x509_key_get_sign_algor(const X509_KEY *key, int *algor);
int x509_key_get_signature_size(const X509_KEY *key, size_t *siglen);

int x509_sign_init(X509_SIGN_CTX *ctx, X509_KEY *key, const char *signer_id, size_t signer_idlen);
int x509_sign_update(X509_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int x509_sign_finish(X509_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int x509_verify_init(X509_SIGN_CTX *ctx, const X509_KEY *key,
	const char *signer_id, size_t signer_idlen, // 这里可能要去掉这个功能
	const uint8_t *sig, size_t siglen);
int x509_verify_update(X509_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int x509_verify_finish(X509_SIGN_CTX *ctx);



#ifdef __cplusplus
}
#endif
#endif
