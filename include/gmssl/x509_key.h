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
#include <gmssl/secp256r1_key.h>
#include <gmssl/ecdsa.h>
#include <gmssl/lms.h>
#include <gmssl/xmss.h>
#include <gmssl/sphincs.h>
#include <gmssl/kyber.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	int algor;
	int algor_param;
	union {
		SM2_KEY sm2_key;
		SECP256R1_KEY secp256r1_key;
		LMS_KEY lms_key;
		HSS_KEY hss_key;
		XMSS_KEY xmss_key;
		XMSSMT_KEY xmssmt_key;
		SPHINCS_KEY sphincs_key;
		KYBER_KEY kyber_key;
	} u;
} X509_KEY;

int x509_key_set_sm2_key(X509_KEY *x509_key, const SM2_KEY *sm2_key);
int x509_key_set_secp256r1_key(X509_KEY *x509_key, const SECP256R1_KEY *secp256r1_key);
int x509_key_set_lms_key(X509_KEY *x509_key, const LMS_KEY *lms_key);
int x509_key_set_hss_key(X509_KEY *x509_key, const HSS_KEY *hss_key);
int x509_key_set_xmss_key(X509_KEY *x509_key, const XMSS_KEY *xmss_key);
int x509_key_set_xmssmt_key(X509_KEY *x509_key, const XMSSMT_KEY *xmssmt_key);
int x509_key_set_sphincs_key(X509_KEY *x509_key, const SPHINCS_KEY *sphincs_key);
int x509_key_set_kyber_key(X509_KEY *x509_key, const KYBER_KEY *kyber_key);

/*
   algor:			algor_param:
   -------------------------------------------------------------------------
   OID_ec_public_key		OID_sm2 or OID_secp256r1
   OID_lms_hashsig		lms_type
   OID_hss_lms_hashsig		x509_algor_param_from_lms_types(lms_types[])
   OID_xmsss_hashsig		xmss_type
   OID_xmsssmt_hashsig		xmssmt_type
   OID_sphincs_hashsig		OID_undef
*/
int x509_key_generate(X509_KEY *key, int algor, const void *param, size_t paramlen);
void x509_key_cleanup(X509_KEY *key);

/*
  x509_public_key_to_bytes() outlen
    ecPublicKey: 65
    lms-hashsig: 56
    hss-lms-hashsig: 60
    xmss-hashsig: 68
    xmssmt-hashsig: 68
    sphincs-hashsig: 32
    kyber-kem: 800/1184/1568 for kyber 512/768/1024
*/
#define X509_PUBLIC_KEY_MAX_SIZE 1184
int x509_public_key_to_bytes(const X509_KEY *key, uint8_t **out, size_t *outlen);
int x509_public_key_from_bytes(X509_KEY *key, int algor, int algor_param, const uint8_t **in, size_t *inlen);
int x509_public_key_digest(const X509_KEY *key, uint8_t dgst[32]);
int x509_public_key_equ(const X509_KEY *key, const X509_KEY *pub);
int x509_public_key_print(FILE *fp, int fmt, int ind, const char *label, const X509_KEY *key);
int x509_private_key_print_ex(FILE *fp, int fmt, int ind, const char *label, const X509_KEY *key);

/*
  X.509 SubjectPublicKeyInfo

  x509_public_key_info_to_der() outlen
    ecPublicKey: 91
    lms-hashsig: 79
    hss-lms-hashsig: 82
    xmss-hashsig: 87
    xmssmt-hashsig: 87
    sphincs-hashsig: 52
    kyber-kem:
*/
#define X509_PUBLIC_KEY_INFO_MAX_SIZE 1280 // for kyber and 91 for others
int x509_public_key_info_to_der(const X509_KEY *key, uint8_t **out, size_t *outlen);
int x509_public_key_info_from_der(X509_KEY *key, const uint8_t **in, size_t *inlen);
int x509_public_key_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);


// ECPrivateKey when key->algor == OID_ec_public_key
int ec_private_key_to_der(const X509_KEY *key, int encode_params, int encode_pubkey, uint8_t **out, size_t *outlen);
int ec_private_key_from_der(X509_KEY *key, int opt_curve, const uint8_t **in, size_t *inlen);
int ec_private_key_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen); // from <gmssl/ec.h>
// X509_KEY lost some information of ECPrivateKey. so no ec_private_key_print_ex(X509_KEY)


// PKCS #8 PrivateKeyInfo
// PrivateKeyInfo.algor.parameters has the named_curve
// so omit the optional ECPrivateKey params(named_curve) a nd omit the public_key
#define X509_ENCODE_EC_PRIVATE_KEY_PARAMS 0
#define X509_ENCODE_EC_PRIVATE_KEY_PUBKEY 1
int x509_private_key_info_to_der(const X509_KEY *key, uint8_t **out, size_t *outlen);
int x509_private_key_info_from_der(X509_KEY *key, const uint8_t **attrs, size_t *attrslen,
	const uint8_t **in, size_t *inlen);
// TODO: no x509_private_key_info_print

// PKCS #8 EncryptedPrivateKeyInfo
#define PKCS8_ENCED_PRIVATE_KEY_INFO_ITER 65536
int x509_private_key_info_encrypt_to_der(const X509_KEY *x509_key, const char *pass,
	uint8_t **out, size_t *outlen);
int x509_private_key_info_decrypt_from_der(X509_KEY *x509_key,
	const uint8_t **attrs, size_t *attrs_len,
	const char *pass, const uint8_t **in, size_t *inlen);



// SM2_SIGNATURE_MAX_SIZE = 72
// LMS_SIGNATURE_MAX_SIZE = 1932
// HSS_SIGNATURE_MAX_SIZE = ?
// XMSS_SIGNATURE_MAX_SIZE = 2820
// XMSSMT_SIGNATURE_MAX_SIZE >= 27688 ?
// SPHINCS_SIGNATURE_SIZE = ?
// ECDSA_SIGNATURE_MAX_SIZE = 72

typedef union {
	uint8_t sm2_sig[SM2_MAX_SIGNATURE_SIZE];
	LMS_SIGNATURE lms_sig;
	HSS_SIGNATURE hss_sig;
	XMSS_SIGNATURE xmss_sig;
	XMSSMT_SIGNATURE xmssmt_sig;
	SPHINCS_SIGNATURE sphincs_sig;
	uint8_t ecdsa_sig[SM2_MAX_SIGNATURE_SIZE];
} X509_SIGNATURE;

// FIXME: give sizeof to a number
#define X509_SIGNATURE_MAX_SIZE	sizeof(X509_SIGNATURE)

typedef struct {
	union {
		SM2_SIGN_CTX sm2_sign_ctx;
		SM2_VERIFY_CTX sm2_verify_ctx;
		ECDSA_SIGN_CTX ecdsa_sign_ctx;
		LMS_SIGN_CTX lms_sign_ctx;
		HSS_SIGN_CTX hss_sign_ctx;
		XMSS_SIGN_CTX xmss_sign_ctx;
		XMSSMT_SIGN_CTX xmssmt_sign_ctx;
		SPHINCS_SIGN_CTX sphincs_sign_ctx;
	} u;
	int sign_algor;
	uint8_t sig[X509_SIGNATURE_MAX_SIZE];
	size_t siglen;
	size_t fixed_siglen;
} X509_SIGN_CTX;


/*
   algor:
	OID_sm2sign_with_sm3
	OID_ecdss_with_sha256
	OID_lms_hashsig
	OID_hss_lms_hashsig
	OID_xmss_hashsig
	OID_xmssmt_hashsig
	OID_sphincs_hashsig
*/
int x509_key_get_sign_algor(const X509_KEY *key, int *algor);
int x509_key_get_signature_size(const X509_KEY *key, size_t *siglen);

// args, argslen:
//	sm2	SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH
//		TLS13_SM2_ID, TLS13_SM2_ID_LENGTH
//	sphincs	optiona_random, 16


/*
  x509_sign_init argumetns

    x509_key->algor:algor_param	    ctx->sign_algor       args         argslen
    ------------------------------------------------------------------------------------------------
    OID_ec_public_key:OID_sm2       OID_sm2sign_with_sm3  char *id     idlen
                                                          NULL         0    use SM2_DEFAULT_ID
    OID_ec_public_key:OID_secp256r1 OID_ecdsa_with_sha256 NULL         0
    OID_lms_hashsig:OID_undef       OID_lms_hashsig       NULL         0
    OID_hss_lms_hashsig:OID_undef   OID_hss_lms_hashsig   NULL         0
    OID_xmss_hashsig:OID_undef      OID_xmss_hashsig      NULL         0
    OID_xmssmt_hashsig:OID_undef    OID_xmssmt_hashsig    NULL         0
    OID_sphincs_hashsig:OID_undef   OID_sphincs_hashsig   u8 rand[16]  16   randomized signature
                                                          NULL         0    deterministic signature
*/
int x509_sign_init(X509_SIGN_CTX *ctx, X509_KEY *key, const void *args, size_t argslen);
int x509_sign_set_signature_size(X509_SIGN_CTX *ctx, size_t siglen);
int x509_sign_update(X509_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int x509_sign_finish(X509_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int x509_sign(X509_SIGN_CTX *ctx, const uint8_t *data, size_t datalen, uint8_t *sig, size_t *siglen);
int x509_verify_init(X509_SIGN_CTX *ctx, const X509_KEY *key, const void *args, size_t argslen,
	const uint8_t *sig, size_t siglen);
int x509_verify_update(X509_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int x509_verify_finish(X509_SIGN_CTX *ctx);
int x509_verify(X509_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
void x509_sign_ctx_cleanup(X509_SIGN_CTX *ctx);

// ECDH for key->algor == OID_ec_public_key
int x509_key_do_exchange(const X509_KEY *key, const X509_KEY *peer_pub, uint8_t *out, size_t *outlen);
int x509_key_exchange(const X509_KEY *key, const uint8_t *peer_pub, size_t peer_publen, uint8_t *out, size_t *outlen);

// KEM
#define X509_KEM_CIPHERTEXT_SIZE sizeof(KYBER_CIPHERTEXT)
int x509_key_encapsulate(const X509_KEY *key, uint8_t *ciphertext, size_t *ciphertext_len, uint8_t secret[32]);
int x509_key_decapsulate(const X509_KEY *key, const uint8_t *ciphertext, size_t ciphertext_len, uint8_t secret[32]);


// require stdio
int x509_private_key_info_encrypt_to_pem(const X509_KEY *key, const char *pass, FILE *fp);
int x509_private_key_info_decrypt_from_pem(X509_KEY *key, const uint8_t **attrs, size_t *attrslen, const char *pass, FILE *fp);
int x509_private_key_from_file(X509_KEY *key, int algor, const char *pass, FILE *fp);


#ifdef __cplusplus
}
#endif
#endif
