/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/ec.h>
#include <gmssl/oid.h>
#include <gmssl/asn1.h>
#include <gmssl/sm2.h>
#include <gmssl/mem.h>
#include <gmssl/error.h>
#include <gmssl/x509_alg.h>
#include <gmssl/x509_cer.h>
#include <gmssl/x509_key.h>


// currently the lms_type(s) of SHA-256 and SM3 are smaller than 4-bit
// so we encode the lms_types into 4-bit array and int value
// TODO: if max lms_type > 15, this function must be change!
int x509_algor_param_from_lms_types(int *algor_param, const int *lms_types, size_t num)
{
	if (!algor_param || !lms_types || !num) {
		error_print();
		return -1;
	}
	if (num > HSS_MAX_LEVELS) {
		error_print();
		return -1;
	}

	*algor_param = 0;
	while (num--) {
		if (lms_types[num] < 0 || lms_types[num] > 15) {
			error_print();
			return -1;
		}
		*algor_param <<= 4;
		*algor_param |= lms_types[num] & 0x0f;
	}
	return 1;
}

int x509_algor_param_to_lms_types(int algor_param, int lms_types[5], size_t *num)
{
	if (!lms_types || !num) {
		error_print();
		return -1;
	}
	for (*num = 0; *num < 5; (*num)++) {
		if (!algor_param) {
			break;
		}
		lms_types[*num] = algor_param & 0x0f;
		if (!lms_type_name(lms_types[*num])) {
			error_print();
			return -1;
		}
		algor_param >>= 4;
	}
	return 1;
}


int x509_key_generate(X509_KEY *key, int algor, int algor_param)
{
	if (!key) {
		error_print();
		return -1;
	}
	memset(key, 0, sizeof(X509_KEY));

	switch (algor) {
	case OID_ec_public_key:
		if (algor_param != OID_sm2) {
			error_print();
			return -1;
		}
		if (sm2_key_generate(&key->u.sm2_key) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_lms_hashsig:
		if (!lms_type_name(algor_param)) {
			error_print();
			return -1;
		}
		if (lms_key_generate(&key->u.lms_key, algor_param) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_hss_lms_hashsig:
		{
			int lms_types[5];
			size_t num;
			if (x509_algor_param_to_lms_types(algor_param, lms_types, &num) != 1) {
				error_print();
				return -1;
			}
			if (hss_key_generate(&key->u.hss_key, lms_types, num) != 1) {
				error_print();
				return -1;
			}
		}
		break;
	case OID_xmss_hashsig:
		if (!xmss_type_name((uint32_t)algor_param)) {
			error_print();
			return -1;
		}
		if (xmss_key_generate(&key->u.xmss_key, (uint32_t)algor_param) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_xmssmt_hashsig:
		if (!xmssmt_type_name((uint32_t)algor_param)) {
			error_print();
			return -1;
		}
		if (xmssmt_key_generate(&key->u.xmssmt_key, (uint32_t)algor_param) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_sphincs_hashsig:
		if (algor_param != OID_undef) {
			error_print();
			return -1;
		}
		if (sphincs_key_generate(&key->u.sphincs_key) != 1) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}
	key->algor = algor;
	key->algor_param = algor_param;

	return 1;
}

int x509_public_key_print(FILE *fp, int fmt, int ind, const char *label, const X509_KEY *key)
{
	switch (key->algor) {
	case OID_ec_public_key:
		if (sm2_public_key_print(fp, fmt, ind, label, &key->u.sm2_key) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_lms_hashsig:
		if (lms_public_key_print(fp, fmt, ind, label, &key->u.lms_key.public_key) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_hss_lms_hashsig:
		if (hss_public_key_print(fp, fmt, ind, label, &key->u.hss_key) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_xmss_hashsig:
		if (xmss_public_key_print(fp, fmt, ind, label, &key->u.xmss_key) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_xmssmt_hashsig:
		if (xmssmt_public_key_print(fp, fmt, ind, label, &key->u.xmssmt_key) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_sphincs_hashsig:
		if (sphincs_public_key_print(fp, fmt, ind, label, &key->u.sphincs_key) != 1) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}


int x509_key_set_sm2_key(X509_KEY *x509_key, SM2_KEY *sm2_key)
{
	memset(x509_key, 0, sizeof(X509_KEY));
	x509_key->algor = OID_ec_public_key;
	x509_key->algor_param = OID_sm2;
	x509_key->u.sm2_key = *sm2_key;
	return 1;
}

int x509_key_set_lms_key(X509_KEY *x509_key, LMS_KEY *lms_key)
{
	memset(x509_key, 0, sizeof(X509_KEY));
	x509_key->algor = OID_lms_hashsig;
	x509_key->algor_param = OID_undef;
	x509_key->u.lms_key = *lms_key;
	return -1;
}

int x509_key_set_hss_key(X509_KEY *x509_key, HSS_KEY *hss_key)
{
	memset(x509_key, 0, sizeof(X509_KEY));
	x509_key->algor = OID_hss_lms_hashsig;
	x509_key->algor_param = OID_undef;
	x509_key->u.hss_key = *hss_key;
	return 1;
}

int x509_key_set_xmss_key(X509_KEY *x509_key, XMSS_KEY *xmss_key)
{
	memset(x509_key, 0, sizeof(X509_KEY));
	x509_key->algor = OID_xmss_hashsig;
	x509_key->algor_param = OID_undef;
	x509_key->u.xmss_key = *xmss_key;
	return 1;
}

int x509_key_set_xmssmt_key(X509_KEY *x509_key, XMSSMT_KEY *xmssmt_key)
{
	memset(x509_key, 0, sizeof(X509_KEY));
	x509_key->algor = OID_xmssmt_hashsig;
	x509_key->algor_param = OID_undef;
	x509_key->u.xmssmt_key = *xmssmt_key;
	return 1;
}

int x509_key_set_sphincs_key(X509_KEY *x509_key, SPHINCS_KEY *sphincs_key)
{
	memset(x509_key, 0, sizeof(X509_KEY));
	x509_key->algor = OID_sphincs_hashsig;
	x509_key->algor_param = OID_undef;
	x509_key->u.sphincs_key = *sphincs_key;
	return 1;
}

int x509_key_get_sign_algor(const X509_KEY *key, int *algor)
{
	if (!key || !algor) {
		error_print();
		return -1;
	}

	switch (key->algor) {
	case OID_lms_hashsig:
	case OID_hss_lms_hashsig:
	case OID_xmss_hashsig:
	case OID_xmssmt_hashsig:
	case OID_sphincs_hashsig:
		*algor = key->algor;
		break;
	case OID_ec_public_key:
		*algor = OID_sm2sign_with_sm3;
		break;
	default:
		fprintf(stderr, "key->algor = %d\n", key->algor);
		error_print();
		return -1;
	}
	return 1;
}

int x509_public_key_digest(const X509_KEY *key, uint8_t dgst[32])
{
	SM3_CTX ctx;
	uint8_t bits[X509_PUBLIC_KEY_MAX_SIZE];
	uint8_t *p = bits;
	size_t len = 0;

	switch (key->algor) {
	case OID_ec_public_key:
		if (sm2_z256_point_to_uncompressed_octets(&key->u.sm2_key.public_key, bits) != 1) {
			error_print();
			return -1;
		}
		len = 65;
		break;
	case OID_hss_lms_hashsig:
		if (hss_public_key_to_bytes(&key->u.hss_key, &p, &len) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_xmss_hashsig:
		if (xmss_public_key_to_bytes(&key->u.xmss_key, &p, &len) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_xmssmt_hashsig:
		if (xmssmt_public_key_to_bytes(&key->u.xmssmt_key, &p, &len) != 1) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}

	sm3_init(&ctx);
	sm3_update(&ctx, bits, len);
	sm3_finish(&ctx, dgst);

	return 1;
}

int x509_key_get_signature_size(const X509_KEY *key, size_t *siglen)
{
	switch (key->algor) {
	case OID_hss_lms_hashsig:
		if (hss_key_get_signature_size(&key->u.hss_key, siglen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_xmss_hashsig:
		if (xmss_key_get_signature_size(&key->u.xmss_key, siglen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_xmssmt_hashsig:
		if (xmssmt_key_get_signature_size(&key->u.xmssmt_key, siglen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_ec_public_key:
		*siglen = SM2_signature_typical_size;
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

int x509_sign_init(X509_SIGN_CTX *ctx, X509_KEY *key, const char *signer_id, size_t signer_idlen)
{
	if (!ctx || !key) {
		error_print();
		return -1;
	}

	switch (key->algor) {
	case OID_hss_lms_hashsig:
		if (hss_sign_init(&ctx->u.hss_sign_ctx, &key->u.hss_key) != 1) {
			error_print();
			return -1;
		}
		ctx->sign_algor = key->algor;
		break;
	case OID_xmss_hashsig:
		if (xmss_sign_init(&ctx->u.xmss_sign_ctx, &key->u.xmss_key) != 1) {
			error_print();
			return -1;
		}
		ctx->sign_algor = key->algor;
		break;
	case OID_xmssmt_hashsig:
		if (xmssmt_sign_init(&ctx->u.xmssmt_sign_ctx, &key->u.xmssmt_key) != 1) {
			error_print();
			return -1;
		}
		ctx->sign_algor = key->algor;
		break;
	case OID_ec_public_key:
		if (sm2_sign_init(&ctx->u.sm2_sign_ctx, &key->u.sm2_key, signer_id, signer_idlen) != 1) {
			error_print();
			return -1;
		}
		ctx->sign_algor = OID_sm2sign_with_sm3;
		break;
	default:
		error_print();
		return -1;
	}

	return 1;
}

int x509_sign_update(X509_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	switch (ctx->sign_algor) {
	case OID_hss_lms_hashsig:
		if (hss_sign_update(&ctx->u.hss_sign_ctx, data, datalen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_xmss_hashsig:
		if (xmss_sign_update(&ctx->u.xmss_sign_ctx, data, datalen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_xmssmt_hashsig:
		if (xmssmt_sign_update(&ctx->u.xmssmt_sign_ctx, data, datalen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_sm2sign_with_sm3:
		if (sm2_sign_update(&ctx->u.sm2_sign_ctx, data, datalen) != 1) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

int x509_sign_finish(X509_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen)
{
	if (!ctx || !sig || !siglen) {
		error_print();
		return -1;
	}
	switch (ctx->sign_algor) {
	case OID_hss_lms_hashsig:
		if (hss_sign_finish(&ctx->u.hss_sign_ctx, sig, siglen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_xmss_hashsig:
		if (xmss_sign_finish(&ctx->u.xmss_sign_ctx, sig, siglen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_xmssmt_hashsig:
		if (xmssmt_sign_finish(&ctx->u.xmssmt_sign_ctx, sig, siglen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_sm2sign_with_sm3:
		*siglen = SM2_signature_typical_size;
		if (sm2_sign_finish_fixlen(&ctx->u.sm2_sign_ctx, *siglen, sig) != 1) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

int x509_verify_init(X509_SIGN_CTX *ctx, const X509_KEY *key, const char *signer_id, size_t signer_idlen,
	const uint8_t *sig, size_t siglen)
{
	if (!ctx || !key || !sig || !siglen) {
		error_print();
		return -1;
	}

	switch (key->algor) {
	case OID_hss_lms_hashsig:
		if (hss_verify_init(&ctx->u.hss_sign_ctx, &key->u.hss_key, sig, siglen) != 1) {
			error_print();
			return -1;
		}
		ctx->sign_algor = key->algor;
		break;
	case OID_xmss_hashsig:
		if (xmss_verify_init(&ctx->u.xmss_sign_ctx, &key->u.xmss_key, sig, siglen) != 1) {
			error_print();
			return -1;
		}
		ctx->sign_algor = key->algor;
		break;
	case OID_xmssmt_hashsig:
		if (xmssmt_verify_init(&ctx->u.xmssmt_sign_ctx, &key->u.xmssmt_key, sig, siglen) != 1) {
			error_print();
			return -1;
		}
		ctx->sign_algor = key->algor;
		break;
	case OID_ec_public_key:
		if (sm2_verify_init(&ctx->u.sm2_verify_ctx, &key->u.sm2_key, signer_id, signer_idlen) != 1) {
			error_print();
			return -1;
		}
		ctx->sign_algor = OID_sm2sign_with_sm3;
		if (siglen > sizeof(ctx->sig)) {
			error_print();
			return -1;
		}
		memcpy(ctx->sig, sig, siglen);
		ctx->siglen = siglen;
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

int x509_verify_update(X509_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	switch (ctx->sign_algor) {
	case OID_hss_lms_hashsig:
		if (hss_verify_update(&ctx->u.hss_sign_ctx, data, datalen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_xmss_hashsig:
		if (xmss_verify_update(&ctx->u.xmss_sign_ctx, data, datalen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_xmssmt_hashsig:
		if (xmssmt_verify_update(&ctx->u.xmssmt_sign_ctx, data, datalen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_sm2sign_with_sm3:
		if (sm2_verify_update(&ctx->u.sm2_verify_ctx, data, datalen) != 1) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}

	return 1;
}

int x509_verify_finish(X509_SIGN_CTX *ctx)
{
	int ret;

	switch (ctx->sign_algor) {
	case OID_hss_lms_hashsig:
		if ((ret = hss_verify_finish(&ctx->u.hss_sign_ctx)) < 0) {
			error_print();
			return -1;
		}
		break;
	case OID_xmss_hashsig:
		if ((ret = xmss_verify_finish(&ctx->u.xmss_sign_ctx)) < 0) {
			error_print();
			return -1;
		}
		break;
	case OID_xmssmt_hashsig:
		if ((ret = xmssmt_verify_finish(&ctx->u.xmssmt_sign_ctx)) < 0) {
			error_print();
			return -1;
		}
		break;
	case OID_sm2sign_with_sm3:
		if ((ret = sm2_verify_update(&ctx->u.sm2_verify_ctx, ctx->sig, ctx->siglen)) < 0) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}


	return 1;
}

int x509_public_key_info_to_der(const X509_KEY *x509_key, uint8_t **out, size_t *outlen)
{
	uint8_t keybuf[300];
	uint8_t *p = keybuf;
	size_t keylen = 0;
	size_t len = 0;

	if (!x509_key || !outlen) {
		error_print();
		return -1;
	}

	switch (x509_key->algor) {
	case OID_hss_lms_hashsig:
		if (hss_public_key_to_bytes(&x509_key->u.hss_key, &p, &keylen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_xmss_hashsig:
		if (xmss_public_key_to_bytes(&x509_key->u.xmss_key, &p, &keylen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_xmssmt_hashsig:
		if (xmssmt_public_key_to_bytes(&x509_key->u.xmssmt_key, &p, &keylen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_ec_public_key:
		sm2_z256_point_to_uncompressed_octets(&x509_key->u.sm2_key.public_key, p);
		keylen = 65;
		break;
	default:
		error_print();
	}

	// 这几个函数需要合并到一起
	if (x509_public_key_algor_to_der(x509_key->algor, x509_key->algor_param, NULL, &len) != 1) {
		error_print();
		return -1;
	}
	if (asn1_bit_octets_to_der(keybuf, keylen, NULL, &len) != 1) {
		error_print();
		return -1;
	}

	if (asn1_sequence_header_to_der(len, out, outlen) != 1) {
		error_print();
		return -1;
	}

	if (x509_public_key_algor_to_der(x509_key->algor, x509_key->algor_param, out, outlen) != 1
		|| asn1_bit_octets_to_der(keybuf, keylen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_public_key_info_from_der(X509_KEY *x509_key, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	int algor;
	int algor_param;
	const uint8_t *pub;
	size_t publen;

	if (!x509_key || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_public_key_algor_from_der(&algor, &algor_param, &d, &dlen) != 1
		|| asn1_bit_octets_from_der(&pub, &publen, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}

	memset(x509_key, 0, sizeof(X509_KEY));

	switch (algor) {
	case OID_ec_public_key:
		if (algor_param != OID_sm2) {
			error_print();
			return -1;
		}
		if (sm2_z256_point_from_octets(&x509_key->u.sm2_key.public_key, pub, publen) != 1) {
			error_print();
			return -1;
		}
		publen = 0;
		break;
	case OID_hss_lms_hashsig:
		if (hss_public_key_from_bytes(&x509_key->u.hss_key, &pub, &publen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_xmss_hashsig:
		if (xmss_public_key_from_bytes(&x509_key->u.xmss_key, &pub, &publen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_xmssmt_hashsig:
		if (xmssmt_public_key_from_bytes(&x509_key->u.xmssmt_key, &pub, &publen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_sphincs_hashsig:
		if (sphincs_public_key_from_bytes(&x509_key->u.sphincs_key, &pub, &publen) != 1) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}
	x509_key->algor = algor;
	x509_key->algor_param = algor_param;

	if (publen) {
		error_print();
		return -1;
	}
	return 1;
}

