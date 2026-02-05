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
#include <gmssl/mem.h>
#include <gmssl/sm4.h>
#include <gmssl/rsa.h>
#include <gmssl/asn1.h>
#include <gmssl/rand.h>
#include <gmssl/pkcs8.h>
#include <gmssl/error.h>
#include <gmssl/x509_alg.h>
#include <gmssl/x509_cer.h>
#include <gmssl/x509_key.h>



int x509_key_set_sm2_key(X509_KEY *x509_key, const SM2_KEY *sm2_key)
{
	if (!x509_key || !sm2_key) {
		error_print();
		return -1;
	}
	memset(x509_key, 0, sizeof(X509_KEY));
	x509_key->algor = OID_ec_public_key;
	x509_key->algor_param = OID_sm2;
	x509_key->u.sm2_key = *sm2_key;
	return 1;
}

int x509_key_set_secp256r1_key(X509_KEY *x509_key, const SECP256R1_KEY *secp256r1_key)
{
	if (!x509_key || !secp256r1_key) {
		error_print();
		return -1;
	}
	memset(x509_key, 0, sizeof(X509_KEY));
	x509_key->algor = OID_ec_public_key;
	x509_key->algor_param = OID_secp256r1;
	x509_key->u.secp256r1_key = *secp256r1_key;
	return 1;
}

int x509_key_set_lms_key(X509_KEY *x509_key, const LMS_KEY *lms_key)
{
	if (!x509_key || !lms_key) {
		error_print();
		return -1;
	}
	memset(x509_key, 0, sizeof(X509_KEY));
	x509_key->algor = OID_lms_hashsig;
	x509_key->algor_param = OID_undef;
	x509_key->u.lms_key = *lms_key;
	return 1;
}

int x509_key_set_hss_key(X509_KEY *x509_key, const HSS_KEY *hss_key)
{
	if (!x509_key || !hss_key) {
		error_print();
		return -1;
	}
	memset(x509_key, 0, sizeof(X509_KEY));
	x509_key->algor = OID_hss_lms_hashsig;
	x509_key->algor_param = OID_undef;
	x509_key->u.hss_key = *hss_key;
	return 1;
}

int x509_key_set_xmss_key(X509_KEY *x509_key, const XMSS_KEY *xmss_key)
{
	if (!x509_key || !xmss_key) {
		error_print();
		return -1;
	}
	memset(x509_key, 0, sizeof(X509_KEY));
	x509_key->algor = OID_xmss_hashsig;
	x509_key->algor_param = OID_undef;
	x509_key->u.xmss_key = *xmss_key;
	return 1;
}

int x509_key_set_xmssmt_key(X509_KEY *x509_key, const XMSSMT_KEY *xmssmt_key)
{
	if (!x509_key || !xmssmt_key) {
		error_print();
		return -1;
	}
	memset(x509_key, 0, sizeof(X509_KEY));
	x509_key->algor = OID_xmssmt_hashsig;
	x509_key->algor_param = OID_undef;
	x509_key->u.xmssmt_key = *xmssmt_key;
	return 1;
}

int x509_key_set_sphincs_key(X509_KEY *x509_key, const SPHINCS_KEY *sphincs_key)
{
	if (!x509_key || !sphincs_key) {
		error_print();
		return -1;
	}
	memset(x509_key, 0, sizeof(X509_KEY));
	x509_key->algor = OID_sphincs_hashsig;
	x509_key->algor_param = OID_undef;
	x509_key->u.sphincs_key = *sphincs_key;
	return 1;
}

int x509_key_set_kyber_key(X509_KEY *x509_key, const KYBER_KEY *kyber_key)
{
	if (!x509_key || !kyber_key) {
		error_print();
		return -1;
	}
	memset(x509_key, 0, sizeof(X509_KEY));
	x509_key->algor = OID_kyber_kem;
	x509_key->algor_param = OID_undef;
	x509_key->u.kyber_key = *kyber_key;
	return 1;
}

int x509_key_generate(X509_KEY *key, int algor, const void *param, size_t paramlen)
{
	int param_val;

	if (!key) {
		error_print();
		return -1;
	}

	memset(key, 0, sizeof(X509_KEY));
	key->algor = algor;
	key->algor_param = OID_undef;

	switch (algor) {
	case OID_ec_public_key:
	case OID_lms_hashsig:
	case OID_xmss_hashsig:
	case OID_xmssmt_hashsig:
		if (!param) {
			error_print();
			return -1;
		}
		if (paramlen != sizeof(int)) {
			error_print();
			return -1;
		}
		param_val = *(const int *)param;
		break;
	case OID_hss_lms_hashsig:
		if (!param) {
			error_print();
			return -1;
		}
		if (paramlen < sizeof(int)) {
			error_print();
			return -1;
		}
		if (paramlen % sizeof(int)) {
			error_print();
			return -1;
		}
		break;
	case OID_sphincs_hashsig:
		if (param || paramlen) {
			error_print();
			return -1;
		}
		break;
	case OID_kyber_kem:
		if (param && paramlen != 32) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}

	switch (algor) {
	case OID_ec_public_key:
		switch (param_val) {
		case OID_sm2:
			if (sm2_key_generate(&key->u.sm2_key) != 1) {
				error_print();
				return -1;
			}
			break;
		case OID_secp256r1:
			if (secp256r1_key_generate(&key->u.secp256r1_key) != 1) {
				error_print();
				return -1;
			}
			break;
		default:
			error_print();
			return -1;
		}
		key->algor_param = param_val;
		break;
	case OID_lms_hashsig:
		if (lms_key_generate(&key->u.lms_key, param_val) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_hss_lms_hashsig:
		if (hss_key_generate(&key->u.hss_key, (int *)param, paramlen/sizeof(int)) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_xmss_hashsig:
		if (xmss_key_generate(&key->u.xmss_key, param_val) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_xmssmt_hashsig:
		if (xmssmt_key_generate(&key->u.xmssmt_key, param_val) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_sphincs_hashsig:
		if (sphincs_key_generate(&key->u.sphincs_key) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_kyber_kem:
		if (kyber_key_generate_ex(&key->u.kyber_key, (uint8_t *)param) != 1) {
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

void x509_key_cleanup(X509_KEY *key)
{
	if (key) {
		switch (key->algor) {
		case OID_ec_public_key:
			switch (key->algor_param) {
			case OID_sm2:
				gmssl_secure_clear(&key->u.sm2_key, sizeof(SM2_KEY));
				break;
			case OID_secp256r1:
				secp256r1_key_cleanup(&key->u.secp256r1_key);
				break;
			default:
				error_print();
				return;
			}
			break;
		case OID_lms_hashsig:
			lms_key_cleanup(&key->u.lms_key);
			break;
		case OID_hss_lms_hashsig:
			hss_key_cleanup(&key->u.hss_key);
			break;
		case OID_xmss_hashsig:
			xmss_key_cleanup(&key->u.xmss_key);
			break;
		case OID_xmssmt_hashsig:
			xmssmt_key_cleanup(&key->u.xmssmt_key);
			break;
		case OID_sphincs_hashsig:
			sphincs_key_cleanup(&key->u.sphincs_key);
			break;
		case OID_kyber_kem:
			kyber_key_cleanup(&key->u.kyber_key);
			break;
		default:
			error_print();
		}
		memset(key, 0, sizeof(X509_KEY));
	}
}

int x509_public_key_to_bytes(const X509_KEY *key, uint8_t **out, size_t *outlen)
{
	if (!key || !outlen) {
		error_print();
		return -1;
	}

	switch (key->algor) {
	case OID_ec_public_key:
		switch (key->algor_param) {
		case OID_sm2:
			if (out && *out) {
				sm2_z256_point_to_uncompressed_octets(&key->u.sm2_key.public_key, *out);
				*out += 65;
			}
			*outlen += 65;
			break;
		case OID_secp256r1:
			if (secp256r1_public_key_to_bytes(&key->u.secp256r1_key, out, outlen) != 1) {
				error_print();
				return -1;
			}
			break;
		default:
			error_print();
			return -1;
		}
		break;
	case OID_lms_hashsig:
		if (lms_public_key_to_bytes(&key->u.lms_key, out, outlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_hss_lms_hashsig:
		if (hss_public_key_to_bytes(&key->u.hss_key, out, outlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_xmss_hashsig:
		if (xmss_public_key_to_bytes(&key->u.xmss_key, out, outlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_xmssmt_hashsig:
		if (xmssmt_public_key_to_bytes(&key->u.xmssmt_key, out, outlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_sphincs_hashsig:
		if (sphincs_public_key_to_bytes(&key->u.sphincs_key, out, outlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_kyber_kem:
		if (kyber_public_key_to_bytes(&key->u.kyber_key, out, outlen) != 1) {
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

int x509_public_key_from_bytes(X509_KEY *key, int algor, int algor_param, const uint8_t **in, size_t *inlen)
{
	if (!key || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}

	memset(key, 0, sizeof(X509_KEY));
	key->algor = algor;
	key->algor_param = algor_param;

	switch (algor) {
	case OID_ec_public_key:
		if (*inlen < 65) {
			error_print();
			return -1;
		}
		switch (algor_param) {
		case OID_sm2:
			if (sm2_z256_point_from_octets(&key->u.sm2_key.public_key, *in, 65) != 1) {
				error_print();
				return -1;
			}
			*in += 65;
			*inlen -= 65;
			break;
		case OID_secp256r1:
			if (secp256r1_public_key_from_bytes(&key->u.secp256r1_key, in, inlen) != 1) {
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
	if (algor_param != OID_undef) {
		error_print();
		return -1;
	}
	switch (algor) {
	case OID_lms_hashsig:
		if (lms_public_key_from_bytes(&key->u.lms_key, in, inlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_hss_lms_hashsig:
		if (hss_public_key_from_bytes(&key->u.hss_key, in, inlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_xmss_hashsig:
		if (xmss_public_key_from_bytes(&key->u.xmss_key, in, inlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_xmssmt_hashsig:
		if (xmssmt_public_key_from_bytes(&key->u.xmssmt_key, in, inlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_sphincs_hashsig:
		if (sphincs_public_key_from_bytes(&key->u.sphincs_key, in, inlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_kyber_kem:
		if (kyber_public_key_from_bytes(&key->u.kyber_key, in, inlen) != 1) {
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

int x509_public_key_digest(const X509_KEY *key, uint8_t dgst[32])
{
	SM3_CTX ctx;
	uint8_t bits[X509_PUBLIC_KEY_MAX_SIZE];
	uint8_t *p = bits;
	size_t len = 0;

	if (x509_public_key_to_bytes(key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	sm3_init(&ctx);
	sm3_update(&ctx, bits, len);
	sm3_finish(&ctx, dgst);
	return 1;
}

int x509_public_key_equ(const X509_KEY *key, const X509_KEY *pub)
{
	int ret;

	if (!key || !pub) {
		error_print();
		return -1;
	}
	if (key->algor != pub->algor) {
		error_print();
		return 0;
	}
	if (key->algor_param != pub->algor_param) {
		error_print();
		return 0;
	}
	switch (key->algor) {
	case OID_ec_public_key:
		if (key->algor_param == OID_sm2) {
			if ((ret = sm2_public_key_equ(&key->u.sm2_key, &pub->u.sm2_key)) != 1) {
				error_print();
				return ret;
			}
		} else if (key->algor_param == OID_secp256r1) {
			if ((ret = secp256r1_public_key_equ(&key->u.secp256r1_key, &pub->u.secp256r1_key)) != 1) {
				error_print();
				return ret;
			}
		} else {
			error_print();
			return -1;
		}
		return 1;
	case OID_hss_lms_hashsig:
		if ((ret = hss_public_key_equ(&key->u.hss_key, &pub->u.hss_key)) != 1) {
			error_print();
			return ret;
		}
		return 1;
	}

	// sizeof(XXX_PUBLIC_KEY) >= XXX_PUBLIC_KEY_SIZE, depends on compiler
	switch (key->algor) {
	case OID_lms_hashsig:
		if (memcmp(&key->u.lms_key, &pub->u.lms_key, sizeof(LMS_PUBLIC_KEY)) != 0) {
			error_print();
			return 0;
		}
		break;
	case OID_xmss_hashsig:
		if (memcmp(&key->u.xmss_key, &pub->u.xmss_key, sizeof(XMSS_PUBLIC_KEY)) != 0) {
			error_print();
			return 0;
		}
		break;
	case OID_xmssmt_hashsig:
		if (memcmp(&key->u.xmssmt_key, &pub->u.xmssmt_key, sizeof(XMSSMT_PUBLIC_KEY)) != 0) {
			error_print();
			return 0;
		}
		break;
	case OID_sphincs_hashsig:
		if (memcmp(&key->u.sphincs_key, &pub->u.sphincs_key, sizeof(SPHINCS_PUBLIC_KEY)) != 0) {
			error_print();
			return 0;
		}
		break;
	case OID_kyber_kem:
		if (memcmp(&key->u.kyber_key, &pub->u.kyber_key, sizeof(KYBER_PUBLIC_KEY)) != 0) {
			error_print();
			return 0;
		}
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

int x509_public_key_print(FILE *fp, int fmt, int ind, const char *label, const X509_KEY *key)
{
	switch (key->algor) {
	case OID_ec_public_key:
		if (key->algor_param == OID_sm2) {
			if (sm2_public_key_print(fp, fmt, ind, label, &key->u.sm2_key) != 1) {
				error_print();
				return -1;
			}
		} else if (key->algor_param == OID_secp256r1) {
			if (secp256r1_public_key_print(fp, fmt, ind, label, &key->u.secp256r1_key) != 1) {
				error_print();
				return -1;
			}
		} else {
			error_print();
			return -1;
		}
		break;
	case OID_lms_hashsig:
		if (lms_public_key_print(fp, fmt, ind, label, &key->u.lms_key) != 1) {
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
	case OID_kyber_kem:
		if (kyber_public_key_print(fp, fmt, ind, label, &key->u.kyber_key) != 1) {
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
	uint8_t keybuf[X509_PUBLIC_KEY_MAX_SIZE];
	uint8_t *p = keybuf;
	size_t keylen = 0;
	size_t len = 0;

	if (!x509_key || !outlen) {
		error_print();
		return -1;
	}

	if (x509_public_key_to_bytes(x509_key, &p, &keylen) != 1) {
		error_print();
		return -1;
	}
	if (x509_public_key_algor_to_der(x509_key->algor, x509_key->algor_param, NULL, &len) != 1
		|| asn1_bit_octets_to_der(keybuf, keylen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_public_key_algor_to_der(x509_key->algor, x509_key->algor_param, out, outlen) != 1
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
	if (x509_public_key_from_bytes(x509_key, algor, algor_param, &pub, &publen) != 1) {
		error_print();
		return -1;
	}
	if (publen) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_public_key_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *p = d;
	size_t len = dlen;
	int alg;
	int params;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (x509_public_key_algor_from_der(&alg, &params, &p, &len) != 1) goto err;
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_public_key_algor_print(fp, fmt, ind, "algorithm", p, len);
	format_print(fp, fmt, ind, "subjectPublicKey\n");
	ind += 4;
	if (asn1_bit_octets_from_der(&p, &len, &d, &dlen) != 1) goto err;
	switch (alg) {
	case OID_ec_public_key:
		format_bytes(fp, fmt, ind, "ECPoint", p, len);
		break;
	case OID_rsa_encryption:
		rsa_public_key_print(fp, fmt, ind, "RSAPublicKey", p, len);
		break;
	case OID_lms_hashsig:
	case OID_hss_lms_hashsig:
	case OID_xmss_hashsig:
	case OID_xmssmt_hashsig:
	case OID_sphincs_hashsig:
	case OID_kyber_kem:
		// TODO: print public key without too much details
	default:
		format_bytes(fp, fmt, ind, "raw_data", p, len);
	}
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int x509_private_key_print_ex(FILE *fp, int fmt, int ind, const char *label, const X509_KEY *key)
{
	// TODO: change lms_private_key_print to lms_private_key_print_ex and xmss ...
	error_print();
	return -1;
}

#define SM2_PRIVATE_KEY_DER_SIZE 121
int ec_private_key_to_der(const X509_KEY *key, int encode_params, int encode_pubkey,
	uint8_t **out, size_t *outlen)
{
	uint8_t params_buf[16]; // = 10 for sm2, p256
	uint8_t pubkey_buf[68]; // = 68 for sm2, p256
	uint8_t *params = NULL;
	uint8_t *pubkey = NULL;
	size_t params_len = 0;
	size_t pubkey_len = 0;
	uint8_t prikey[32];
	size_t len = 0;

	if (!key) {
		error_print();
		return -1;
	}
	if (key->algor != OID_ec_public_key) {
		error_print();
		return -1;
	}

	if (encode_params) {
		params = params_buf;
		if (ec_named_curve_to_der(key->algor_param, &params, &params_len) != 1) {
			gmssl_secure_clear(prikey, 32);
			error_print();
			return -1;
		}
		params = params_buf;
	}
	switch (key->algor_param) {
	case OID_sm2:
		if (encode_pubkey) {
			pubkey = pubkey_buf;
			if (sm2_public_key_to_der(&key->u.sm2_key, &pubkey, &pubkey_len) != 1) {
				error_print();
				return -1;
			}
			pubkey = pubkey_buf;
		}
		sm2_z256_to_bytes(key->u.sm2_key.private_key, prikey);
		break;
	case OID_secp256r1:
		if (encode_pubkey) {
			pubkey = pubkey_buf;
			if (secp256r1_public_key_to_der(&key->u.secp256r1_key, &pubkey, &pubkey_len) != 1) {
				error_print();
				return -1;
			}
			pubkey = pubkey_buf;
		}
		secp256r1_to_32bytes(key->u.secp256r1_key.private_key, prikey);
		break;
	default:
		error_print();
		return -1;
	}

	if (asn1_int_to_der(EC_private_key_version, NULL, &len) != 1
		|| asn1_octet_string_to_der(prikey, 32, NULL, &len) != 1
		|| asn1_explicit_to_der(0, params, params_len, NULL, &len) < 0
		|| asn1_explicit_to_der(1, pubkey, pubkey_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(EC_private_key_version, out, outlen) != 1
		|| asn1_octet_string_to_der(prikey, 32, out, outlen) != 1
		|| asn1_explicit_to_der(0, params, params_len, out, outlen) < 0
		|| asn1_explicit_to_der(1, pubkey, pubkey_len, out, outlen) < 0) {
		gmssl_secure_clear(prikey, 32);
		error_print();
		return -1;
	}
	gmssl_secure_clear(prikey, 32);
	return 1;
}

// when params(curve) is omitted in ECPrivateKey, curve should be given explicitly
int ec_private_key_from_der(X509_KEY *key, int opt_curve, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	int ver;
	const uint8_t *prikey;
	const uint8_t *params;
	const uint8_t *pubkey;
	size_t prikey_len, params_len, pubkey_len;
	int curve;

	if (!key || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(&ver, &d, &dlen) != 1
		|| asn1_octet_string_from_der(&prikey, &prikey_len, &d, &dlen) != 1
		|| asn1_explicit_from_der(0, &params, &params_len, &d, &dlen) < 0
		|| asn1_explicit_from_der(1, &pubkey, &pubkey_len, &d, &dlen) < 0
		|| asn1_check(ver == EC_private_key_version) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (!prikey || prikey_len != 32) {
		error_print();
		return -1;
	}

	if (params) {
		if (ec_named_curve_from_der(&curve, &params, &params_len) != 1
			|| asn1_length_is_zero(params_len) != 1) {
			error_print();
			return -1;
		}
		if (curve != opt_curve && opt_curve != OID_undef) {
			error_print();
			return -1;
		}
	} else {
		curve = opt_curve;
	}

	memset(key, 0, sizeof(X509_KEY));

	if (curve == OID_sm2) {

		sm2_z256_t sm2_private;
		SM2_KEY sm2_pub;

		sm2_z256_from_bytes(sm2_private, prikey);
		if (sm2_key_set_private_key(&key->u.sm2_key, sm2_private) != 1) {
			gmssl_secure_clear(sm2_private, sizeof(sm2_z256_t));
			error_print();
			return -1;
		}
		gmssl_secure_clear(sm2_private, sizeof(sm2_z256_t));

		if (pubkey) {
			if (sm2_public_key_from_der(&sm2_pub, &pubkey, &pubkey_len) != 1
				|| asn1_length_is_zero(pubkey_len) != 1) {
				error_print();
				return -1;
			}
			if (sm2_public_key_equ(&key->u.sm2_key, &sm2_pub) != 1) {
				gmssl_secure_clear(&key->u.sm2_key, sizeof(SM2_KEY)); // sm2_key_cleanup?
				error_print();
				return -1;
			}
		}

	} else if (curve == OID_secp256r1) {

		secp256r1_t p256_private;
		SECP256R1_KEY p256_pub;

		secp256r1_from_32bytes(p256_private, prikey);
		if (secp256r1_key_set_private_key(&key->u.secp256r1_key, p256_private) != 1) {
			gmssl_secure_clear(p256_private, sizeof(secp256r1_t));
			error_print();
			return -1;
		}
		gmssl_secure_clear(p256_private, sizeof(secp256r1_t));

		if (pubkey) {
			if (secp256r1_public_key_from_der(&p256_pub, &pubkey, &pubkey_len) != 1
				|| asn1_length_is_zero(pubkey_len) != 1) {
				error_print();
				return -1;
			}
			if (secp256r1_public_key_equ(&key->u.secp256r1_key, &p256_pub) != 1) {
				secp256r1_key_cleanup(&key->u.secp256r1_key);
				error_print();
				return -1;
			}
		}
	} else {
		error_print();
		return -1;
	}

	key->algor = OID_ec_public_key;
	key->algor_param = curve;
	return 1;
}

int x509_private_key_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	if (sm2_private_key_info_print(fp, fmt, ind, label, d, dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_private_key_info_to_der(const X509_KEY *key, uint8_t **out, size_t *outlen)
{
	uint8_t private_key[128]; // 121
	uint8_t *p = private_key;
	size_t private_key_len = 0;
	size_t len = 0;

	if (!key || !outlen) {
		error_print();
		return -1;
	}

	switch (key->algor) {
	case OID_ec_public_key:
		if (ec_private_key_to_der(key,
			X509_ENCODE_EC_PRIVATE_KEY_PARAMS, X509_ENCODE_EC_PRIVATE_KEY_PUBKEY,
			&p, &private_key_len) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_lms_hashsig:
	case OID_hss_lms_hashsig:
	case OID_xmss_hashsig:
	case OID_xmssmt_hashsig:
	case OID_sphincs_hashsig:
	case OID_kyber_kem:
	// TODO: support these algors, (MUST change private_key[] size)!
	default:
		error_print();
		return -1;
	}

	if (asn1_int_to_der(PKCS8_private_key_info_version, NULL, &len) != 1
		|| x509_public_key_algor_to_der(key->algor, key->algor_param, NULL, &len) != 1
		|| asn1_octet_string_to_der(private_key, private_key_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(PKCS8_private_key_info_version, out, outlen) != 1
		|| x509_public_key_algor_to_der(key->algor, key->algor_param, out, outlen) != 1
		|| asn1_octet_string_to_der(private_key, private_key_len, out, outlen) != 1) {
		gmssl_secure_clear(private_key, private_key_len);
		error_print();
		return -1;
	}
	gmssl_secure_clear(private_key, private_key_len);
	return 1;
}

int x509_private_key_info_from_der(X509_KEY *key, const uint8_t **attrs, size_t *attrslen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	int version;
	int algor;
	int algor_param;
	const uint8_t *private_key;
	size_t private_key_len;

	if (!key || !attrs || !attrslen || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		if (ret == 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(&version, &d, &dlen) != 1
		|| x509_public_key_algor_from_der(&algor, &algor_param, &d, &dlen) != 1
		|| asn1_octet_string_from_der(&private_key, &private_key_len, &d, &dlen) != 1
		|| asn1_implicit_set_from_der(0, attrs, attrslen, &d, &dlen) < 0
		|| asn1_check(version == PKCS8_private_key_info_version) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	switch (algor) {
	case OID_ec_public_key:
		if (ec_private_key_from_der(key, algor_param, &private_key, &private_key_len) != 1
			|| asn1_length_is_zero(private_key_len) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_lms_hashsig:
	case OID_hss_lms_hashsig:
	case OID_xmss_hashsig:
	case OID_xmssmt_hashsig:
	case OID_sphincs_hashsig:
	case OID_kyber_kem:
	default:
		error_print();
		return -1;
	}
	return 1;
}

int x509_private_key_info_encrypt_to_der(const X509_KEY *x509_key, const char *pass,
	uint8_t **out, size_t *outlen)
{
	int ret = -1;
	uint8_t private_key_info[168]; // 150
	uint8_t *p = private_key_info;
	size_t private_key_info_len = 0;
	uint8_t salt[16];
	int iter = PKCS8_ENCED_PRIVATE_KEY_INFO_ITER;
	uint8_t iv[16];
	uint8_t key[16];
	SM4_KEY sm4_key;
	uint8_t enced_private_key_info[sizeof(private_key_info) + 32];
	size_t enced_private_key_info_len;

	if (!x509_key || !pass || !outlen) {
		error_print();
		return -1;
	}

	if (rand_bytes(salt, sizeof(salt)) != 1
		|| rand_bytes(iv, sizeof(iv)) != 1) {
		error_print();
		return -1;
	}
	if (sm3_pbkdf2(pass, strlen(pass), salt, sizeof(salt), iter, sizeof(key), key) != 1) {
		error_print();
		return -1;
	}

	if (x509_private_key_info_to_der(x509_key, &p, &private_key_info_len) != 1) {
		error_print();
		goto end;
	}
	sm4_set_encrypt_key(&sm4_key, key);
	if (sm4_cbc_padding_encrypt(&sm4_key, iv,
		private_key_info, private_key_info_len,
		enced_private_key_info, &enced_private_key_info_len) != 1) {
		error_print();
		goto end;
	}
	if (pkcs8_enced_private_key_info_to_der(salt, sizeof(salt), iter,
		sizeof(key), OID_hmac_sm3, OID_sm4_cbc, iv, sizeof(iv),
		enced_private_key_info, enced_private_key_info_len,
		out, outlen) != 1) {
		error_print();
		goto end;
	}

	ret = 1;
end:
	gmssl_secure_clear(private_key_info, sizeof(private_key_info));
	gmssl_secure_clear(key, sizeof(key));
	gmssl_secure_clear(&sm4_key, sizeof(sm4_key));
	return ret;
}

int x509_private_key_info_decrypt_from_der(X509_KEY *x509_key,
	const uint8_t **attrs, size_t *attrs_len,
	const char *pass, const uint8_t **in, size_t *inlen)
{
	int ret = -1;
	const uint8_t *salt;
	size_t saltlen;
	int iter;
	int keylen;
	int prf;
	int cipher;
	const uint8_t *iv;
	size_t ivlen;
	uint8_t key[16];
	SM4_KEY sm4_key;
	const uint8_t *enced_private_key_info;
	size_t enced_private_key_info_len; // 160
	uint8_t private_key_info[168];
	const uint8_t *cp = private_key_info;
	size_t private_key_info_len;

	if (!x509_key || !attrs || !attrs_len || !pass || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (pkcs8_enced_private_key_info_from_der(&salt, &saltlen, &iter, &keylen, &prf,
		&cipher, &iv, &ivlen, &enced_private_key_info, &enced_private_key_info_len, in, inlen) != 1
		|| asn1_check(keylen == -1 || keylen == 16) != 1
		|| asn1_check(prf == - 1 || prf == OID_hmac_sm3) != 1
		|| asn1_check(cipher == OID_sm4_cbc) != 1
		|| asn1_check(ivlen == 16) != 1
		|| asn1_length_le(enced_private_key_info_len, sizeof(private_key_info)) != 1) {
		error_print();
		return -1;
	}
	if (enced_private_key_info_len > sizeof(private_key_info)) {
		// sm4_cbc_padding_decrypt might buffer overflow
		error_print();
		return -1;
	}
	if (sm3_pbkdf2(pass, strlen(pass), salt, saltlen, iter, sizeof(key), key) != 1) {
		error_print();
		goto end;
	}
	sm4_set_decrypt_key(&sm4_key, key);
	if (sm4_cbc_padding_decrypt(&sm4_key, iv,
		enced_private_key_info, enced_private_key_info_len,
		private_key_info, &private_key_info_len) != 1) {
		error_print();
		goto end;
	}
	if (x509_private_key_info_from_der(x509_key, attrs, attrs_len, &cp, &private_key_info_len) != 1) {
		error_print();
		goto end;
	}
	if (asn1_length_is_zero(private_key_info_len) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	gmssl_secure_clear(&sm4_key, sizeof(sm4_key));
	gmssl_secure_clear(key, sizeof(key));
	gmssl_secure_clear(private_key_info, sizeof(private_key_info));
	return ret;
}

int x509_private_key_info_encrypt_to_pem(const X509_KEY *key, const char *pass, FILE *fp)
{
	uint8_t buf[1024];
	uint8_t *p = buf;
	size_t len = 0;

	if (!fp) {
		error_print();
		return -1;
	}
	if (x509_private_key_info_encrypt_to_der(key, pass, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (pem_write(fp, "ENCRYPTED PRIVATE KEY", buf, len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_private_key_info_decrypt_from_pem(X509_KEY *key, const uint8_t **attrs, size_t *attrslen, const char *pass, FILE *fp)
{
	uint8_t buf[512];
	const uint8_t *cp = buf;
	size_t len;

	if (!key || !pass || !fp) {
		error_print();
		return -1;
	}
	if (pem_read(fp, "ENCRYPTED PRIVATE KEY", buf, &len, sizeof(buf)) != 1) {
		error_print();
		return -1;
	}
	if (x509_private_key_info_decrypt_from_der(key, attrs, attrslen, pass, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_private_key_from_file(X509_KEY *key, int algor, const char *pass, FILE *fp)
{
	if (!key || !fp) {
		error_print();
		return -1;
	}

	if (algor == OID_ec_public_key) {
		const uint8_t *attrs;
		size_t attrslen;
		if (!pass) {
			error_print();
			return -1;
		}
		if (x509_private_key_info_decrypt_from_pem(key, &attrs, &attrslen, pass, fp) != 1) {
			error_print();
			return -1;
		}
	} else if (algor == OID_lms_hashsig) {
		uint8_t buf[LMS_PRIVATE_KEY_SIZE];
		const uint8_t *cp = buf;
		size_t len = sizeof(buf);

		if (fread(buf, 1, len, fp) != len) {
			error_print();
			return -1;
		}
		if (lms_private_key_from_bytes(&key->u.lms_key, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (len) {
			error_print();
			return -1;
		}
	} else if (algor == OID_hss_lms_hashsig) {
		uint8_t buf[HSS_PRIVATE_KEY_MAX_SIZE];
		const uint8_t *cp = buf;
		size_t len = sizeof(buf);

		if ((len = fread(buf, 1, len, fp)) <= 0) {
			error_print();
			return -1;
		}
		if (hss_private_key_from_bytes(&key->u.hss_key, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (len) {
			error_print();
			return -1;
		}
	} else if (algor == OID_xmss_hashsig) {
		if (xmss_private_key_from_file(&key->u.xmss_key, fp) != 1) {
			error_print();
			return -1;
		}
	} else if (algor == OID_xmssmt_hashsig) {
		if (xmssmt_private_key_from_file(&key->u.xmssmt_key, fp) != 1) {
			error_print();
			return -1;
		}
	} else if (algor == OID_sphincs_hashsig) {
		uint8_t buf[SPHINCS_PRIVATE_KEY_SIZE];
		const uint8_t *cp = buf;
		size_t len = sizeof(buf);

		if (fread(buf, 1, len, fp) != len) {
			error_print();
			return -1;
		}
		if (sphincs_private_key_from_bytes(&key->u.sphincs_key, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (len) {
			error_print();
			return -1;
		}
	} else if (algor == OID_kyber_kem) {
		uint8_t buf[KYBER_PRIVATE_KEY_SIZE];
		const uint8_t *cp = buf;
		size_t len = sizeof(buf);

		if (fread(buf, 1, len, fp) != len) {
			error_print();
			return -1;
		}
		if (kyber_private_key_from_bytes(&key->u.kyber_key, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (len) {
			error_print();
			return -1;
		}
	} else {
		error_print();
		return -1;
	}
	return 1;
}

int x509_key_get_sign_algor(const X509_KEY *key, int *algor)
{
	if (!key || !algor) {
		error_print();
		return -1;
	}

	switch (key->algor) {
	case OID_ec_public_key:
		switch (key->algor_param) {
		case OID_sm2:
			*algor = OID_sm2sign_with_sm3;
			break;
		case OID_secp256r1:
			*algor = OID_ecdsa_with_sha256;
			break;
		default:
			error_print();
			return -1;
		}
		break;
	case OID_lms_hashsig:
	case OID_hss_lms_hashsig:
	case OID_xmss_hashsig:
	case OID_xmssmt_hashsig:
	case OID_sphincs_hashsig:
		*algor = key->algor;
		break;
	case OID_kyber_kem:
	default:
		error_print();
		return -1;
	}
	return 1;
}

int x509_key_get_signature_size(const X509_KEY *key, size_t *siglen)
{
	switch (key->algor) {
	case OID_ec_public_key:
		*siglen = SM2_signature_max_size;
		break;
	case OID_lms_hashsig:
		if (lms_key_get_signature_size(&key->u.lms_key, siglen) != 1) {
			error_print();
			return -1;
		}
		break;
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
	case OID_sphincs_hashsig:
		*siglen = SPHINCS_SIGNATURE_SIZE;
		break;
	case OID_kyber_kem:
	default:
		error_print();
		return -1;
	}
	return 1;
}

int x509_sign_init(X509_SIGN_CTX *ctx, X509_KEY *key, const void *args, size_t argslen)
{
	if (!ctx || !key) {
		error_print();
		return -1;
	}
	switch (key->algor) {
	case OID_lms_hashsig:
	case OID_hss_lms_hashsig:
	case OID_xmss_hashsig:
	case OID_xmssmt_hashsig:
		if (args) {
			error_print();
			return -1;
		}
		break;
	}

	memset(ctx, 0, sizeof(X509_SIGN_CTX));

	switch (key->algor) {
	case OID_ec_public_key:
		switch (key->algor_param) {
		case OID_sm2:
			if (!args) {
				args = SM2_DEFAULT_ID;
				argslen = SM2_DEFAULT_ID_LENGTH;
			}
			if (!argslen) {
				error_print();
				return -1;
			}
			if (sm2_sign_init(&ctx->u.sm2_sign_ctx, &key->u.sm2_key, args, argslen) != 1) {
				error_print();
				return -1;
			}
			ctx->sign_algor = OID_sm2sign_with_sm3;
			break;
		case OID_secp256r1:
			if (ecdsa_sign_init(&ctx->u.ecdsa_sign_ctx, &key->u.secp256r1_key) != 1) {
				error_print();
				return -1;
			}
			ctx->sign_algor = OID_ecdsa_with_sha256;
			break;
		default:
			error_print();
			return -1;
		}
		break;
	case OID_lms_hashsig:
		if (lms_sign_init(&ctx->u.lms_sign_ctx, &key->u.lms_key) != 1) {
			error_print();
			return -1;
		}
		ctx->sign_algor = key->algor;
		break;
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

	// to generate a random signature (instead of a deterministic one), caller should prepare uint8_t rand[16]
	case OID_sphincs_hashsig:
		if (args) {
			if (argslen != sizeof(sphincs_hash128_t)) {
				error_print();
				return -1;
			}
		}
		if (sphincs_sign_init_ex(&ctx->u.sphincs_sign_ctx, &key->u.sphincs_key, args) != 1) {
			error_print();
			return -1;
		}
		ctx->sign_algor = key->algor;
		break;
	default:
		error_print();
		return -1;
	}

	return 1;
}

int x509_sign_set_signature_size(X509_SIGN_CTX *ctx, size_t siglen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	switch (ctx->sign_algor) {
	case OID_sm2sign_with_sm3:
	case OID_ecdsa_with_sha256:
		switch (siglen) {
		case SM2_signature_compact_size:
		case SM2_signature_typical_size:
		case SM2_signature_max_size:
			ctx->fixed_siglen = siglen;
			break;
		default:
			error_print();
			return -1;
		}
	default:
		error_print();
		return -1;
	}
	return 1;
}

int x509_sign_update(X509_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}

	switch (ctx->sign_algor) {
	case OID_sm2sign_with_sm3:
		if (sm2_sign_update(&ctx->u.sm2_sign_ctx, data, datalen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_ecdsa_with_sha256:
		if (ecdsa_sign_update(&ctx->u.ecdsa_sign_ctx, data, datalen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_lms_hashsig:
		if (lms_sign_update(&ctx->u.lms_sign_ctx, data, datalen) != 1) {
			error_print();
			return -1;
		}
		break;
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
	case OID_sphincs_hashsig:
		error_print();
		return -1;
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
	case OID_sm2sign_with_sm3:
		if (ctx->fixed_siglen) {
			if (sm2_sign_finish_fixlen(&ctx->u.sm2_sign_ctx, ctx->fixed_siglen, sig) != 1) {
				error_print();
				return -1;
			}
			*siglen = ctx->fixed_siglen;
		} else {
			if (sm2_sign_finish(&ctx->u.sm2_sign_ctx, sig, siglen) != 1) {
				error_print();
				return -1;
			}
		}
		break;
	case OID_ecdsa_with_sha256:
		if (ctx->fixed_siglen) {
			if (ecdsa_sign_finish_fixlen(&ctx->u.ecdsa_sign_ctx, ctx->fixed_siglen, sig) != 1) {
				error_print();
				return -1;
			}
			*siglen = ctx->fixed_siglen;
		} else {
			if (ecdsa_sign_finish(&ctx->u.ecdsa_sign_ctx, sig, siglen) != 1) {
				error_print();
				return -1;
			}
		}
		break;
	case OID_lms_hashsig:
		if (lms_sign_finish(&ctx->u.lms_sign_ctx, sig, siglen) != 1) {
			error_print();
			return -1;
		}
		break;
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
	case OID_sphincs_hashsig:
		error_print();
		return -1;
	default:
		error_print();
		return -1;
	}
	return 1;
}

int x509_sign(X509_SIGN_CTX *ctx, const uint8_t *data, size_t datalen, uint8_t *sig, size_t *siglen)
{
	if (!ctx || !sig || !siglen) {
		error_print();
		return -1;
	}
	if (!data || !datalen) {
		error_print();
		return -1;
	}

	switch (ctx->sign_algor) {
	case OID_sm2sign_with_sm3:
	case OID_ecdsa_with_sha256:
	case OID_lms_hashsig:
	case OID_hss_lms_hashsig:
	case OID_xmss_hashsig:
	case OID_xmssmt_hashsig:
		if (x509_sign_update(ctx, data, datalen) != 1) {
			error_print();
			return -1;
		}
		if (x509_sign_finish(ctx, sig, siglen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_sphincs_hashsig:
		if (sphincs_sign_prepare(&ctx->u.sphincs_sign_ctx, data, datalen) != 1) {
			error_print();
			return -1;
		}
		if (sphincs_sign_update(&ctx->u.sphincs_sign_ctx, data, datalen) != 1) {
			error_print();
			return -1;
		}
		if (sphincs_sign_finish(&ctx->u.sphincs_sign_ctx, sig, siglen) != 1) {
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

int x509_verify_init(X509_SIGN_CTX *ctx, const X509_KEY *key, const void *args, size_t argslen,
	const uint8_t *sig, size_t siglen)
{
	if (!ctx || !key || !sig || !siglen) {
		error_print();
		return -1;
	}
	if (args && key->algor != OID_ec_public_key) {
		error_print();
		return -1;
	}

	switch (key->algor) {
	case OID_ec_public_key:
		switch (key->algor_param) {
		case OID_sm2:
			if (!args) {
				args = SM2_DEFAULT_ID;
				argslen = SM2_DEFAULT_ID_LENGTH;
			}
			if (!argslen) {
				error_print();
				return -1;
			}
			if (sm2_verify_init(&ctx->u.sm2_verify_ctx, &key->u.sm2_key, args, argslen) != 1) {
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
		case OID_secp256r1:
			if (ecdsa_verify_init(&ctx->u.ecdsa_sign_ctx, &key->u.secp256r1_key, sig, siglen) != 1) {
				error_print();
				return -1;
			}
			ctx->sign_algor = OID_ecdsa_with_sha256;
			break;
		default:
			error_print();
			return -1;
		}
		break;
	case OID_lms_hashsig:
		if (lms_verify_init(&ctx->u.lms_sign_ctx, &key->u.lms_key, sig, siglen) != 1) {
			error_print();
			return -1;
		}
		ctx->sign_algor = key->algor;
		break;
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
	case OID_sphincs_hashsig:
		if (sphincs_verify_init(&ctx->u.sphincs_sign_ctx, &key->u.sphincs_key, sig, siglen) != 1) {
			error_print();
			return -1;
		}
		ctx->sign_algor = key->algor;
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
	case OID_sm2sign_with_sm3:
		if (sm2_verify_update(&ctx->u.sm2_verify_ctx, data, datalen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_ecdsa_with_sha256:
		if (ecdsa_verify_update(&ctx->u.ecdsa_sign_ctx, data, datalen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_lms_hashsig:
		if (lms_verify_update(&ctx->u.lms_sign_ctx, data, datalen) != 1) {
			error_print();
			return -1;
		}
		break;
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
	case OID_sphincs_hashsig:
		error_print();
		return -1;
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
	case OID_sm2sign_with_sm3:
		if ((ret = sm2_verify_finish(&ctx->u.sm2_verify_ctx, ctx->sig, ctx->siglen)) < 0) {
			error_print();
			return -1;
		}
		break;
	case OID_ecdsa_with_sha256:
		if ((ret = ecdsa_verify_finish(&ctx->u.ecdsa_sign_ctx)) < 0) {
			error_print();
			return -1;
		}
		break;
	case OID_lms_hashsig:
		if ((ret = lms_verify_finish(&ctx->u.lms_sign_ctx)) < 0) {
			error_print();
			return -1;
		}
		break;
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
	case OID_sphincs_hashsig:
		error_print();
		return -1;
	default:
		error_print();
		return -1;
	}
	return ret;
}

int x509_verify(X509_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	int ret;

	if (!ctx) {
		error_print();
		return -1;
	}
	switch (ctx->sign_algor) {
	case OID_sm2sign_with_sm3:
	case OID_ecdsa_with_sha256:
	case OID_lms_hashsig:
	case OID_hss_lms_hashsig:
	case OID_xmss_hashsig:
	case OID_xmssmt_hashsig:
		if (x509_verify_update(ctx, data, datalen) != 1) {
			error_print();
			return -1;
		}
		if ((ret = x509_verify_finish(ctx)) < 0) {
			error_print();
			return -1;
		}
		break;
	case OID_sphincs_hashsig:
		if (sphincs_verify_update(&ctx->u.sphincs_sign_ctx, data, datalen) != 1) {
			error_print();
			return -1;
		}
		if ((ret = sphincs_verify_finish(&ctx->u.sphincs_sign_ctx)) < 0) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}
	return ret;
}

void x509_sign_ctx_cleanup(X509_SIGN_CTX *ctx)
{
	if (ctx) {
		switch (ctx->sign_algor) {
		case OID_sm2sign_with_sm3:
			gmssl_secure_clear(&ctx->u.sm2_sign_ctx, sizeof(SM2_SIGN_CTX));
			break;
		case OID_ecdsa_with_sha256:
			gmssl_secure_clear(&ctx->u.ecdsa_sign_ctx, sizeof(ECDSA_SIGN_CTX));
			break;
		case OID_lms_hashsig:
			lms_sign_ctx_cleanup(&ctx->u.lms_sign_ctx);
			break;
		case OID_hss_lms_hashsig:
			hss_sign_ctx_cleanup(&ctx->u.hss_sign_ctx);
			break;
		case OID_xmss_hashsig:
			xmss_sign_ctx_cleanup(&ctx->u.xmss_sign_ctx);
			break;
		case OID_xmssmt_hashsig:
			xmssmt_sign_ctx_cleanup(&ctx->u.xmssmt_sign_ctx);
			break;
		case OID_sphincs_hashsig:
			sphincs_sign_ctx_cleanup(&ctx->u.sphincs_sign_ctx);
			break;
		}
		memset(ctx, 0, sizeof(X509_SIGN_CTX));
	}
}

int x509_key_do_exchange(const X509_KEY *key, const X509_KEY *pub, uint8_t *out, size_t *outlen)
{
	if (!key || !pub || !out || !outlen) {
		error_print();
		return -1;
	}
	if (key->algor != pub->algor || key->algor_param != pub->algor_param) {
		error_print();
		return -1;
	}
	if (key->algor != OID_ec_public_key) {
		error_print();
		return -1;
	}

	switch (key->algor_param) {
	case OID_sm2:
		if (sm2_do_ecdh(&key->u.sm2_key, &pub->u.sm2_key, out) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_secp256r1:
		if (secp256r1_do_ecdh(&key->u.secp256r1_key, &pub->u.secp256r1_key, out) != 1) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}
	*outlen = 32;
	return 1;
}

int x509_key_exchange(const X509_KEY *key, const uint8_t *peer_pub, size_t peer_publen, uint8_t *out, size_t *outlen)
{
	if (!key || !peer_pub || !out || !outlen) {
		error_print();
		return -1;
	}
	if (key->algor != OID_ec_public_key) {
		error_print();
		return -1;
	}
	if (peer_publen != 65) {
		error_print();
		return -1;
	}
	switch (key->algor_param) {
	case OID_sm2:
		if (sm2_ecdh(&key->u.sm2_key, peer_pub, out) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_secp256r1:
		if (secp256r1_ecdh(&key->u.secp256r1_key, peer_pub, out) != 1) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}
	*outlen = 32;
	return 1;
}

int x509_key_encapsulate(const X509_KEY *key, uint8_t *ciphertext, size_t *ciphertext_len, uint8_t secret[32])
{
	if (!key || !ciphertext || !ciphertext_len || !secret) {
		error_print();
		return -1;
	}
	if (key->algor != OID_kyber_kem) {
		error_print();
		return -1;
	}
	if (kyber_encap(&key->u.kyber_key, (KYBER_CIPHERTEXT *)ciphertext, secret) != 1) {
		error_print();
		return -1;
	}
	*ciphertext_len = sizeof(KYBER_CIPHERTEXT);
	return 1;
}

int x509_key_decapsulate(const X509_KEY *key, const uint8_t *ciphertext, size_t ciphertext_len, uint8_t secret[32])
{
	if (!key || !ciphertext || !secret) {
		error_print();
		return -1;
	}
	if (key->algor != OID_kyber_kem) {
		error_print();
		return -1;
	}
	if (ciphertext_len != sizeof(KYBER_CIPHERTEXT)) {
		error_print();
		return -1;
	}
	if (kyber_decap(&key->u.kyber_key, (KYBER_CIPHERTEXT *)ciphertext, secret) != 1) {
		error_print();
		return -1;
	}
	return 1;
}
