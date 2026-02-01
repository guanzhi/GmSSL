/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <gmssl/bn.h>
#include <gmssl/ec.h>
#include <gmssl/mem.h>
#include <gmssl/oid.h>
#include <gmssl/sm4.h>
#include <gmssl/rand.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/pkcs8.h>
#include <gmssl/x509_alg.h>
#include <gmssl/secp256r1_key.h>


int secp256r1_key_generate(SECP256R1_KEY *key)
{
	do {
		if (rand_bytes((uint8_t *)key->private_key, sizeof(secp256r1_t)) != 1) {
			error_print();
			return -1;
		}
	} while (secp256r1_is_zero(key->private_key) || secp256r1_cmp(key->private_key, SECP256R1_N) >= 0);

	secp256r1_point_mul_generator(&key->public_key, key->private_key);

	return 1;
}

int secp256r1_key_set_private_key(SECP256R1_KEY *key, const secp256r1_t private_key)
{
	if (!key || !private_key) {
		error_print();
		return -1;
	}
	if (secp256r1_is_zero(private_key) || secp256r1_cmp(private_key, SECP256R1_N) >= 0) {
		error_print();
		return -1;
	}
	memset(key, 0, sizeof(SECP256R1_KEY));

	secp256r1_copy(key->private_key, private_key);
	secp256r1_point_mul_generator(&key->public_key, key->private_key);
	return 1;
}

int secp256r1_public_key_equ(const SECP256R1_KEY *key, const SECP256R1_KEY *pub)
{
	if (secp256r1_point_equ(&key->public_key, &pub->public_key) == 1) {
		return 1;
	} else {
		return 0;
	}
}


void secp256r1_key_cleanup(SECP256R1_KEY *key)
{
	if (key) {
		gmssl_secure_clear(key->private_key, sizeof(secp256r1_t));
		memset(key, 0, sizeof(SECP256R1_KEY));
	}
}


// SM2将这个命名为_to_octets，应该更准确一些
int secp256r1_public_key_to_bytes(const SECP256R1_KEY *key, uint8_t **out, size_t *outlen)
{
	if (!key || !outlen) {
		error_print();
		return -1;
	}
	if (out && *out) {
		if (secp256r1_point_to_uncompressed_octets(&key->public_key, *out) != 1) {
			error_print();
			return -1;
		}
		*out += 65;
	}
	*outlen += 65;
	return 1;
}

int secp256r1_public_key_from_bytes(SECP256R1_KEY *key, const uint8_t **in, size_t *inlen)
{
	secp256r1_t x;
	secp256r1_t y;

	if (!key || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen < 65) {
		error_print();
		return -1;
	}
	memset(key, 0, sizeof(SECP256R1_KEY));

	if (secp256r1_point_from_uncompressed_octets(&key->public_key, *in) != 1) {
		error_print();
		return -1;
	}
	*in += 65;
	*inlen -= 65;

	return 1;
}

int secp256r1_public_key_print(FILE *fp, int fmt, int ind, const char *label, const SECP256R1_KEY *key)
{
	secp256r1_t x;
	secp256r1_t y;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	secp256r1_print(fp, fmt, ind, "X", key->public_key.X);
	secp256r1_print(fp, fmt, ind, "Y", key->public_key.Y);
	secp256r1_print(fp, fmt, ind, "Z", key->public_key.Z);

	secp256r1_point_get_xy(&key->public_key, x, y);
	secp256r1_print(fp, fmt, ind, "x", x);
	secp256r1_print(fp, fmt, ind, "y", y);
	return 1;
}

int secp256r1_private_key_print(FILE *fp, int fmt, int ind, const char *label, const SECP256R1_KEY *key)
{
	uint8_t buf[32];

	secp256r1_to_32bytes(key->private_key, buf);

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	if (secp256r1_public_key_print(fp, fmt, ind, "public_key", key) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "private_key", buf, 32);
	return 1;
}

int secp256r1_public_key_to_der(const SECP256R1_KEY *key, uint8_t **out, size_t *outlen)
{
	uint8_t octets[65];
	uint8_t *p = octets;
	size_t len = 0;

	if (!key) {
		return 0;
	}

	// different from SM2
	if (out && *out) {
		if (secp256r1_public_key_to_bytes(key, &p, &len) != 1) {
			error_print();
			return -1;
		}
	}

	if (asn1_bit_octets_to_der(octets, sizeof(octets), out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_public_key_from_der(SECP256R1_KEY *key, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_bit_octets_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (secp256r1_public_key_from_bytes(key, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	if (dlen) {
		error_print();
		return -1;
	}
	return 1;
}





















int secp256r1_private_key_to_der(const SECP256R1_KEY *key, uint8_t **out, size_t *outlen)
{
	int curve = OID_secp256r1;
	uint8_t params[64];
	uint8_t pubkey[128];
	uint8_t *params_ptr = params;
	uint8_t *pubkey_ptr = pubkey;
	size_t params_len = 0;
	size_t pubkey_len = 0;
	uint8_t prikey[32];
	size_t len = 0;

	if (!key) {
		error_print();
		return -1;
	}
	if (ec_named_curve_to_der(curve, &params_ptr, &params_len) != 1
		|| secp256r1_public_key_to_der(key, &pubkey_ptr, &pubkey_len) != 1) {
		error_print();
		return -1;
	}
	// fprintf(stderr, "%s %d: params_len = %zu\n", params_len);
	// fprintf(stderr, "%s %d: pubkey_len = %zu\n", pubkey_len);
	secp256r1_to_32bytes(key->private_key, prikey);
	if (asn1_int_to_der(EC_private_key_version, NULL, &len) != 1
		|| asn1_octet_string_to_der(prikey, 32, NULL, &len) != 1
		|| asn1_explicit_to_der(0, params, params_len, NULL, &len) != 1
		|| asn1_explicit_to_der(1, pubkey, pubkey_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(EC_private_key_version, out, outlen) != 1
		|| asn1_octet_string_to_der(prikey, 32, out, outlen) != 1
		|| asn1_explicit_to_der(0, params, params_len, out, outlen) != 1
		|| asn1_explicit_to_der(1, pubkey, pubkey_len, out, outlen) != 1) {
		gmssl_secure_clear(prikey, 32);
		error_print();
		return -1;
	}
	gmssl_secure_clear(prikey, 32);
	return 1;
}

int secp256r1_private_key_from_der(SECP256R1_KEY *key, const uint8_t **in, size_t *inlen)
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
	SECP256R1_KEY tmp_key;
	secp256r1_t private_key;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(&ver, &d, &dlen) != 1
		|| asn1_octet_string_from_der(&prikey, &prikey_len, &d, &dlen) != 1
		|| asn1_explicit_from_der(0, &params, &params_len, &d, &dlen) != 1
		|| asn1_explicit_from_der(1, &pubkey, &pubkey_len, &d, &dlen) != 1
		|| asn1_check(ver == EC_private_key_version) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (!params || !pubkey) {
		error_print();
		return -1;
	}

	// public_key
	if (ec_named_curve_from_der(&curve, &params, &params_len) != 1
		|| asn1_check(curve == OID_secp256r1) != 1
		|| asn1_length_is_zero(params_len) != 1) {
		error_print();
		return -1;
	}
	if (secp256r1_public_key_from_der(&tmp_key, &pubkey, &pubkey_len) != 1
		|| asn1_length_is_zero(pubkey_len) != 1) {
		error_print();
		return -1;
	}

	// private_key
	if (!prikey || prikey_len != 32) {
		error_print();
		return -1;
	}
	secp256r1_from_32bytes(private_key, prikey);
	if (secp256r1_key_set_private_key(key, private_key) != 1) {
		gmssl_secure_clear(private_key, 32);
		error_print();
		return -1;
	}
	gmssl_secure_clear(private_key, 32);

	// check
	if (secp256r1_public_key_equ(key, &tmp_key) != 1) {
		secp256r1_key_cleanup(key);
		error_print();
		return -1;
	}

	return 1;
}

int secp256r1_private_key_info_to_der(const SECP256R1_KEY *key, uint8_t **out, size_t *outlen)
{
	int algor = OID_ec_public_key;
	int algor_param = OID_secp256r1;
	size_t len = 0;
	uint8_t prikey[256];
	uint8_t *p = prikey;
	size_t prikey_len = 0;

	if (secp256r1_private_key_to_der(key, &p, &prikey_len) != 1) {
		error_print();
		return -1;
	}
	//fprintf(stderr, "%s %d: prikey_len = %zu\n", __FILE__, __LINE__, prikey_len);

	if (asn1_int_to_der(PKCS8_private_key_info_version, NULL, &len) != 1
		|| x509_public_key_algor_to_der(algor, algor_param, NULL, &len) != 1
		|| asn1_octet_string_to_der(prikey, prikey_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(PKCS8_private_key_info_version, out, outlen) != 1
		|| x509_public_key_algor_to_der(algor, algor_param, out, outlen) != 1
		|| asn1_octet_string_to_der(prikey, prikey_len, out, outlen) != 1) {
		memset(prikey, 0, sizeof(prikey));
		error_print();
		return -1;
	}
	memset(prikey, 0, sizeof(prikey));
	return 1;
}

int secp256r1_private_key_info_from_der(SECP256R1_KEY *key, const uint8_t **attrs, size_t *attrslen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	int version;
	int algor;
	int algor_param;
	const uint8_t *prikey;
	size_t prikey_len;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(&version, &d, &dlen) != 1
		|| x509_public_key_algor_from_der(&algor, &algor_param, &d, &dlen) != 1
		|| asn1_octet_string_from_der(&prikey, &prikey_len, &d, &dlen) != 1
		|| asn1_implicit_set_from_der(0, attrs, attrslen, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (asn1_check(version == PKCS8_private_key_info_version) != 1
		|| asn1_check(algor == OID_ec_public_key) != 1
		|| asn1_check(algor_param == OID_secp256r1) != 1
		|| secp256r1_private_key_from_der(key, &prikey, &prikey_len) != 1
		|| asn1_length_is_zero(prikey_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_private_key_info_encrypt_to_der(const SECP256R1_KEY *ec_key, const char *pass,
	uint8_t **out, size_t *outlen)
{
	int ret = -1;
	uint8_t pkey_info[512];
	uint8_t *p = pkey_info;
	size_t pkey_info_len = 0;
	uint8_t salt[16];
	int iter = 65536;
	uint8_t iv[16];
	uint8_t key[16];
	SM4_KEY sm4_key;
	uint8_t enced_pkey_info[sizeof(pkey_info) + 32];
	size_t enced_pkey_info_len;

	if (!ec_key || !pass || !outlen) {
		error_print();
		return -1;
	}
	if (secp256r1_private_key_info_to_der(ec_key, &p, &pkey_info_len) != 1
		|| rand_bytes(salt, sizeof(salt)) != 1
		|| rand_bytes(iv, sizeof(iv)) != 1
		|| sm3_pbkdf2(pass, strlen(pass), salt, sizeof(salt), iter, sizeof(key), key) != 1) {
		error_print();
		goto end;
	}
	/*
	if (pkey_info_len != sizeof(pkey_info)) {
		error_print();
		goto end;
	}
	*/
	sm4_set_encrypt_key(&sm4_key, key);
	if (sm4_cbc_padding_encrypt(
			&sm4_key, iv, pkey_info, pkey_info_len,
			enced_pkey_info, &enced_pkey_info_len) != 1
		|| pkcs8_enced_private_key_info_to_der(
			salt, sizeof(salt), iter, sizeof(key), OID_hmac_sm3,
			OID_sm4_cbc, iv, sizeof(iv),
			enced_pkey_info, enced_pkey_info_len, out, outlen) != 1) {
		error_print();
		goto end;
	}

	ret = 1;
end:
	gmssl_secure_clear(pkey_info, sizeof(pkey_info));
	gmssl_secure_clear(key, sizeof(key));
	gmssl_secure_clear(&sm4_key, sizeof(sm4_key));
	return ret;
}

int secp256r1_private_key_info_decrypt_from_der(SECP256R1_KEY *ec_key,
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
	const uint8_t *enced_pkey_info;
	size_t enced_pkey_info_len;
	uint8_t pkey_info[256];
	const uint8_t *cp = pkey_info;
	size_t pkey_info_len;

	if (!ec_key || !attrs || !attrs_len || !pass || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (pkcs8_enced_private_key_info_from_der(&salt, &saltlen, &iter, &keylen, &prf,
		&cipher, &iv, &ivlen, &enced_pkey_info, &enced_pkey_info_len, in, inlen) != 1
		|| asn1_check(keylen == -1 || keylen == 16) != 1
		|| asn1_check(prf == - 1 || prf == OID_hmac_sm3) != 1
		|| asn1_check(cipher == OID_sm4_cbc) != 1
		|| asn1_check(ivlen == 16) != 1
		|| asn1_length_le(enced_pkey_info_len, sizeof(pkey_info)) != 1) {
		error_print();
		return -1;
	}
	if (sm3_pbkdf2(pass, strlen(pass), salt, saltlen, iter, sizeof(key), key) != 1) {
		error_print();
		goto end;
	}
	sm4_set_decrypt_key(&sm4_key, key);
	if (sm4_cbc_padding_decrypt(&sm4_key, iv, enced_pkey_info, enced_pkey_info_len,
			pkey_info, &pkey_info_len) != 1
		|| secp256r1_private_key_info_from_der(ec_key, attrs, attrs_len, &cp, &pkey_info_len) != 1
		|| asn1_length_is_zero(pkey_info_len) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	gmssl_secure_clear(&sm4_key, sizeof(sm4_key));
	gmssl_secure_clear(key, sizeof(key));
	gmssl_secure_clear(pkey_info, sizeof(pkey_info));
	return ret;
}

int secp256r1_private_key_info_encrypt_to_pem(const SECP256R1_KEY *key, const char *pass, FILE *fp)
{
	uint8_t buf[1024];
	uint8_t *p = buf;
	size_t len = 0;

	if (!fp) {
		error_print();
		return -1;
	}
	if (secp256r1_private_key_info_encrypt_to_der(key, pass, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (pem_write(fp, "ENCRYPTED PRIVATE KEY", buf, len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_private_key_info_decrypt_from_pem(SECP256R1_KEY *key, const char *pass, FILE *fp)
{
	uint8_t buf[512];
	const uint8_t *cp = buf;
	size_t len;
	const uint8_t *attrs;
	size_t attrs_len;

	if (!key || !pass || !fp) {
		error_print();
		return -1;
	}
	if (pem_read(fp, "ENCRYPTED PRIVATE KEY", buf, &len, sizeof(buf)) != 1
		|| secp256r1_private_key_info_decrypt_from_der(key, &attrs, &attrs_len, pass, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}






