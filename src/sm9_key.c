/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/sm9.h>
#include <gmssl/mem.h>
#include <gmssl/oid.h>
#include <gmssl/rand.h>
#include <gmssl/asn1.h>
#include <gmssl/pkcs8.h>
#include <gmssl/pbkdf2.h>
#include <gmssl/error.h>


extern const sm9_bn_t SM9_ZERO;
extern const sm9_bn_t SM9_N;

// generate h1 in [1, n-1]
int sm9_hash1(sm9_bn_t h1, const char *id, size_t idlen, uint8_t hid)
{
	SM3_CTX ctx;
	uint8_t prefix[1] = { SM9_HASH1_PREFIX };
	uint8_t ct1[4] = {0x00, 0x00, 0x00, 0x01};
	uint8_t ct2[4] = {0x00, 0x00, 0x00, 0x02};
	uint8_t Ha[64];

	sm3_init(&ctx);
	sm3_update(&ctx, prefix, sizeof(prefix));
	sm3_update(&ctx, (uint8_t *)id, idlen);
	sm3_update(&ctx, &hid, 1);
	sm3_update(&ctx, ct1, sizeof(ct1));
	sm3_finish(&ctx, Ha);

	sm3_init(&ctx);
	sm3_update(&ctx, prefix, sizeof(prefix));
	sm3_update(&ctx, (uint8_t *)id, idlen);
	sm3_update(&ctx, &hid, 1);
	sm3_update(&ctx, ct2, sizeof(ct2));
	sm3_finish(&ctx, Ha + 32);

	sm9_fn_from_hash(h1, Ha);
	return 1;
}

int sm9_sign_master_key_to_der(const SM9_SIGN_MASTER_KEY *msk, uint8_t **out, size_t *outlen)
{
	uint8_t ks[32];
	uint8_t Ppubs[1 + 32 * 4];
	size_t len = 0;

	sm9_fn_to_bytes(msk->ks, ks);
	sm9_twist_point_to_uncompressed_octets(&msk->Ppubs, Ppubs);

	if (asn1_integer_to_der(ks, sizeof(ks), NULL, &len) != 1
		|| asn1_bit_octets_to_der(Ppubs, sizeof(Ppubs), NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_integer_to_der(ks, sizeof(ks), out, outlen) != 1
		|| asn1_bit_octets_to_der(Ppubs, sizeof(Ppubs), out, outlen) != 1) {
		gmssl_secure_clear(ks, sizeof(ks));
		error_print();
		return -1;
	}
	gmssl_secure_clear(ks, sizeof(ks));
	return 1;
}

int sm9_sign_master_key_from_der(SM9_SIGN_MASTER_KEY *msk, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *ks;
	size_t kslen;
	const uint8_t *Ppubs;
	size_t Ppubslen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_integer_from_der(&ks, &kslen, &d, &dlen) != 1
		|| asn1_bit_octets_from_der(&Ppubs, &Ppubslen, &d, &dlen) != 1
		|| asn1_check(kslen == 32) != 1
		|| asn1_check(Ppubslen == 1 + 32 * 4) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	memset(msk, 0, sizeof(*msk));
	if (sm9_fn_from_bytes(msk->ks, ks) != 1
		|| sm9_twist_point_from_uncompressed_octets(&msk->Ppubs, Ppubs) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_sign_master_public_key_to_der(const SM9_SIGN_MASTER_KEY *mpk, uint8_t **out, size_t *outlen)
{
	uint8_t Ppubs[1 + 32 * 4];
	size_t len = 0;

	sm9_twist_point_to_uncompressed_octets(&mpk->Ppubs, Ppubs);
	if (asn1_bit_octets_to_der(Ppubs, sizeof(Ppubs), NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_bit_octets_to_der(Ppubs, sizeof(Ppubs), out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_sign_master_public_key_from_der(SM9_SIGN_MASTER_KEY *mpk, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *Ppubs;
	size_t Ppubslen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_bit_octets_from_der(&Ppubs, &Ppubslen, &d, &dlen) != 1
		|| asn1_check(Ppubslen == 1 + 32 * 4) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	memset(mpk, 0, sizeof(*mpk));
	if (sm9_twist_point_from_uncompressed_octets(&mpk->Ppubs, Ppubs) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_sign_key_to_der(const SM9_SIGN_KEY *key, uint8_t **out, size_t *outlen)
{
	uint8_t ds[65];
	uint8_t Ppubs[129];
	size_t len = 0;

	sm9_point_to_uncompressed_octets(&key->ds, ds);
	sm9_twist_point_to_uncompressed_octets(&key->Ppubs, Ppubs);

	if (asn1_bit_octets_to_der(ds, sizeof(ds), NULL, &len) != 1
		|| asn1_bit_octets_to_der(Ppubs, sizeof(Ppubs), NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_bit_octets_to_der(ds, sizeof(ds), out, outlen) != 1
		|| asn1_bit_octets_to_der(Ppubs, sizeof(Ppubs), out, outlen) != 1) {
		gmssl_secure_clear(ds, sizeof(ds));
		error_print();
		return -1;
	}
	gmssl_secure_clear(ds, sizeof(ds));
	return 1;
}

int sm9_sign_key_from_der(SM9_SIGN_KEY *key, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *ds;
	size_t dslen;
	const uint8_t *Ppubs;
	size_t Ppubslen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_bit_octets_from_der(&ds, &dslen, &d, &dlen) != 1
		|| asn1_bit_octets_from_der(&Ppubs, &Ppubslen, &d, &dlen) != 1
		|| asn1_check(dslen == 65) != 1
		|| asn1_check(Ppubslen == 129) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	memset(key, 0, sizeof(*key));
	if (sm9_point_from_uncompressed_octets(&key->ds, ds) != 1
		|| sm9_twist_point_from_uncompressed_octets(&key->Ppubs, Ppubs) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_enc_master_key_to_der(const SM9_ENC_MASTER_KEY *msk, uint8_t **out, size_t *outlen)
{
	uint8_t ke[32];
	uint8_t Ppube[1 + 32 * 2];
	size_t len = 0;

	sm9_fn_to_bytes(msk->ke, ke);
	sm9_point_to_uncompressed_octets(&msk->Ppube, Ppube);

	if (asn1_integer_to_der(ke, sizeof(ke), NULL, &len) != 1
		|| asn1_bit_octets_to_der(Ppube, sizeof(Ppube), NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_integer_to_der(ke, sizeof(ke), out, outlen) != 1
		|| asn1_bit_octets_to_der(Ppube, sizeof(Ppube), out, outlen) != 1) {
		gmssl_secure_clear(ke, sizeof(ke));
		error_print();
		return -1;
	}
	gmssl_secure_clear(ke, sizeof(ke));
	return 1;
}

int sm9_enc_master_key_from_der(SM9_ENC_MASTER_KEY *msk, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *ke;
	size_t kelen;
	const uint8_t *Ppube;
	size_t Ppubelen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_integer_from_der(&ke, &kelen, &d, &dlen) != 1
		|| asn1_bit_octets_from_der(&Ppube, &Ppubelen, &d, &dlen) != 1
		|| asn1_check(kelen == 32) != 1
		|| asn1_check(Ppubelen == 1 + 32 * 2) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	memset(msk, 0, sizeof(*msk));
	if (sm9_fn_from_bytes(msk->ke, ke) != 1
		|| sm9_point_from_uncompressed_octets(&msk->Ppube, Ppube) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_enc_master_public_key_to_der(const SM9_ENC_MASTER_KEY *mpk, uint8_t **out, size_t *outlen)
{
	uint8_t Ppube[1 + 32 * 2];
	size_t len = 0;

	sm9_point_to_uncompressed_octets(&mpk->Ppube, Ppube);

	if (asn1_bit_octets_to_der(Ppube, sizeof(Ppube), NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_bit_octets_to_der(Ppube, sizeof(Ppube), out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_enc_master_public_key_from_der(SM9_ENC_MASTER_KEY *mpk, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *Ppube;
	size_t Ppubelen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_bit_octets_from_der(&Ppube, &Ppubelen, &d, &dlen) != 1
		|| asn1_check(Ppubelen == 1 + 32 * 2) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	memset(mpk, 0, sizeof(*mpk));
	if (sm9_point_from_uncompressed_octets(&mpk->Ppube, Ppube) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_enc_key_to_der(const SM9_ENC_KEY *key, uint8_t **out, size_t *outlen)
{
	uint8_t de[129];
	uint8_t Ppube[65];
	size_t len = 0;

	sm9_twist_point_to_uncompressed_octets(&key->de, de);
	sm9_point_to_uncompressed_octets(&key->Ppube, Ppube);

	if (asn1_bit_octets_to_der(de, sizeof(de), NULL, &len) != 1
		|| asn1_bit_octets_to_der(Ppube, sizeof(Ppube), NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_bit_octets_to_der(de, sizeof(de), out, outlen) != 1
		|| asn1_bit_octets_to_der(Ppube, sizeof(Ppube), out, outlen) != 1) {
		gmssl_secure_clear(de, sizeof(de));
		error_print();
		return -1;
	}
	gmssl_secure_clear(de, sizeof(de));
	return 1;
}

int sm9_enc_key_from_der(SM9_ENC_KEY *key, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *de;
	size_t delen;
	const uint8_t *Ppube;
	size_t Ppubelen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_bit_octets_from_der(&de, &delen, &d, &dlen) != 1
		|| asn1_bit_octets_from_der(&Ppube, &Ppubelen, &d, &dlen) != 1
		|| asn1_check(delen == 129) != 1
		|| asn1_check(Ppubelen == 65) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	memset(key, 0, sizeof(*key));
	if (sm9_twist_point_from_uncompressed_octets(&key->de, de) != 1
		|| sm9_point_from_uncompressed_octets(&key->Ppube, Ppube) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_sign_master_key_generate(SM9_SIGN_MASTER_KEY *msk)
{
	if (!msk) {
		error_print();
		return -1;
	}
	// k = rand(1, n-1)
	if (sm9_fn_rand(msk->ks) != 1) {
		error_print();
		return -1;
	}
	// Ppubs = k * P2 in E'(F_p^2)
	sm9_twist_point_mul_generator(&msk->Ppubs, msk->ks);
	return 1;
}

int sm9_enc_master_key_generate(SM9_ENC_MASTER_KEY *msk)
{
	// k = rand(1, n-1)
	if (sm9_fn_rand(msk->ke) != 1) {
		error_print();
		return -1;
	}
	// Ppube = ke * P1 in E(F_p)
	sm9_point_mul_generator(&msk->Ppube, msk->ke);
	return 1;
}

int sm9_sign_master_key_extract_key(SM9_SIGN_MASTER_KEY *msk, const char *id, size_t idlen, SM9_SIGN_KEY *key)
{
	sm9_fn_t t;

	// t1 = H1(ID || hid, N) + ks
	sm9_hash1(t, id, idlen, SM9_HID_SIGN);
	sm9_fn_add(t, t, msk->ks);
	if (sm9_fn_is_zero(t)) {
		// 这是一个严重问题，意味着整个msk都需要作废了
		error_print();
		return -1;
	}

	// t2 = ks * t1^-1
	sm9_fn_inv(t, t);
	sm9_fn_mul(t, t, msk->ks);

	// ds = t2 * P1
	sm9_point_mul_generator(&key->ds, t);
	key->Ppubs = msk->Ppubs;

	return 1;
}

int sm9_enc_master_key_extract_key(SM9_ENC_MASTER_KEY *msk, const char *id, size_t idlen,
	SM9_ENC_KEY *key)
{
	sm9_fn_t t;

	// t1 = H1(ID || hid, N) + ke
	sm9_hash1(t, id, idlen, SM9_HID_ENC);
	sm9_fn_add(t, t, msk->ke);
	if (sm9_fn_is_zero(t)) {
		error_print();
		return -1;
	}

	// t2 = ke * t1^-1
	sm9_fn_inv(t, t);
	sm9_fn_mul(t, t, msk->ke);

	// de = t2 * P2
	sm9_twist_point_mul_generator(&key->de, t);
	key->Ppube = msk->Ppube;

	return 1;
}


#define OID_SM9	oid_sm_algors,302
static uint32_t oid_sm9[] = { OID_SM9 };
static uint32_t oid_sm9sign[] = { OID_SM9,1 };
static uint32_t oid_sm9keyagreement[] = { OID_SM9,2 };
static uint32_t oid_sm9encrypt[] = { OID_SM9,3 };

static const ASN1_OID_INFO sm9_oids[] = {
	{ OID_sm9, "sm9", oid_sm9, sizeof(oid_sm9)/sizeof(int) },
	{ OID_sm9sign, "sm9sign", oid_sm9sign, sizeof(oid_sm9sign)/sizeof(int) },
	{ OID_sm9keyagreement, "sm9keyagreement", oid_sm9keyagreement, sizeof(oid_sm9keyagreement)/sizeof(int) },
	{ OID_sm9encrypt, "sm9encrypt", oid_sm9encrypt, sizeof(oid_sm9encrypt)/sizeof(int) },
};

static const int sm9_oids_count = sizeof(sm9_oids)/sizeof(sm9_oids[0]);


const char *sm9_oid_name(int oid)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(sm9_oids, sm9_oids_count, oid))) {
		error_print();
		return NULL;
	}
	return info->name;
}

int sm9_oid_from_name(const char *name)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_name(sm9_oids, sm9_oids_count, name))) {
		error_print();
		return OID_undef;
	}
	return info->oid;
}

int sm9_oid_to_der(int oid, uint8_t **out, size_t *outlen)
{
	const ASN1_OID_INFO *info;
	if (oid == -1) {
		// TODO: 检查其他的oid_to_der是否支持这个default == -1 的特性
		return 0;
	}
	if (!(info = asn1_oid_info_from_oid(sm9_oids, sm9_oids_count, oid))) {
		error_print();
		return -1;
	}
	if (asn1_object_identifier_to_der(info->nodes, info->nodes_cnt, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_oid_from_der(int *oid, const uint8_t **in, size_t *inlen)
{
	int ret;
	const ASN1_OID_INFO *info;

	if ((ret = asn1_oid_info_from_der(&info, sm9_oids, sm9_oids_count, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else *oid = -1;
		return ret;
	}
	*oid = info->oid;
	return 1;
}

int sm9_algor_to_der(int alg, int params, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (sm9_oid_to_der(alg, NULL, &len) != 1
		|| sm9_oid_to_der(params, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| sm9_oid_to_der(alg, out, outlen) != 1
		|| sm9_oid_to_der(params, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_algor_from_der(int *alg, int *params, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (sm9_oid_from_der(alg, &d, &dlen) != 1
		|| sm9_oid_from_der(params, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int sm9_private_key_info_to_der(int alg, int params, const uint8_t *prikey, size_t prikey_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (prikey_len > SM9_MAX_PRIVATE_KEY_SIZE) {
		error_print();
		return -1;
	}
	if (asn1_int_to_der(PKCS8_private_key_info_version, NULL, &len) != 1
		|| sm9_algor_to_der(alg, params, NULL, &len) != 1
		|| asn1_octet_string_to_der(prikey, prikey_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(PKCS8_private_key_info_version, out, outlen) != 1
		|| sm9_algor_to_der(alg, params, out, outlen) != 1
		|| asn1_octet_string_to_der(prikey, prikey_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	//printf("alg %s params %s prikey_len %zu: SM9_PRIVATE_KEY_INFO_SIZE %zu\n", sm9_oid_name(alg), sm9_oid_name(params), prikey_len, *outlen);
	return 1;
}

static int sm9_private_key_info_from_der(int *alg, int *params, const uint8_t **prikey, size_t *prikey_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	int ver;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else error_print();
		return ret;
	}
	if (asn1_int_from_der(&ver, &d, &dlen) != 1
		|| sm9_algor_from_der(alg, params, &d, &dlen) != 1
		|| asn1_octet_string_from_der(prikey, prikey_len, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (ver != PKCS8_private_key_info_version) {
		error_print();
		return -1;
	}
	if (*prikey_len > SM9_MAX_PRIVATE_KEY_SIZE) {
		error_print();
		return -1;
	}
	return 1;
}

static int sm9_private_key_info_encrypt_to_der(int alg, int params, const uint8_t *prikey, size_t prikey_len,
	const char *pass, uint8_t **out, size_t *outlen)
{
	int ret = -1;
	uint8_t pkey_info[SM9_MAX_PRIVATE_KEY_INFO_SIZE];
	uint8_t *p = pkey_info;
	size_t pkey_info_len = 0;
	uint8_t salt[16];
	int iter = 65536;
	uint8_t iv[16];
	uint8_t key[16];
	SM4_KEY sm4_key;
	uint8_t enced_pkey_info[sizeof(pkey_info) + 16]; // cbc-padding of pkey_info
	size_t enced_pkey_info_len;

	if (sm9_private_key_info_to_der(alg, params, prikey, prikey_len, &p, &pkey_info_len) != 1
		|| rand_bytes(salt, sizeof(salt)) != 1
		|| rand_bytes(iv, sizeof(iv)) != 1
		|| pbkdf2_hmac_sm3_genkey(pass, strlen(pass), salt, sizeof(salt), iter, sizeof(key), key) != 1) {
		error_print();
		goto end;
	}
	sm4_set_encrypt_key(&sm4_key, key);
	if (sm4_cbc_padding_encrypt(&sm4_key, iv, pkey_info, pkey_info_len, enced_pkey_info, &enced_pkey_info_len) != 1
		|| pkcs8_enced_private_key_info_to_der(salt, sizeof(salt), iter, sizeof(key),
			OID_hmac_sm3, OID_sm4_cbc, iv, sizeof(iv),
			enced_pkey_info, enced_pkey_info_len, out, outlen) != 1) {
		error_print();
		goto end;
	}
	//printf("SM9_ENCED_PRIVATE_KEY_INFO_SIZE %zu\n", *outlen);
	ret = 1;
end:
	gmssl_secure_clear(pkey_info, sizeof(pkey_info));
	gmssl_secure_clear(salt, sizeof(salt));
	gmssl_secure_clear(iv, sizeof(iv));
	gmssl_secure_clear(key, sizeof(key));
	return ret;
}

static int sm9_private_key_info_decrypt_from_der(int *alg, int *params, uint8_t *prikey, size_t *prikey_len,
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
	uint8_t pkey_info[SM9_MAX_PRIVATE_KEY_INFO_SIZE];
	const uint8_t *cp = pkey_info;
	size_t pkey_info_len;
	const uint8_t *cp_prikey;

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
	if (pbkdf2_genkey(DIGEST_sm3(), pass, strlen(pass), salt, saltlen, iter, sizeof(key), key) != 1) {
		error_print();
		goto end;
	}
	sm4_set_decrypt_key(&sm4_key, key);
	if (sm4_cbc_padding_decrypt(&sm4_key, iv, enced_pkey_info, enced_pkey_info_len,
			pkey_info, &pkey_info_len) != 1
		|| sm9_private_key_info_from_der(alg, params, &cp_prikey, prikey_len, // 注意这里的是const uint8_t *，必须拷贝到外面
			&cp, &pkey_info_len) != 1
		|| asn1_length_is_zero(pkey_info_len) != 1) {
		error_print();
		goto end;
	}
	memcpy(prikey, cp_prikey, *prikey_len);
	ret = 1;
end:
	gmssl_secure_clear(&sm4_key, sizeof(sm4_key));
	gmssl_secure_clear(key, sizeof(key));
	gmssl_secure_clear(pkey_info, sizeof(pkey_info));
	return ret;
}



int sm9_sign_master_key_info_encrypt_to_der(const SM9_SIGN_MASTER_KEY *msk, const char *pass, uint8_t **out, size_t *outlen)
{
	uint8_t buf[SM9_SIGN_MASTER_KEY_MAX_SIZE];
	uint8_t *p = buf;
	size_t len = 0;

	if (sm9_sign_master_key_to_der(msk, &p, &len) != 1
		|| sm9_private_key_info_encrypt_to_der(OID_sm9, OID_sm9sign, buf, len, pass, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}


int sm9_sign_master_key_info_decrypt_from_der(SM9_SIGN_MASTER_KEY *msk, const char *pass, const uint8_t **in, size_t *inlen)
{
	int ret = -1;
	int alg, params;
	uint8_t prikey[SM9_MAX_PRIVATE_KEY_SIZE];
	size_t prikey_len;
	const uint8_t *cp = prikey;

	if (sm9_private_key_info_decrypt_from_der(&alg, &params, prikey, &prikey_len, pass, in, inlen) != 1) {
		error_print();
		goto end;
	}
	if (alg != OID_sm9) {
		error_print();
		goto end;
	}
	if (params != OID_sm9sign) {
		error_print();
		goto end;
	}
	if (sm9_sign_master_key_from_der(msk, &cp, &prikey_len) != 1
		|| asn1_length_is_zero(prikey_len) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	gmssl_secure_clear(prikey, sizeof(prikey));
	return ret;
}

int sm9_sign_master_key_info_encrypt_to_pem(const SM9_SIGN_MASTER_KEY *msk, const char *pass, FILE *fp)
{
	uint8_t buf[SM9_MAX_ENCED_PRIVATE_KEY_INFO_SIZE];
	uint8_t *p = buf;
	size_t len = 0;

	if (sm9_sign_master_key_info_encrypt_to_der(msk, pass, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (pem_write(fp, PEM_SM9_SIGN_MASTER_KEY, buf, len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_sign_master_key_info_decrypt_from_pem(SM9_SIGN_MASTER_KEY *msk, const char *pass, FILE *fp)
{
	uint8_t buf[SM9_MAX_ENCED_PRIVATE_KEY_INFO_SIZE];
	const uint8_t *cp = buf;
	size_t len;

	if (pem_read(fp, PEM_SM9_SIGN_MASTER_KEY, buf, &len, sizeof(buf)) != 1
		|| sm9_sign_master_key_info_decrypt_from_der(msk, pass, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_sign_master_public_key_to_pem(const SM9_SIGN_MASTER_KEY *mpk, FILE *fp)
{
	uint8_t buf[SM9_SIGN_MASTER_PUBLIC_KEY_SIZE];
	uint8_t *p = buf;
	size_t len = 0;

	if (sm9_sign_master_public_key_to_der(mpk, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (pem_write(fp, PEM_SM9_SIGN_MASTER_PUBLIC_KEY, buf, len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_sign_master_public_key_from_pem(SM9_SIGN_MASTER_KEY *mpk, FILE *fp)
{
	uint8_t buf[512];
	const uint8_t *cp = buf;
	size_t len;

	if (pem_read(fp, PEM_SM9_SIGN_MASTER_PUBLIC_KEY, buf, &len, sizeof(buf)) != 1
		|| sm9_sign_master_public_key_from_der(mpk, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_sign_key_info_encrypt_to_der(const SM9_SIGN_KEY *key, const char *pass, uint8_t **out, size_t *outlen)
{
	uint8_t buf[SM9_SIGN_KEY_SIZE];
	uint8_t *p = buf;
	size_t len = 0;

	if (sm9_sign_key_to_der(key, &p, &len) != 1
		|| sm9_private_key_info_encrypt_to_der(OID_sm9sign, -1, buf, len, pass, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_sign_key_info_decrypt_from_der(SM9_SIGN_KEY *key, const char *pass, const uint8_t **in, size_t *inlen)
{
	int ret = -1;
	int alg, params;
	uint8_t prikey[512];
	size_t prikey_len;
	const uint8_t *cp = prikey;

	if (sm9_private_key_info_decrypt_from_der(&alg, &params, prikey, &prikey_len, pass, in, inlen) != 1) {
		error_print();
		goto end;
	}
	if (alg != OID_sm9sign) {
		error_print();
		goto end;
	}
	if (params != -1) {
		error_print();
		goto end;
	}
	if (sm9_sign_key_from_der(key, &cp, &prikey_len) != 1
		|| asn1_length_is_zero(prikey_len) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	gmssl_secure_clear(prikey, sizeof(prikey));
	return ret;
}

int sm9_sign_key_info_encrypt_to_pem(const SM9_SIGN_KEY *key, const char *pass, FILE *fp)
{
	uint8_t buf[SM9_MAX_ENCED_PRIVATE_KEY_INFO_SIZE];
	uint8_t *p = buf;
	size_t len = 0;

	if (sm9_sign_key_info_encrypt_to_der(key, pass, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (pem_write(fp, PEM_SM9_SIGN_PRIVATE_KEY, buf, len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_sign_key_info_decrypt_from_pem(SM9_SIGN_KEY *key, const char *pass, FILE *fp)
{
	uint8_t buf[SM9_MAX_ENCED_PRIVATE_KEY_INFO_SIZE];
	const uint8_t *cp = buf;
	size_t len;

	if (pem_read(fp, PEM_SM9_SIGN_PRIVATE_KEY, buf, &len, sizeof(buf)) != 1
		|| sm9_sign_key_info_decrypt_from_der(key, pass, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_enc_master_key_info_encrypt_to_der(const SM9_ENC_MASTER_KEY *msk, const char *pass, uint8_t **out, size_t *outlen)
{
	uint8_t buf[256];
	uint8_t *p = buf;
	size_t len = 0;

	if (sm9_enc_master_key_to_der(msk, &p, &len) != 1
		|| sm9_private_key_info_encrypt_to_der(OID_sm9, OID_sm9encrypt, buf, len, pass, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_enc_master_key_info_decrypt_from_der(SM9_ENC_MASTER_KEY *msk, const char *pass, const uint8_t **in, size_t *inlen)
{
	int ret = -1;
	int alg, params;
	uint8_t prikey[512];
	size_t prikey_len;
	const uint8_t *cp = prikey;

	if (sm9_private_key_info_decrypt_from_der(&alg, &params, prikey, &prikey_len, pass, in, inlen) != 1) {
		error_print();
		goto end;
	}
	if (alg != OID_sm9) {
		error_print();
		goto end;
	}
	if (params != OID_sm9encrypt) {
		error_print();
		goto end;
	}
	if (sm9_enc_master_key_from_der(msk, &cp, &prikey_len) != 1
		|| asn1_length_is_zero(prikey_len) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	gmssl_secure_clear(prikey, sizeof(prikey));
	return 1;
}

int sm9_enc_master_key_info_encrypt_to_pem(const SM9_ENC_MASTER_KEY *msk, const char *pass, FILE *fp)
{
	uint8_t buf[SM9_MAX_ENCED_PRIVATE_KEY_INFO_SIZE];
	uint8_t *p = buf;
	size_t len = 0;

	if (sm9_enc_master_key_info_encrypt_to_der(msk, pass, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (pem_write(fp, PEM_SM9_ENC_MASTER_KEY, buf, len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_enc_master_key_info_decrypt_from_pem(SM9_ENC_MASTER_KEY *msk, const char *pass, FILE *fp)
{
	uint8_t buf[SM9_MAX_ENCED_PRIVATE_KEY_INFO_SIZE];
	const uint8_t *cp = buf;
	size_t len;

	if (pem_read(fp, PEM_SM9_ENC_MASTER_KEY, buf, &len, sizeof(buf)) != 1
		|| sm9_enc_master_key_info_decrypt_from_der(msk, pass, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_enc_master_public_key_to_pem(const SM9_ENC_MASTER_KEY *mpk, FILE *fp)
{
	uint8_t buf[1024];
	uint8_t *p = buf;
	size_t len = 0;

	if (sm9_enc_master_public_key_to_der(mpk, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (pem_write(fp, PEM_SM9_ENC_MASTER_PUBLIC_KEY, buf, len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_enc_master_public_key_from_pem(SM9_ENC_MASTER_KEY *mpk, FILE *fp)
{
	uint8_t buf[512];
	const uint8_t *cp = buf;
	size_t len;

	if (pem_read(fp, PEM_SM9_ENC_MASTER_PUBLIC_KEY, buf, &len, sizeof(buf)) != 1
		|| sm9_enc_master_public_key_from_der(mpk, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_enc_key_info_encrypt_to_der(const SM9_ENC_KEY *key, const char *pass, uint8_t **out, size_t *outlen)
{
	uint8_t buf[1024];
	uint8_t *p = buf;
	size_t len = 0;

	if (sm9_enc_key_to_der(key, &p, &len) != 1
		|| sm9_private_key_info_encrypt_to_der(OID_sm9encrypt, -1, buf, len, pass, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_enc_key_info_decrypt_from_der(SM9_ENC_KEY *key, const char *pass, const uint8_t **in, size_t *inlen)
{
	int ret = -1;
	int alg, params;
	uint8_t prikey[512];
	size_t prikey_len;
	const uint8_t *cp = prikey;

	if (sm9_private_key_info_decrypt_from_der(&alg, &params, prikey, &prikey_len, pass, in, inlen) != 1) {
		error_print();
		goto end;
	}
	if (alg != OID_sm9encrypt) {
		error_print();
		goto end;
	}
	if (params != -1) {
		error_print();
		goto end;
	}
	if (sm9_enc_key_from_der(key, &cp, &prikey_len) != 1
		|| asn1_length_is_zero(prikey_len) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	gmssl_secure_clear(prikey, sizeof(prikey));
	return ret;
}

int sm9_enc_key_info_encrypt_to_pem(const SM9_ENC_KEY *key, const char *pass, FILE *fp)
{
	uint8_t buf[SM9_MAX_ENCED_PRIVATE_KEY_INFO_SIZE];
	uint8_t *p = buf;
	size_t len = 0;

	if (sm9_enc_key_info_encrypt_to_der(key, pass, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (pem_write(fp, PEM_SM9_ENC_PRIVATE_KEY, buf, len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_enc_key_info_decrypt_from_pem(SM9_ENC_KEY *key, const char *pass, FILE *fp)
{
	uint8_t buf[SM9_MAX_ENCED_PRIVATE_KEY_INFO_SIZE];
	const uint8_t *cp = buf;
	size_t len;

	if (pem_read(fp, PEM_SM9_ENC_PRIVATE_KEY, buf, &len, sizeof(buf)) != 1
		|| sm9_enc_key_info_decrypt_from_der(key, pass, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_sign_master_key_print(FILE *fp, int fmt, int ind, const char *label, const SM9_SIGN_MASTER_KEY *msk)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	sm9_fn_print(fp, fmt, ind, "ks", msk->ks);
	sm9_twist_point_print(fp, fmt, ind, "Ppubs", &msk->Ppubs);
	return 1;
}

int sm9_sign_master_public_key_print(FILE *fp, int fmt, int ind, const char *label, const SM9_SIGN_MASTER_KEY *mpk)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	sm9_twist_point_print(fp, fmt, ind, "Ppubs", &mpk->Ppubs);
	return 1;
}

int sm9_sign_key_print(FILE *fp, int fmt, int ind, const char *label, const SM9_SIGN_KEY *key)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	sm9_point_print(fp, fmt, ind, "ds", &key->ds);
	sm9_twist_point_print(fp, fmt, ind, "Ppubs", &key->Ppubs);
	return 1;
}

int sm9_enc_master_key_print(FILE *fp, int fmt, int ind, const char *label, const SM9_ENC_MASTER_KEY *msk)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	sm9_fn_print(fp, fmt, ind, "ke", msk->ke);
	sm9_point_print(fp, fmt, ind, "Ppube", &msk->Ppube);
	return 1;
}

int sm9_enc_master_public_key_print(FILE *fp, int fmt, int ind, const char *label, const SM9_ENC_MASTER_KEY *mpk)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	sm9_point_print(fp, fmt, ind, "Ppube", &mpk->Ppube);
	return 1;
}

int sm9_enc_key_print(FILE *fp, int fmt, int ind, const char *label, const SM9_ENC_KEY *key)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	sm9_twist_point_print(fp, fmt, ind, "de", &key->de);
	sm9_point_print(fp, fmt, ind, "Ppube", &key->Ppube);
	return 1;
}

int sm9_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen)
{
	const uint8_t *d;
	size_t dlen;
	const uint8_t *p;
	size_t len;

	if (asn1_sequence_from_der(&d, &dlen, &sig, &siglen) != 1
		|| asn1_length_is_zero(siglen) != 1) {
		error_print();
		return -1;
	}

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	if (asn1_octet_string_from_der(&p, &len, &d, &dlen) != 1) goto err;
	format_bytes(fp, fmt, ind, "h", p, len);
	if (asn1_bit_octets_from_der(&p, &len, &d, &dlen) != 1) goto err;
	format_bytes(fp, fmt, ind, "S", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int sm9_ciphertext_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen)
{
	const uint8_t *d;
	size_t dlen;
	int val;
	const uint8_t *p;
	size_t len;

	if (asn1_sequence_from_der(&d, &dlen, &a, &alen) != 1
		|| asn1_length_is_zero(alen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_int_from_der(&val, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "EnType: %d\n", val);
	if (asn1_bit_octets_from_der(&p, &len, &d, &dlen) != 1) goto err;
	format_bytes(fp, fmt, ind, "C1", p, len);
	if (asn1_octet_string_from_der(&p, &len, &d, &dlen) != 1) goto err;
	format_bytes(fp, fmt, ind, "C3", p, len);
	if (asn1_octet_string_from_der(&p, &len, &d, &dlen) != 1) goto err;
	format_bytes(fp, fmt, ind, "CipherText", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}
