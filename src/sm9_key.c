/*
 * Copyright (c) 2014 - 2020 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm3.h>
#include <gmssl/sm9.h>
#include <gmssl/mem.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>


// generate h1 in [1, n-1]
int sm9_hash1(sm9_bn_t h1, const char *id, size_t idlen, uint8_t hid)
{
	SM3_CTX ctx;
	uint8_t prefix[1] = {0x01};
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
	uint8_t ds[32];
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
	// k = rand(1, n-1)
	sm9_fn_rand(msk->ks);

	// Ppubs = k * P2 in E'(F_p^2)
	sm9_twist_point_mul_generator(&msk->Ppubs, msk->ks);

	return 1;
}

int sm9_enc_master_key_generate(SM9_ENC_MASTER_KEY *msk)
{
	// k = rand(1, n-1)
	sm9_fn_rand(msk->ke);

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
