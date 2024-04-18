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
#include <stdint.h>
#include <gmssl/mem.h>
#include <gmssl/sm3.h>
#include <gmssl/sm9.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>


int sm9_signature_to_der(const SM9_SIGNATURE *sig, uint8_t **out, size_t *outlen)
{
	uint8_t hbuf[32];
	uint8_t Sbuf[65];
	size_t len = 0;

	sm9_z256_to_bytes(sig->h, hbuf);
	sm9_z256_point_to_uncompressed_octets(&sig->S, Sbuf);

	if (asn1_octet_string_to_der(hbuf, sizeof(hbuf), NULL, &len) != 1
		|| asn1_bit_octets_to_der(Sbuf, sizeof(Sbuf), NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_octet_string_to_der(hbuf, sizeof(hbuf), out, outlen) != 1
		|| asn1_bit_octets_to_der(Sbuf, sizeof(Sbuf), out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_signature_from_der(SM9_SIGNATURE *sig, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *h;
	size_t hlen;
	const uint8_t *S;
	size_t Slen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_octet_string_from_der(&h, &hlen, &d, &dlen) != 1
		|| asn1_bit_octets_from_der(&S, &Slen, &d, &dlen) != 1
		|| asn1_check(hlen == 32) != 1
		|| asn1_check(Slen == 65) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}

	sm9_z256_from_bytes(sig->h, h);
	if (sm9_z256_cmp(sig->h, sm9_z256_order()) >= 0) {
		error_print();
		return -1;
	}

	if (sm9_z256_point_from_uncompressed_octets(&sig->S, S) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_sign_init(SM9_SIGN_CTX *ctx)
{
	const uint8_t prefix[1] = { SM9_HASH2_PREFIX };
	sm3_init(&ctx->sm3_ctx);
	sm3_update(&ctx->sm3_ctx, prefix, sizeof(prefix));
	return 1;
}

int sm9_sign_update(SM9_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	sm3_update(&ctx->sm3_ctx, data, datalen);
	return 1;
}

int sm9_sign_finish(SM9_SIGN_CTX *ctx, const SM9_SIGN_KEY *key, uint8_t *sig, size_t *siglen)
{
	SM9_SIGNATURE signature;

	if (sm9_do_sign(key, &ctx->sm3_ctx, &signature) != 1) {
		error_print();
		return -1;
	}
	*siglen = 0;
	if (sm9_signature_to_der(&signature, &sig, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_do_sign(const SM9_SIGN_KEY *key, const SM3_CTX *sm3_ctx, SM9_SIGNATURE *sig)
{
	sm9_z256_t r;
	sm9_z256_fp12_t g;
	uint8_t wbuf[32 * 12];
	SM3_CTX ctx = *sm3_ctx;
	SM3_CTX tmp_ctx;
	uint8_t ct1[4] = {0,0,0,1};
	uint8_t ct2[4] = {0,0,0,2};
	uint8_t Ha[64];

	// A1: g = e(P1, Ppubs)
	sm9_z256_pairing(g, &key->Ppubs, sm9_z256_generator());

	do {
		// A2: rand r in [1, N-1]
		if (sm9_z256_rand_range(r, sm9_z256_order()) != 1) {
			error_print();
			return -1;
		}
		
		// Only for testing
		//sm9_z256_from_hex(r, "00033C8616B06704813203DFD00965022ED15975C662337AED648835DC4B1CBE");

		// A3: w = g^r
		sm9_z256_fp12_pow(g, g, r);
		sm9_z256_fp12_to_bytes(g, wbuf);

		// A4: h = H2(M || w, N)
		sm3_update(&ctx, wbuf, sizeof(wbuf));
		tmp_ctx = ctx;
		sm3_update(&ctx, ct1, sizeof(ct1));
		sm3_finish(&ctx, Ha);
		sm3_update(&tmp_ctx, ct2, sizeof(ct2));
		sm3_finish(&tmp_ctx, Ha + 32);
		sm9_z256_modn_from_hash(sig->h, Ha);

		// A5: l = (r - h) mod N, if l = 0, goto A2
		sm9_z256_modn_sub(r, r, sig->h);

	} while (sm9_z256_is_zero(r));

	// A6: S = l * dsA
	sm9_z256_point_mul(&sig->S, r, &key->ds);

	gmssl_secure_clear(&r, sizeof(r));
	gmssl_secure_clear(&g, sizeof(g));
	gmssl_secure_clear(wbuf, sizeof(wbuf));
	gmssl_secure_clear(&tmp_ctx, sizeof(tmp_ctx));
	gmssl_secure_clear(Ha, sizeof(Ha));

	return 1;
}

int sm9_verify_init(SM9_SIGN_CTX *ctx)
{
	const uint8_t prefix[1] = { SM9_HASH2_PREFIX };
	sm3_init(&ctx->sm3_ctx);
	sm3_update(&ctx->sm3_ctx, prefix, sizeof(prefix));
	return 1;
}

int sm9_verify_update(SM9_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	sm3_update(&ctx->sm3_ctx, data, datalen);
	return 1;
}

int sm9_verify_finish(SM9_SIGN_CTX *ctx, const uint8_t *sig, size_t siglen,
	const SM9_SIGN_MASTER_KEY *mpk, const char *id, size_t idlen)
{
	int ret;
	SM9_SIGNATURE signature;

	if (sm9_signature_from_der(&signature, &sig, &siglen) != 1
		|| asn1_length_is_zero(siglen) != 1) {
		error_print();
		return -1;
	}

	if ((ret = sm9_do_verify(mpk, id, idlen, &ctx->sm3_ctx, &signature)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

int sm9_do_verify(const SM9_SIGN_MASTER_KEY *mpk, const char *id, size_t idlen,
	const SM3_CTX *sm3_ctx, const SM9_SIGNATURE *sig)
{
	sm9_z256_t h1;
	sm9_z256_t h2;
	sm9_z256_fp12_t g;
	sm9_z256_fp12_t t;
	sm9_z256_fp12_t u;
	sm9_z256_fp12_t w;
	SM9_Z256_TWIST_POINT P;
	uint8_t wbuf[32 * 12];
	SM3_CTX ctx = *sm3_ctx;
	SM3_CTX tmp_ctx;
	uint8_t ct1[4] = {0,0,0,1};
	uint8_t ct2[4] = {0,0,0,2};
	uint8_t Ha[64];

	// B1: check h in [1, N-1]

	// B2: check S in G1

	// B3: g = e(P1, Ppubs)
	sm9_z256_pairing(g, &mpk->Ppubs, sm9_z256_generator());

	// B4: t = g^h
	sm9_z256_fp12_pow(t, g, sig->h);

	// B5: h1 = H1(ID || hid, N)
	sm9_z256_hash1(h1, id, idlen, SM9_HID_SIGN);

	// B6: P = h1 * P2 + Ppubs
	sm9_z256_twist_point_mul_generator(&P, h1);
	sm9_z256_twist_point_add_full(&P, &P, &mpk->Ppubs);

	// B7: u = e(S, P)
	sm9_z256_pairing(u, &P, &sig->S);

	// B8: w = u * t
	sm9_z256_fp12_mul(w, u, t);
	sm9_z256_fp12_to_bytes(w, wbuf);

	// B9: h2 = H2(M || w, N), check h2 == h
	sm3_update(&ctx, wbuf, sizeof(wbuf));
	tmp_ctx = ctx;
	sm3_update(&ctx, ct1, sizeof(ct1));
	sm3_finish(&ctx, Ha);
	sm3_update(&tmp_ctx, ct2, sizeof(ct2));
	sm3_finish(&tmp_ctx, Ha + 32);
	sm9_z256_modn_from_hash(h2, Ha);
	if (sm9_z256_equ(h2, sig->h) != 1) {
		return 0;
	}

	return 1;
}
