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
#include <stdint.h>
#include <gmssl/mem.h>
#include <gmssl/sm3.h>
#include <gmssl/sm9.h>
#include <gmssl/error.h>


int sm9_sign_init(SM9_SIGN_CTX *ctx)
{
	const uint8_t prefix[1] = {0x02};
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
	return -1;
}

int sm9_do_sign(const SM9_SIGN_KEY *key, const SM3_CTX *sm3_ctx, SM9_SIGNATURE *sig)
{
	sm9_fn_t r;
	sm9_fp12_t g;
	uint8_t wbuf[32 * 12];
	SM3_CTX ctx = *sm3_ctx;
	SM3_CTX tmp_ctx;
	uint8_t ct1[4] = {0,0,0,1};
	uint8_t ct2[4] = {0,0,0,2};
	uint8_t Ha[64];

	// A1: g = e(P1, Ppubs)
	sm9_pairing(g, &key->Ppubs, SM9_P1);

	do {
		// A2: rand r in [1, N-1]
		sm9_fn_rand(r);

		// A3: w = g^r
		sm9_fp12_pow(g, g, r);
		sm9_fp12_to_bytes(g, wbuf);

		// A4: h = H2(M || w, N)
		sm3_update(&ctx, wbuf, sizeof(wbuf));
		tmp_ctx = ctx;
		sm3_update(&ctx, ct1, sizeof(ct1));
		sm3_finish(&ctx, Ha);
		sm3_update(&tmp_ctx, ct2, sizeof(ct2));
		sm3_finish(&tmp_ctx, Ha + 32);
		sm9_fn_from_hash(sig->h, Ha);

		// A5: l = (r - h) mod N, if l = 0, goto A2
		sm9_fn_sub(r, r, sig->h);

	} while (sm9_fn_is_zero(r));

	// A6: S = l * dsA
	sm9_point_mul(&sig->S, r, &key->ds);

	gmssl_secure_clear(&r, sizeof(r));
	gmssl_secure_clear(&g, sizeof(g));
	gmssl_secure_clear(wbuf, sizeof(wbuf));
	gmssl_secure_clear(&tmp_ctx, sizeof(tmp_ctx));
	gmssl_secure_clear(Ha, sizeof(Ha));

	return 1;
}

int sm9_verify_init(SM9_SIGN_CTX *ctx)
{
	const uint8_t prefix[1] = {0x02};
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
	return -1;
}

int sm9_do_verify(const SM9_SIGN_MASTER_KEY *mpk, const char *id, size_t idlen,
	const SM3_CTX *sm3_ctx, const SM9_SIGNATURE *sig)
{
	sm9_fn_t h1;
	sm9_fn_t h2;
	sm9_fp12_t g;
	sm9_fp12_t t;
	sm9_fp12_t u;
	sm9_fp12_t w;
	sm9_twist_point_t P;
	uint8_t wbuf[32 * 12];
	SM3_CTX ctx = *sm3_ctx;
	SM3_CTX tmp_ctx;
	uint8_t ct1[4] = {0,0,0,1};
	uint8_t ct2[4] = {0,0,0,2};
	uint8_t Ha[64];

	// B1: check h in [1, N-1]

	// B2: check S in G1

	// B3: g = e(P1, Ppubs)
	sm9_pairing(g, &mpk->Ppubs, SM9_P1);

	// B4: t = g^h
	sm9_fp12_pow(t, g, sig->h);

	// B5: h1 = H1(ID || hid, N)
	sm9_hash1(h1, id, idlen, SM9_HID_SIGN);

	// B6: P = h1 * P2 + Ppubs
	sm9_twist_point_mul_generator(&P, h1);
	sm9_twist_point_add(&P, &P, &mpk->Ppubs);

	// B7: u = e(S, P)
	sm9_pairing(u, &P, &sig->S);

	// B8: w = u * t
	sm9_fp12_mul(w, u, t);
	sm9_fp12_to_bytes(w, wbuf);

	// B9: h2 = H2(M || w, N), check h2 == h
	sm3_update(&ctx, wbuf, sizeof(wbuf));
	tmp_ctx = ctx;
	sm3_update(&ctx, ct1, sizeof(ct1));
	sm3_finish(&ctx, Ha);
	sm3_update(&tmp_ctx, ct2, sizeof(ct2));
	sm3_finish(&tmp_ctx, Ha + 32);
	sm9_fn_from_hash(h2, Ha);
	if (sm9_fn_equ(h2, sig->h) != 1) {
		return 0;
	}

	return 1;
}

int sm9_kem_encrypt(const SM9_ENC_MASTER_KEY *mpk, const char *id, size_t idlen,
	size_t klen, uint8_t *kbuf, uint8_t cbuf[64])
{
	sm9_fn_t r;
	sm9_fp12_t w;
	sm9_point_t C;
	uint8_t wbuf[32 * 12];
	SM3_KDF_CTX kdf_ctx;

	// A1: Q = H1(ID||hid,N) * P1 + Ppube
	sm9_hash1(r, id, idlen, SM9_HID_EXCH);
	sm9_point_mul(&C, r, SM9_P1);
	sm9_point_add(&C, &C, &mpk->Ppube);

	do {
		// A2: rand r in [1, N-1]
		sm9_fn_rand(r);

		// A3: C1 = r * Q
		sm9_point_mul(&C, r, &C);
		sm9_point_to_bytes(&C, cbuf);

		// A4: g = e(Ppube, P2)
		sm9_pairing(w, SM9_P2, &mpk->Ppube);

		// A5: w = g^r
		sm9_fp12_pow(w, w, r);
		sm9_fp12_to_bytes(w, wbuf);

		// A6: K = KDF(C || w || ID_B, klen), if K == 0, goto A2
		sm3_kdf_init(&kdf_ctx, klen);
		sm3_kdf_update(&kdf_ctx, cbuf, 64);
		sm3_kdf_update(&kdf_ctx, wbuf, sizeof(wbuf));
		sm3_kdf_update(&kdf_ctx, (uint8_t *)id, idlen);
		sm3_kdf_finish(&kdf_ctx, kbuf);

	} while (mem_is_zero(kbuf, klen) == 1);

	gmssl_secure_clear(&r, sizeof(r));
	gmssl_secure_clear(&w, sizeof(w));
	gmssl_secure_clear(&C, sizeof(C));
	gmssl_secure_clear(wbuf, sizeof(wbuf));
	gmssl_secure_clear(&kdf_ctx, sizeof(kdf_ctx));

	// A7: output (K, C)
	return 1;
}

int sm9_kem_decrypt(const SM9_ENC_KEY *key, const char *id, size_t idlen, const uint8_t cbuf[64],
	size_t klen, uint8_t *kbuf)
{
	sm9_fp12_t w;
	sm9_point_t C;
	uint8_t wbuf[32 * 12];
	SM3_KDF_CTX kdf_ctx;

	// B1: check C in G1
	if (sm9_point_from_bytes(&C, cbuf) != 1) {
		error_print();
		return -1;
	}

	// B2: w = e(C, de);
	sm9_pairing(w, &key->de, &C);

	// B3: K = KDF(C || w || ID, klen)
	sm3_kdf_init(&kdf_ctx, klen);
	sm3_kdf_update(&kdf_ctx, cbuf, 64);
	sm3_kdf_update(&kdf_ctx, wbuf, sizeof(wbuf));
	sm3_kdf_update(&kdf_ctx, (uint8_t *)id, idlen);
	sm3_kdf_finish(&kdf_ctx, kbuf);

	if (mem_is_zero(kbuf, klen) != 1) {
		error_print();
		return -1;
	}

	gmssl_secure_clear(&w, sizeof(w));
	gmssl_secure_clear(&C, sizeof(C));
	gmssl_secure_clear(wbuf, sizeof(wbuf));
	gmssl_secure_clear(&kdf_ctx, sizeof(kdf_ctx));

	// B4: output K
	return 1;
}

int sm9_do_encrypt(const SM9_ENC_MASTER_KEY *mpk, const char *id, size_t idlen,
	const uint8_t *in, size_t inlen,
	uint8_t C1[64], uint8_t *C2, uint8_t C3[32])
{
	uint8_t K[inlen + 32];

	sm9_kem_encrypt(mpk, id, idlen, sizeof(K), K, C1);
	gmssl_memxor(C2, K, in, inlen);
	sm3_hmac(K + inlen, 32, C2, inlen, C3);

	return 1;
}

int sm9_do_decrypt(const SM9_ENC_KEY *key, const char *id, size_t idlen,
	const uint8_t C1[64], const uint8_t *C2, size_t C2len, const uint8_t C3[32],
	uint8_t *out)
{
	uint8_t K[C2len + 32];
	uint8_t mac[32];

	sm9_kem_decrypt(key, id, idlen, C1, sizeof(K), K);
	sm3_hmac(K + C2len, 32, C2, C2len, mac);
	if (gmssl_secure_memcmp(C3, mac, sizeof(mac)) != 0) {
		error_print();
		return -1;
	}
	gmssl_memxor(out, K, C2, C2len);
	return 1;
}
