/* ====================================================================
 * Copyright (c) 2016 - 2018 The GmSSL Project.  All rights reserved.
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
 * ====================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/sm9.h>
#include "sm9_lcl.h"

/*
 * compute Q = H1(peer_id) * P1 + Ppube
 * r = rand(1, n-1)
 * R = r * Q
 * g = e(Ppube, P2)
 * g1' = g2 = g^r
 * send R to peer
 */
int SM9_generate_key_exchange(unsigned char *R, size_t *Rlen,
	BIGNUM *r, unsigned char *gr, size_t *grlen,
	const char *peer_id, size_t peer_idlen,
	SM9PrivateKey *sk, int initiator)
{
	int ret = 0;
	EC_GROUP *group = NULL;
	EC_POINT *Ppube = NULL;
	EC_POINT *Q = NULL;
	BN_CTX *bn_ctx = NULL;
	BIGNUM *h = NULL;
	const EVP_MD *md;
	int point_form = POINT_CONVERSION_UNCOMPRESSED;
	const BIGNUM *p = SM9_get0_prime();
	const BIGNUM *n = SM9_get0_order();
	fp12_t g;
	int len;

	if (!(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
		|| !(Ppube = EC_POINT_new(group))
		|| !(Q = EC_POINT_new(group))
		|| !(bn_ctx = BN_CTX_new())) {
		SM9err(SM9_F_SM9_GENERATE_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);
	if (!fp12_init(g, bn_ctx)) {
		SM9err(SM9_F_SM9_GENERATE_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* r = rand(1, n-1) */
	do {
		if (!BN_rand_range(r, n)) {
			SM9err(SM9_F_SM9_GENERATE_KEY_EXCHANGE, ERR_R_BN_LIB);
			goto end;
		}
	} while (BN_is_zero(r));

	switch (OBJ_obj2nid(sk->hash1)) {
	case NID_sm9hash1_with_sm3:
		md = EVP_sm3();
		break;
	case NID_sm9hash1_with_sha256:
		md = EVP_sha256();
		break;
	default:
		SM9err(SM9_F_SM9_GENERATE_KEY_EXCHANGE, ERR_R_SM9_LIB);
		goto end;
	}

	/* h = H1(peer_id) */
	if (!SM9_hash1(md, &h, peer_id, peer_idlen, SM9_HID_EXCH, n, bn_ctx)) {
		SM9err(SM9_F_SM9_GENERATE_KEY_EXCHANGE, ERR_R_SM9_LIB);
		goto end;
	}

	/* get Ppube from sk */
	if (!EC_POINT_oct2point(group, Ppube, ASN1_STRING_get0_data(sk->pointPpub),
		ASN1_STRING_length(sk->pointPpub), bn_ctx)) {
		SM9err(SM9_F_SM9_GENERATE_KEY_EXCHANGE, ERR_R_SM9_LIB);
		goto end;
	}

	if (!EC_POINT_mul(group, Q, h, NULL, NULL, bn_ctx)
		/* Q = H1(peer_id) * P1 + Ppube */
		|| !EC_POINT_add(group, Q, Q, Ppube, bn_ctx)
		/* R = r * Q */
		|| !EC_POINT_mul(group, Q, NULL, Q, r, bn_ctx)
		|| (len = EC_POINT_point2oct(group, Q, point_form, R, *Rlen, bn_ctx)) <= 0) {
		SM9err(SM9_F_SM9_GENERATE_KEY_EXCHANGE, ERR_R_SM9_LIB);
		goto end;
	}
	*Rlen = len;

	/* g = e(Ppube, P2) */
	if (!rate_pairing(g, NULL, Ppube, bn_ctx)) {
		SM9err(SM9_F_SM9_GENERATE_KEY_EXCHANGE, ERR_R_SM9_LIB);
		goto end;
	}

	/* g1' = g2 = g^r */
	if (!fp12_pow(g, g, r, p, bn_ctx) || !fp12_to_bin(g, gr)) {
		SM9err(SM9_F_SM9_GENERATE_KEY_EXCHANGE, ERR_R_SM9_LIB);
		goto end;
	}

	ret = 1;

end:
	EC_GROUP_free(group);
	EC_POINT_free(Ppube);
	EC_POINT_free(Q);
	BN_free(h);
	fp12_cleanup(g);
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	return ret;
}

int SM9_compute_share_key_A(int type,
	unsigned char *SKA, size_t SKAlen,
	unsigned char SA[32], /* optional, send to B */
	const unsigned char SB[32], /* optional, recv from B */
	const BIGNUM *rA,
	const unsigned char RA[65],
	const unsigned char RB[65],
	const unsigned char g1[384],
	const char *IDB, size_t IDBlen,
	SM9PrivateKey *skA)
{
	int ret = 0;
	const EVP_MD *md = EVP_sm3();
	const char *IDA;
	int IDAlen;
	EC_GROUP *group = NULL;
	EC_POINT *P = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	BN_CTX *bn_ctx = NULL;
	fp12_t g;
	point_t deA;
	const BIGNUM *p = SM9_get0_prime();
	unsigned char x82[1] = {0x82};
	unsigned char x83[1] = {0x83};
	unsigned char buf[384 * 2];
	unsigned char counter[4] = {0, 0, 0, 1};
	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned int dgstlen;

	switch (type) {
	case NID_sm9kdf_with_sm3:
		md = EVP_sm3();
		break;
	case NID_sm9kdf_with_sha256:
		md = EVP_sha256();
		break;
	default:
		goto end;
	}

	/* get IDA */
	IDA = ASN1_STRING_get0_data(skA->identity);
	IDAlen = ASN1_STRING_length(skA->identity);

	/* malloc */
	if (!(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
		|| !(P = EC_POINT_new(group))
		|| !(md_ctx = EVP_MD_CTX_new())
		|| !(bn_ctx = BN_CTX_new())) {
		SM9err(SM9_F_SM9_COMPUTE_SHARE_KEY_A, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);
	if (!point_init(&deA, bn_ctx)
		|| !fp12_init(g, bn_ctx)) {
		SM9err(SM9_F_SM9_COMPUTE_SHARE_KEY_A, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* parse deA */
	if (ASN1_STRING_length(skA->privatePoint) != 129
		|| !point_from_octets(&deA, ASN1_STRING_get0_data(skA->privatePoint), p, bn_ctx)) {
		SM9err(SM9_F_SM9_COMPUTE_SHARE_KEY_A, ERR_R_SM9_LIB);
		goto end;
	}

	/* parse RB */
	if (!EC_POINT_oct2point(group, P, RB, 65, bn_ctx)) {
		SM9err(SM9_F_SM9_COMPUTE_SHARE_KEY_A, ERR_R_SM9_LIB);
		goto end;
	}

	/* g2' = e(RB, deA) */
	if (!rate_pairing(g, &deA, P, bn_ctx) || !fp12_to_bin(g, buf)) {
		SM9err(SM9_F_SM9_COMPUTE_SHARE_KEY_A, ERR_R_SM9_LIB);
		goto end;
	}

	/* g3' = (g2')^r_A */
	if (!fp12_pow(g, g, rA, p, bn_ctx) || !fp12_to_bin(g, buf + 384)) {
		SM9err(SM9_F_SM9_COMPUTE_SHARE_KEY_A, ERR_R_SM9_LIB);
		goto end;
	}

	/* compute optional S1 */
	if (SA) {
		unsigned char S1[32];

		/* dgst =  H(g2 || g3 || ID_A || ID_B || R_A || R_B) */
		if (!EVP_DigestInit_ex(md_ctx, md, NULL)
			|| !EVP_DigestUpdate(md_ctx, buf, sizeof(buf))
			|| !EVP_DigestUpdate(md_ctx, IDA, IDAlen)
			|| !EVP_DigestUpdate(md_ctx, IDB, IDBlen)
			|| !EVP_DigestUpdate(md_ctx, RA + 1, 64)
			|| !EVP_DigestUpdate(md_ctx, RB + 1, 64)
			|| !EVP_DigestFinal_ex(md_ctx, dgst, &dgstlen)) {
			SM9err(SM9_F_SM9_COMPUTE_SHARE_KEY_A, ERR_R_EVP_LIB);
			goto end;
		}

		/* S1 = H(0x82 || g1' || dgst) */
		if (!EVP_DigestInit_ex(md_ctx, md, NULL)
			|| !EVP_DigestUpdate(md_ctx, x82, 1)
			|| !EVP_DigestUpdate(md_ctx, g1, 384)
			|| !EVP_DigestUpdate(md_ctx, dgst, dgstlen)
			|| !EVP_DigestFinal_ex(md_ctx, S1, &dgstlen)) {
			SM9err(SM9_F_SM9_COMPUTE_SHARE_KEY_A, ERR_R_EVP_LIB);
			goto end;
		}

		/* given SB, check if S1 == SB */
		if (SB) {
			if (memcmp(S1, SB, dgstlen) != 0) {
				SM9err(SM9_F_SM9_COMPUTE_SHARE_KEY_A, SM9_R_INVALID_KEY_AGREEMENT_CHECKSUM);
				goto end;
			}
		}
	}

 	/* SKA = KDF(ID_A || ID_B || R_A || R_B || g1 || g2 || g3, Klen) */
	while (SKAlen > 0) {
		unsigned char key[64];
		unsigned int len;

		if (!EVP_DigestInit_ex(md_ctx, md, NULL)
			|| !EVP_DigestUpdate(md_ctx, IDA, IDAlen)
			|| !EVP_DigestUpdate(md_ctx, IDB, IDBlen)
			|| !EVP_DigestUpdate(md_ctx, RA + 1, 64)
			|| !EVP_DigestUpdate(md_ctx, RB + 1, 64)
			|| !EVP_DigestUpdate(md_ctx, g1, 384)
			|| !EVP_DigestUpdate(md_ctx, buf, sizeof(buf))
			|| !EVP_DigestUpdate(md_ctx, counter, 4)
			|| !EVP_DigestFinal_ex(md_ctx, key, &len)) {
			SM9err(SM9_F_SM9_COMPUTE_SHARE_KEY_A, ERR_R_EVP_LIB);
			goto end;
		}

		if (len > SKAlen)
			len = SKAlen;
		memcpy(SKA, key, len);

		SKA += len;
		SKAlen -= len;
		counter[3]++;
	}

	if (SA) {
		/* SA = H(0x83 || g1 || dgst) */
		if (!EVP_DigestInit_ex(md_ctx, md, NULL)
			|| !EVP_DigestUpdate(md_ctx, x83, 1)
			|| !EVP_DigestUpdate(md_ctx, g1, 384)
			|| !EVP_DigestUpdate(md_ctx, dgst, dgstlen)
			|| !EVP_DigestFinal_ex(md_ctx, SA, &dgstlen)) {
			SM9err(SM9_F_SM9_COMPUTE_SHARE_KEY_A, ERR_R_EVP_LIB);
			goto end;
		}
	}

	ret = 1;

end:
	EC_GROUP_free(group);
	EC_POINT_free(P);
	EVP_MD_CTX_free(md_ctx);
	fp12_cleanup(g);
	point_cleanup(&deA);
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	return ret;
}

int SM9_compute_share_key_B(int type,
	unsigned char *SKB, size_t SKBlen,
	unsigned char SB[32], /* optional, send to A */
	unsigned char S2[32], /* optional, to be compared with recved SA */
	const BIGNUM *rB,
	const unsigned char RB[65],
	const unsigned char RA[65],
	const unsigned char g2[384],
	const char *IDA, size_t IDAlen,
	SM9PrivateKey *skB)
{
	int ret = 0;
	const EVP_MD *md = EVP_sm3();
	const char *IDB;
	int IDBlen;
	EC_GROUP *group = NULL;
	EC_POINT *P = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	BN_CTX *bn_ctx = NULL;
	fp12_t g;
	point_t deB;
	const BIGNUM *p = SM9_get0_prime();
	unsigned char x82[1] = {0x82};
	unsigned char x83[1] = {0x83};
	unsigned char g1[384];
	unsigned char g3[384];
	unsigned char counter[4] = {0, 0, 0, 1};
	unsigned char key[EVP_MAX_MD_SIZE];
	unsigned int len;

	switch (type) {
	case NID_sm9kdf_with_sm3:
		md = EVP_sm3();
		break;
	case NID_sm9kdf_with_sha256:
		md = EVP_sha256();
		break;
	default:
		goto end;
	}

	/* get IDB */
	IDB = ASN1_STRING_get0_data(skB->identity);
	IDBlen = ASN1_STRING_length(skB->identity);

	/* malloc */
	if (!(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
		|| !(P = EC_POINT_new(group))
		|| !(md_ctx = EVP_MD_CTX_new())
		|| !(bn_ctx = BN_CTX_new())) {
		SM9err(SM9_F_SM9_COMPUTE_SHARE_KEY_B, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);
	if (!point_init(&deB, bn_ctx)
		|| !fp12_init(g, bn_ctx)) {
		SM9err(SM9_F_SM9_COMPUTE_SHARE_KEY_B, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* parse deB */
	if (ASN1_STRING_length(skB->privatePoint) != 129
		|| !point_from_octets(&deB, ASN1_STRING_get0_data(skB->privatePoint), p, bn_ctx)) {
		SM9err(SM9_F_SM9_COMPUTE_SHARE_KEY_B, ERR_R_SM9_LIB);
		goto end;
	}

	/* parse RA */
	if (!EC_POINT_oct2point(group, P, RA, 65, bn_ctx)) {
		SM9err(SM9_F_SM9_COMPUTE_SHARE_KEY_B, ERR_R_SM9_LIB);
		goto end;
	}

	/* g1 = e(RA, deB) */
	if (!rate_pairing(g, &deB, P, bn_ctx) || !fp12_to_bin(g, g1)) {
		SM9err(SM9_F_SM9_COMPUTE_SHARE_KEY_B, ERR_R_SM9_LIB);
		goto end;
	}

	/* g3 = (g1)^r_B */
	if (!fp12_pow(g, g, rB, p, bn_ctx) || !fp12_to_bin(g, g3)) {
		SM9err(SM9_F_SM9_COMPUTE_SHARE_KEY_B, ERR_R_SM9_LIB);
		goto end;
	}

 	/* SKB = KDF(ID_A || ID_B || R_A || R_B || g1 || g2 || g3, Klen) */
	while (SKBlen > 0) {
		if (!EVP_DigestInit_ex(md_ctx, md, NULL)
			|| !EVP_DigestUpdate(md_ctx, IDA, IDAlen)
			|| !EVP_DigestUpdate(md_ctx, IDB, IDBlen)
			|| !EVP_DigestUpdate(md_ctx, RA + 1, 64)
			|| !EVP_DigestUpdate(md_ctx, RB + 1, 64)
			|| !EVP_DigestUpdate(md_ctx, g1, 384)
			|| !EVP_DigestUpdate(md_ctx, g2, 384)
			|| !EVP_DigestUpdate(md_ctx, g3, 384)
			|| !EVP_DigestUpdate(md_ctx, counter, 4)
			|| !EVP_DigestFinal_ex(md_ctx, key, &len)) {
			SM9err(SM9_F_SM9_COMPUTE_SHARE_KEY_B, ERR_R_EVP_LIB);
			goto end;
		}

		if (len > SKBlen)
			len = SKBlen;
		memcpy(SKB, key, len);

		SKB += len;
		SKBlen -= len;
		counter[3]++;
	}

	/* compute optional S1 */
	if (S2 && SB) {
		/* dgst =  H(g2 || g3 || ID_A || ID_B || R_A || R_B) */
		if (!EVP_DigestInit_ex(md_ctx, md, NULL)
			|| !EVP_DigestUpdate(md_ctx, g2, 384)
			|| !EVP_DigestUpdate(md_ctx, g3, 384)
			|| !EVP_DigestUpdate(md_ctx, IDA, IDAlen)
			|| !EVP_DigestUpdate(md_ctx, IDB, IDBlen)
			|| !EVP_DigestUpdate(md_ctx, RA + 1, 64)
			|| !EVP_DigestUpdate(md_ctx, RB + 1, 64)
			|| !EVP_DigestFinal_ex(md_ctx, key, &len)) {
			SM9err(SM9_F_SM9_COMPUTE_SHARE_KEY_B, ERR_R_EVP_LIB);
			goto end;
		}

		/* SB = H(0x82 || g1 || dgst) */
		if (!EVP_DigestInit_ex(md_ctx, md, NULL)
			|| !EVP_DigestUpdate(md_ctx, x82, 1)
			|| !EVP_DigestUpdate(md_ctx, g1, 384)
			|| !EVP_DigestUpdate(md_ctx, key, len)
			|| !EVP_DigestFinal_ex(md_ctx, SB, &len)) {
			SM9err(SM9_F_SM9_COMPUTE_SHARE_KEY_B, ERR_R_EVP_LIB);
			goto end;
		}

		/* S2 = H(0x83 || g1 || dgst) */
		if (!EVP_DigestInit_ex(md_ctx, md, NULL)
			|| !EVP_DigestUpdate(md_ctx, x83, 1)
			|| !EVP_DigestUpdate(md_ctx, g1, 384)
			|| !EVP_DigestUpdate(md_ctx, key, len)
			|| !EVP_DigestFinal_ex(md_ctx, S2, &len)) {
			SM9err(SM9_F_SM9_COMPUTE_SHARE_KEY_B, ERR_R_EVP_LIB);
			goto end;
		}
	}

	ret = 1;

end:
	EC_GROUP_free(group);
	EC_POINT_free(P);
	EVP_MD_CTX_free(md_ctx);
	fp12_cleanup(g);
	point_cleanup(&deB);
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	OPENSSL_cleanse(key, sizeof(key));
	return ret;
}
