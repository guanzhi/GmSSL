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
	int point_form = POINT_CONVERSION_COMPRESSED;
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
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	BN_free(h);
	fp12_cleanup(g);
	return ret;
}

/*
 * check peer's R in E(F_p)
 * e = g2' = g1 = e(peer_R, sk)
 * g3' = g3 = g2'^r = g1^r = er
 * S' = H(0x82 || g1' || H(g2' || g3' || ID_A || ID_B || R_A || R_B))
 * SA = H(0x83 || g1' || H(g2' || g3' || ID_A || ID_B || R_A || R_B))
 * KA = KDF(ID_A || ID_B || R_A || R_B || g1' || g2' || g3')
 *
 * KB = KDF(ID_A || ID_B || R_A || R_B || g1 || g2 || g3)
 * SB = H(0x82 || g1 || Hash(g2 || g3 || ID_A || ID_B || R_A || R_B))
 * SA'= H(0x83 || g1 || Hash(g2 || g3 || ID_A || ID_B || R_A || R_B))
 *
 */
int SM9_compute_share_key(unsigned char *key, size_t keylen,
	unsigned char *peer_mac, size_t *peer_maclen, /* compure with received peer's mac */
	unsigned char *mac, size_t *maclen, int compute_mac, /* send to peer */
	const unsigned char *peer_R, size_t peer_Rlen, /* recv from peer */
	const unsigned char *R, size_t Rlen, /* cached from SM9_generate_key_exchange */
	const BIGNUM *r, /* cached from SM9_generate_key_exchange */
	const char *peer_id, size_t peer_idlen,
	SM9PrivateKey *sk, int initiator)
{
	return 0;
}
