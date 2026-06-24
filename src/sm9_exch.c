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



static int sm9_key_exchange_compute_g(int is_initiator,
	const SM9_EXCH_MASTER_KEY *mpk,
	const SM9_EXCH_KEY *key,
	const sm9_z256_t r,
	const SM9_Z256_POINT *R, const SM9_Z256_POINT *peer_R,
	uint8_t g1[32 * 12], uint8_t g2[32 * 12], uint8_t g3[32 * 12],
	uint8_t ra[65], uint8_t rb[65])
{
	sm9_z256_fp12_t G1, G2, G3;
	const SM9_Z256_POINT *RA;
	const SM9_Z256_POINT *RB;
	const SM9_Z256_POINT *check_R;
	int ret = -1;

	if (!mpk || !key || !r || !R || !peer_R || !g1 || !g2 || !g3 || !ra || !rb) {
		error_print();
		return -1;
	}

	if (is_initiator) {
		RA = R;
		RB = peer_R;
		check_R = RB;
	} else {
		RA = peer_R;
		RB = R;
		check_R = RA;
	}
	if (!sm9_z256_point_is_on_curve(RA) || !sm9_z256_point_is_on_curve(RB)) {
		error_print();
		goto end;
	}

	if (is_initiator) {
		sm9_z256_pairing(G1, sm9_z256_twist_generator(), &mpk->Ppube);
		sm9_z256_fp12_pow(G1, G1, r);
		sm9_z256_pairing(G2, &key->de, check_R);
		sm9_z256_fp12_pow(G3, G2, r);
	} else {
		sm9_z256_pairing(G1, &key->de, check_R);
		sm9_z256_pairing(G2, sm9_z256_twist_generator(), &mpk->Ppube);
		sm9_z256_fp12_pow(G2, G2, r);
		sm9_z256_fp12_pow(G3, G1, r);
	}

	sm9_z256_point_to_uncompressed_octets(RA, ra);
	sm9_z256_point_to_uncompressed_octets(RB, rb);
	sm9_z256_fp12_to_bytes(G1, g1);
	sm9_z256_fp12_to_bytes(G2, g2);
	sm9_z256_fp12_to_bytes(G3, g3);

	ret = 1;

end:
	gmssl_secure_clear(&G1, sizeof(G1));
	gmssl_secure_clear(&G2, sizeof(G2));
	gmssl_secure_clear(&G3, sizeof(G3));
	return ret;
}

int sm9_key_exchange(int is_initiator,
	const SM9_EXCH_MASTER_KEY *mpk,
	const SM9_EXCH_KEY *key, const char *id, size_t idlen,
	const char *peer_id, size_t peer_idlen,
	const sm9_z256_t r,
	const SM9_Z256_POINT *R, const SM9_Z256_POINT *peer_R,
	size_t shared_key_len, uint8_t *shared_key)
{
	uint8_t g1[32 * 12], g2[32 * 12], g3[32 * 12];
	uint8_t ra[65], rb[65];
	const char *idA = is_initiator ? id : peer_id;
	const char *idB = is_initiator ? peer_id : id;
	size_t idAlen = is_initiator ? idlen : peer_idlen;
	size_t idBlen = is_initiator ? peer_idlen : idlen;
	SM3_KDF_CTX kdf_ctx;
	int ret = -1;

	if (!id || !peer_id || !shared_key_len || !shared_key) {
		error_print();
		return -1;
	}
	if (idlen > SM9_MAX_ID_SIZE || peer_idlen > SM9_MAX_ID_SIZE) {
		error_print();
		return -1;
	}
	if (sm9_key_exchange_compute_g(is_initiator, mpk, key,
		r, R, peer_R, g1, g2, g3, ra, rb) != 1) {
		error_print();
		goto end;
	}

	sm3_kdf_init(&kdf_ctx, shared_key_len);
	sm3_kdf_update(&kdf_ctx, (uint8_t *)idA, idAlen);
	sm3_kdf_update(&kdf_ctx, (uint8_t *)idB, idBlen);
	sm3_kdf_update(&kdf_ctx, ra + 1, 64);
	sm3_kdf_update(&kdf_ctx, rb + 1, 64);
	sm3_kdf_update(&kdf_ctx, g1, sizeof(g1));
	sm3_kdf_update(&kdf_ctx, g2, sizeof(g2));
	sm3_kdf_update(&kdf_ctx, g3, sizeof(g3));
	sm3_kdf_finish(&kdf_ctx, shared_key);

	if (mem_is_zero(shared_key, shared_key_len)) {
		error_print();
		goto end;
	}

	ret = 1;

end:
	gmssl_secure_clear(g1, sizeof(g1));
	gmssl_secure_clear(g2, sizeof(g2));
	gmssl_secure_clear(g3, sizeof(g3));
	gmssl_secure_clear(ra, sizeof(ra));
	gmssl_secure_clear(rb, sizeof(rb));
	gmssl_secure_clear(&kdf_ctx, sizeof(kdf_ctx));
	return ret;
}

static int sm9_key_exchange_compute_confirm_ex(int is_initiator,
	const SM9_EXCH_MASTER_KEY *mpk,
	const SM9_EXCH_KEY *key, const char *id, size_t idlen,
	const char *peer_id, size_t peer_idlen,
	const sm9_z256_t r,
	const SM9_Z256_POINT *R, const SM9_Z256_POINT *peer_R,
	int is_initiator_confirm, uint8_t confirm[32])
{
	uint8_t g1[32 * 12], g2[32 * 12], g3[32 * 12];
	uint8_t ra[65], rb[65];
	const char *idA = is_initiator ? id : peer_id;
	const char *idB = is_initiator ? peer_id : id;
	size_t idAlen = is_initiator ? idlen : peer_idlen;
	size_t idBlen = is_initiator ? peer_idlen : idlen;
	uint8_t hash[32];
	uint8_t prefix = is_initiator_confirm ? 0x83 : 0x82;
	SM3_CTX ctx;
	int ret = -1;

	if (!id || !peer_id || !confirm) {
		error_print();
		return -1;
	}
	if (idlen > SM9_MAX_ID_SIZE || peer_idlen > SM9_MAX_ID_SIZE) {
		error_print();
		return -1;
	}
	if (sm9_key_exchange_compute_g(is_initiator, mpk, key,
		r, R, peer_R, g1, g2, g3, ra, rb) != 1) {
		error_print();
		goto end;
	}

	sm3_init(&ctx);
	sm3_update(&ctx, g2, sizeof(g2));
	sm3_update(&ctx, g3, sizeof(g3));
	sm3_update(&ctx, (uint8_t *)idA, idAlen);
	sm3_update(&ctx, (uint8_t *)idB, idBlen);
	sm3_update(&ctx, ra + 1, 64);
	sm3_update(&ctx, rb + 1, 64);
	sm3_finish(&ctx, hash);

	sm3_init(&ctx);
	sm3_update(&ctx, &prefix, sizeof(prefix));
	sm3_update(&ctx, g1, sizeof(g1));
	sm3_update(&ctx, hash, sizeof(hash));
	sm3_finish(&ctx, confirm);

	ret = 1;

end:
	gmssl_secure_clear(g1, sizeof(g1));
	gmssl_secure_clear(g2, sizeof(g2));
	gmssl_secure_clear(g3, sizeof(g3));
	gmssl_secure_clear(ra, sizeof(ra));
	gmssl_secure_clear(rb, sizeof(rb));
	gmssl_secure_clear(hash, sizeof(hash));
	gmssl_secure_clear(&ctx, sizeof(ctx));
	return ret;
}

int sm9_key_exchange_compute_confirm(int is_initiator,
	const SM9_EXCH_MASTER_KEY *mpk,
	const SM9_EXCH_KEY *key, const char *id, size_t idlen,
	const char *peer_id, size_t peer_idlen,
	const sm9_z256_t r,
	const SM9_Z256_POINT *R, const SM9_Z256_POINT *peer_R,
	uint8_t confirm[32])
{
	if (sm9_key_exchange_compute_confirm_ex(is_initiator, mpk, key, id, idlen,
		peer_id, peer_idlen, r, R, peer_R, is_initiator, confirm) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_key_exchange_verify_confirm(int is_initiator,
	const SM9_EXCH_MASTER_KEY *mpk,
	const SM9_EXCH_KEY *key, const char *id, size_t idlen,
	const char *peer_id, size_t peer_idlen,
	const sm9_z256_t r,
	const SM9_Z256_POINT *R, const SM9_Z256_POINT *peer_R,
	const uint8_t confirm[32])
{
	uint8_t expected[32];
	int ret;

	if (!confirm) {
		error_print();
		return -1;
	}
	if (sm9_key_exchange_compute_confirm_ex(is_initiator, mpk, key, id, idlen,
		peer_id, peer_idlen, r, R, peer_R, !is_initiator, expected) != 1) {
		error_print();
		return -1;
	}

	ret = gmssl_secure_memcmp(expected, confirm, sizeof(expected)) == 0 ? 1 : 0;
	gmssl_secure_clear(expected, sizeof(expected));
	return ret;
}

int sm9_exch_step_1A(const SM9_EXCH_MASTER_KEY *mpk, const char *idB, size_t idBlen, SM9_Z256_POINT *RA, sm9_z256_t rA)
{
	// A1: Q = H1(ID_B||hid,N) * P1 + Ppube
	sm9_z256_hash1(rA, idB, idBlen, SM9_HID_EXCH);
	sm9_z256_point_mul(RA, rA, sm9_z256_generator());
	sm9_z256_point_add(RA, RA, &mpk->Ppube);

	// A2: rand rA in [1, N-1]
	if (sm9_z256_rand_range(rA, sm9_z256_order()) != 1) {
		error_print();
		return -1;
	}

	// A3: RA = rA * Q
	sm9_z256_point_mul(RA, rA, RA);

	// A4: Output RA, save rA
	return 1;
}

int sm9_exch_step_1B(const SM9_EXCH_MASTER_KEY *mpk, const char *idA, size_t idAlen, const char *idB, size_t idBlen,
	const SM9_EXCH_KEY *key, const SM9_Z256_POINT *RA, SM9_Z256_POINT *RB, uint8_t *sk, size_t klen)
{
	sm9_z256_t rB;
	sm9_z256_fp12_t G1, G2, G3;
	uint8_t g1[32 * 12], g2[32 * 12], g3[32 * 12];
	uint8_t ta[65], tb[65];
	SM3_KDF_CTX kdf_ctx;

	// B1: Q = H1(ID_A||hid,N) * P1 + Ppube
	sm9_z256_hash1(rB, idA, idAlen, SM9_HID_EXCH);
	sm9_z256_point_mul(RB, rB, sm9_z256_generator());
	sm9_z256_point_add(RB, RB, &mpk->Ppube);

	do {
		// B2: rand rB in [1, N-1]
		do {
			if (sm9_z256_rand_range(rB, sm9_z256_order()) != 1) {
				error_print();
				return -1;
			}
		} while (sm9_z256_is_zero(rB));

		// B3: RB = rB * Q
		sm9_z256_point_mul(RB, rB, RB);

		// B4: check RA on curve; G1 = e(RA, deB), G2 = e(Ppube, P2) ^ rB, G3 = G1 ^ rB
		if (!sm9_z256_point_is_on_curve(RA)) {
			error_print();
			return -1;
		}
		sm9_z256_pairing(G1, &key->de, RA);
		sm9_z256_pairing(G2, sm9_z256_twist_generator(), &mpk->Ppube);
		sm9_z256_fp12_pow(G2, G2, rB);
		sm9_z256_fp12_pow(G3, G1, rB);

		sm9_z256_point_to_uncompressed_octets(RA, ta);
		sm9_z256_point_to_uncompressed_octets(RB, tb);
		sm9_z256_fp12_to_bytes(G1, g1);
		sm9_z256_fp12_to_bytes(G2, g2);
		sm9_z256_fp12_to_bytes(G3, g3);

		// B5: sk = KDF(ID_A || ID_B || RA || RB || g1 || g2 || g3, klen)
		sm3_kdf_init(&kdf_ctx, klen);
		sm3_kdf_update(&kdf_ctx, (uint8_t *)idA, idAlen);
		sm3_kdf_update(&kdf_ctx, (uint8_t *)idB, idBlen);
		sm3_kdf_update(&kdf_ctx, ta + 1, 64);
		sm3_kdf_update(&kdf_ctx, tb + 1, 64);
		sm3_kdf_update(&kdf_ctx, g1, sizeof(g1));
		sm3_kdf_update(&kdf_ctx, g2, sizeof(g2));
		sm3_kdf_update(&kdf_ctx, g3, sizeof(g3));
		sm3_kdf_finish(&kdf_ctx, sk);

	} while (mem_is_zero(sk, klen) == 1);

	// B6: SB = Hash(0x82 || g1 || Hash(g2 || g3 || ID_A || ID_B || RA || RB)) [optional]

	gmssl_secure_clear(&rB, sizeof(rB));
	gmssl_secure_clear(&G1, sizeof(G1));
	gmssl_secure_clear(&G2, sizeof(G2));
	gmssl_secure_clear(&G3, sizeof(G3));
	gmssl_secure_clear(g1, sizeof(g1));
	gmssl_secure_clear(g2, sizeof(g2));
	gmssl_secure_clear(g3, sizeof(g3));
	gmssl_secure_clear(ta, sizeof(ta));
	gmssl_secure_clear(tb, sizeof(tb));
	gmssl_secure_clear(&kdf_ctx, sizeof(kdf_ctx));

	// B7: Output RB
	return 1;
}

int sm9_exch_step_2A(const SM9_EXCH_MASTER_KEY *mpk, const char *idA, size_t idAlen, const char *idB, size_t idBlen,
	const SM9_EXCH_KEY *key, const sm9_z256_t rA, const SM9_Z256_POINT *RA, const SM9_Z256_POINT *RB, uint8_t *sk, size_t klen)
{
	sm9_z256_t r;
	sm9_z256_fp12_t G1, G2, G3;
	uint8_t g1[32 * 12], g2[32 * 12], g3[32 * 12];
	uint8_t ta[65], tb[65];
	SM3_KDF_CTX kdf_ctx;

	do {
		// A5: check RB on curve; G1 = e(Ppube, P2) ^ rA, G2 = e(RB, deA),  G3 = G2 ^ rA
		if (!sm9_z256_point_is_on_curve(RB)) {
			error_print();
			return -1;
		}
		sm9_z256_pairing(G1, sm9_z256_twist_generator(), &mpk->Ppube);
		sm9_z256_fp12_pow(G1, G1, rA);
		sm9_z256_pairing(G2, &key->de, RB);
		sm9_z256_fp12_pow(G3, G2, rA);

		sm9_z256_point_to_uncompressed_octets(RA, ta);
		sm9_z256_point_to_uncompressed_octets(RB, tb);
		sm9_z256_fp12_to_bytes(G1, g1);
		sm9_z256_fp12_to_bytes(G2, g2);
		sm9_z256_fp12_to_bytes(G3, g3);

		// A6: S1 = Hash(0x82 || g1 || Hash(g2 || g3 || ID_A || ID_B || RA || RB)), check S1 = SB [optional]

		// A7: sk = KDF(ID_A || ID_B || RA || RB || g1 || g2 || g3, klen) 
		sm3_kdf_init(&kdf_ctx, klen);
		sm3_kdf_update(&kdf_ctx, (uint8_t *)idA, idAlen);
		sm3_kdf_update(&kdf_ctx, (uint8_t *)idB, idBlen);
		sm3_kdf_update(&kdf_ctx, ta + 1, 64);
		sm3_kdf_update(&kdf_ctx, tb + 1, 64);
		sm3_kdf_update(&kdf_ctx, g1, sizeof(g1));
		sm3_kdf_update(&kdf_ctx, g2, sizeof(g2));
		sm3_kdf_update(&kdf_ctx, g3, sizeof(g3));
		sm3_kdf_finish(&kdf_ctx, sk);

	} while (mem_is_zero(sk, klen) == 1);

	// A8: SA = Hash(0x83 || g1 || Hash(g2 || g3 || ID_A || ID_B || RA || RB)) [optional]

	gmssl_secure_clear(&r, sizeof(r));
	gmssl_secure_clear(&G1, sizeof(G1));
	gmssl_secure_clear(&G2, sizeof(G2));
	gmssl_secure_clear(&G3, sizeof(G3));
	gmssl_secure_clear(g1, sizeof(g1));
	gmssl_secure_clear(g2, sizeof(g2));
	gmssl_secure_clear(g3, sizeof(g3));
	gmssl_secure_clear(ta, sizeof(ta));
	gmssl_secure_clear(tb, sizeof(tb));
	gmssl_secure_clear(&kdf_ctx, sizeof(kdf_ctx));

	return 1;
}

int sm9_exch_step_2B()
{
	// B8: S2 = Hash(0x83 || g1 || Hash(g2 || g3 || ID_A || ID_B || RA || RB)), check S2 = SA [optional]
	return 1;
}
