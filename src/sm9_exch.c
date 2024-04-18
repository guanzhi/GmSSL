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
	// Only for testing
	sm9_z256_from_hex(rA, "00005879DD1D51E175946F23B1B41E93BA31C584AE59A426EC1046A4D03B06C8");

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
		// FIXME: check rb != 0			
		if (sm9_z256_rand_range(rB, sm9_z256_order()) != 1) {
			error_print();
			return -1;
		}
		// Only for testing
		sm9_z256_from_hex(rB, "00018B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE");

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


