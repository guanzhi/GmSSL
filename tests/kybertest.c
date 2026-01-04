/*
 *  Copyright 2014-2025 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/hex.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/kyber.h>





static int test_kyber_poly_uniform_sample(void)
{
	kyber_poly_t a;
	uint8_t rho[32];

	rand_bytes(rho, sizeof(rho));


	kyber_poly_uniform_sample(a, rho, 0, 0);
	kyber_poly_to_signed(a, a);

	//kyber_poly_print(stderr, 0, 0, "a from uniform sampling", a);

	return 1;
}

static int test_kyber_poly_cbd_sample(void)
{
	kyber_poly_t a;
	uint8_t seed[32];


	rand_bytes(seed, sizeof(seed));
	kyber_poly_cbd_sample(a, 2, seed, 0);
	kyber_poly_to_signed(a, a);
	//kyber_poly_print(stderr, 0, 0, "cbd(eta=2)", a);

	kyber_poly_cbd_sample(a, 3, seed, 0);
	kyber_poly_to_signed(a, a);
	//kyber_poly_print(stderr, 0, 0, "cbd(eta=3)", a);

	return 1;
}

static int test_kyber_poly_to_signed(void)
{
	kyber_poly_t a, b;
	int i;


	if (kyber_poly_rand(a) != 1) {
		error_print();
		return -1;
	}
	if (kyber_poly_to_signed(a, b) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; i < 256; i++) {
		if (b[i] < -(KYBER_Q - 1)/2 || b[i] > (KYBER_Q - 1)/2) {
			error_print();
			return -1;
		}
	}

	if (kyber_poly_from_signed(b, b) != 1) {
		error_print();
		return -1;
	}
	if (kyber_poly_equ(a, b) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_kyber_poly_ntt(void)
{
	kyber_poly_t a, b;
	int i;


	if (kyber_poly_rand(a) != 1) {
		error_print();
		return -1;
	}

	memcpy(b, a, sizeof(kyber_poly_t));
	if (kyber_poly_ntt(b) != 1) {
		error_print();
		return -1;
	}
	if (kyber_poly_inv_ntt(b) != 1) {
		error_print();
		return -1;
	}

	if (kyber_poly_equ(a, b) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

/*
#!/bin/sage

	q = 3329
	n = 256

	R.<x> = PolynomialRing(Integers(q))
	Rq = R.quotient(x^n + 1, 'x')

	# a = 1 + 2*x + 3*x^2 + ... + 256*x^255
	coefficients = list(range(1, n+1))
	a = sum(coeff * x^i for i, coeff in enumerate(coefficients))
	a = Rq(a)

	# b = 256 + 255*x + ... + 1*x^255
	coefficients = list(range(n, 0, -1))
	b = sum(coeff * x^i for i, coeff in enumerate(coefficients))
	b = Rq(b)

	r = a * b

	r = r.lift() # Quotient ring element back to a polynomial
	r = r.coefficients(sparse=False)
	for i in range(0, n, 16):
		print(r[i:i+16])

*/
static int test_kyber_poly_ntt_mul(void)
{
	const kyber_poly_t r = {
		656, 772, 1140, 1758, 2624, 407, 1763, 32, 1870, 617, 2929, 2146, 1595, 1274, 1181, 1314,
		1671, 2250, 3049, 737, 1970, 88, 1747, 287, 2364, 1318, 476, 3165, 2725, 2483, 2437, 2585,
		2925, 126, 844, 1748, 2836, 777, 2227, 526, 2330, 979, 3129, 2120, 1279, 604, 93, 3073,
		2884, 2853, 2978, 3257, 359, 940, 1669, 2544, 234, 1395, 2696, 806, 2381, 761, 2602, 1244,
		14, 2239, 1259, 401, 2992, 2372, 1868, 1478, 1200, 1032, 972, 1018, 1168, 1420, 1772, 2222,
		2768, 79, 811, 1633, 2543, 210, 1290, 2452, 365, 1685, 3081, 1222, 2764, 1047, 2727, 1144,
		2954, 1497, 100, 2090, 807, 2907, 1730, 603, 2853, 1820, 831, 3213, 2306, 1437, 604, 3134,
		2367, 1630, 921, 238, 2908, 2271, 1654, 1055, 472, 3232, 2675, 2128, 1589, 1056, 527, 0,
		2802, 2273, 1740, 1201, 654, 97, 2857, 2274, 1675, 1058, 421, 3091, 2408, 1699, 962, 195,
		2725, 1892, 1023, 116, 2498, 1509, 476, 2726, 1599, 422, 2522, 1239, 3229, 1832, 375, 2185,
		602, 2282, 565, 2107, 248, 1644, 2964, 877, 2039, 3119, 786, 1696, 2518, 3250, 561, 1107,
		1557, 1909, 2161, 2311, 2357, 2297, 2129, 1851, 1461, 957, 337, 2928, 2070, 1090, 3315, 2085,
		727, 2568, 948, 2523, 633, 1934, 3095, 785, 1660, 2389, 2970, 72, 351, 476, 445, 256,
		3236, 2725, 2050, 1209, 200, 2350, 999, 2803, 1102, 2552, 493, 1581, 2485, 3203, 404, 744,
		892, 846, 604, 164, 2853, 2011, 965, 3042, 1582, 3241, 1359, 2592, 280, 1079, 1658, 2015,
		2148, 2055, 1734, 1183, 400, 2712, 1459, 3297, 1566, 2922, 705, 1571, 2189, 2557, 2673, 2535,
	};
	kyber_poly_t a; // [1, 2, 3, ..., 256]
	kyber_poly_t b; // [256, 255, ...,  1]
	kyber_poly_t r_;
	int i;

	for (i = 0; i < 256; i++) {
		a[i] = i + 1;
		b[i] = 256 - i;
	}

	kyber_poly_ntt(a);
	kyber_poly_ntt(b);

	kyber_poly_ntt_mul(r_, a, b);
	kyber_poly_inv_ntt(r_);

	if (kyber_poly_equ(r_, r) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_kyber_poly_add(void)
{
	kyber_poly_t a, b;

	if (kyber_poly_rand(a) != 1) {
		error_print();
		return -1;
	}

	// (a + a) - a =?= a
	kyber_poly_add(b, a, a);
	kyber_poly_sub(b, b, a);
	if (kyber_poly_equ(a, b) != 1) {
		error_print();
		return -1;
	}

	// (a + a) + (a + a) =?= 4*a
	kyber_poly_add(b, a, a);
	kyber_poly_add(b, b, b);
	kyber_poly_ntt_mul_scalar(a, 4, a);

	if (kyber_poly_equ(a, b) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}




static int round_div(int a, int b)
{
	return (a + (b + 1)/2)/b;
}

// a' = Decompress(Compress(a, d), d), check |a - a' mod+- q| <= round(q/2^(d + 1))
static int test_kyber_poly_compress(void)
{
	kyber_poly_t a, b;
	int16_t bound;
	int i;

	if (kyber_poly_rand(a) != 1) {
		error_print();
		return -1;
	}

	// compress(a, 10)
	if (kyber_poly_compress(a, 10, b) != 1) {
		error_print();
		return -1;
	}
	if (kyber_poly_decompress(b, 10, b) != 1) {
		error_print();
		return -1;
	}
	kyber_poly_sub(b, a, b);
	if (kyber_poly_to_signed(b, b) != 1) {
		error_print();
		return -1;
	}
	bound = round_div(KYBER_Q, 1 << (10 + 1));
	//printf("compress(-, 10) bound = %d\n", bound);
	for (i = 0; i < 256; i++) {
		if (b[i] < -bound || b[i] > bound) {
			error_print();
			return -1;
		}
	}

	// compress(a, 4)
	if (kyber_poly_compress(a, 4, b) != 1) {
		error_print();
		return -1;
	}
	if (kyber_poly_decompress(b, 4, b) != 1) {
		error_print();
		return -1;
	}
	kyber_poly_sub(b, a, b);
	if (kyber_poly_to_signed(b, b) != 1) {
		error_print();
		return -1;
	}
	bound = round_div(KYBER_Q, 1 << (4 + 1));
	//printf("compress(-, 4) bound = %d\n", bound);
	for (i = 0; i < 256; i++) {
		if (b[i] < -bound || b[i] > bound) {
			error_print();
			return -1;
		}
	}

	// compress(a, 1)
	if (kyber_poly_compress(a, 1, b) != 1) {
		error_print();
		return -1;
	}
	if (kyber_poly_decompress(b, 1, b) != 1) {
		error_print();
		return -1;
	}
	kyber_poly_sub(b, a, b);
	if (kyber_poly_to_signed(b, b) != 1) {
		error_print();
		return -1;
	}
	bound = round_div(KYBER_Q, 1 << (1 + 1));
	//printf("compress(-, 1) bound = %d\n", bound);
	for (i = 0; i < 256; i++) {
		if (b[i] < -bound || b[i] > bound) {
			// FIXME: might failed				
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_kyber_poly_encode12(void)
{
	kyber_poly_t a;
	kyber_poly_t b;
	uint8_t bytes[384];

	if (kyber_poly_rand(a) != 1) {
		error_print();
		return -1;
	}
	if (kyber_poly_encode12(a, bytes) != 1) {
		error_print();
		return -1;
	}
	if (kyber_poly_decode12(b, bytes) != 1) {
		error_print();
		return -1;
	}
	if (kyber_poly_equ(a, b) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_kyber_poly_encode10(void)
{
	kyber_poly_t a;
	kyber_poly_t b;
	uint8_t bytes[320];

	if (kyber_poly_rand(a) != 1) {
		error_print();
		return -1;
	}
	if (kyber_poly_compress(a, 10, a) != 1) {
		error_print();
		return -1;
	}
	if (kyber_poly_encode10(a, bytes) != 1) {
		error_print();
		return -1;
	}
	kyber_poly_decode10(b, bytes);
	if (kyber_poly_equ(a, b) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_kyber_poly_encode4(void)
{
	kyber_poly_t a;
	kyber_poly_t b;
	uint8_t bytes[128];

	if (kyber_poly_rand(a) != 1) {
		error_print();
		return -1;
	}
	if (kyber_poly_compress(a, 4, a) != 1) {
		error_print();
		return -1;
	}
	if (kyber_poly_encode4(a, bytes) != 1) {
		error_print();
		return -1;
	}
	kyber_poly_decode4(b, bytes);
	if (kyber_poly_equ(a, b) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_kyber_poly_encode1(void)
{
	kyber_poly_t a;
	kyber_poly_t b;
	uint8_t bytes[32];

	if (kyber_poly_rand(a) != 1) {
		error_print();
		return -1;
	}
	if (kyber_poly_compress(a, 1, a) != 1) {
		error_print();
		return -1;
	}
	if (kyber_poly_encode1(a, bytes) != 1) {
		error_print();
		return -1;
	}
	kyber_poly_decode1(b, bytes);
	if (kyber_poly_equ(a, b) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


static int test_kyber_cpa(void)
{
	KYBER_CPA_PUBLIC_KEY pk;
	KYBER_CPA_PRIVATE_KEY sk;
	KYBER_CPA_CIPHERTEXT c;
	uint8_t m[32];
	uint8_t r[32];
	uint8_t m_[32];

	if (rand_bytes(m, 32) != 1) {
		error_print();
		return -1;
	}
	if (rand_bytes(r, 32) != 1) {
		error_print();
		return -1;
	}

	if (kyber_cpa_keygen(&pk, &sk) != 1) {
		error_print();
		return -1;
	}
	kyber_cpa_public_key_print(stderr, 0, 0, "publicKey", &pk);
	kyber_cpa_private_key_print(stderr, 0, 0, "privateKey", &sk);

	if (kyber_cpa_encrypt(&pk, m, r, &c) != 1) {
		error_print();
		return -1;
	}
	kyber_cpa_ciphertext_print(stderr, 0, 0, "ciphertext", &c);

	if (kyber_cpa_decrypt(&sk, &c, m_) != 1) {
		error_print();
		return -1;
	}
	if (memcmp(m_, m, 32) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_kyber_kem(void)
{
	KYBER_PRIVATE_KEY sk;
	KYBER_PUBLIC_KEY pk;
	KYBER_CIPHERTEXT c;
	uint8_t K[32];
	uint8_t K_[32];

	if (kyber_keygen(&pk, &sk) != 1) {
		error_print();
		return -1;
	}

	kyber_public_key_print(stderr, 0, 0, "pk", &sk);
	kyber_private_key_print(stderr, 0, 0, "sk", &sk);

	if (kyber_encap(&pk, &c, K) != 1) {
		error_print();
		return -1;
	}
	kyber_ciphertext_print(stderr, 0, 0, "ciphertext", &c);
	format_bytes(stderr, 0, 0, "KEM_K", K, 32);

	if (kyber_decap(&sk, &c, K_) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 0, "DEC_K", K_, 32);

	if (memcmp(K_, K, 32) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_kyber_cpa_key_to_bytes(void)
{
	KYBER_CPA_PUBLIC_KEY pk;
	KYBER_CPA_PRIVATE_KEY sk;
	uint8_t buf[30000];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	if (kyber_cpa_keygen(&pk, &sk) != 1) {
		error_print();
		return -1;
	}
	if (kyber_cpa_public_key_to_bytes(&pk, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (kyber_cpa_private_key_to_bytes(&sk, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (kyber_cpa_public_key_from_bytes(&pk, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (kyber_cpa_private_key_from_bytes(&sk, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (len) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


static int test_kyber_key_to_bytes(void)
{
	KYBER_PRIVATE_KEY key;
	uint8_t buf[sizeof(KYBER_PRIVATE_KEY) + sizeof(KYBER_PRIVATE_KEY)];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	if (kyber_key_generate(&key) != 1) {
		error_print();
		return -1;
	}
	if (kyber_public_key_to_bytes(&key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (kyber_private_key_to_bytes(&key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (kyber_public_key_from_bytes(&key, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (kyber_private_key_from_bytes(&key, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (len) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


static int test_kyber_cpa_ciphertext_to_bytes(void)
{
	KYBER_CPA_PUBLIC_KEY pk;
	KYBER_CPA_PRIVATE_KEY sk;
	KYBER_CPA_CIPHERTEXT c;
	uint8_t m[32];
	uint8_t r[32];
	uint8_t m_[32];


	uint8_t buf[sizeof(KYBER_CPA_CIPHERTEXT)];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;


	if (rand_bytes(m, 32) != 1) {
		error_print();
		return -1;
	}
	if (rand_bytes(r, 32) != 1) {
		error_print();
		return -1;
	}

	if (kyber_cpa_keygen(&pk, &sk) != 1) {
		error_print();
		return -1;
	}
	if (kyber_cpa_encrypt(&pk, m, r, &c) != 1) {
		error_print();
		return -1;
	}

	if (kyber_cpa_ciphertext_to_bytes(&c, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (kyber_cpa_ciphertext_from_bytes(&c, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (len) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	init_zeta();

	if (test_kyber_poly_uniform_sample() != 1) goto err;
	if (test_kyber_poly_cbd_sample() != 1) goto err;
	if (test_kyber_poly_to_signed() != 1) goto err;
	if (test_kyber_poly_compress() != 1) goto err;
	if (test_kyber_poly_encode12() != 1) goto err;
	if (test_kyber_poly_encode10() != 1) goto err;
	if (test_kyber_poly_encode4() != 1) goto err;
	if (test_kyber_poly_encode1() != 1) goto err;
	if (test_kyber_poly_add() != 1) goto err;
	if (test_kyber_poly_ntt() != 1) goto err;
	if (test_kyber_poly_ntt_mul() != 1) goto err;
	if (test_kyber_cpa() != 1) goto err;
	if (test_kyber_kem() != 1) goto err;
	if (test_kyber_cpa_key_to_bytes() != 1) goto err;
	if (test_kyber_key_to_bytes() != 1) goto err;
	if (test_kyber_cpa_ciphertext_to_bytes() != 1) goto err;

	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}

