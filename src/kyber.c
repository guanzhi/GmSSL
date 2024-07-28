/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/hex.h>
#include <gmssl/mem.h>
#include <gmssl/rand.h>
#include <gmssl/hkdf.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>


#define KYBER_Q 3329
#define KYBER_ZETA 17
#define KYBER_N 256
#define KYBER_ETA2 2
#define KYBER_POLY_NBYTES (256 * 12 / 8)

#define KYBER512_K		2
#define KYBER768_K		3
#define KYBER1024_K		4

#define KYBER512_ETA1		3
#define KYBER768_ETA1		2
#define KYBER1024_ETA1		2

#define KYBER512_DU	10
#define KYBER768_DU	10
#define KYBER1024_DU	11

#define KYBER512_DV	4
#define KYBER769_DV	4
#define KYBER1024_DV	5

#define KYBER_K		KYBER512_K
#define KYBER_ETA1	KYBER512_ETA1
#define KYBER_DU	KYBER512_DU
#define KYBER_DV	KYBER512_DV


#define KYBER_C1_SIZE	((256 * KYBER_DU)/8)
#define KYBER_C2_SIZE	((256 * KYBER_DV)/8)


#define KYBER_TEST


/*
CRYSTALS-Kyber Algorithm Specifications and Supporing Documentation (version 3.02)


			FIPS-202		90s

	XOF		SHAKE-128		AES256-CTR		MGF1-SM3
	H		SHA3-256		SHA256			SM3
	G		SHA3-512		SHA512			MGF1-SM3
	PRF(s,b)	SHAKE-256(s||b)		AES256-CTR		HKDF-SM3
	KDF		SHAKE-256		SHA256			HKDF-SM3

*/



typedef int16_t kyber_poly_t[256];

typedef struct {
	uint8_t t[KYBER_K][384];
	uint8_t rho[32];
} KYBER_CPA_PUBLIC_KEY;

typedef struct {
	uint8_t s[KYBER_K][384];
} KYBER_CPA_PRIVATE_KEY;

typedef struct {
	uint8_t c1[KYBER_K][KYBER_C1_SIZE];
	uint8_t c2[KYBER_C2_SIZE];
} KYBER_CPA_CIPHERTEXT;


typedef KYBER_CPA_PUBLIC_KEY KYBER_PUBLIC_KEY;

typedef struct {
	KYBER_CPA_PRIVATE_KEY sk;
	KYBER_CPA_PUBLIC_KEY pk;
	uint8_t pk_hash[32];
	uint8_t z[32];
} KYBER_PRIVATE_KEY;

typedef KYBER_CPA_CIPHERTEXT KYBER_CIPHERTEXT;



void kyber_h_hash(const uint8_t *in, size_t inlen, uint8_t out[32])
{
	SM3_CTX ctx;
	sm3_init(&ctx);
	sm3_update(&ctx, in, inlen);
	sm3_finish(&ctx, out);
}

void kyber_g_hash(const uint8_t *in, size_t inlen, uint8_t out[64])
{
	SM3_CTX ctx;
	uint8_t ctr[4] = {0};

	sm3_init(&ctx);
	sm3_update(&ctx, in, inlen);
	sm3_update(&ctx, ctr, 4);
	sm3_finish(&ctx, out);

	ctr[3] = 1;
	sm3_init(&ctx);
	sm3_update(&ctx, in, inlen);
	sm3_update(&ctx, ctr, 4);
	sm3_finish(&ctx, out + 32);
}

// https://www.cryptosys.net/pki/manpki/pki_prfxof.html
static int kyber_prf(const uint8_t seed[32], uint8_t N, size_t outlen, uint8_t *out)
{
	uint8_t salt[1];
	uint8_t key[32];
	size_t len;

	salt[0] = (uint8_t)N;

	if (sm3_hkdf_extract(NULL, 0, seed, 32, key) != 1) {
		error_print();
		return -1;
	}
	sm3_hkdf_expand(key, &N, 1, outlen, out);
	return 1;
}

static int kyber_kdf(const uint8_t in[64], uint8_t out[32])
{
	uint8_t key[32];
	sm3_hkdf_extract(NULL, 0, in, 64, key);
	sm3_hkdf_expand(key, NULL, 0, 32, out);
	gmssl_secure_clear(key, 32);
	return 1;
}

#define KYBER_FMT_POLY	1
#define KYBER_FMT_HEX	2

int kyber_poly_print(FILE *fp, int fmt, int ind, const char *label, const kyber_poly_t a)
{
	int i;
	format_print(fp, fmt, ind, "%s: [", label);
	for (i = 0; i < 256; i++) {
		if (i % 16 == 0) printf("\n");
		fprintf(fp, "%d, ", a[i]);
	}
	fprintf(fp, "]\n");

	return 1;
}

void kyber_poly_set_zero(kyber_poly_t r)
{
	int i;
	for (i = 0; i < 256; i++) {
		r[i] = 0;
	}
}

static void kyber_poly_set_all(kyber_poly_t r, int16_t val)
{
	int i;
	for (i = 0; i < 256; i++) {
		r[i] = val;
	}
}

int kyber_poly_rand(kyber_poly_t r)
{
	int i;

	rand_bytes((uint8_t *)r, sizeof(kyber_poly_t));

	for (i = 0; i < 256; i++) {
		r[i] = (r[i] & 0xfff) % KYBER_Q;
	}
	return 1;
}

int kyber_poly_uniform_sample(kyber_poly_t r, const uint8_t rho[32], uint8_t j, uint8_t i)
{
	SM3_CTX ctx;
	uint8_t seed[32 + 2 + 4];
	uint8_t rand[32 * 3];
	uint32_t counter = 0;
	size_t n;
	int16_t *out = r;
	int16_t *end = r + 256;

	memcpy(seed, rho, 32);
	seed[32] = j;
	seed[33] = i;

	for (;;) {
		for (n = 0; n < sizeof(rand)/32; n++) {
			PUTU32(seed + 34, counter);
			counter++;
			sm3_init(&ctx);
			sm3_update(&ctx, seed, sizeof(seed));
			sm3_finish(&ctx, rand + 32 * n);
		}
		for (n = 0; n < sizeof(rand); n += 3) {
			int16_t a0 = rand[n] | ((int16_t)(rand[n + 1] & 0xf) << 8);
			int16_t a1 = (rand[n + 1] >> 4) | ((int16_t)rand[n + 2] << 4);

			if (a0 < KYBER_Q) {

				*out++ = a0;
				if (out >= end) {
					goto end;
				}
			}
			if (a1 < KYBER_Q) {
				*out++ = a1;
				if (out >= end) {
					goto end;
				}
			}
		}
	}

end:
	return 1;
}

int kyber_poly_cbd_sample(kyber_poly_t r, int eta, const uint8_t secret[32], uint8_t n)
{
	int i;

	if (eta == 2) {
		uint8_t in[128];

		kyber_prf(secret, n, sizeof(in), in);

		for (i = 0; i < 128; i++) {
			uint8_t t = (in[i] & 0x55) + ((in[i] >> 1) & 0x55);
			r[2*i] = (t & 0x3) - ((t >> 2) & 0x3);
			r[2*i + 1] = ((t >> 4) & 0x3) - ((t >> 6) & 0x3);
		}

		gmssl_secure_clear(in, sizeof(in));

	} else if (eta == 3) {
		uint8_t bytes[192];
		uint32_t b24;

		kyber_prf(secret, n, sizeof(bytes), bytes);

		//format_bytes(stderr, 0, 0, "prf_bytes", bytes, 192);

		for (i = 0; i < 64; i++) {
			b24 = bytes[3*i]
				| ((uint32_t)bytes[3*i+1] << 8)
				| ((uint32_t)bytes[3*i+2] << 16);

			b24 = (b24 & 0x249249)
				+ ((b24 >> 1) & 0x249249)
				+ ((b24 >> 2) & 0x249249);

			r[4*i] = (b24 & 0x7) - ((b24 >> 3) & 0x7);
			r[4*i + 1] = ((b24 >> 6) & 0x7) - ((b24 >> 9) & 0x7);
			r[4*i + 2] = ((b24 >> 12) & 0x7) - ((b24 >> 15) & 0x7);
			r[4*i + 3] = ((b24 >> 18) & 0x7) - ((b24 >> 21) & 0x7);
		}

		gmssl_secure_clear(bytes, sizeof(bytes));
	}

	for (i = 0; i < 256; i++) {
		if (r[i] < 0) {
			r[i] += KYBER_Q;
		}
	}
	return 1;
}

int kyber_poly_equ(const kyber_poly_t a, const kyber_poly_t b)
{
	int i;
	for (i = 0; i < 256; i++) {
		if (a[i] != b[i]) {
			return 0;
		}
	}
	return 1;
}

void kyber_poly_add(kyber_poly_t r, const kyber_poly_t a, const kyber_poly_t b)
{
	int i;
	for (i = 0; i < 256; i++) {
		r[i] = (a[i] + b[i]) % 3329;
	}
}

void kyber_poly_sub(kyber_poly_t r, const kyber_poly_t a, const kyber_poly_t b)
{
	int i;
	for (i = 0; i < 256; i++) {
		r[i] = (a[i] + 3329 - b[i]) % 3329;
	}
}

int16_t zeta[256];

void init_zeta(void)
{
	int i;

	zeta[0] = 1;
	for (i = 1; i < sizeof(zeta)/sizeof(zeta[0]); i++) {
		zeta[i] = (zeta[i - 1] * 17) % 3329;
	}
}

static uint8_t br7(uint8_t i)
{
	int j;
	uint8_t r = 0;

	for (j = 0; j < 7; j++) {
		r <<= 1;
		r |= i & 0x1;
		i >>= 1;
	}

	return r;
}

int kyber_poly_ntt(int16_t a[256])
{
	int br_i = 1;
	int n = 128;
	int g;
	int i;

	for (n = 128; n >= 2; n /= 2) {
		int16_t *A = a;
		for (g = 0; g < 256/(2*n); g++) {
			for (i = 0; i < n; i++) {
				int t = (A[n + i] * zeta[br7(br_i)]) % 3329;
				A[n + i] = (A[i] + 3329 - t) % 3329;
				A[i    ] = (A[i]        + t) % 3329;
			}
			br_i++;
			A += 2*n;
		}
	}

	return 1;
}

static int16_t div2(int16_t a)
{
	if (a & 1) {
		return (a + 3329)/2;
	} else {
		return a/2;
	}
}

int kyber_poly_inv_ntt(int16_t a[256])
{
	int br_i = 127;
	int n;
	int g;
	int i;

	for (n = 2; n <= 128; n *= 2) {
		int16_t *A = a;
		for (g = 0; g < 256/(2*n); g++) {

			for (i = 0; i < n; i++) {
				int t0 = (A[i] + A[n + i]) % 3329;
				t0 = div2(t0);

				int t1 = (A[i] + 3329 - A[n + i]) % 3329;

				t1 = (t1 * (3329 - zeta[br7(br_i)])) % 3329;
				t1 = div2(t1);

				A[i] = (int16_t)t0;
				A[n+i]=(int16_t)t1;
			}
			br_i--;
			A += 2*n;
		}
	}

	return 1;
}

// (a0 + a1*X) * (b0 + b1*X) = (a0*b0 + a1*b1*zeta) + (a0*b1 + a1*b0)*X
static void kyber_linear_poly_mul(int16_t r[2], const int16_t a[2], const int16_t b[2], int zeta)
{
	r[0] = (a[0] * b[0] + ((a[1] * b[1])%3329) * zeta) % 3329;
	r[1] = (a[0] * b[1] + a[1] * b[0]) % 3329;
}

int kyber_poly_ntt_mul(kyber_poly_t r, const kyber_poly_t a, const kyber_poly_t b)
{
	int i;

	for (i = 0; i < 64; i++) {
		kyber_linear_poly_mul(r, a, b, zeta[br7(64 + i)]);
		r += 2;
		a += 2;
		b += 2;

		kyber_linear_poly_mul(r, a, b, 3329 - zeta[br7(64 + i)]);
		r += 2;
		a += 2;
		b += 2;
	}

	return 1;
}

void kyber_poly_copy(kyber_poly_t r, const kyber_poly_t a)
{
	int i;
	for (i = 0; i < 256; i++) {
		r[i] = a[i];
	}
}

int kyber_poly_mul(kyber_poly_t r, const kyber_poly_t a, const kyber_poly_t b)
{
	kyber_poly_t ntt_a;
	kyber_poly_t ntt_b;
	kyber_poly_t ntt_r;

	kyber_poly_copy(ntt_a, a);
	kyber_poly_ntt(ntt_a);

	kyber_poly_copy(ntt_b, b);
	kyber_poly_ntt(ntt_b);

	kyber_poly_ntt_mul(ntt_r, ntt_a, ntt_b);

	kyber_poly_inv_ntt(ntt_r);
	kyber_poly_copy(r, ntt_r);
	return 1;
}

void kyber_poly_ntt_mul_scalar(kyber_poly_t r, int scalar, const kyber_poly_t a)
{
	int i;

	scalar %= KYBER_Q;

	for (i = 0; i < 256; i++) {
		r[i] = (scalar * a[i]) % KYBER_Q;
	}
}

int kyber_poly_to_signed(const kyber_poly_t a, kyber_poly_t r)
{
	int i;
	for (i = 0; i < 256; i++) {
		if (a[i] < 0 || a[i] >= KYBER_Q) {
			error_print();
			return -1;
		}
		if (a[i] > (KYBER_Q - 1)/2) {
			r[i] = a[i] - KYBER_Q;
		} else {
			r[i] = a[i];
		}
	}
	return 1;
}

int kyber_poly_from_signed(kyber_poly_t r, const kyber_poly_t a)
{
	int i;

	for (i = 0; i < 256; i++) {
		if (a[i] < -(KYBER_Q - 1)/2 || a[i] > (KYBER_Q - 1)/2) {
			return -1;
		}
		if (a[i] < 0) {
			r[i] = a[i] + KYBER_Q;
		} else {
			r[i] = a[i];
		}
	}
	return 1;
}

int kyber_poly_compress(const kyber_poly_t a, int dbits, kyber_poly_t z)
{
	int i;
	int d = 1 << dbits;

	for (i = 0; i < 256; i++) {
		z[i] = (a[i] * d + (KYBER_Q +1)/2)/KYBER_Q;
		z[i] = z[i] % d;
	}
	return 1;
}

int kyber_poly_decompress(kyber_poly_t r, int dbits, const kyber_poly_t z)
{
	int i;
	int d = 1 << dbits;

	for (i = 0; i < 256; i++) {
		r[i] = (z[i] * KYBER_Q + d/2)/d;
	}

	return 1;
}

int kyber_poly_encode12(const kyber_poly_t a, uint8_t out[384])
{
	const int16_t *in = a;
	int i;

	for (i = 0; i < 256; i++) {
		if (a[i] < 0 || a[i] >= KYBER_Q) {
			error_print();
			return -1;
		}
	}
	for (i = 0; i < 256/2; i++) {
		out[0] = in[0];
		out[1] = (in[1] << 4) | (in[0] >> 8);
		out[2] = in[1] >> 4;
		in += 2;
		out += 3;
	}
	return 1;
}

int kyber_poly_decode12(kyber_poly_t r, const uint8_t in[384])
{
	int16_t *out = r;
	int i;

	for (i = 0; i < 384; i += 3) {



		*out++ = (((int16_t)in[i + 1] & 0xf) << 8) | in[i];
		*out++ = ((int16_t)in[i + 2] << 4) | (in[i + 1] >> 4);
	}
	for (i = 0; i < 256; i++) {
		if (r[i] >= KYBER_Q) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int kyber_poly_encode10(const kyber_poly_t a, uint8_t out[320])
{
	const int16_t *in = a;
	int i;

	for (i = 0; i < 256; i++) {
		if (a[i] < 0 || a[i] >= (1 << 10)) {
			error_print();
			return -1;
		}
	}
	for (i = 0; i < 256/4; i++) {
		out[0] = in[0];
		out[1] = (in[1] << 2) | (in[0] >> 8);
		out[2] = (in[2] << 4) | (in[1] >> 6);
		out[3] = (in[3] << 6) | (in[2] >> 4);
		out[4] = in[3] >> 2;
		in  += 4;
		out += 5;
	}
	return 1;
}

int kyber_poly_decode10(kyber_poly_t r, const uint8_t in[320])
{
	int i;
	int16_t *out = r;

	for (i = 0; i < 256/4; i++) {
		out[0] = (((int16_t)in[1] << 8) | in[0]) & 0x3ff;
		out[1] = (((int16_t)in[2] << 6) | (in[1] >> 2)) & 0x3ff;
		out[2] = (((int16_t)in[3] << 4) | (in[2] >> 4)) & 0x3ff;
		out[3] = ((int16_t)in[4] << 2) | (in[3] >> 6);
		in += 5;
		out += 4;
	}
	return 1;
}

int kyber_poly_encode4(const kyber_poly_t a, uint8_t out[128])
{
	int i;

	for (i = 0; i < 256; i++) {
		if (a[i] < 0 || a[i] >= (1<<4)) {
			error_print();
			return -1;
		}
	}
	for (i = 0; i < 256; i += 2) {
		*out++ = a[i] | (a[i + 1] << 4);
	}
	return 1;
}

void kyber_poly_decode4(kyber_poly_t r, const uint8_t in[128])
{
	int i;

	for (i = 0; i < 128; i++) {
		r[2 * i] = in[i] & 0xf;
		r[2 * i + 1] = in[i] >> 4;
	}
}

void kyber_poly_decode1(kyber_poly_t r, const uint8_t in[32])
{
	int i, j;
	for (i = 0; i < 32; i++) {
		for (j = 0; j < 8; j++) {
			r[8*i + j] = ((in[i] >> j) & 1);
		}
	}
}

int kyber_poly_encode1(const kyber_poly_t a, uint8_t out[32])
{
	int i, j;
	for (i = 0; i < 32; i++) {
		out[i] = 0;
		for (j = 0; j < 8; j++) {
			if (a[8*i + j] >> 1) {
				error_print();
				return -1;
			}
			out[i] |= (a[8*i + j] & 1) << j;
		}
	}
	return 1;
}




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

int kyber_cpa_keygen(KYBER_CPA_PUBLIC_KEY *pk, KYBER_CPA_PRIVATE_KEY *sk)
{
	kyber_poly_t A[KYBER_K][KYBER_K];
	kyber_poly_t s[KYBER_K];
	kyber_poly_t e[KYBER_K];
	kyber_poly_t t[KYBER_K];
	uint8_t d[64];
	uint8_t *rho = d;
	uint8_t *sigma = d + 32;
	uint8_t N = 0;
	int i,j;

	if (rand_bytes(d, 32) != 1) {
		error_print();
		return -1;
	}

	kyber_g_hash(d, 32, d);

	// AHat[i][j] = Parse(XOR(rho, j, i))
	for (i = 0; i < KYBER_K; i++) {
		for (j = 0; j < KYBER_K; j++) {
			kyber_poly_uniform_sample(A[i][j], rho, j, i);
		}
	}

	// s[i] = CBD_eta1(PRF(sigma, N++))
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_cbd_sample(s[i], KYBER_ETA1, sigma, N);
		N++;
	}

	// e[i] = CBD_eta1(PRF(sigma, N++))
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_cbd_sample(e[i], KYBER_ETA1, sigma, N);
		N++;
	}

	// sHat = NTT(s)
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_ntt(s[i]);
	}
	// eHat = NTT(e)
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_ntt(e[i]);
	}

	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_set_zero(t[i]);
	}

	// t = A*s + e
	for (i = 0; i < KYBER_K; i++) {
		for (j = 0; j < KYBER_K; j++) {
			kyber_poly_t tmp;
			kyber_poly_ntt_mul(tmp, A[i][j], s[j]);
			kyber_poly_add(t[i], t[i], tmp);
		}
		kyber_poly_add(t[i], t[i], e[i]);
	}

	// output (pk, sk)
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_encode12(t[i], pk->t[i]);
		kyber_poly_encode12(s[i], sk->s[i]);
	}
	memcpy(pk->rho, rho, 32);

	gmssl_secure_clear(d, sizeof(d));
	gmssl_secure_clear(s, sizeof(s));
	gmssl_secure_clear(e, sizeof(e));

	return 1;
}


/*

	t = A * s + e

	u = A * r + e1
	v = t * r + e2 + M

	v - u * s
	= (t * r + e2 + M) - (A * r + e1) * s
	= (A * s + e)*r + e2 + M - A*r*s - e1*s
	= A*r*s + e*r + e2 + M - A*r*s - e1*s
	= M + e*r + e2 - e1*s

	when A is matrix, s, r is vector:

	(A * s)^T * r == (A^T * r)^T * s == s^T * (A^T * r)

*/


int kyber_cpa_ciphertext_print(FILE *fp, int fmt, int ind, const char *label, const KYBER_CPA_CIPHERTEXT *c)
{
	int i;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	for (i = 0; i < KYBER_K; i++) {
		format_print(fp, fmt, ind, "c1[%d] (Compress10(u[%d]))", i, i);
		format_bytes(fp, fmt, 0, "", c->c1[i], KYBER_C1_SIZE);
	}
	format_bytes(fp, fmt, ind, "c2 (Compress4(v))", c->c2, KYBER_C2_SIZE);
	return 1;
}

int kyber_ciphertext_print(FILE *fp, int fmt, int ind, const char *label, const KYBER_CPA_CIPHERTEXT *c)
{
	return kyber_cpa_ciphertext_print(fp, fmt, ind, label, c);
}

int kyber_cpa_public_key_print(FILE *fp, int fmt, int ind, const char *label, const KYBER_CPA_PUBLIC_KEY *pk)
{
	int i;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	for (i = 0; i < KYBER_K; i++) {
		format_print(fp, fmt, ind, "ntt(t[%d])", i);
		format_bytes(fp, fmt, 0, "", pk->t[i], 384);
	}
	format_bytes(fp, fmt, ind, "rho", pk->rho, 32);
	return 1;
}



int kyber_cpa_private_key_print(FILE *fp, int fmt, int ind, const char *label, const KYBER_CPA_PRIVATE_KEY *sk)
{
	int i;
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	for (i = 0; i < KYBER_K; i++) {
		format_print(fp, fmt, ind, "ntt(s[%d])", i);
		format_bytes(fp, fmt, 0, "", sk->s[i], 384);
	}
	return 1;
}


int kyber_cpa_encrypt(const KYBER_CPA_PUBLIC_KEY *pk, const uint8_t in[32],
	const uint8_t rand[32], KYBER_CPA_CIPHERTEXT *out)
{
	kyber_poly_t A[KYBER_K][KYBER_K];
	kyber_poly_t t[KYBER_K];
	kyber_poly_t r[KYBER_K];
	kyber_poly_t u[KYBER_K];
	kyber_poly_t e1[KYBER_K];
	kyber_poly_t e2;
	kyber_poly_t v;
	kyber_poly_t m;
	int i, j;
	int N = 0;

	// tHat = Decode12(pk)
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_decode12(t[i], pk->t[i]);
	}

	// AHat^T[i][j] = Parse(XOR(rho, i, j))
	for (i = 0; i < KYBER_K; i++) {
		for (j = 0; j < KYBER_K; j++) {
			kyber_poly_uniform_sample(A[i][j], pk->rho, i, j);
		}
	}

	// r[i] = CBD_eta1(PRF(rand, N++))
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_cbd_sample(r[i], KYBER_ETA1, rand, N);
		N++;
	}

	// e1[i] = CBD_eta2(PRF(rand, N++))
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_cbd_sample(e1[i], KYBER_ETA2, rand, N);
		N++;
	}

	// e2 = CBD_eta2(PRF(rand, N))
	kyber_poly_cbd_sample(e2, KYBER_ETA2, rand, N);

	// rHat = NTT(r)
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_ntt(r[i]);
	}

	// u = NTT^-1(A^T * r) + e1
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_set_zero(u[i]);
	}
	for (i = 0; i < KYBER_K; i++) {
		for (j = 0; j < KYBER_K; j++) {
			kyber_poly_t tmp;
			kyber_poly_ntt_mul(tmp, A[i][j], r[j]);
			kyber_poly_add(u[i], u[i], tmp);
		}
		kyber_poly_inv_ntt(u[i]);

		kyber_poly_add(u[i], u[i], e1[i]);
	}

	// v = NTT^-1( t^T * r ) + e2 + round(q/2)*m
	kyber_poly_set_zero(v);
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_t tmp;
		kyber_poly_ntt_mul(tmp, t[i], r[i]);
		kyber_poly_add(v, v, tmp);
	}
	kyber_poly_inv_ntt(v);
	kyber_poly_add(v, v, e2);

	if (0) {
		kyber_poly_t s[KYBER_K];
		kyber_poly_t v_;
		kyber_poly_t tmp;

		for (i = 0; i < KYBER_K; i++) {
			kyber_poly_set_all(s[i], 1);
		}
		kyber_poly_set_zero(v_);

		for (i = 0; i < KYBER_K; i++) {

			kyber_poly_mul(tmp, s[i], u[i]);
			kyber_poly_add(v_, v_, tmp);
		}

		kyber_poly_sub(v_, v_, v);
		kyber_poly_to_signed(v_, v_);
		kyber_poly_print(stderr, 0, 0, "delta", v_);
	}

	kyber_poly_decode1(m, in);
	kyber_poly_decompress(m, 1, m);
	kyber_poly_add(v, v, m);

	// c1 = Encode10(Compress(u, 10))
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_compress(u[i], 10, u[i]);
		kyber_poly_encode10(u[i], out->c1[i]);
	}

	// c2 = Encode4(Compress(v, 4))
	kyber_poly_compress(v, 4, v);
	kyber_poly_encode4(v, out->c2);

	gmssl_secure_clear(m, sizeof(m));
	gmssl_secure_clear(r, sizeof(r));
	gmssl_secure_clear(e1, sizeof(e1));
	gmssl_secure_clear(e2, sizeof(e2));

	return 1;
}

int kyber_cpa_decrypt(const KYBER_CPA_PRIVATE_KEY *sk, const KYBER_CPA_CIPHERTEXT *in, uint8_t out[32])
{
	kyber_poly_t u[KYBER_K];
	kyber_poly_t s[KYBER_K];
	kyber_poly_t v;
	kyber_poly_t m;

	int i;

	// u = Decompress(Decode_du(c1), du)
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_decode10(u[i], in->c1[i]);
		kyber_poly_decompress(u[i], KYBER_DU, u[i]);
	}


	// v = Decompress(Decode_dv(c2), dv)
	kyber_poly_decode4(v, in->c2);
	kyber_poly_decompress(v, 4, v);



	// s = Decode_12(sk)
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_decode12(s[i], sk->s[i]);
	}

	// m = Encode_1(Compress(v - NTT^-1(s^T * NTT(u)), 1))
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_ntt(u[i]);
	}
	kyber_poly_set_zero(m);
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_t tmp;
		kyber_poly_ntt_mul(tmp, s[i], u[i]);
		kyber_poly_add(m, m, tmp);
	}
	kyber_poly_inv_ntt(m);
	kyber_poly_sub(m, v, m);
	kyber_poly_compress(m, 1, m);
	kyber_poly_encode1(m, out);

	gmssl_secure_clear(s, sizeof(s));
	gmssl_secure_clear(m, sizeof(m));

	return 1;
}

int kyber_keygen(KYBER_PUBLIC_KEY *pk, KYBER_PRIVATE_KEY *sk)
{
	if (kyber_cpa_keygen(pk, &sk->sk) != 1) {
		error_print();
		return -1;
	}

	memcpy(&sk->pk, pk, sizeof(KYBER_PUBLIC_KEY));

	kyber_h_hash((uint8_t *)pk, sizeof(KYBER_CPA_PUBLIC_KEY), sk->pk_hash);

	if (rand_bytes(sk->z, 32) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int kyber_private_key_print(FILE *fp, int fmt, int ind, const char *label, const KYBER_PRIVATE_KEY *sk)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	kyber_cpa_private_key_print(fp, fmt, ind, "privateKey", &sk->sk);
	kyber_cpa_public_key_print(fp, fmt, ind, "publicKey", &sk->pk);
	format_bytes(fp, fmt, ind, "publicKeyHash", sk->pk_hash, 32);
	format_bytes(fp, fmt, ind, "z", sk->z, 32);
	return 1;
}




int kyber_public_key_print(FILE *fp, int fmt, int ind, const char *label, const KYBER_PUBLIC_KEY *pk)
{
	return kyber_cpa_public_key_print(fp, fmt, ind, label, pk);
}


int kyber_encap(const KYBER_PUBLIC_KEY *pk, KYBER_CIPHERTEXT *c, uint8_t K[32])
{
	uint8_t m_h[64];
	uint8_t K_r[64];
	uint8_t *m = m_h;
	uint8_t *h = m_h + 32;
	uint8_t *K_ = K_r;
	uint8_t *r = K_r + 32;

	// m = rand(32)
	if (rand_bytes(m, 32) != 1) {
		error_print();
		return -1;
	}

	// m = H(m)
	kyber_h_hash(m, 32, m);

	// h = H(pk)
	kyber_h_hash((const uint8_t *)pk, sizeof(KYBER_PUBLIC_KEY), h);

	// (K_, r) = G(m || H(pk))
	kyber_g_hash(m_h, 64, K_r);

	// c = Kyber.CPA.Enc(pk, m, r)
	if (kyber_cpa_encrypt(pk, m, r, c) != 1) {
		error_print();
		return -1;
	}

	// H(c)
	kyber_h_hash((uint8_t *)c, sizeof(KYBER_CIPHERTEXT), r);

	// K = KDF(K_ || H(c))
	kyber_kdf(K_r, K);

	gmssl_secure_clear(m_h, sizeof(m_h));
	gmssl_secure_clear(K_r, sizeof(K_r));
	return 1;
}

int kyber_decap(const KYBER_PRIVATE_KEY *sk, const KYBER_CIPHERTEXT *c, uint8_t K[32])
{
	uint8_t m_h[64];
	uint8_t K_r[64];
	uint8_t *m = m_h;
	uint8_t *h = m_h + 32;
	uint8_t *K_ = K_r;
	uint8_t *r = K_r + 32;
	KYBER_CIPHERTEXT c_;
	uint8_t c_hash[32];


	// m' = Dec(sk, c)
	if (kyber_cpa_decrypt(&sk->sk, c, m) != 1) {
		error_print();
		return -1;
	}

	// h = H(pk)
	memcpy(h, sk->pk_hash, 32);

	// (K_, r) = G(m || h)
	kyber_g_hash(m_h, 64, K_r);

	// c_ = CPA.Enc(pk, m, r)
	if (kyber_cpa_encrypt(&sk->pk, m, r, &c_) != 1) {
		gmssl_secure_clear(m_h, sizeof(m_h));
		gmssl_secure_clear(K_r, sizeof(K_r));
		error_print();
		return -1;
	}

	// H(c)
	kyber_h_hash((uint8_t *)c, sizeof(KYBER_CIPHERTEXT), r);

	if (memcmp(c, &c_, sizeof(KYBER_CIPHERTEXT)) == 0) {
		// K = KDF(K_||H(c))
		kyber_kdf(K_r, K);
	} else {
		error_print();
		memcpy(K_r, sk->z, 32); // TODO: const time
		kyber_kdf(K_r, K);
	}

	gmssl_secure_clear(m_h, sizeof(m_h));
	gmssl_secure_clear(K_r, sizeof(K_r));
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

	kyber_public_key_print(stderr, 0, 0, "pk", &pk);
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

	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
