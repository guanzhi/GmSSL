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
	return 0;
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

uint8_t br7(uint8_t i)
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

int kyber_poly_uniform_sampling(kyber_poly_t r, const uint8_t rho[32], uint8_t j, uint8_t i)
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

static int test_kyber_poly_uniform_sampling(void)
{
	kyber_poly_t a;
	uint8_t rho[32];

	rand_bytes(rho, sizeof(rho));


	kyber_poly_uniform_sampling(a, rho, 0, 0);
	kyber_poly_to_signed(a, a);

	kyber_poly_print(stderr, 0, 0, "a from uniform sampling", a);

	return 1;
}


void kyber_poly_set_zero(kyber_poly_t r)
{
	int i;
	for (i = 0; i < 256; i++) {
		r[i] = 0;
	}
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


int kyber_poly_cbd_sampling(kyber_poly_t r, int eta, const uint8_t secret[32], uint8_t n)
{
	int i;

	if (eta == 2) {
		uint8_t in[128];

		kyber_prf(secret, n, sizeof(in), in);

		format_bytes(stderr, 0, 0, "prf_in", in, 128);


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

		format_bytes(stderr, 0, 0, "prf_bytes", bytes, 192);

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





static int test_kyber_poly_cbd_sampling(void)
{
	kyber_poly_t a;
	uint8_t seed[32];


	rand_bytes(seed, sizeof(seed));
	kyber_poly_cbd_sampling(a, 2, seed, 0);
	kyber_poly_to_signed(a, a);
	kyber_poly_print(stderr, 0, 0, "cbd(eta=2)", a);

	kyber_poly_cbd_sampling(a, 3, seed, 0);
	kyber_poly_to_signed(a, a);
	kyber_poly_print(stderr, 0, 0, "cbd(eta=3)", a);

	return 1;
}

static int kyber_poly_num_encode_coeffs(int dbits, int *n)
{
	switch (dbits) {
	case 12: *n = 2; break;
	case 11: *n = 8; break;
	case 10: *n = 4; break;
	case  4: *n = 5; break;
	default:
		error_print();
		return -1;
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
	for (i = 0; i < 256; i += 4) {
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

	for (i = 0; i < 256; i += 4) {
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

int kyber_poly_decode4(kyber_poly_t r, const uint8_t in[128])
{
	int i;

	for (i = 0; i < 128; i++) {
		r[2 * i] = in[i] & 0xf;
		r[2 * i + 1] = in[i] >> 4;
	}
	return 1;
}



int kyber_poly_to_bytes(const kyber_poly_t a, uint8_t out[384])
{
	int i;

	for (i = 0; i < 256; i++) {
		if (a[i] < 0 || a[i] >= KYBER_Q) {
			error_print();
			return -1;
		}
	}
	for (i = 0; i < 256; i += 2) {
		*out++ = a[i];
		*out++ = ((a[i + 1] & 0xf) << 4) | (a[i] >> 8);
		*out++ = a[i + 1] >> 4;
	}
	return 1;
}

int kyber_poly_from_bytes(kyber_poly_t r, const uint8_t in[384])
{
	int16_t *out = &r[0];
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

static int test_kyber_poly_to_bytes(void)
{
	kyber_poly_t a;
	kyber_poly_t b;
	uint8_t bytes[384] = {0};

	kyber_poly_rand(a);
	kyber_poly_to_bytes(a, bytes);
	kyber_poly_from_bytes(b, bytes);

	if (kyber_poly_equ(a, b) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

void kyber_poly_from_plaintext(kyber_poly_t r, const uint8_t in[32])
{
	int i, j;
	for (i = 0; i < 32; i++) {
		for (j = 0; j < 8; j++) {
			r[8*i + j] = ((in[i] >> j) & 1);
		}
	}
}

int kyber_poly_to_plaintext(const kyber_poly_t a, uint8_t out[32])
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


int16_t zeta[256];

void init_zeta(void)
{
	int i;

	zeta[0] = 1;
	for (i = 1; i < sizeof(zeta)/sizeof(zeta[0]); i++) {
		zeta[i] = (zeta[i - 1] * 17) % 3329;
	}
}

void eval2(short r[2], const short a[256], int x)
{
	int r0 = 0;
	int r1 = 0;
	int x_pow = 1;
	int i;

	for (i = 0 ; i < 128; i++) {
		r0 = (r0 + a[2*i  ] * x_pow) % 3329;
		r1 = (r1 + a[2*i+1] * x_pow) % 3329;
		x_pow = (x_pow * x) % 3329;
	}

	r[0] = (short)r0;
	r[1] = (short)r1;
}

void ntt(int16_t a[256])
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
}

int16_t div2(int16_t a)
{
	if (a & 1) {
		return (a + 3329)/2;
	} else {
		return a/2;
	}
}

void ntt_inv(int16_t a[256])
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
}

// (a0 + a1*X) * (b0 + b1*X) = (a0*b0 + a1*b1*zeta) + (a0*b1 + a1*b0)*X
void linear_poly_mul(int16_t r[2], const int16_t a[2], const int16_t b[2], int zeta)
{
	r[0] = (a[0] * b[0] + ((a[1] * b[1])%3329) * zeta) % 3329;
	r[1] = (a[0] * b[1] + a[1] * b[0]) % 3329;
}

void kyber_poly_mul(kyber_poly_t r, const kyber_poly_t a, const kyber_poly_t b)
{
	int i;
	for (i = 0; i < 64; i++) {
		linear_poly_mul(r, a, b, zeta[br7(64 + i)]);
		r += 2;
		a += 2;
		b += 2;

		linear_poly_mul(r, a, b, 3329 - zeta[br7(64 + i)]);
		r += 2;
		a += 2;
		b += 2;
	}
}

void kyber_poly_mul_scalar(kyber_poly_t r, int scalar, const kyber_poly_t a)
{
	int i;

	scalar %= KYBER_Q;

	for (i = 0; i < 256; i++) {
		r[i] = (scalar * a[i]) % KYBER_Q;
	}
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

static int test_kyber_poly_compress(void)
{
	kyber_poly_t a, b, z;
	int i;

	kyber_poly_rand(a);
	kyber_poly_compress(a, 10, z);
	kyber_poly_decompress(b, 10, z);

	for (i = 0; i < 256; i++) {
		if (a[i] != b[i]) {
			printf("%d: %d %d\n", i, a[i], b[i]);
		}
	}
	return 1;
}

static int test_kyber_poly_to_plaintext(void)
{
	kyber_poly_t a;
	kyber_poly_t b;
	uint8_t msg[32];
	uint8_t out[32];


	int i;

	for (i = 0; i < 32; i++) {
		msg[i] = i;
	}


	format_bytes(stderr, 0, 0, "msg", msg, 32);

	kyber_poly_from_plaintext(a, msg);
	kyber_poly_print(stderr, 0, 0, "poly", a);

	kyber_poly_decompress(b, 1, a);
	kyber_poly_print(stderr, 0, 0, "poly", a);

	kyber_poly_compress(b, 1, b);
	kyber_poly_print(stderr, 0, 0, "poly", a);

	for (i = 0; i < 256; i++) {
		if (a[i] != b[i]) {
			printf("%d: %d %d\n", i, a[i], b[i]);
			error_print();
		}
	}


	kyber_poly_to_plaintext(a, out);
	format_bytes(stderr, 0, 0, "out", out, 32);

	if (memcmp(out, msg, sizeof(msg)) != 0) {
		error_print();
		return -1;
	}
	return 1;
}

int kyber_cpa_encrypt(const KYBER_CPA_PUBLIC_KEY *pk, const uint8_t in[32],
	const uint8_t rand[32], KYBER_CPA_CIPHERTEXT *out)
{
	int i, j;
	int N = 0;

	kyber_poly_t A[KYBER_K][KYBER_K];

	kyber_poly_t t[KYBER_K];
	kyber_poly_t r[KYBER_K];
	kyber_poly_t u[KYBER_K];
	kyber_poly_t e1[KYBER_K];
	kyber_poly_t e2;
	kyber_poly_t v;
	kyber_poly_t m;

	// tHat = Decode12(pk)
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_from_bytes(t[i], pk->t[i]);
	}

	// AHat^T[i][j] = Parse(XOR(rho, i, j))
	for (i = 0; i < KYBER_K; i++) {
		for (j = 0; j < KYBER_K; j++) {
			kyber_poly_uniform_sampling(A[i][j], pk->rho, i, j);
			//kyber_poly_print(stderr, 0, 0, "A[i][j]", A[i][j]);
		}
	}


	// r[i] = CBD_eta1(PRF(rand, N++))
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_cbd_sampling(r[i], KYBER_ETA1, rand, N);
		kyber_poly_print(stderr, 0, 0, "r[i]", r[i]);
		N++;
	}

	// e1[i] = CBD_eta2(PRF(rand, N++))
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_cbd_sampling(e1[i], KYBER_ETA2, rand, N);
		kyber_poly_print(stderr, 0, 0, "e1[i]", e1[i]);
		N++;
	}

	// e2 = CBD_eta2(PRF(rand, N))
	kyber_poly_cbd_sampling(e2, KYBER_ETA2, rand, N);


	// rHat = NTT(r)
	for (i = 0; i < KYBER_K; i++) {
		ntt(r[i]);
	}


	// u = NTT^-1(A^T * r) + e1
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_set_zero(u[i]);
	}
	for (i = 0; i < KYBER_K; i++) {
		for (j = 0; j < KYBER_K; j++) {
			kyber_poly_t tmp;
			kyber_poly_mul(tmp, A[i][j], r[j]);
			kyber_poly_add(u[i], u[i], tmp);
		}
		ntt_inv(u[i]);

		kyber_poly_add(u[i], u[i], e1[i]);
	}


	// v = NTT^-1( t^T * r ) + e2 + round(q/2)*m

	kyber_poly_set_zero(v);
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_t tmp;
		kyber_poly_mul(tmp, t[i], r[i]);
		kyber_poly_add(v, v, tmp);
	}
	kyber_poly_add(v, v, e2);

	kyber_poly_from_plaintext(m, in);
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
		kyber_poly_from_bytes(s[i], sk->s[i]);
	}

	// m = Encode_1(Compress(v - NTT^-1(s^T * NTT(u)), 1))
	for (i = 0; i < KYBER_K; i++) {
		ntt(u[i]);
	}
	kyber_poly_set_zero(m);
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_t tmp;
		kyber_poly_mul(tmp, s[i], u[i]);
		kyber_poly_add(m, m, tmp);
	}
	ntt_inv(m);
	kyber_poly_sub(m, v, m);
	kyber_poly_compress(m, 1, m);
	kyber_poly_to_plaintext(m, out);


	return 1;
}

int kyber_cpa_keygen(KYBER_CPA_PUBLIC_KEY *pk, KYBER_CPA_PRIVATE_KEY *sk)
{
	kyber_poly_t t[KYBER_K];
	kyber_poly_t A[KYBER_K][KYBER_K];
	kyber_poly_t s[KYBER_K];
	kyber_poly_t e[KYBER_K];

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


	format_bytes(stderr, 0, 0, "rho", rho, 32);
	format_bytes(stderr, 0, 0, "sigma", sigma, 32);


	// AHat[i][j] = Parse(XOR(rho, j, i))
	for (i = 0; i < KYBER_K; i++) {
		for (j = 0; j < KYBER_K; j++) {
			kyber_poly_uniform_sampling(A[i][j], rho, j, i);

			//kyber_poly_print(stderr, 0, 0, "A[i][j]", A[i][j]);
		}
	}

	// s[i] = CBD_eta1(PRF(sigma, N++))
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_cbd_sampling(s[i], KYBER_ETA1, sigma, N);
		kyber_poly_print(stderr, 0, 0, "s[i]", s[i]);
		N++;
	}

	// e[i] = CBD_eta1(PRF(sigma, N++))
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_cbd_sampling(e[i], KYBER_ETA1, sigma, N);
		kyber_poly_print(stderr, 0, 0, "e[i]", e[i]);
		N++;
	}

	// sHat = NTT(s)
	for (i = 0; i < KYBER_K; i++) {
		ntt(s[i]);
		kyber_poly_print(stderr, 0, 0, "s[i]", s[i]);
	}
	// eHat = NTT(e)
	for (i = 0; i < KYBER_K; i++) {
		ntt(e[i]);
		kyber_poly_print(stderr, 0, 0, "e[i]", e[i]);
	}



	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_set_zero(t[i]);
	}

	// t = A*s + e
	for (i = 0; i < KYBER_K; i++) {
		for (j = 0; j < KYBER_K; j++) {
			kyber_poly_t tmp;
			kyber_poly_mul(tmp, A[i][j], s[j]);
			kyber_poly_add(t[i], t[i], tmp);
		}
		kyber_poly_add(t[i], t[i], e[i]);
	}


	// output (pk, sk)
	for (i = 0; i < KYBER_K; i++) {
		kyber_poly_to_bytes(t[i], pk->t[i]);
		kyber_poly_to_bytes(s[i], sk->s[i]);
	}
	memcpy(pk->rho, rho, 32);

	return 1;
}

static int test_kyber_poly_encode4(void)
{
	kyber_poly_t a;
	kyber_poly_t b;
	uint8_t bytes[320];

	kyber_poly_rand(a);
	kyber_poly_print(stderr, 0, 0, "a", a);


	kyber_poly_compress(a, 4, a);
	kyber_poly_print(stderr, 0, 0, "a", a);


	kyber_poly_encode4(a, bytes);

	kyber_poly_decode4(b, bytes);

	if (kyber_poly_equ(a, b) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

static int test_kyber_poly_encode10(void)
{
	kyber_poly_t a;
	kyber_poly_t b;
	uint8_t bytes[320];

	kyber_poly_rand(a);
	kyber_poly_print(stderr, 0, 0, "a", a);


	kyber_poly_compress(a, 10, a);
	kyber_poly_print(stderr, 0, 0, "a", a);


	kyber_poly_encode10(a, bytes);

	kyber_poly_decode10(b, bytes);

	if (kyber_poly_equ(a, b) != 1) {
		error_print();
		return -1;
	}

	return 1;
}


typedef KYBER_CPA_PUBLIC_KEY KYBER_PUBLIC_KEY;

typedef struct {
	KYBER_CPA_PRIVATE_KEY sk;
	KYBER_CPA_PUBLIC_KEY pk;
	uint8_t pk_hash[32];
	uint8_t z[32];
} KYBER_PRIVATE_KEY;

typedef KYBER_CPA_CIPHERTEXT KYBER_CIPHERTEXT;


int kyber_keygen(KYBER_PUBLIC_KEY *pk, KYBER_PRIVATE_KEY *sk)
{

	if (rand_bytes(sk->z, 32) != 1) {
		error_print();
		return -1;
	}
	if (kyber_cpa_keygen(&sk->pk, &sk->sk) != 1) {
		error_print();
		return -1;
	}

	kyber_h_hash((uint8_t *)&sk->pk, sizeof(KYBER_CPA_PUBLIC_KEY), sk->pk_hash);


	return 1;
}

int kyber_encap(const KYBER_PUBLIC_KEY *pk, KYBER_CIPHERTEXT *c, uint8_t K[32])
{
	uint8_t m[64];
	uint8_t K_r[64];
	uint8_t *r = K_r + 32;

	if (rand_bytes(m, 32) != 1) {
		error_print();
		return -1;
	}

	// m = H(rand(32))
	kyber_h_hash(m, 32, m);


	// (K_, r) = G(m || H(pk))
	kyber_h_hash((const uint8_t *)pk, sizeof(KYBER_PUBLIC_KEY), m + 32);
	kyber_g_hash(m, 64, K_r);

	// c = Kyber.CPA.Enc(pk, m, r)
	if (kyber_cpa_encrypt(pk, m, r, c) != 1) {
		error_print();
		return -1;
	}

	// K = KDF(K_ || H(c))
	kyber_h_hash((uint8_t *)c, sizeof(KYBER_CIPHERTEXT), K_r + 32);
	kyber_kdf(K_r, K);

	return 1;
}

int kyber_decap(const KYBER_PRIVATE_KEY *sk, const KYBER_CIPHERTEXT *c, uint8_t K[32])
{
	uint8_t m_h[64];
	uint8_t K_r[64];
	uint8_t *r = K_r + 32;


	KYBER_CIPHERTEXT c_;
	uint8_t c_hash[32];

	if (kyber_cpa_decrypt(&sk->sk, c, m_h) != 1) {
		error_print();
		return -1;
	}

	// (K, r) = G(m || H(pk))
	memcpy(m_h + 32, sk->pk_hash, 32);
	kyber_g_hash(m_h, 64, K_r);

	if (kyber_cpa_encrypt(&sk->pk, m_h, r, &c_) != 1) {
		error_print();
		return -1;
	}

	kyber_h_hash((uint8_t *)c, sizeof(KYBER_CIPHERTEXT), r);

	if (memcmp(c, &c_, sizeof(KYBER_CIPHERTEXT)) == 0) {
		kyber_kdf(K_r, K);
	} else {
		memcpy(K_r, sk->z, 32);
		kyber_kdf(K_r, K);
	}


	return 1;
}

static int test_kyber_cpa_keygen(void)
{
	KYBER_CPA_PUBLIC_KEY pk;
	KYBER_CPA_PRIVATE_KEY sk;
	KYBER_CPA_CIPHERTEXT c;

	uint8_t r[32] = {0};
	uint8_t m[32] = {0};

	kyber_cpa_keygen(&pk, &sk);

	kyber_cpa_encrypt(&pk, m, r, &c);

	return 1;
}

int main(void)
{
	init_zeta();

	if (test_kyber_poly_encode10() != 1) goto err;


	if (test_kyber_cpa_keygen() != 1) goto err;

	if (test_kyber_poly_to_bytes() != 1) goto err;
	if (test_kyber_poly_uniform_sampling() != 1) goto err;
	if (test_kyber_poly_cbd_sampling() != 1) goto err;
	if (test_kyber_poly_compress() != 1) goto err;
	if (test_kyber_poly_to_plaintext() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
