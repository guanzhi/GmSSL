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
#include <gmssl/kyber.h>



/*
CRYSTALS-Kyber Algorithm Specifications and Supporing Documentation (version 3.02)


			FIPS-202		90s

	XOF		SHAKE-128		AES256-CTR		MGF1-SM3
	H		SHA3-256		SHA256			SM3
	G		SHA3-512		SHA512			MGF1-SM3
	PRF(s,b)	SHAKE-256(s||b)		AES256-CTR		HKDF-SM3
	KDF		SHAKE-256		SHA256			HKDF-SM3

*/




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

/*
 78 typedef struct {
 79         uint8_t t[KYBER_K][384];
 80         uint8_t rho[32];
 81 } KYBER_CPA_PUBLIC_KEY;
 82 
 83 typedef struct {
 84         // should add public key
 85         uint8_t s[KYBER_K][384];
 86 } KYBER_CPA_PRIVATE_KEY;
*/

int kyber_cpa_public_key_to_bytes(const KYBER_CPA_PUBLIC_KEY *key, uint8_t **out, size_t *outlen)
{
	if (!key || !outlen) {
		error_print();
		return -1;
	}
	if (out && *out) {
		memcpy(*out, key->t, sizeof(key->t));
		*out += sizeof(key->t);
		memcpy(*out, key->rho, sizeof(key->rho));
		*out += sizeof(key->rho);
	}
	*outlen += sizeof(key->t);
	*outlen += sizeof(key->rho);
	return 1;
}

int kyber_cpa_public_key_from_bytes(KYBER_CPA_PUBLIC_KEY *key, const uint8_t **in, size_t *inlen)
{
	if (!key || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen < sizeof(key->t) + sizeof(key->rho)) {
		error_print();
		return -1;
	}
	memset(key, 0, sizeof(*key));
	memcpy(key->t, *in, sizeof(key->t));
	*in += sizeof(key->t);
	*inlen -= sizeof(key->t);
	memcpy(key->rho, *in, sizeof(key->rho));
	*in += sizeof(key->rho);
	*inlen -= sizeof(key->rho);
	return 1;
}

int kyber_cpa_private_key_to_bytes(const KYBER_CPA_PRIVATE_KEY *key, uint8_t **out, size_t *outlen)
{
	if (!key || !outlen) {
		error_print();
		return -1;
	}
	if (kyber_cpa_public_key_to_bytes(&key->public_key, out, outlen) != 1) {
		error_print();
		return -1;
	}
	if (out && *out) {
		memcpy(*out, key->s, sizeof(key->s));
	}
	*outlen += sizeof(key->s);
	return 1;
}

int kyber_cpa_private_key_from_bytes(KYBER_CPA_PRIVATE_KEY *key, const uint8_t **in, size_t *inlen)
{
	if (!key || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	/*
	if (*inlen < sizeof(key->s)) {
		error_print();
		return -1;
	}
	*/
	memset(key, 0, sizeof(*key));
	if (kyber_cpa_public_key_from_bytes(&key->public_key, in, inlen) != 1) {
		error_print();
		return -1;
	}
	memcpy(key->s, *in, sizeof(key->s));
	*in += sizeof(key->s);
	*inlen -= sizeof(key->s);
	return 1;
}

int kyber_cpa_key_generate(KYBER_CPA_PRIVATE_KEY *key)
{
	kyber_cpa_keygen(&key->public_key, key);
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

	// 应该支持这个函数是由确定的值导出的					
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

int kyber_ciphertext_print(FILE *fp, int fmt, int ind, const char *label, const KYBER_CIPHERTEXT *c)
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

	kyber_cpa_public_key_print(fp, fmt, ind, "public_key", &sk->public_key);

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


int kyber_key_generate(KYBER_PRIVATE_KEY *sk)
{
	KYBER_PUBLIC_KEY pk;
	if (kyber_keygen(&pk, sk) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

void kyber_key_cleanup(KYBER_PRIVATE_KEY *key)
{
	gmssl_secure_clear(key, sizeof(*key));
}


int kyber_public_key_to_bytes(const KYBER_PRIVATE_KEY *key, uint8_t **out, size_t *outlen)
{
	return kyber_cpa_public_key_to_bytes(&key->pk, out, outlen);
}

int kyber_public_key_from_bytes(KYBER_PRIVATE_KEY *key, const uint8_t **in, size_t *inlen)
{
	memset(key, 0, sizeof(*key));
	return kyber_cpa_public_key_from_bytes(&key->pk, in, inlen);
}

/*
165 typedef struct {
166         KYBER_CPA_PUBLIC_KEY pk;
167         KYBER_CPA_PRIVATE_KEY sk;
168         uint8_t pk_hash[32];
169         uint8_t z[32];
170 } KYBER_PRIVATE_KEY;
*/

int kyber_private_key_to_bytes(const KYBER_PRIVATE_KEY *key, uint8_t **out, size_t *outlen)
{
	if (!key || !outlen) {
		error_print();
		return -1;
	}
	if (kyber_cpa_public_key_to_bytes(&key->pk, out, outlen) != 1) {
		error_print();
		return -1;
	}
	if (kyber_cpa_private_key_to_bytes(&key->sk, out, outlen) != 1) {
		error_print();
		return -1;
	}
	if (out && *out) {
		memcpy(*out, key->pk_hash, sizeof(key->pk_hash));
		*out += sizeof(key->pk_hash);
		memcpy(*out, key->z, sizeof(key->z));
		*out += sizeof(key->z);
	}
	*outlen += sizeof(key->pk_hash);
	*outlen += sizeof(key->z);
	return 1;
}

int kyber_private_key_from_bytes(KYBER_PRIVATE_KEY *key, const uint8_t **in, size_t *inlen)
{
	if (!key || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen < sizeof(*key)) {
		error_print();
		return -1;
	}
	if (kyber_cpa_public_key_from_bytes(&key->pk, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (kyber_cpa_private_key_from_bytes(&key->sk, in, inlen) != 1) {
		error_print();
		return -1;
	}
	memcpy(key->pk_hash, *in, sizeof(key->pk_hash));
	*in += sizeof(key->pk_hash);
	*inlen -= sizeof(key->pk_hash);
	memcpy(key->z, *in, sizeof(key->z));
	*in += sizeof(key->z);
	*inlen -= sizeof(key->z);

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


int kyber_public_key_print(FILE *fp, int fmt, int ind, const char *label, const KYBER_PRIVATE_KEY *key)
{
	return kyber_cpa_public_key_print(fp, fmt, ind, label, &key->pk);
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

int kyber_cpa_ciphertext_to_bytes(const KYBER_CPA_CIPHERTEXT *ciphertext, uint8_t **out, size_t *outlen)
{
	if (!ciphertext || !outlen) {
		error_print();
		return -1;
	}
	if (out && *out) {
		memcpy(*out, ciphertext->c1, sizeof(ciphertext->c1));
		*out += sizeof(ciphertext->c1);
		memcpy(*out, ciphertext->c2, sizeof(ciphertext->c2));
		*out += sizeof(ciphertext->c2);
	}
	*outlen += sizeof(ciphertext->c1);
	*outlen += sizeof(ciphertext->c2);
	return 1;
}

int kyber_cpa_ciphertext_from_bytes(KYBER_CPA_CIPHERTEXT *ciphertext, const uint8_t **in, size_t *inlen)
{
	if (!ciphertext || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen < sizeof(ciphertext->c1) + sizeof(ciphertext->c2)) {
		error_print();
		return -1;
	}
	memcpy(ciphertext->c1, *in, sizeof(ciphertext->c1));
	*in += sizeof(ciphertext->c1);
	*inlen -= sizeof(ciphertext->c1);
	memcpy(ciphertext->c2, *in, sizeof(ciphertext->c2));
	*in += sizeof(ciphertext->c2);
	*inlen -= sizeof(ciphertext->c2);
	return 1;
}

int kyber_ciphertext_to_bytes(const KYBER_CIPHERTEXT *ciphertext, uint8_t **out, size_t *outlen)
{
	return kyber_cpa_ciphertext_to_bytes(ciphertext, out, outlen);
}

int kyber_ciphertext_from_bytes(KYBER_CIPHERTEXT *ciphertext, const uint8_t **in, size_t *inlen)
{
	return kyber_cpa_ciphertext_from_bytes(ciphertext, in, inlen);
}

