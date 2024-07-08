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
#include <assert.h>
#include <gmssl/mem.h>
#include <gmssl/hex.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/sha2.h>
#include <gmssl/sm3.h>
#include <gmssl/endian.h>


#define SM3_HSS_MAX_LEVELS 5
#define SM3_LMS_MAX_HEIGHT 25

#define SM3_LMOTS_TYPE	LMOTS_SHA256_N32_W8

# define HASH256_CTX	SHA256_CTX
# define hash256_init	sha256_init
# define hash256_update	sha256_update
# define hash256_finish	sha256_finish

typedef uint8_t hash256_t[32];

enum {
	LMOTS_RESERVED		= 0,
	LMOTS_SHA256_N32_W1	= 1,
	LMOTS_SHA256_N32_W2	= 2,
	LMOTS_SHA256_N32_W4	= 3,
	LMOTS_SHA256_N32_W8	= 4,
	LMOTS_SM3_N32_W1	= 11,
	LMOTS_SM3_N32_W2	= 12,
	LMOTS_SM3_N32_W4	= 13,
	LMOTS_SM3_N32_W8	= 14,
};

char *sm3_lmots_type_name(int lmots_type)
{
	switch (lmots_type) {
	case LMOTS_RESERVED:
		return "LMOTS_RESERVED";
	case LMOTS_SHA256_N32_W1:
		return "LMOTS_SHA256_N32_W1";
	case LMOTS_SHA256_N32_W2:
		return "LMOTS_SHA256_N32_W2";
	case LMOTS_SHA256_N32_W4:
		return "LMOTS_SHA256_N32_W4";
	case LMOTS_SHA256_N32_W8:
		return "LMOTS_SHA256_N32_W8";
	case LMOTS_SM3_N32_W1:
		return "LMOTS_SM3_N32_W1";
	case LMOTS_SM3_N32_W2:
		return "LMOTS_SM3_N32_W2";
	case LMOTS_SM3_N32_W4:
		return "LMOTS_SM3_N32_W4";
	case LMOTS_SM3_N32_W8:
		return "LMOTS_SM3_N32_W8";
	}
	return NULL;
}

enum {
	LMS_SM3_M32_H5		= 5,
	LMS_SM3_M32_H10		= 6,
	LMS_SM3_M32_H15		= 7,
	LMS_SM3_M32_H20		= 8,
	LMS_SM3_M32_H25		= 9,
	/*
	LMS_SHA256_M32_H5	= 5,
	LMS_SHA256_M32_H10	= 6,
	LMS_SHA256_M32_H15	= 7,
	LMS_SHA256_M32_H20	= 8,
	LMS_SHA256_M32_H25	= 9,
	*/
};


static const uint8_t D_PBLC[2] = { 0x80, 0x80 };
static const uint8_t D_MESG[2] = { 0x81, 0x81 };
static const uint8_t D_LEAF[2] = { 0x82, 0x82 };
static const uint8_t D_INTR[2] = { 0x83, 0x83 };



// TODO: SM3/SHA256 lms_types has same number!
char *sm3_lms_type_name(int lms_type)
{
	switch (lms_type) {
	case LMS_SM3_M32_H5:
		return "LMS_SM3_M32_H5";
	case LMS_SM3_M32_H10:
		return "LMS_SM3_M32_H10";
	case LMS_SM3_M32_H15:
		return "LMS_SM3_M32_H15";
	case LMS_SM3_M32_H20:
		return "LMS_SM3_M32_H20";
	case LMS_SM3_M32_H25:
		return "LMS_SM3_M32_H25";
	}
	return NULL;
}

int sm3_lms_type_to_height(int type, int *h)
{
	switch (type) {
	case LMS_SM3_M32_H5:
		*h = 5;
		break;
	case LMS_SM3_M32_H10:
		*h = 10;
		break;
	case LMS_SM3_M32_H15:
		*h = 15;
		break;
	case LMS_SM3_M32_H20:
		*h = 20;
		break;
	case LMS_SM3_M32_H25:
		*h = 25;
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}


void sm3_lmots_derive_secrets(const hash256_t seed, const uint8_t I[16], int q, hash256_t x[34])
{
	HASH256_CTX ctx;
	uint8_t qbytes[4];
	uint8_t ibytes[2];
	const uint8_t jbytes[1] = { 0xff };
	int i;

	PUTU32(qbytes, q);

	// x[i] = SM3(I||u32str(q)||u16str(i)||u8str(0xFF)||SEED)
	for (i = 0; i < 34; i++) {
		PUTU16(ibytes, i);

		hash256_init(&ctx);
		hash256_update(&ctx, I, 16);
		hash256_update(&ctx, qbytes, 4);
		hash256_update(&ctx, ibytes, 2);
		hash256_update(&ctx, jbytes, 1);
		hash256_update(&ctx, seed, 32);
		hash256_finish(&ctx, x[i]);
	}

	gmssl_secure_clear(&ctx, sizeof(ctx));
}

void sm3_lmots_secrets_to_public_hash(const uint8_t I[16], int q, const hash256_t x[34], hash256_t pub)
{
	HASH256_CTX ctx;
	uint8_t qbytes[4];
	uint8_t ibytes[2];
	uint8_t jbytes[1];
	hash256_t z[34];
	int i, j;

	PUTU32(qbytes, q);

	for (i = 0; i < 34; i++) {
		PUTU16(ibytes, i);
		memcpy(z[i], x[i], 32);

		for (j = 0; j < 255; j++) {
			jbytes[0] = (uint8_t)j;

			hash256_init(&ctx);
			hash256_update(&ctx, I, 16);
			hash256_update(&ctx, qbytes, 4);
			hash256_update(&ctx, ibytes, 2);
			hash256_update(&ctx, jbytes, 1);
			hash256_update(&ctx, z[i], 32);
			hash256_finish(&ctx, z[i]);
		}
	}

	// K = H(I || u32str(q) || u16str(D_PBLC) || y[0] || ... || y[p-1])
	hash256_init(&ctx);
	hash256_update(&ctx, I, 16);
	hash256_update(&ctx, qbytes, 4);
	hash256_update(&ctx, D_PBLC, 2);
	for (i = 0; i < 34; i++) {
		hash256_update(&ctx, z[i], 32);
	}
	hash256_finish(&ctx, pub);
}

static void winternitz_checksum(const hash256_t dgst, uint8_t checksum[2])
{
	uint16_t sum = 0;
	int i;

	for (i = 0; i < 32; i++) {
		sum += 255 - dgst[i];
	}

	PUTU16(checksum, sum);
}

void sm3_lmots_compute_signature(const uint8_t I[16], int q, const hash256_t dgst, const hash256_t x[34], hash256_t y[34])
{
	HASH256_CTX ctx;
	uint8_t checksum[2];
	uint8_t qbytes[4];
	uint8_t ibytes[2];
	uint8_t jbytes[1];
	int i, j, a;

	winternitz_checksum(dgst, checksum);

	PUTU32(qbytes, q);

	for (i = 0; i < 34; i++) {
		PUTU16(ibytes, i);
		memcpy(y[i], x[i], 32);

		a =  (i < 32) ? dgst[i] : checksum[i - 32];

		for (j = 0; j < a; j++) {
			jbytes[0] = j;

			hash256_init(&ctx);
			hash256_update(&ctx, I, 16);
			hash256_update(&ctx, qbytes, 4);
			hash256_update(&ctx, ibytes, 2);
			hash256_update(&ctx, jbytes, 1);
			hash256_update(&ctx, y[i], 32);
			hash256_finish(&ctx, y[i]);
		}
	}
}

void sm3_lmots_signature_to_public_hash(const uint8_t I[16], int q, const hash256_t y[34], const hash256_t dgst, hash256_t pub)
{
	uint8_t checksum[2];
	HASH256_CTX ctx;
	hash256_t z[34];
	uint8_t qbytes[4];
	uint8_t ibytes[2];
	uint8_t jbytes[1];
	int i, j, a;

	PUTU32(qbytes, q);

	winternitz_checksum(dgst, checksum);

	for (i = 0; i < 34; i++) {
		PUTU16(ibytes, i);
		memcpy(z[i], y[i], 32);

		a =  (i < 32) ? dgst[i] : checksum[i - 32];

		for (j = a; j < 255; j++) {
			jbytes[0] = (uint8_t)j;

			hash256_init(&ctx);
			hash256_update(&ctx, I, 16);
			hash256_update(&ctx, qbytes, 4);
			hash256_update(&ctx, ibytes, 2);
			hash256_update(&ctx, jbytes, 1);
			hash256_update(&ctx, z[i], 32);
			hash256_finish(&ctx, z[i]);
		}
	}

	// Kc = H(I || u32str(q) || u16str(D_PBLC) || z[0] || z[1] || ... || z[p-1])
	hash256_init(&ctx);
	hash256_update(&ctx, I, 16);
	hash256_update(&ctx, qbytes, 4);
	hash256_update(&ctx, D_PBLC, 2);
	for (i = 0; i < 34; i++) {
		hash256_update(&ctx, z[i], 32);
	}
	hash256_finish(&ctx, pub);
}

static int test_sm3_lmots(void)
{
	hash256_t seed = {0}; // TODO: change to test vector
	uint8_t I[16] = {0};
	int q = 0;
	hash256_t dgst = {0};
	hash256_t x[34];
	hash256_t y[34];
	hash256_t pub;
	hash256_t pub2;

	sm3_lmots_derive_secrets(seed, I, q, x); // TODO: compare results with test vector
	sm3_lmots_secrets_to_public_hash(I, q, x, pub); // TODO: compare results with test vector

	sm3_lmots_compute_signature(I, q, dgst, x, y); // TODO: compare results with test vector
	sm3_lmots_signature_to_public_hash(I, q, y, dgst, pub2);

	if (memcmp(pub, pub2, 32) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

// derive full merkle tree[2^h * 2 - 1] from seed, tree[0] is the root
void sm3_lms_derive_merkle_tree(const uint8_t seed[32], const uint8_t I[16], int h, hash256_t *tree)
{
	int r, n = (1 << h);
	uint8_t rbytes[4];
	HASH256_CTX ctx;
	hash256_t x[34];
	hash256_t pub;
	hash256_t *T = tree - 1;

	for (r = 2*n - 1; r >= 1; r--) {

		PUTU32(rbytes, r);

		if (r >= n) {
			int q = r - n;
			sm3_lmots_derive_secrets(seed, I, q, x);
			sm3_lmots_secrets_to_public_hash(I, q, x, pub);

			// H(I||u32str(r)||u16str(D_LEAF)||OTS_PUB_HASH[r-2^h])
			hash256_init(&ctx);
			hash256_update(&ctx, I, 16);
			hash256_update(&ctx, rbytes, 4);
			hash256_update(&ctx, D_LEAF, 2);
			hash256_update(&ctx, pub, 32);
			hash256_finish(&ctx, T[r]);

		} else {
			// H(I||u32str(r)||u16str(D_INTR)||T[2*r]||T[2*r+1])
			hash256_init(&ctx);
			hash256_update(&ctx, I, 16);
			hash256_update(&ctx, rbytes, 4);
			hash256_update(&ctx, D_INTR, 2);
			hash256_update(&ctx, T[2*r], 32);
			hash256_update(&ctx, T[2*r + 1], 32);
			hash256_finish(&ctx, T[r]);
		}
	}
}

void sm3_lms_derive_merkle_root(const hash256_t seed, const uint8_t I[16], int h, hash256_t root)
{
	int q, r, n = 1 << h;
	int qbits;
	HASH256_CTX ctx;
	hash256_t stack[25];
	int num = 0;
	hash256_t x[34];
	uint8_t rbytes[4];

	for (q = 0; q < n; q++) {

		sm3_lmots_derive_secrets(seed, I, q, x);
		sm3_lmots_secrets_to_public_hash(I, q, x, stack[num]);

		r = q + n;
		PUTU32(rbytes, r);

		// H(I||u32str(r)||u16str(D_LEAF)||OTS_PUB_HASH[r-2^h])
		hash256_init(&ctx);
		hash256_update(&ctx, I, 16);
		hash256_update(&ctx, rbytes, 4);
		hash256_update(&ctx, D_LEAF, 2);
		hash256_update(&ctx, stack[num], 32);
		hash256_finish(&ctx, stack[num]);

		num++;
		qbits = q;

		while (qbits & 0x1) {

			r = r/2;
			PUTU32(rbytes, r);

			hash256_init(&ctx);
			hash256_update(&ctx, I, 16);
			hash256_update(&ctx, rbytes, 4);
			hash256_update(&ctx, D_INTR, 2);
			hash256_update(&ctx, stack[num - 2], 32);
			hash256_update(&ctx, stack[num - 1], 32);
			hash256_finish(&ctx, stack[num - 2]);

			num--;
			qbits >>= 1;
		}

	}
	memcpy(root, stack[0], 32);
}

static int test_sm3_lms_derive_merkle_root(void)
{
	hash256_t seed = {0}; // TODO: change to test vector
	uint8_t I[16] = {0};
	int h = 5;
	int n = 1<<h;
	hash256_t *tree = NULL;
	hash256_t root;

	if (!(tree = (hash256_t *)malloc(sizeof(hash256_t)*(2*n - 1)))) {
		error_print();
		return -1;
	}

	sm3_lms_derive_merkle_tree(seed, I, h, tree);
	sm3_lms_derive_merkle_root(seed, I, h, root);

	if (memcmp(tree[0], root, 32) != 0) {
		free(tree);
		error_print();
		return -1;
	}
	free(tree);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


typedef struct {
	uint8_t lms_type[4];
	uint8_t lmots_type[4];
	uint8_t I[16];
	hash256_t root;
} SM3_LMS_PUBLIC_KEY;


typedef struct {
	SM3_LMS_PUBLIC_KEY public_key;
	hash256_t *tree;
	hash256_t seed;
	int q;
} SM3_LMS_KEY;

#define SM3_LMS_PUBLIC_KEY_SIZE sizeof(SM3_LMS_PUBLIC_KEY)



int sm3_lms_public_key_print(FILE *fp, int fmt, int ind, const char *label, const SM3_LMS_PUBLIC_KEY *pub)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	format_print(fp, fmt, ind, "lms_type: %s\n", sm3_lms_type_name(GETU32(pub->lms_type)));
	format_print(fp, fmt, ind, "lmots_type: %s\n", sm3_lmots_type_name(GETU32(pub->lmots_type)));
	format_bytes(fp, fmt, ind, "I", pub->I, 16);
	format_bytes(fp, fmt, ind, "root", pub->root, 32);
	return 1;
}

int sm3_lms_key_print(FILE *fp, int fmt, int ind, const char *label, const SM3_LMS_KEY *key)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	sm3_lms_public_key_print(fp, fmt, ind, "PublicKey", &key->public_key);
	format_bytes(fp, fmt, ind, "seed", key->seed, 32);
	format_print(fp, fmt, ind, "q = %d\n", key->q);
	if (key->tree && fmt) {
		int i;
		format_print(fp, fmt, ind, "tree\n");
		for (i = 0; i < 63; i++) {

			format_print(fp, fmt, ind + 4, "%d", i);
			format_bytes(fp, fmt, 0, "", key->tree[i], 32);
		}
	}
	return 1;
}

int sm3_lms_public_key_from_bytes_ex(const SM3_LMS_PUBLIC_KEY **key, const uint8_t **in, size_t *inlen)
{
	int lms_type;
	int lmots_type;
	int h;

	if (*inlen < sizeof(SM3_LMS_PUBLIC_KEY)) {
		error_print();
		return -1;
	}

	lms_type = GETU32(*in);
	if (sm3_lms_type_to_height(lms_type, &h) != 1) {
		error_print();
		return -1;
	}

	lmots_type = GETU32((*in) + 4);
	if (lmots_type != SM3_LMOTS_TYPE) {
		error_print();
		return -1;
	}

	(*key) = (const SM3_LMS_PUBLIC_KEY *)(*in);
	(*in) += SM3_LMS_PUBLIC_KEY_SIZE;
	(*inlen) -= SM3_LMS_PUBLIC_KEY_SIZE;
	return 1;
}

void sm3_lms_key_cleanup(SM3_LMS_KEY *key)
{
	if (key) {
		gmssl_secure_clear(key->seed, 32);
		if (key->tree) {
			free(key->tree);
			key->tree = NULL;
		}
		memset(key, 0, sizeof(SM3_LMS_KEY));
	}
}

int sm3_lms_key_generate_ex(SM3_LMS_KEY *key, int lms_type, const uint8_t seed[32], const uint8_t I[16], int cache_tree)
{
	int h, n;

	if (sm3_lms_type_to_height(lms_type, &h) != 1) {
		error_print();
		return -1;
	}
	n = 1 << h;

	PUTU32(key->public_key.lms_type, lms_type);
	PUTU32(key->public_key.lmots_type, SM3_LMOTS_TYPE);

	if (I) {
		memcpy(key->public_key.I, I, 16);
	} else {
		if (rand_bytes(key->public_key.I, 16) != 1) {
			error_print();
			return -1;
		}
	}

	if (seed) {
		memcpy(key->seed, seed, 32);
	} else {
		if (rand_bytes(key->seed, 32) != 1) {
			error_print();
			return -1;
		}
	}

	if (cache_tree) {
		if (!(key->tree = (hash256_t *)malloc(sizeof(hash256_t) * (2*n - 1)))) {
			error_print();
			return -1;
		}
		sm3_lms_derive_merkle_tree(key->seed, key->public_key.I, h, key->tree);
		memcpy(key->public_key.root, key->tree[0], 32);
	} else {
		key->tree = NULL;
		sm3_lms_derive_merkle_root(key->seed, key->public_key.I, h, key->public_key.root);
	}

	key->q = 0;
	return 1;
}

int sm3_lms_key_generate(SM3_LMS_KEY *key, int lms_type)
{
	if (sm3_lms_key_generate_ex(key, lms_type, NULL, NULL, 1) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int test_sm3_lms_key_generate(void)
{
	SM3_LMS_KEY lms_key;
	int lms_type = LMS_SM3_M32_H5;

	if (sm3_lms_key_generate(&lms_key, lms_type) != 1) {
		error_print();
		return -1;
	}
	//sm3_lms_key_print(stdout, 0, 0, "lms_key", &lms_key);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

// lmots_signature = u32str(type) || C || y[0] || ... || y[p-1]

// lms_signature = u32str(q) || lmots_signature || u32str(type) ||
//			path[0] || path[1] || path[2] || ... || path[h-1]

typedef struct {
	uint8_t lms_type[4]; // FIXME: move lms_type before path
	uint8_t q[4];
	struct {
		uint8_t lmots_type[4];
		hash256_t y[34];
		hash256_t C;
	} lmots_sig;
	hash256_t path[25];
} SM3_LMS_SIGNATURE;


static size_t sm3_lms_signature_size(int tree_height)
{
	return 4 * 3 + 32*34 + 32 + 32*tree_height;
}


int sm3_lms_signature_print(FILE *fp, int fmt, int ind, const char *label, const SM3_LMS_SIGNATURE *sig)
{
	int lms_type;
	int h;
	int i;

	lms_type = GETU32(sig->lms_type);
	if (sm3_lms_type_to_height(lms_type, &h) != 1) {
		error_print();
		return -1;
	}

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	format_print(fp, fmt, ind, "lms_type: %s\n", sm3_lms_type_name(GETU32(sig->lms_type)));
	format_print(fp, fmt, ind, "q: %d\n", GETU32(sig->q));
	format_print(fp, fmt, ind, "lmots_type: %s\n", sm3_lmots_type_name(GETU32(sig->lmots_sig.lmots_type)));
	format_print(fp, fmt, ind, "lmots_sig.y\n");
	for (i = 0; i < 34; i++) {
		format_print(fp, fmt, ind + 4, "%d", i);
		format_bytes(fp, fmt, 0, "", sig->lmots_sig.y[i], 32);
	}
	format_bytes(fp, fmt, ind, "lmots_sig.C", sig->lmots_sig.C, 32);
	format_print(fp, fmt, ind, "path\n");
	for (i = 0; i < h; i++) {
		format_bytes(fp, fmt, ind + 4, "", sig->path[i], 32);
	}
	return 1;
}

int sm3_lms_signature_to_bytes(const SM3_LMS_SIGNATURE *sig, uint8_t *out, size_t *outlen)
{
	int h;
	if (sm3_lms_type_to_height(GETU32(sig->lms_type), &h) != 1) {
		error_print();
		return -1;
	}
	*outlen = sm3_lms_signature_size(h);
	memcpy(out, sig, *outlen);
	return 1;
}

int sm3_lms_signature_from_bytes_ex(const SM3_LMS_SIGNATURE **sig, size_t *siglen, const uint8_t **in, size_t *inlen)
{
	int lms_type;
	int h;

	if (*inlen < 4) {
		error_print();
		return -1;
	}

	lms_type = GETU32(*in);
	if (sm3_lms_type_to_height(lms_type, &h) != 1) {
		error_print();
		return -1;
	}

	*sig = (const SM3_LMS_SIGNATURE *)(*in);
	*siglen = sm3_lms_signature_size(h);

	if (*inlen < *siglen) {
		error_print();
		return -1;
	}

	(*in) += *siglen;
	(*inlen) -= *siglen;
	return 1;
}

int sm3_lms_signature_from_bytes(SM3_LMS_SIGNATURE *sig, const uint8_t *in, size_t inlen)
{
	const SM3_LMS_SIGNATURE *ptr;
	size_t siglen;

	if (sm3_lms_signature_from_bytes_ex(&ptr, &siglen, &in, &inlen) != 1) {
		error_print();
		return -1;
	}
	if (inlen) {
		error_print();
		return -1;
	}
	*sig = *ptr;
	return 1;
}

int sm3_lms_do_sign(SM3_LMS_KEY *key, const hash256_t C, const hash256_t dgst, SM3_LMS_SIGNATURE *sig)
{
	int lms_type;
	int h, n, r;
	const hash256_t *T;
	int i;

	lms_type = GETU32(key->public_key.lms_type);
	if (sm3_lms_type_to_height(lms_type, &h) != 1) {
		error_print();
		return -1;
	}
	n = 1 << h;
	r = n + key->q;

	if (!key->tree) {
		if (!(key->tree = (hash256_t *)malloc(sizeof(hash256_t) * (2*n - 1)))) {
			error_print();
			return -1;
		}
		sm3_lms_derive_merkle_tree(key->seed, key->public_key.I, h, key->tree);
	}
	T = key->tree - 1;

	PUTU32(sig->lms_type, lms_type);
	PUTU32(sig->q, key->q);
	PUTU32(sig->lmots_sig.lmots_type, SM3_LMOTS_TYPE);

	sm3_lmots_derive_secrets(key->seed, key->public_key.I, key->q, sig->lmots_sig.y);
	sm3_lmots_compute_signature(key->public_key.I, key->q, dgst, sig->lmots_sig.y, sig->lmots_sig.y);
	(key->q)++;

	memcpy(sig->lmots_sig.C, C, 32);

	for (i = 0; i < h; i++) {
		memcpy(sig->path[i], T[r ^ 0x1], 32);
		r /= 2;
	}
	return 1;
}

int sm3_lms_signature_to_merkle_root(const uint8_t I[16], int h, int q,
	const hash256_t y[34], const hash256_t *path,
	const hash256_t dgst, hash256_t root)
{
	int n, r;
	uint8_t rbytes[4];
	HASH256_CTX ctx;
	int i;

	n = 1 << h;
	if (q >= n) {
		error_print();
		return -1;
	}
	r = n + q;
	PUTU32(rbytes, r);

	sm3_lmots_signature_to_public_hash(I, q, y, dgst, root);

	// leaf[q] = H(I||u32str(r)||u16str(D_LEAF)||OTS_PUB_HASH[r-2^h])
	hash256_init(&ctx);
	hash256_update(&ctx, I, 16);
	hash256_update(&ctx, rbytes, 4);
	hash256_update(&ctx, D_LEAF, 2);
	hash256_update(&ctx, root, 32);
	hash256_finish(&ctx, root);

	for (i = 0; i < h; i++) {
		PUTU32(rbytes, r/2);

		hash256_init(&ctx);
		hash256_update(&ctx, I, 16);
		hash256_update(&ctx, rbytes, 4);
		hash256_update(&ctx, D_INTR, 2);
		if (r & 0x01) {
			hash256_update(&ctx, path[i], 32);
			hash256_update(&ctx, root, 32);
		} else {
			hash256_update(&ctx, root, 32);
			hash256_update(&ctx, path[i], 32);
		}
		hash256_finish(&ctx, root);
		r = r/2;
	}

	return 1;
}

int sm3_lms_do_verify(const SM3_LMS_PUBLIC_KEY *pub, const uint8_t dgst[32], const SM3_LMS_SIGNATURE *sig)
{
	int lms_type;
	int lmots_type;
	int h, n, q;
	hash256_t root;

	lms_type = GETU32(sig->lms_type);
	if (sm3_lms_type_to_height(lms_type, &h) != 1) {
		error_print();
		return -1;
	}
	n = 1 << h;

	if (lms_type != GETU32(pub->lms_type)) {
		error_print();
		return -1;
	}

	q = GETU32(sig->q);
	if (q >= n) {
		error_print();
		return -1;
	}

	if (sm3_lms_signature_to_merkle_root(pub->I, h, q, sig->lmots_sig.y, sig->path, dgst, root) != 1) {
		error_print();
		return -1;
	}

	if (memcmp(root, pub->root, 32) == 0) {
		return 1;
	} else {
		error_print();
		return 0;
	}
}

static int test_sm3_lms_do_sign(void)
{
	int lms_type = LMS_SM3_M32_H5;
	SM3_LMS_KEY key;
	hash256_t C = {0};
	hash256_t dgst;
	SM3_LMS_SIGNATURE sig;

	if (sm3_lms_key_generate(&key, lms_type) != 1) {
		error_print();
		return -1;
	}

	if (rand_bytes(dgst, 32) != 1) {
		error_print();
		return -1;
	}

	if (sm3_lms_do_sign(&key, C, dgst, &sig) != 1) {
		error_print();
		return -1;
	}

	if (sm3_lms_do_verify(&key.public_key, dgst, &sig) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


void sm3_lms_digest(const SM3_LMS_PUBLIC_KEY *pub, int q, const hash256_t C, const uint8_t *data, size_t datalen, hash256_t dgst)
{
	HASH256_CTX ctx;
	uint8_t qbytes[4];

	PUTU32(qbytes, q);

	hash256_init(&ctx);
	hash256_update(&ctx, pub->I, 16);
	hash256_update(&ctx, qbytes, 4);
	hash256_update(&ctx, D_MESG, 2);
	hash256_update(&ctx, C, 32);
	hash256_update(&ctx, data, datalen);
	hash256_finish(&ctx, dgst);
}

int sm3_lms_verify_data(const SM3_LMS_PUBLIC_KEY *pub, const uint8_t *data, size_t datalen, const uint8_t *sigbuf, size_t siglen)
{
	const SM3_LMS_SIGNATURE *sig;
	size_t len;
	HASH256_CTX ctx;
	hash256_t dgst;
	hash256_t Kc;
	int ret;


	if (sm3_lms_signature_from_bytes_ex(&sig, &len, &sigbuf, &siglen) != 1) {
		error_print();
		return -1;
	}
	if (siglen) {
		error_print();
		return -1;
	}

	ret = sm3_lms_do_verify(pub, dgst, sig);

	return ret;
}

typedef struct {
	int levels;
	SM3_LMS_PUBLIC_KEY lms_pub;
} SM3_HSS_PUBLIC_KEY;

typedef struct {
	SM3_HSS_PUBLIC_KEY public_key;
	SM3_LMS_KEY lms_key[5];
	SM3_LMS_SIGNATURE lms_sig[4];
} SM3_HSS_KEY;

int sm3_hss_public_key_print(FILE *fp, int fmt, int ind, const char *label, const SM3_HSS_PUBLIC_KEY *pub)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	format_print(fp, fmt, ind, "levels: %d\n", pub->levels);
	sm3_lms_public_key_print(fp, fmt, ind, "lms_pub", &pub->lms_pub);
	return 1;
}

int sm3_hss_key_print(FILE *fp, int fmt, int ind, const char *label, const SM3_HSS_KEY *key)
{
	int i;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	format_print(fp, fmt, ind, "levels: %d\n", key->public_key.levels);

	sm3_lms_key_print(fp, fmt, ind, "lms_key", &key->lms_key[0]);

	for (i = 1; i < key->public_key.levels; i++) {
		sm3_lms_signature_print(fp, fmt, ind, "lms_signature", &key->lms_sig[i - 1]);
		sm3_lms_key_print(fp, fmt, ind, "lms_key", &key->lms_key[i]);
	}

	return 1;
}

void sm3_hss_key_cleanup(SM3_HSS_KEY *key)
{
	if (key) {
		int i;
		for (i = 0; i < key->public_key.levels; i++) {
			sm3_lms_key_cleanup(&key->lms_key[i]);
		}
		memset(key, 0, sizeof(SM3_HSS_KEY));
	}
}

int sm3_hss_key_generate(SM3_HSS_KEY *key, int levels, int *lms_types)
{
	int ret = -1;
	uint8_t seed[32];
	int cache_tree = 1;
	const int q = 0;
	int i;

	//printf("sm3_hss_key_generate\n");

	if (levels <= 0 || levels > SM3_HSS_MAX_LEVELS) {
		error_print();
		return -1;
	}
	if (rand_bytes(seed, 32) != 1) {
		error_print();
		return -1;
	}

	memset(key, 0, sizeof(SM3_HSS_KEY));
	if (sm3_lms_key_generate_ex(&key->lms_key[0], lms_types[0], seed, NULL, cache_tree) != 1) {
		error_print();
		goto end;
	}

	key->public_key.levels = levels;
	key->public_key.lms_pub = key->lms_key[0].public_key;

	for (i = 1; i < levels; i++) {
		hash256_t C;
		hash256_t dgst;

		if (sm3_lms_key_generate_ex(&key->lms_key[i], lms_types[i], seed, NULL, cache_tree) != 1) {
			error_print();
			goto end;
		}
		if (rand_bytes(C, 32) != 1) {
			error_print();
			goto end;
		}

		sm3_lms_digest(&key->lms_key[i - 1].public_key, q, C,
			(uint8_t *)&key->lms_key[i].public_key, SM3_LMS_PUBLIC_KEY_SIZE, dgst);

		if (sm3_lms_do_sign(&key->lms_key[i - 1], C, dgst, &key->lms_sig[i - 1]) != 1) {
			error_print();
			goto end;
		}
	}

	ret = 1;
end:
	gmssl_secure_clear(seed, sizeof(seed));
	if (ret != 1) sm3_hss_key_cleanup(key);
	return ret;
}

static int test_sm3_hss_key_generate(void)
{
	int lms_types[] = {
		LMS_SM3_M32_H5,
		LMS_SM3_M32_H5,
		LMS_SM3_M32_H5,
		LMS_SM3_M32_H5,
	};
	SM3_HSS_KEY key;

	if (sm3_hss_key_generate(&key, sizeof(lms_types)/sizeof(lms_types[0]), lms_types) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


int sm3_hss_sign(SM3_HSS_KEY *key, const hash256_t C, const hash256_t dgst, uint8_t *sig, size_t *siglen)
{
	int num;
	int i;
	uint8_t *out = sig;
	size_t len;
	SM3_LMS_SIGNATURE msg_sig;

	num = key->public_key.levels - 1;
	PUTU32(out, num);
	out += 4;

	for (i = 0; i < num; i++) {
		sm3_lms_signature_to_bytes(&(key->lms_sig[i]), out, &len);
		out += len;
		memcpy(out, (const uint8_t *)&(key->lms_key[i + 1].public_key), SM3_LMS_PUBLIC_KEY_SIZE);
		out += SM3_LMS_PUBLIC_KEY_SIZE;
	}

	if (sm3_lms_do_sign(&key->lms_key[i], C, dgst, &msg_sig) != 1) {
		error_print();
		return -1;
	}
	sm3_lms_signature_to_bytes(&msg_sig, out, &len);

	out += len;
	*siglen = out - sig;

	return 1;
}

int sm3_hss_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen)
{
	const SM3_LMS_SIGNATURE *lms_sig;
	size_t lms_siglen;
	const SM3_LMS_PUBLIC_KEY *lms_pub;

	int num;
	int i;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;


	if (siglen < 4) {
		error_print();
		return -1;
	}
	num = GETU32(sig);
	sig += 4;
	siglen -= 4;


	format_print(fp, fmt, ind, "num: %d\n", num);

	for (i = 0; i < num; i++) {

		if (sm3_lms_signature_from_bytes_ex(&lms_sig, &lms_siglen, &sig, &siglen) != 1) {
			error_print();
			return -1;
		}
		sm3_lms_signature_print(fp, fmt, ind, "lms_sig(pub)", lms_sig);

		if (sm3_lms_public_key_from_bytes_ex(&lms_pub, &sig, &siglen) != 1) {
			error_print();
			return -1;
		}
		sm3_lms_public_key_print(fp, fmt, ind, "lms_pub", lms_pub);
	}

	if (sm3_lms_signature_from_bytes_ex(&lms_sig, &lms_siglen, &sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	sm3_lms_signature_print(fp, fmt, ind, "lms_sig(msg)", lms_sig);

	return 1;
}

int sm3_hss_verify(const SM3_HSS_PUBLIC_KEY *pub, const hash256_t dgst, const uint8_t *sig, size_t siglen)
{
	int num, i;
	const SM3_LMS_PUBLIC_KEY *lms_pub;
	const SM3_LMS_PUBLIC_KEY *next_lms_pub;
	const SM3_LMS_SIGNATURE *lms_sig;
	size_t lms_siglen;

	if (siglen < 4) {
		error_print();
		return -1;
	}

	num = GETU32(sig);
	sig += 4;
	siglen -= 4;

	if (num != pub->levels - 1) {
		error_print();
		return -1;
	}

	lms_pub = &pub->lms_pub;

	for (i = 0; i < num; i++) {

		hash256_t pub_dgst;

		if (sm3_lms_signature_from_bytes_ex(&lms_sig, &lms_siglen, &sig, &siglen) != 1) {
			error_print();
			return -1;
		}

		if (sm3_lms_public_key_from_bytes_ex(&next_lms_pub, &sig, &siglen) != 1) {
			error_print();
			return -1;
		}


		int lms_type = GETU32(lms_sig->lms_type);
		int q = GETU32(lms_sig->q);
		int lmots_type = GETU32(lms_sig->lmots_sig.lmots_type);

		sm3_lms_digest(lms_pub, q, lms_sig->lmots_sig.C,
			(uint8_t *)next_lms_pub, SM3_LMS_PUBLIC_KEY_SIZE, pub_dgst);


		if (sm3_lms_do_verify(lms_pub, pub_dgst, lms_sig) != 1) {
			error_print();
			return -1;
		}

		lms_pub = next_lms_pub;
	}

	if (sm3_lms_signature_from_bytes_ex(&lms_sig, &lms_siglen, &sig, &siglen) != 1) {
		error_print();
		return -1;
	}

	if (sm3_lms_do_verify(lms_pub, dgst, lms_sig) != 1) {
		error_print();
		return -1;
	}
	if (siglen) {
		error_print();
		return -1;
	}

	return 1;
}

static int test_sm3_hss_sign(void)
{
	int lms_types[] = {
		LMS_SM3_M32_H5,
		LMS_SM3_M32_H5,
		LMS_SM3_M32_H5,
	};
	SM3_HSS_KEY key;
	uint8_t sig[1024 * 16];
	size_t siglen;
	uint8_t dgst[32];

	if (sm3_hss_key_generate(&key, sizeof(lms_types)/sizeof(lms_types[0]), lms_types) != 1) {
		error_print();
		return -1;
	}

	int level = key.public_key.levels;
	const SM3_LMS_PUBLIC_KEY *last_lms_pub = &key.lms_key[level - 1].public_key;

	hash256_t C;
	int q = 0;
	rand_bytes(C, 32);

	sm3_lms_digest(last_lms_pub, q, C, (uint8_t *)last_lms_pub, SM3_LMS_PUBLIC_KEY_SIZE, dgst);

	if (sm3_hss_sign(&key, C, dgst, sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	if (sm3_hss_verify((SM3_HSS_PUBLIC_KEY *)&key, dgst, sig, siglen) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_sm3_lmots() != 1) goto err;
	if (test_sm3_lms_derive_merkle_root() != 1) goto err;
	if (test_sm3_lms_key_generate() != 1) goto err;
	if (test_sm3_lms_do_sign() != 1) goto err;
	if (test_sm3_hss_key_generate() != 1) goto err;
	if (test_sm3_hss_sign() != 1) goto err;

	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
