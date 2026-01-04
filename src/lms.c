/*
 *  Copyright 2014-2025 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <gmssl/mem.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>
#include <gmssl/lms.h>
#include <gmssl/x509_alg.h>

/*
 * TODO:
 *  1. add key_update callback
 *  2. only update q, and updated elments of hss key of files
 *  3. consider append only mode of files
 */

static const uint8_t D_PBLC[2] = { 0x80, 0x80 };
static const uint8_t D_MESG[2] = { 0x81, 0x81 };
static const uint8_t D_LEAF[2] = { 0x82, 0x82 };
static const uint8_t D_INTR[2] = { 0x83, 0x83 };


char *lmots_type_name(int lmots_type)
{
	switch (lmots_type) {
	case LMOTS_HASH256_N32_W8:
		return LMOTS_HASH256_N32_W8_NAME;
	}
	return NULL;
}

char *lms_type_name(int lms_type)
{
	switch (lms_type) {
	case LMS_HASH256_M32_H5:
		return LMS_HASH256_M32_H5_NAME;
	case LMS_HASH256_M32_H10:
		return LMS_HASH256_M32_H10_NAME;
	case LMS_HASH256_M32_H15:
		return LMS_HASH256_M32_H15_NAME;
	case LMS_HASH256_M32_H20:
		return LMS_HASH256_M32_H20_NAME;
	case LMS_HASH256_M32_H25:
		return LMS_HASH256_M32_H25_NAME;
	}
	return NULL;
}

int lms_type_from_name(const char *name)
{
	if (!strcmp(name, LMS_HASH256_M32_H5_NAME)) {
		return LMS_HASH256_M32_H5;
	} else if (!strcmp(name, LMS_HASH256_M32_H10_NAME)) {
		return LMS_HASH256_M32_H10;
	} else if (!strcmp(name, LMS_HASH256_M32_H15_NAME)) {
		return LMS_HASH256_M32_H15;
	} else if (!strcmp(name, LMS_HASH256_M32_H20_NAME)) {
		return LMS_HASH256_M32_H20;
	} else if (!strcmp(name, LMS_HASH256_M32_H25_NAME)) {
		return LMS_HASH256_M32_H25;
	}
	return 0;
}

int lms_type_to_height(int type, size_t *height)
{
	switch (type) {
	case LMS_HASH256_M32_H5:
		*height = 5;
		break;
	case LMS_HASH256_M32_H10:
		*height = 10;
		break;
	case LMS_HASH256_M32_H15:
		*height = 15;
		break;
	case LMS_HASH256_M32_H20:
		*height = 20;
		break;
	case LMS_HASH256_M32_H25:
		*height = 25;
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

void lmots_derive_secrets(const hash256_t seed, const uint8_t I[16], int q, hash256_t x[34])
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

void lmots_secrets_to_public_hash(const uint8_t I[16], int q, const hash256_t x[34], hash256_t pub)
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

// signed digest Q = H(I || u32str(q) || u16str(D_MESG) || C || message)
void lmots_compute_signature(const uint8_t I[16], int q, const hash256_t dgst, const hash256_t x[34], hash256_t y[34])
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

void lmots_signature_to_public_hash(const uint8_t I[16], int q, const hash256_t y[34], const hash256_t dgst, hash256_t pub)
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

// derive full merkle tree[2^h * 2 - 1] from seed, tree[0] is the root
void lms_derive_merkle_tree(const hash256_t seed, const uint8_t I[16], int h, hash256_t *tree)
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
			lmots_derive_secrets(seed, I, q, x);
			lmots_secrets_to_public_hash(I, q, x, pub);

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

void lms_derive_merkle_root(const hash256_t seed, const uint8_t I[16], int h, hash256_t root)
{
	int q, r, n = 1 << h;
	int qbits;
	HASH256_CTX ctx;
	hash256_t stack[25];
	int num = 0;
	hash256_t x[34];
	uint8_t rbytes[4];

	for (q = 0; q < n; q++) {

		lmots_derive_secrets(seed, I, q, x);
		lmots_secrets_to_public_hash(I, q, x, stack[num]);

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

int lms_public_key_to_bytes(const LMS_KEY *key, uint8_t **out, size_t *outlen)
{
	if (!key || !outlen) {
		error_print();
		return -1;
	}
	if (out && *out) {
		PUTU32(*out, key->public_key.lms_type);
		*out += 4;
		PUTU32(*out, key->public_key.lmots_type);
		*out += 4;
		memcpy(*out, key->public_key.I, 16);
		*out += 16;
		memcpy(*out, key->public_key.root, 32);
		*out += 32;
	}
	*outlen += LMS_PUBLIC_KEY_SIZE;
	return 1;
}

int lms_private_key_to_bytes(const LMS_KEY *key, uint8_t **out, size_t *outlen)
{
	if (lms_public_key_to_bytes(key, out, outlen) != 1) {
		error_print();
		return -1;
	}
	if (out && *out) {
		memcpy(*out, key->seed, 32);
		*out += 32;
		PUTU32(*out, key->q);
		*out += 4;
	}
	*outlen += 32 + 4;
	return 1;
}

int lms_public_key_from_bytes(LMS_KEY *key, const uint8_t **in, size_t *inlen)
{
	if (!key || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen < LMS_PUBLIC_KEY_SIZE) {
		error_print();
		return -1;
	}

	memset(key, 0, sizeof(*key));

	key->public_key.lms_type = GETU32(*in);
	if (!lms_type_name(key->public_key.lms_type)) {
		error_print();
		return -1;
	}
	*in += 4;
	*inlen -= 4;

	key->public_key.lmots_type = GETU32(*in);
	if (!lmots_type_name(key->public_key.lmots_type)) {
		error_print();
		return -1;
	}
	*in += 4;
	*inlen -= 4;

	memcpy(key->public_key.I, *in, 16);
	*in += 16;
	*inlen -= 16;

	memcpy(key->public_key.root, *in, 32);
	*in += 32;
	*inlen -= 32;

	return 1;
}

int lms_key_check(const LMS_KEY *key, const LMS_PUBLIC_KEY *pub)
{
	// FIXME: implement this
	return 1;
}

int lms_key_remaining_signs(const LMS_KEY *key, size_t *count)
{
	size_t height;
	size_t n;

	if (!key || !count) {
		error_print();
		return -1;
	}
	if (lms_type_to_height(key->public_key.lms_type, &height) != 1) {
		error_print();
		return -1;
	}
	n = 1 << height;
	if (key->q > n) {
		error_print();
		return -1;
	}
	*count = n - key->q;
	return 1;
}

int lms_private_key_from_bytes(LMS_KEY *key, const uint8_t **in, size_t *inlen)
{
	size_t height;
	int cache_tree = 1;

	if (!key || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen < LMS_PRIVATE_KEY_SIZE) {
		error_print();
		return -1;
	}

	if (lms_public_key_from_bytes(key, in, inlen) != 1) {
		error_print();
		return -1;
	}

	memcpy(key->seed, *in, 32);
	*in += 32;
	*inlen -= 32;

	key->q = GETU32(*in);
	*in += 4;
	*inlen -= 4;

	if (lms_type_to_height(key->public_key.lms_type, &height) != 1) {
		error_print();
		return -1;
	}
	if (key->q >= (1 << height)) {
		error_print();
		return -1;
	}

	if (cache_tree) {
		size_t n = 1 << height;
		if (!(key->tree = (hash256_t *)malloc(sizeof(hash256_t) * (2*n - 1)))) {
			error_print();
			return -1;
		}
		lms_derive_merkle_tree(key->seed, key->public_key.I, height, key->tree);
		memcpy(key->public_key.root, key->tree[0], 32);
	}

	return 1;
}

int lms_public_key_print(FILE *fp, int fmt, int ind, const char *label, const LMS_PUBLIC_KEY *pub)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	format_print(fp, fmt, ind, "lms_type: %s\n", lms_type_name(pub->lms_type));
	format_print(fp, fmt, ind, "lmots_type: %s\n", lmots_type_name(pub->lmots_type));
	format_bytes(fp, fmt, ind, "I", pub->I, 16);
	format_bytes(fp, fmt, ind, "root", pub->root, 32);
	return 1;
}

int lms_key_print(FILE *fp, int fmt, int ind, const char *label, const LMS_KEY *key)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	lms_public_key_print(fp, fmt, ind, "lms_public_key", &key->public_key);
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

void lms_key_cleanup(LMS_KEY *key)
{
	if (key) {
		gmssl_secure_clear(key->seed, 32);
		if (key->tree) {
			free(key->tree);
			key->tree = NULL;
		}
		memset(key, 0, sizeof(LMS_KEY));
	}
}

int lms_key_generate_ex(LMS_KEY *key, int lms_type, const hash256_t seed, const uint8_t I[16], int cache_tree)
{
	size_t h, n;

	if (!key || !seed || !I) {
		error_print();
		return -1;
	}

	if (lms_type_to_height(lms_type, &h) != 1) {
		error_print();
		return -1;
	}
	n = 1 << h;

	key->public_key.lms_type = lms_type;
	key->public_key.lmots_type = LMOTS_HASH256_N32_W8;

	memcpy(key->public_key.I, I, 16);
	memcpy(key->seed, seed, 32);

	if (cache_tree) {
		if (!(key->tree = (hash256_t *)malloc(sizeof(hash256_t) * (2*n - 1)))) {
			error_print();
			return -1;
		}
		lms_derive_merkle_tree(key->seed, key->public_key.I, h, key->tree);
		memcpy(key->public_key.root, key->tree[0], 32);
	} else {
		key->tree = NULL;
		lms_derive_merkle_root(key->seed, key->public_key.I, h, key->public_key.root);
	}

	key->q = 0;
	return 1;
}

int lms_key_generate(LMS_KEY *key, int lms_type)
{
	hash256_t seed;
	uint8_t I[16];
	int cache_tree = 1;

	if (rand_bytes(seed, sizeof(seed)) != 1) {
		error_print();
		return -1;
	}
	if (rand_bytes(I, sizeof(I)) != 1) {
		error_print();
		return -1;
	}
	if (lms_key_generate_ex(key, lms_type, seed, I, cache_tree) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int lms_signature_size(int lms_type, size_t *len)
{
	size_t height;

	if (!len) {
		error_print();
		return -1;
	}
	if (lms_type_to_height(lms_type, &height) != 1) {
		error_print();
		return -1;
	}
	*len = sizeof(uint32_t) // q
		+ sizeof(uint32_t) // lmots_type
		+ sizeof(hash256_t) // C
		+ sizeof(hash256_t) * 34 // y[34]
		+ sizeof(uint32_t) // lms_type
		+ sizeof(hash256_t) * height; // path[hegith]
	return 1;
}

int lms_key_get_signature_size(const LMS_KEY *key, size_t *siglen)
{
	if (!key || !siglen) {
		error_print();
		return -1;
	}
	if (lms_signature_size(key->public_key.lms_type, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int lms_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const LMS_SIGNATURE *sig)
{
	size_t h;
	size_t i;

	if (lms_type_to_height(sig->lms_type, &h) != 1) {
		error_print();
		return -1;
	}

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	format_print(fp, fmt, ind, "q: %d\n", sig->q);
	format_print(fp, fmt, ind, "lmots_type: %s\n", lmots_type_name(sig->lmots_sig.lmots_type));
	format_bytes(fp, fmt, ind, "lmots_sig.C", sig->lmots_sig.C, 32);
	format_print(fp, fmt, ind, "lmots_sig.y\n");
	for (i = 0; i < 34; i++) {
		format_print(fp, fmt, ind + 4, "zu", i);
		format_bytes(fp, fmt, 0, "", sig->lmots_sig.y[i], 32);
	}
	format_print(fp, fmt, ind, "lms_type: %s\n", lms_type_name(sig->lms_type));
	format_print(fp, fmt, ind, "path\n");
	for (i = 0; i < h; i++) {
		format_print(fp, fmt, ind + 4, "%zu", i);
		format_bytes(fp, fmt, 0, "", sig->path[i], 32);
	}
	return 1;
}

int lms_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen)
{
	uint32_t q, lmots_type, lms_type;
	size_t height, i;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (siglen < 4) {
		error_print();
		return -1;
	}
	q = GETU32(sig);
	format_print(fp, fmt, ind, "q: %zu\n", q);
	sig += 4;
	siglen -= 4;

	if (siglen < 4) {
		error_print();
		return -1;
	}
	lmots_type = GETU32(sig);
	sig += 4;
	siglen -= 4;
	format_print(fp, fmt, ind, "lmots_type: %s\n", lmots_type_name(lmots_type));

	if (siglen < 32) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "lmots_sig.C", sig, 32);
	sig += 32;
	siglen -= 32;

	format_print(fp, fmt, ind, "lmots_sig.y\n");
	for (i = 0; i < 34; i++) {
		if (siglen < 32) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind + 4, "%zu", i);
		format_bytes(fp, fmt, 0, "", sig, 32);
		sig += 32;
		siglen -= 32;
	}

	if (siglen < 4) {
		error_print();
		return -1;
	}
	lms_type = GETU32(sig);
	format_print(fp, fmt, ind, "lms_type: %s\n", lms_type_name(lms_type));
	if (lms_type_to_height(lms_type, &height) != 1) {
		error_print();
		return -1;
	}
	sig += 4;
	siglen -= 4;

	format_print(fp, fmt, ind, "path\n");

	for (i = 0; i < height; i++) {
		if (siglen < 32) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind + 4, "%zu", i);
		format_bytes(fp, fmt, 0, "", sig, 32);
		sig += 32;
		siglen -= 32;
	}

	return 1;
}

int lms_signature_to_bytes(const LMS_SIGNATURE *sig, uint8_t **out, size_t *outlen)
{
	size_t height;

	if (!sig || !outlen) {
		error_print();
		return -1;
	}
	if (lms_type_to_height(sig->lms_type, &height) != 1) {
		error_print();
		return -1;
	}
	if (out && *out) {
		PUTU32(*out, sig->q);
		*out += 4;
		PUTU32(*out, sig->lmots_sig.lmots_type);
		*out += 4;
		memcpy(*out, sig->lmots_sig.C, 32);
		*out += 32;
		memcpy(*out, sig->lmots_sig.y, 32*34);
		*out += 32*34;
		PUTU32(*out, sig->lms_type);
		*out += 4;
		memcpy(*out, sig->path, 32*height);
		*out += 32*height;
	}
	*outlen += 4 + 4 + 32 + 32*34 + 4 + 32*height;
	return 1;
}

int lms_signature_from_bytes(LMS_SIGNATURE *sig, const uint8_t **in, size_t *inlen)
{
	size_t height;

	if (!sig || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}

	if (*inlen < LMS_SIGNATURE_MIN_SIZE) {
		error_print();
		return -1;
	}
	memset(sig, 0, sizeof(*sig));

	sig->q = GETU32(*in);
	*in += 4;
	*inlen -= 4;

	sig->lmots_sig.lmots_type = GETU32(*in);
	if (!lmots_type_name(sig->lmots_sig.lmots_type)) {
		error_print();
		return -1;
	}
	*in += 4;
	*inlen -= 4;

	memcpy(sig->lmots_sig.C, *in, 32);
	*in += 32;
	*inlen -= 32;

	memcpy(sig->lmots_sig.y, *in, 32*34);
	*in += 32*34;
	*inlen -= 32*34;

	sig->lms_type = GETU32(*in);
	if (lms_type_to_height(sig->lms_type, &height) != 1) {
		error_print();
		return -1;
	}
	if (sig->q < 0 || sig->q >= (1 << height)) {
		error_print();
		return -1;
	}
	*in += 4;
	*inlen -= 4;

	if (*inlen < 32*height) {
		error_print();
		return -1;
	}
	memcpy(sig->path, *in, 32*height);
	*in += 32*height;
	*inlen -= 32*height;

	return 1;
}

int lms_signature_to_merkle_root(const uint8_t I[16], size_t h, int q,
	const hash256_t y[34], const hash256_t *path,
	const hash256_t dgst, hash256_t root)
{
	size_t n, r;
	uint8_t rbytes[4];
	HASH256_CTX ctx;
	size_t i;

	n = 1 << h;
	if (q >= n) {
		error_print();
		return -1;
	}
	r = n + q;
	PUTU32(rbytes, r);

	lmots_signature_to_public_hash(I, q, y, dgst, root);

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

void lms_sign_ctx_cleanup(LMS_SIGN_CTX *ctx)
{
	if (ctx) {
		gmssl_secure_clear(ctx->lms_sig.lmots_sig.y, sizeof(hash256_t)*34);
	}
}

int lms_sign_init(LMS_SIGN_CTX *ctx, LMS_KEY *key)
{
	LMS_SIGNATURE *lms_sig;
	uint8_t qbytes[4];
	const hash256_t *T;
	size_t height, r, i;

	if (!ctx || !key) {
		error_print();
		return -1;
	}

	// check key state
	if (lms_type_to_height(key->public_key.lms_type, &height) != 1) {
		error_print();
		return -1;
	}
	if (key->q >= (1 << height)) {
		error_print();
		return -1;
	}
	r = (1 << height) + key->q;

	memset(ctx, 0, sizeof(*ctx));
	memcpy(ctx->lms_public_key.I, key->public_key.I, 16);

	lms_sig = &ctx->lms_sig;
	lms_sig->q = key->q;
	PUTU32(qbytes, key->q);

	lms_sig->lmots_sig.lmots_type = key->public_key.lmots_type;

	if (rand_bytes(lms_sig->lmots_sig.C, 32) != 1) {
		error_print();
		return -1;
	}

	// cache lmots private in lmots_sig.y, overwitten by sign_finish
	lmots_derive_secrets(key->seed, key->public_key.I, key->q, lms_sig->lmots_sig.y);

	// update key state, SHOULD not use the updated key->q
	(key->q)++;

	lms_sig->lms_type = key->public_key.lms_type;


	// FIXME: re-generate tree?
	if (!key->tree) {
		error_print();
		return -1;
	}
	T = key->tree - 1;
	for (i = 0; i < height; i++) {
		memcpy(lms_sig->path[i], T[r ^ 0x1], 32);
		r /= 2;
	}

	hash256_init(&ctx->hash256_ctx);
	hash256_update(&ctx->hash256_ctx, key->public_key.I, 16);
	hash256_update(&ctx->hash256_ctx, qbytes, 4);
	hash256_update(&ctx->hash256_ctx, D_MESG, 2);
	hash256_update(&ctx->hash256_ctx, lms_sig->lmots_sig.C, 32);

	return 1;
}

int lms_sign_update(LMS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (data && datalen > 0) {
		hash256_update(&ctx->hash256_ctx, data, datalen);
	}
	return 1;
}

int lms_sign_finish_ex(LMS_SIGN_CTX *ctx, LMS_SIGNATURE *sig)
{
	LMS_SIGNATURE *lms_sig;
	uint8_t dgst[32];

	if (!ctx || !sig) {
		error_print();
		return -1;
	}

	hash256_finish(&ctx->hash256_ctx, dgst);

	lms_sig = &ctx->lms_sig;
	lmots_compute_signature(ctx->lms_public_key.I, lms_sig->q, dgst, lms_sig->lmots_sig.y, lms_sig->lmots_sig.y);

	*sig = *lms_sig;
	return 1;
}

int lms_sign_finish(LMS_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen)
{
	LMS_SIGNATURE *lms_sig;
	uint8_t dgst[32];

	if (!ctx || !sig || !siglen) {
		error_print();
		return -1;
	}

	hash256_finish(&ctx->hash256_ctx, dgst);

	lms_sig = &ctx->lms_sig;
	lmots_compute_signature(ctx->lms_public_key.I, lms_sig->q, dgst, lms_sig->lmots_sig.y, lms_sig->lmots_sig.y);

	*siglen = 0;
	if (lms_signature_to_bytes(lms_sig, &sig, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int lms_verify_init_ex(LMS_SIGN_CTX *ctx, const LMS_KEY *key, const LMS_SIGNATURE *sig)
{
	LMS_SIGNATURE *lms_sig;
	uint8_t qbytes[4];

	if (!ctx || !key || !sig) {
		error_print();
		return -1;
	}

	memset(ctx, 0, sizeof(*ctx));

	ctx->lms_public_key = key->public_key;

	ctx->lms_sig = *sig;
	lms_sig = &ctx->lms_sig;

	if (lms_sig->lmots_sig.lmots_type != key->public_key.lmots_type) {
		error_print();
		return -1;
	}
	if (lms_sig->lms_type != key->public_key.lms_type) {
		error_print();
		return -1;
	}

	PUTU32(qbytes, lms_sig->q);

	hash256_init(&ctx->hash256_ctx);
	hash256_update(&ctx->hash256_ctx, key->public_key.I, 16);
	hash256_update(&ctx->hash256_ctx, qbytes, 4);
	hash256_update(&ctx->hash256_ctx, D_MESG, 2);
	hash256_update(&ctx->hash256_ctx, lms_sig->lmots_sig.C, 32);

	return 1;
}

int lms_verify_init(LMS_SIGN_CTX *ctx, const LMS_KEY *key, const uint8_t *sig, size_t siglen)
{
	LMS_SIGNATURE *lms_sig;
	uint8_t qbytes[4];

	if (!ctx || !key || !sig || !siglen) {
		error_print();
		return -1;
	}

	memset(ctx, 0, sizeof(*ctx));

	ctx->lms_public_key = key->public_key;

	lms_sig = &ctx->lms_sig;
	if (lms_signature_from_bytes(lms_sig, &sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	if (siglen) {
		error_print();
		return -1;
	}

	if (lms_sig->lmots_sig.lmots_type != key->public_key.lmots_type) {
		error_print();
		return -1;
	}
	if (lms_sig->lms_type != key->public_key.lms_type) {
		error_print();
		return -1;
	}

	PUTU32(qbytes, lms_sig->q);

	hash256_init(&ctx->hash256_ctx);
	hash256_update(&ctx->hash256_ctx, key->public_key.I, 16);
	hash256_update(&ctx->hash256_ctx, qbytes, 4);
	hash256_update(&ctx->hash256_ctx, D_MESG, 2);
	hash256_update(&ctx->hash256_ctx, lms_sig->lmots_sig.C, 32);

	return 1;
}

int lms_verify_update(LMS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (data && datalen > 0) {
		hash256_update(&ctx->hash256_ctx, data, datalen);
	}
	return 1;
}

int lms_verify_finish(LMS_SIGN_CTX *ctx)
{
	LMS_SIGNATURE *lms_sig;
	hash256_t dgst;
	size_t height;
	hash256_t root;

	if (!ctx) {
		error_print();
		return -1;
	}

	lms_sig = &ctx->lms_sig;
	if (lms_type_to_height(lms_sig->lms_type, &height) != 1) {
		error_print();
		return -1;
	}

	hash256_finish(&ctx->hash256_ctx, dgst);

	if (lms_signature_to_merkle_root(ctx->lms_public_key.I, height,
		lms_sig->q, lms_sig->lmots_sig.y, lms_sig->path, dgst, root) != 1) {
		error_print();
		return -1;
	}

	if (memcmp(root, ctx->lms_public_key.root, 32) == 0) {
		return 1;
	} else {
		error_print();
		return 0;
	}
}

int hss_public_key_digest(const HSS_KEY *key, uint8_t dgst[32])
{
	SM3_CTX ctx;
	uint8_t bytes[HSS_PUBLIC_KEY_SIZE];
	uint8_t *p = bytes;
	size_t len;

	if (hss_public_key_to_bytes(key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	sm3_init(&ctx);
	sm3_update(&ctx, bytes, sizeof(bytes));
	sm3_finish(&ctx, dgst);
	return 1;
}

int hss_public_key_print(FILE *fp, int fmt, int ind, const char *label, const HSS_KEY *key)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	format_print(fp, fmt, ind, "levels: %d\n", key->levels);
	lms_public_key_print(fp, fmt, ind, "lms_public_key", &key->lms_key[0].public_key);
	return 1;
}

int hss_public_key_to_bytes(const HSS_KEY *key, uint8_t **out, size_t *outlen)
{
	if (!key || !outlen) {
		error_print();
		return -1;
	}
	if (out && *out) {
		PUTU32(*out, key->levels);
		*out += 4;
		PUTU32(*out, key->lms_key[0].public_key.lms_type);
		*out += 4;
		PUTU32(*out, key->lms_key[0].public_key.lmots_type);
		*out += 4;
		memcpy(*out, key->lms_key[0].public_key.I, 16);
		*out += 16;
		memcpy(*out, key->lms_key[0].public_key.root, 32);
		*out += 32;
	}
	*outlen += HSS_PUBLIC_KEY_SIZE;
	return 1;
}

int hss_public_key_from_bytes(HSS_KEY *key, const uint8_t **in, size_t *inlen)
{
	if (!key || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen < HSS_PUBLIC_KEY_SIZE) {
		error_print();
		return -1;
	}

	memset(key, 0, sizeof(*key));

	key->levels = GETU32(*in);
	if (key->levels > HSS_MAX_LEVELS) {
		error_print();
		return -1;
	}
	*in += 4;
	*inlen -= 4;

	if (lms_public_key_from_bytes(&key->lms_key[0], in, inlen) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int hss_private_key_to_bytes(const HSS_KEY *key, uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (!key || !out) {
		error_print();
		return -1;
	}
	if (key->levels < 1 || key->levels > HSS_MAX_LEVELS) {
		error_print();
		return -1;
	}

	if (out && *out) {
		uint32_t i;

		PUTU32(*out, key->levels);
		*out += 4;
		len += 4;

		if (lms_private_key_to_bytes(&key->lms_key[0], out, &len) != 1) {
			error_print();
			return -1;
		}

		for (i = 1; i < key->levels; i++) {
			if (lms_private_key_to_bytes(&key->lms_key[i], out, &len) != 1) {
				error_print();
				return -1;
			}
			if (lms_signature_to_bytes(&key->lms_sig[i - 1], out, &len) != 1) {
				error_print();
				return -1;
			}
		}
	}

	*outlen += len;
	return 1;
}

int hss_private_key_from_bytes(HSS_KEY *key, const uint8_t **in, size_t *inlen)
{
	size_t i;

	if (!key || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}

	if (*inlen < 4) {
		error_print();
		return -1;
	}

	key->levels = GETU32(*in);
	if (key->levels < 1 || key->levels > HSS_MAX_LEVELS) {
		error_print();
		return -1;
	}
	*in += 4;
	*inlen -= 4;

	if (lms_private_key_from_bytes(&key->lms_key[0], in, inlen) != 1) {
		error_print();
		return -1;
	}

	for (i = 1; i < key->levels; i++) {
		LMS_SIGN_CTX ctx;
		uint8_t buf[LMS_PUBLIC_KEY_SIZE];
		uint8_t *p = buf;
		size_t len = 0;

		if (lms_private_key_from_bytes(&key->lms_key[i], in, inlen) != 1) {
			error_print();
			return -1;
		}
		if (lms_signature_from_bytes(&key->lms_sig[i - 1], in, inlen) != 1) {
			error_print();
			return -1;
		}

		// verify public_key[i] by key[i - 1]
		if (lms_public_key_to_bytes(&key->lms_key[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (lms_verify_init_ex(&ctx, &key->lms_key[i - 1], &key->lms_sig[i - 1]) != 1
			|| lms_verify_update(&ctx, buf, len) != 1
			|| lms_verify_finish(&ctx) != 1) {
			error_print();
			return -1;
		}
	}

	return 1;
}

int hss_key_print(FILE *fp, int fmt, int ind, const char *label, const HSS_KEY *key)
{
	int i;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	format_print(fp, fmt, ind, "levels: %d\n", key->levels);

	lms_key_print(fp, fmt, ind, "lms_key[0]", &key->lms_key[0]);

	for (i = 1; i < key->levels; i++) {
		char title[64];
		snprintf(title, sizeof(title), "lms_signature[%d]", i - 1);
		lms_signature_print_ex(fp, fmt, ind, title, &key->lms_sig[i - 1]);
		snprintf(title, sizeof(title), "lms_key[%d]", i);
		lms_key_print(fp, fmt, ind, title, &key->lms_key[i]);
	}

	return 1;
}

void hss_key_cleanup(HSS_KEY *key)
{
	if (key) {
		int i;
		for (i = 0; i < key->levels; i++) {
			lms_key_cleanup(&key->lms_key[i]);
		}
		memset(key, 0, sizeof(HSS_KEY));
	}
}

int hss_key_generate(HSS_KEY *key, const int *lms_types, size_t levels)
{
	int ret = -1;
	hash256_t seed;
	uint8_t I[16];
	LMS_SIGN_CTX ctx;
	uint8_t buf[LMS_SIGNATURE_MAX_SIZE]; // LMS_SIGNATURE_MAX_SIZE > SM3_PUBLIC_KEY_SIZE

	int cache_tree = 1;
	const int q = 0;
	size_t i;

	if (!key || !lms_types) {
		error_print();
		return -1;
	}
	if (levels > HSS_MAX_LEVELS) {
		error_print();
		return -1;
	}
	for (i = 0; i < levels; i++) {
		if (!lms_type_name(lms_types[i])) {
			error_print();
			return -1;
		}
	}

	memset(key, 0, sizeof(*key));

	key->levels = (uint32_t)levels;

	// level-0 lms key
	if (rand_bytes(seed, sizeof(seed)) != 1) {
		error_print();
		goto end;
	}
	if (rand_bytes(I, sizeof(I)) != 1) {
		error_print();
		goto end;
	}
	if (lms_key_generate_ex(&key->lms_key[0], lms_types[0], seed, I, cache_tree) != 1) {
		error_print();
		goto end;
	}

	for (i = 1; i < levels; i++) {
		uint8_t *p = buf;
		size_t len = 0;

		if (rand_bytes(seed, sizeof(seed)) != 1) {
			error_print();
			goto end;
		}
		if (rand_bytes(I, sizeof(I)) != 1) {
			error_print();
			goto end;
		}
		if (lms_key_generate_ex(&key->lms_key[i], lms_types[i], seed, I, cache_tree) != 1) {
			error_print();
			goto end;
		}

		// sign public_key[i] by key[i - 1]
		if (lms_public_key_to_bytes(&key->lms_key[i], &p, &len) != 1) {
			error_print();
			goto end;
		}
		if (lms_sign_init(&ctx, &key->lms_key[i - 1]) != 1
			|| lms_sign_update(&ctx, buf, len) != 1
			|| lms_sign_finish(&ctx, buf, &len) != 1) {
			error_print();
			goto end;
		}
		// save LMS_SIGNATURE struct
		key->lms_sig[i - 1] = ctx.lms_sig;
	}

	ret = 1;
end:
	gmssl_secure_clear(seed, sizeof(seed));
	lms_sign_ctx_cleanup(&ctx);
	if (ret != 1) hss_key_cleanup(key);
	return ret;
}

int hss_signature_size(const int *lms_types, size_t levels, size_t *siglen)
{
	size_t i;

	if (!lms_types || !siglen) {
		error_print();
		return -1;
	}
	if (levels < 1 || levels > HSS_MAX_LEVELS) {
		error_print();
		return -1;
	}

	*siglen = 4;
	for (i = 0; i < levels; i++) {
		size_t lms_siglen;
		if (lms_signature_size(lms_types[i], &lms_siglen) != 1) {
			error_print();
			return -1;
		}
		*siglen += lms_siglen;
	}
	*siglen += LMS_PUBLIC_KEY_SIZE * (levels - 1);

	return 1;
}

int hss_key_get_signature_size(const HSS_KEY *key, size_t *siglen)
{
	int lms_types[5];
	int i;

	if (!key || !siglen) {
		error_print();
		return -1;
	}

	for (i = 0; i < key->levels; i++) {
		lms_types[i] = key->lms_key[i].public_key.lms_type;
	}
	if (hss_signature_size(lms_types, key->levels, siglen) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int hss_signature_from_bytes(HSS_SIGNATURE *sig, const uint8_t **in, size_t *inlen)
{
	size_t i;

	if (!sig || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen < 4) {
		error_print();
		return -1;
	}

	sig->num_signed_public_keys = GETU32(*in);
	if (sig->num_signed_public_keys >= HSS_MAX_LEVELS) {
		error_print();
		return -1;
	}
	*in += 4;
	*inlen -= 4;

	for (i = 0; i < sig->num_signed_public_keys; i++) {
		LMS_SIGNATURE *lms_sig = &sig->signed_public_keys[i].lms_sig;
		LMS_KEY *lms_key = (LMS_KEY *)&sig->signed_public_keys[i].lms_public_key;

		if (lms_signature_from_bytes(lms_sig, in, inlen) != 1) {
			error_print();
			return -1;
		}
		if (lms_public_key_from_bytes(lms_key, in, inlen) != 1) {
			error_print();
			return -1;
		}
	}
	if (lms_signature_from_bytes(&sig->msg_lms_sig, in, inlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int hss_signature_to_bytes(const HSS_SIGNATURE *sig, uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (!sig || !outlen) {
		error_print();
		return -1;
	}
	if (sig->num_signed_public_keys >= HSS_MAX_LEVELS) {
		error_print();
		return -1;
	}

	if (out && *out) {
		size_t i;

		PUTU32(*out, sig->num_signed_public_keys);
		*out += 4;
		len += 4;

		for (i = 0; i < sig->num_signed_public_keys; i++) {
			if (lms_signature_to_bytes(&sig->signed_public_keys[i].lms_sig, out, &len) != 1) {
				error_print();
				return -1;
			}
			if (lms_public_key_to_bytes((LMS_KEY *)&sig->signed_public_keys[i].lms_public_key, out, &len) != 1) {
				error_print();
				return -1;
			}
		}

		if (lms_signature_to_bytes(&sig->msg_lms_sig, out, &len) != 1) {
			error_print();
			return -1;
		}
	}

	*outlen += len;
	return 1;
}


int hss_key_update(HSS_KEY *key)
{
	int level;
	LMS_KEY *lms_key;
	size_t count;


	for (level = key->levels; level > 0; level--) {
		lms_key = &key->lms_key[level - 1];
		if (lms_key_remaining_signs(lms_key, &count) != 1) {
			error_print();
			return -1;
		}
		if (count > 0) {
			break;
		}
	}
	// the lowest level is not out of keys
	if (level >= key->levels) {

		fprintf(stderr, "key->levels = %d\n", key->levels);
		fprintf(stderr, "level out of key = %d\n", level);


		error_print();
		return -1;
	}
	// all levels are out of keys
	if (level == 0) {
		return 0;
	}

	for (; level < key->levels; level++) {
		int lms_type = key->lms_key[level].public_key.lms_type;
		LMS_SIGN_CTX ctx;
		uint8_t buf[LMS_PUBLIC_KEY_SIZE];
		uint8_t *p = buf;
		size_t len = 0;

		lms_key_cleanup(&key->lms_key[level]);

		if (lms_key_generate(&key->lms_key[level], lms_type) != 1) {
			error_print();
			return -1;
		}
		if (lms_public_key_to_bytes(&key->lms_key[level], &p, &len) != 1) {
			error_print();
			return -1;
		}

		if (lms_sign_init(&ctx, &key->lms_key[level - 1]) != 1) {
			error_print();
			return -1;
		}
		if (lms_sign_update(&ctx, buf, len) != 1) {
			error_print();
			return -1;
		}
		if (lms_sign_finish_ex(&ctx, &key->lms_sig[level - 1]) != 1) {
			error_print();
			return -1;
		}
	}

	return 1;
}

int hss_sign_init(HSS_SIGN_CTX *ctx, HSS_KEY *key)
{
	size_t count;
	size_t i;

	if (!ctx || !key) {
		error_print();
		return -1;
	}
	if (key->levels < 1 || key->levels > HSS_MAX_LEVELS) {
		error_print();
		return -1;
	}

	memset(ctx, 0, sizeof(*ctx));

	if (lms_sign_init(&ctx->lms_ctx, &key->lms_key[key->levels - 1]) != 1) {
		error_print();
		return -1;
	}

	ctx->levels = key->levels;

	for (i = 0; i < key->levels; i++) {
		ctx->lms_public_keys[i] = key->lms_key[i + 1].public_key;
		ctx->lms_sigs[i] = key->lms_sig[i];
	}

	if (lms_key_remaining_signs(&key->lms_key[key->levels - 1], &count) != 1) {
		error_print();
		return -1;
	}
	if (count == 0) {
		if (hss_key_update(key) != 1) {
			error_print();
			return -1;
		}
	}

	return 1;
}

int hss_sign_update(HSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (data && datalen) {
		if (lms_sign_update(&ctx->lms_ctx, data, datalen) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int hss_sign_finish(HSS_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen)
{
	HSS_SIGNATURE signature;
	uint8_t *p = sig;

	if (!ctx || !sig || !siglen) {
		error_print();
		return -1;
	}
	if (hss_sign_finish_ex(ctx, &signature) != 1) {
		error_print();
		return -1;
	}

	*siglen = 0;
	if (hss_signature_to_bytes(&signature, &p, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int hss_sign_finish_ex(HSS_SIGN_CTX *ctx, HSS_SIGNATURE *sig)
{
	size_t i;

	if (!ctx || !sig) {
		error_print();
		return -1;
	}

	sig->num_signed_public_keys = ctx->levels - 1;

	for (i = 0; i < ctx->levels - 1; i++) {
		sig->signed_public_keys[i].lms_sig = ctx->lms_sigs[i];
		sig->signed_public_keys[i].lms_public_key = ctx->lms_public_keys[i];
	}

	if (lms_sign_finish_ex(&ctx->lms_ctx, &sig->msg_lms_sig) != 1) {
		error_print();
		return -1;
	}

	return 1;
}


// optimize this function,	 
int hss_verify_init_ex(HSS_SIGN_CTX *ctx, const HSS_KEY *key, const HSS_SIGNATURE *sig)
{
	uint8_t buf[LMS_PUBLIC_KEY_SIZE];
	uint8_t *p = buf;
	size_t len = 0;
	size_t i;

	if (!ctx || !key || !sig) {
		error_print();
		return -1;
	}

	if (key->levels < 1 || key->levels > HSS_MAX_LEVELS) {
		error_print();
		return -1;
	}
	if (sig->num_signed_public_keys != key->levels - 1) {
		error_print();
		return -1;
	}

	if (sig->num_signed_public_keys == 0) {
		if (lms_verify_init_ex(&ctx->lms_ctx, &key->lms_key[0],
			&sig->msg_lms_sig) != 1) {
			error_print();
			return -1;
		}
		return 1;
	}

	// verify(public_root, sig->pk[0], sig[0])
	if (lms_public_key_to_bytes((LMS_KEY *)&sig->signed_public_keys[0].lms_public_key, &p, &len) != 1) {
		error_print();
		return -1;
	}

	if (lms_verify_init_ex(&ctx->lms_ctx, &key->lms_key[0],
		&sig->signed_public_keys[0].lms_sig) != 1) {
		error_print();
		return -1;
	}

	if (lms_verify_update(&ctx->lms_ctx, buf, len) != 1) {
		error_print();
		return -1;
	}
	if (lms_verify_finish(&ctx->lms_ctx) != 1) {
		error_print();
		return -1;
	}

	// verify(pk[i - 1], pk[i], sig[i])
	for (i = 1; i < sig->num_signed_public_keys; i++) {
		p = buf;
		len = 0;
		if (lms_public_key_to_bytes((LMS_KEY *)&sig->signed_public_keys[i].lms_public_key, &p, &len) != 1) {
			error_print();
			return -1;
		}

		if (lms_verify_init_ex(&ctx->lms_ctx,
			(LMS_KEY *)&sig->signed_public_keys[i - 1].lms_public_key,
			&sig->signed_public_keys[i].lms_sig) != 1) {
			error_print();
			return -1;
		}
		if (lms_verify_update(&ctx->lms_ctx, buf, len) != 1) {
			error_print();
			return -1;
		}

		if (lms_verify_finish(&ctx->lms_ctx) != 1) {
			error_print();
			return -1;
		}
	}

	// verify(pk[last], msg, msg_sig)
	if (lms_verify_init_ex(&ctx->lms_ctx,
		(LMS_KEY *)&sig->signed_public_keys[sig->num_signed_public_keys - 1].lms_public_key,
		&sig->msg_lms_sig) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int hss_verify_init(HSS_SIGN_CTX *ctx, const HSS_KEY *key, const uint8_t *sig, size_t siglen)
{
	HSS_SIGNATURE signature;

	if (!ctx || !key || !sig) {
		error_print();
		return -1;
	}
	if (hss_signature_from_bytes(&signature, &sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	if (siglen) {
		error_print();
		return -1;
	}

	if (hss_verify_init_ex(ctx, key, &signature) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int hss_verify_update(HSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (data && datalen) {
		if (lms_verify_update(&ctx->lms_ctx, data, datalen) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int hss_verify_finish(HSS_SIGN_CTX *ctx)
{
	int ret = -1;
	if (!ctx) {
		error_print();
		return -1;
	}
	if ((ret = lms_verify_finish(&ctx->lms_ctx)) != 1) {
		error_print();
		return ret;
	}
	return 1;
}

int hss_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const HSS_SIGNATURE *sig)
{
	size_t i;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	format_print(fp, fmt, ind, "num_signed_public_keys: %d\n", sig->num_signed_public_keys);

	for (i = 0; i < sig->num_signed_public_keys; i++) {
		char title[64];
		snprintf(title, sizeof(title), "lms_signature[%zu]", i);
		lms_signature_print_ex(fp, fmt, ind, title, &sig->signed_public_keys[0].lms_sig);
		snprintf(title, sizeof(title), "lms_public_key[%zu]", i + 1);
		lms_public_key_print(fp, fmt, ind, title, &sig->signed_public_keys[0].lms_public_key);
	}
	lms_signature_print_ex(fp, fmt, ind, "message_signature", &sig->msg_lms_sig);

	return 1;
}

int hss_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen)
{
	LMS_SIGNATURE lms_sig;
	size_t lms_siglen;
	LMS_PUBLIC_KEY lms_pub;

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


	format_print(fp, fmt, ind, "num_signed_public_keys: %d\n", num);

	for (i = 0; i < num; i++) {
		char title[64];

		if (lms_signature_from_bytes(&lms_sig, &sig, &siglen) != 1) {
			error_print();
			return -1;
		}
		snprintf(title, sizeof(title), "lms_signature[%d]", i);
		lms_signature_print_ex(fp, fmt, ind, title, &lms_sig);

		if (lms_public_key_from_bytes((LMS_KEY *)&lms_pub, &sig, &siglen) != 1) {
			error_print();
			return -1;
		}
		snprintf(title, sizeof(title), "lms_public_key[%d]", i + 1);
		lms_public_key_print(fp, fmt, ind, title, &lms_pub);
	}

	if (lms_signature_from_bytes(&lms_sig, &sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	lms_signature_print_ex(fp, fmt, ind, "message_signature", &lms_sig);

	return 1;
}

int hss_private_key_size(const int *lms_types, size_t levels, size_t *len)
{
	size_t i;

	if (!lms_types || !len) {
		error_print();
		return -1;
	}
	if (levels < 1 || levels > HSS_MAX_LEVELS) {
		error_print();
		return -1;
	}

	*len = sizeof(uint32_t) + LMS_PRIVATE_KEY_SIZE * levels;
	for (i = 0; i < levels - 1; i++) {
		size_t siglen;
		if (lms_signature_size(lms_types[i], &siglen) != 1) {
			error_print();
			return -1;
		}
		*len += siglen;
	}

	return 1;
}

// X.509 related
int hss_public_key_to_der(const HSS_KEY *key, uint8_t **out, size_t *outlen)
{
	uint8_t octets[HSS_PUBLIC_KEY_SIZE];
	uint8_t *p = octets;
	size_t len = 0;

	if (!key) {
		return 0;
	}

	if (hss_public_key_to_bytes(key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (len != sizeof(octets)) {
		error_print();
		return -1;
	}
	if (asn1_bit_octets_to_der(octets, sizeof(octets), out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int hss_public_key_from_der(HSS_KEY *key, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_bit_octets_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (dlen != HSS_PUBLIC_KEY_SIZE) {
		error_print();
		return -1;
	}

	if (hss_public_key_from_bytes(key, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	if (dlen) {
		error_print();
		return -1;
	}

	return 1;
}

int hss_public_key_algor_to_der(uint8_t **out, size_t *outlen)
{
	if (x509_public_key_algor_to_der(OID_hss_lms_hashsig, OID_undef, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int hss_public_key_algor_from_der(const uint8_t **in, size_t *inlen)
{
	int ret;
	int oid;
	int param = OID_undef;

	if ((ret = x509_public_key_algor_from_der(&oid, &param, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (oid != OID_hss_lms_hashsig) {
		error_print();
		return -1;
	}
	// param == 0: parameter is empty
	// param == 1: parameter is null object
	// param == other values, x509_public_key_algor_from_der fail
	return 1;
}

int hss_public_key_info_to_der(const HSS_KEY *key, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (hss_public_key_algor_to_der(NULL, &len) != 1
		|| hss_public_key_to_der(key, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| hss_public_key_algor_to_der(out, outlen) != 1
		|| hss_public_key_to_der(key, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int hss_public_key_info_from_der(HSS_KEY *key, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (hss_public_key_algor_from_der(&d, &dlen) != 1
		|| hss_public_key_from_der(key, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}
