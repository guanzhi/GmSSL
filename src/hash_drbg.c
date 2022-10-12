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
#include <gmssl/hash_drbg.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>


static int hash_df(const DIGEST *digest, const uint8_t *in, size_t inlen,
	size_t outlen, uint8_t *out)
{
	int ret = 0;
	DIGEST_CTX ctx;
	uint8_t counter;
	uint8_t outbits[4];
	unsigned char dgst[64];
	size_t len;

	counter = 0x01;
	PUTU32(outbits, (uint32_t)outlen << 3);

	while (outlen > 0) {
		if (digest_init(&ctx, digest) != 1
			|| digest_update(&ctx, &counter, sizeof(counter)) != 1
			|| digest_update(&ctx, outbits, sizeof(outbits)) != 1
			|| digest_update(&ctx, in, inlen) != 1
			|| digest_finish(&ctx, dgst, &len) != 1) {
			goto end;
		}

		if (outlen < len) {
			len = outlen;
		}
		memcpy(out, dgst, len);
		out += len;
		outlen -= len;

		counter++;
	}

	ret = 1;
end:
	memset(&ctx, 0, sizeof(ctx));
	memset(dgst, 0, sizeof(dgst));
	return ret;
}

int hash_drbg_init(HASH_DRBG *drbg, const DIGEST *digest,
	const uint8_t *entropy, size_t entropy_len,
	const uint8_t *nonce, size_t nonce_len,
	const uint8_t *personalstr, size_t personalstr_len)
{
	int ret = 0;
	unsigned char *seed_material = NULL;
	size_t seed_material_len;
	uint8_t buf[1 + HASH_DRBG_MAX_SEED_SIZE];
	uint8_t *p;

	memset(drbg, 0, sizeof(HASH_DRBG));

	/* set digest */
	drbg->digest = digest;

	/* set seedlen */
	if (digest->digest_size <= 32) {
		drbg->seedlen = HASH_DRBG_SM3_SEED_SIZE;
	} else {
		drbg->seedlen = HASH_DRBG_SHA512_SEED_SIZE;
	}

	/* seed_material = entropy_input || nonce || personalization_string */
	seed_material_len = entropy_len + nonce_len + personalstr_len;
	if (!(seed_material = malloc(seed_material_len))) {
		return 0;
	}
	p = seed_material;
	memcpy(p, entropy, entropy_len);
	p += entropy_len;
	memcpy(p, nonce, nonce_len);
	p += nonce_len;
	memcpy(p, personalstr, personalstr_len);

	/* V = Hash_df (seed_material, seedlen) */
	if (!hash_df(drbg->digest, seed_material, seed_material_len, drbg->seedlen,
		drbg->V)) {
		goto end;
	}

	/* C = Hash_df ((0x00 || V), seedlen) */
	buf[0] = 0x00;
	memcpy(buf + 1, drbg->V, drbg->seedlen);
	if (!hash_df(drbg->digest, buf, 1 + drbg->seedlen, drbg->seedlen,
		drbg->C)) {
		goto end;
	}

	/* reseed_counter = 1 */
	drbg->reseed_counter = 1;

	ret = 1;
end:
	if (seed_material) {
		memset(seed_material, 0, seed_material_len);
		free(seed_material);
	}
	memset(buf, 0, sizeof(buf));
	return ret;
}

int hash_drbg_reseed(HASH_DRBG *drbg,
	const uint8_t *entropy, size_t entropy_len,
	const uint8_t *additional, size_t additional_len)
{
	int ret = 0;
	uint8_t *seed_material = NULL;
	size_t seed_material_len;
	uint8_t *p;
	uint8_t buf[1 + HASH_DRBG_MAX_SEED_SIZE];

	/* seed_material = 0x01 || V || entropy_input || additional_input */
	seed_material_len = 1 + drbg->seedlen + entropy_len + additional_len;
	if (!(seed_material = malloc(seed_material_len))) {
		return 0;
	}
	seed_material[0] = 0x01;
	p = seed_material + 1;
	memcpy(p, drbg->V, drbg->seedlen);
	p += drbg->seedlen;
	memcpy(p, entropy, entropy_len);
	p += entropy_len;
	memcpy(p, additional, additional_len);

	/* V = Hash_df(seed_material, seedlen) */
	if (!hash_df(drbg->digest, seed_material, seed_material_len, drbg->seedlen,
		drbg->V)) {
		goto end;
	}

	/* C = Hash_df((0x00 || V), seedlen) */
	buf[0] = 0x00;
	memcpy(buf + 1, drbg->V, drbg->seedlen);
	if (!hash_df(drbg->digest, buf, 1 + drbg->seedlen, drbg->seedlen,
		drbg->C)) {
		goto end;
	}

	/* reseed_counter = 1 */
	drbg->reseed_counter = 1;

	ret = 1;
end:
	if (seed_material) {
		memset(seed_material, 0, seed_material_len);
		free(seed_material);
	}
	memset(buf, 0, sizeof(buf));
	return ret;
}

/* seedlen is always >= dgstlen
 *      R0 ...  Ru-v .. .. ..   Ru-1
 *    +          A0    A1 A2 .. Av-1
 */
static void drbg_add(uint8_t *R, const uint8_t *A, size_t seedlen)
{
	int temp = 0;
	while (seedlen--) {
		temp += R[seedlen] + A[seedlen];
		R[seedlen] = temp & 0xff;
		temp >>= 8;
	}
}

static void drbg_add1(uint8_t *R, size_t seedlen)
{
	int temp = 1;
	while (seedlen--) {
		temp += R[seedlen];
		R[seedlen] = temp & 0xff;
		temp >>= 8;
	}
}

static int drbg_hashgen(HASH_DRBG *drbg, size_t outlen, uint8_t *out)
{
	int ret = 0;
	DIGEST_CTX ctx;
	uint8_t data[HASH_DRBG_MAX_SEED_SIZE];
	uint8_t dgst[DIGEST_MAX_SIZE];
	size_t len;

	/* data = V */
	memcpy(data, drbg->V, drbg->seedlen);

	while (outlen > 0) {

		/* output Hash(data) */
		if (digest_init(&ctx, drbg->digest) != 1
			|| digest_update(&ctx, data, drbg->seedlen) != 1
			|| digest_finish(&ctx, dgst, &len) != 1) {
			goto end;
		}

		if (outlen < len) {
			len = outlen;
		}
		memcpy(out, dgst, len);
		out += len;
		outlen -= len;

		/* data = (data + 1) mod 2^seedlen */
		drbg_add1(data, drbg->seedlen);
	}

	ret = 1;
end:
	memset(&ctx, 0, sizeof(ctx));
	memset(data, 0, sizeof(data));
	return ret;
}

int hash_drbg_generate(HASH_DRBG *drbg,
	const uint8_t *additional, size_t additional_len,
	size_t outlen, uint8_t *out)
{
	int ret = 0;
	DIGEST_CTX ctx;
	uint8_t prefix;
	uint8_t T[HASH_DRBG_MAX_SEED_SIZE];
	uint8_t dgst[DIGEST_MAX_SIZE];
	size_t dgstlen;

	// FIXME: check outlen max value

	if (drbg->reseed_counter > HASH_DRBG_RESEED_INTERVAL) {
		return 0;
	}

	if (additional) {
		/* w = Hash (0x02 || V || additional_input) */
		prefix = 0x02;
		if (digest_init(&ctx, drbg->digest) != 1
			|| digest_update(&ctx, &prefix, 1) != 1
			|| digest_update(&ctx, drbg->V, drbg->seedlen) != 1
			|| digest_update(&ctx, additional, additional_len) != 1
			|| digest_finish(&ctx, dgst, &dgstlen) != 1) {
			goto end;
		}

		/* V = (V + w) mod 2^seedlen */
		memset(T, 0, drbg->seedlen - dgstlen);
		memcpy(T + drbg->seedlen - dgstlen, dgst, dgstlen);
		drbg_add(drbg->V, T, drbg->seedlen);
	}

	/* (returned_bits) = Hashgen (requested_number_of_bits, V). */
	drbg_hashgen(drbg, outlen, out);

	/* H = Hash (0x03 || V). */
	prefix = 0x03;
	if (digest_init(&ctx, drbg->digest) != 1
		|| digest_update(&ctx, &prefix, 1) != 1
		|| digest_update(&ctx, drbg->V, drbg->seedlen) != 1
		|| digest_finish(&ctx, dgst, &dgstlen) != 1) {
		goto end;
	}

	/* V = (V + H + C + reseed_counter) mod 2^seedlen */
	memset(T, 0, drbg->seedlen - dgstlen);
	memcpy(T + drbg->seedlen - dgstlen, dgst, dgstlen);
	drbg_add(drbg->V, T, drbg->seedlen);

	drbg_add(drbg->V, drbg->C, drbg->seedlen);

	memset(T, 0, drbg->seedlen - sizeof(uint64_t));
	PUTU64(T + drbg->seedlen - sizeof(uint64_t), drbg->reseed_counter);
	drbg_add(drbg->V, T, drbg->seedlen);

	/* reseed_counter = reseed_counter + 1 */
	drbg->reseed_counter++;

	ret = 1;
end:
	memset(&ctx, 0, sizeof(ctx));
	memset(T, 0, sizeof(T));
	memset(dgst, 0, sizeof(dgst));
	return ret;
}
