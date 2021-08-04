/*
 * Copyright (c) 2014 - 2020 The GmSSL Project.  All rights reserved.
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
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/hash_drbg.h>
#include "endian.h"

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

	digest_ctx_init(&ctx);

	while (outlen > 0) {
		if (!digest_init(&ctx, digest)
			|| !digest_update(&ctx, &counter, sizeof(counter))
			|| !digest_update(&ctx, outbits, sizeof(outbits))
			|| !digest_update(&ctx, in, inlen)
			|| !digest_finish(&ctx, dgst, &len)) {
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
	digest_ctx_cleanup(&ctx);
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
	if (digest_size(digest) <= 32) {
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
	size_t i;
	for (i = seedlen - 1; i >= 0; i--) {
		temp += R[i] + A[i];
		R[i] = temp & 0xff;
		temp >>= 8;
	}
}

static void drbg_add1(uint8_t *R, size_t seedlen)
{
	int temp = 1;
	size_t i;
	for (i = seedlen - 1; i >= 0; i--) {
		temp += R[i];
		R[i] = temp & 0xff;
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

	digest_ctx_init(&ctx);

	/* data = V */
	memcpy(data, drbg->V, drbg->seedlen);

	while (outlen > 0) {

		/* output Hash(data) */
		if (!digest_init(&ctx, drbg->digest)
			|| !digest_update(&ctx, data, drbg->seedlen)
			|| !digest_finish(&ctx, dgst, &len)) {
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

	digest_ctx_init(&ctx);

	if (additional) {
		/* w = Hash (0x02 || V || additional_input) */
		prefix = 0x02;
		if (!digest_init(&ctx, drbg->digest)
			|| !digest_update(&ctx, &prefix, 1)
			|| !digest_update(&ctx, drbg->V, drbg->seedlen)
			|| !digest_update(&ctx, additional, additional_len)
			|| !digest_finish(&ctx, dgst, &dgstlen)) {
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
	if (!digest_init(&ctx, drbg->digest)
		|| !digest_update(&ctx, &prefix, 1)
		|| !digest_update(&ctx, drbg->V, drbg->seedlen)
		|| !digest_finish(&ctx, dgst, &dgstlen)) {
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
	digest_ctx_cleanup(&ctx);
	memset(T, 0, sizeof(T));
	memset(dgst, 0, sizeof(dgst));
	return ret;
}
