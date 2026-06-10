/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#include <stdio.h>
#include <gmssl/sm3.h>
#include <gmssl/oid.h>
#include <gmssl/digest.h>
#include <gmssl/error.h>


const DIGEST *digest_from_name(const char *name)
{
	if (!name) {
		error_print();
		return NULL;
	}
	if (!strcmp(name, "sm3")) {
		return DIGEST_sm3();
#ifdef ENABLE_SHA1
	} else if (!strcmp(name, "sha1")) {
		return DIGEST_sha1();
#endif
#ifdef ENABLE_SHA2
	} else if (!strcmp(name, "sha224")) {
		return DIGEST_sha224();
	} else if (!strcmp(name, "sha256")) {
		return DIGEST_sha256();
	} else if (!strcmp(name, "sha384")) {
		return DIGEST_sha384();
	} else if (!strcmp(name, "sha512")) {
		return DIGEST_sha512();
	} else if (!strcmp(name, "sha512-224")) {
		return DIGEST_sha512_224();
	} else if (!strcmp(name, "sha512-256")) {
		return DIGEST_sha512_256();
#endif
	}
	error_print();
	return NULL;
}

const char *digest_name(const DIGEST *digest)
{
	if (!digest) {
		error_print();
		return NULL;
	}
	switch (digest->oid) {
	case OID_sm3: return "sm3";
	case OID_sha1: return "sha1";
	case OID_sha224: return "sha224";
	case OID_sha256: return "sha256";
	case OID_sha384: return "sha384";
	case OID_sha512: return "sha512";
	case OID_sha512_224: return "sha512-224";
	case OID_sha512_256: return "sha512-256";
	}
	error_print();
	return NULL;
}

int digest_init(DIGEST_CTX *ctx, const DIGEST *algor)
{
	if (!ctx || !algor || !algor->init) {
		error_print();
		return -1;
	}
	memset(ctx, 0, sizeof(DIGEST_CTX));
	ctx->digest = algor;
	if (ctx->digest->init(ctx) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int digest_update(DIGEST_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx || !ctx->digest || !ctx->digest->update) {
		error_print();
		return -1;
	}
	if (!data && datalen) {
		error_print();
		return -1;
	}
	if (!data || !datalen) {
		return 1;
	}
	if (ctx->digest->update(ctx, data, datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int digest_finish(DIGEST_CTX *ctx, uint8_t *dgst, size_t *dgstlen)
{
	if (!ctx || !ctx->digest || !ctx->digest->finish || !dgst || !dgstlen) {
		error_print();
		return -1;
	}
	if (ctx->digest->finish(ctx, dgst) != 1) {
		error_print();
		return -1;
	}
	*dgstlen = ctx->digest->digest_size;
	return 1;
}

int digest(const DIGEST *digest, const uint8_t *data, size_t datalen,
	uint8_t *dgst, size_t *dgstlen)
{
	DIGEST_CTX ctx;
	if (digest_init(&ctx, digest) != 1
		|| digest_update(&ctx, data, datalen) != 1
		|| digest_finish(&ctx, dgst, dgstlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}


static int _sm3_digest_init(DIGEST_CTX *ctx)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	sm3_init(&ctx->u.sm3_ctx);
	return 1;
}

static int _sm3_digest_update(DIGEST_CTX *ctx, const uint8_t *in, size_t inlen)
{
	if (!ctx || (!in && inlen != 0)) {
		error_print();
		return -1;
	}
	sm3_update(&ctx->u.sm3_ctx, in, inlen);
	return 1;
}

static int _sm3_digest_finish(DIGEST_CTX *ctx, uint8_t *dgst)
{
	if (!ctx || !dgst) {
		error_print();
		return -1;
	}
	sm3_finish(&ctx->u.sm3_ctx, dgst);
	return 1;
}

static const DIGEST sm3_digest_object = {
	OID_sm3,
	SM3_DIGEST_SIZE,
	SM3_BLOCK_SIZE,
	sizeof(SM3_CTX),
	_sm3_digest_init,
	_sm3_digest_update,
	_sm3_digest_finish,
};

const DIGEST *DIGEST_sm3(void)
{
        return &sm3_digest_object;
}

#ifdef ENABLE_SHA1
#include <gmssl/sha1.h>

static int sha1_digest_init(DIGEST_CTX *ctx)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	sha1_init(&ctx->u.sha1_ctx);
	return 1;
}

static int sha1_digest_update(DIGEST_CTX *ctx, const uint8_t *in, size_t inlen)
{
	if (!ctx || (!in && inlen != 0)) {
		error_print();
		return -1;
	}
	sha1_update(&ctx->u.sha1_ctx, in, inlen);
	return 1;
}

static int sha1_digest_finish(DIGEST_CTX *ctx, uint8_t *dgst)
{
	if (!ctx || !dgst) {
		error_print();
		return -1;
	}
	sha1_finish(&ctx->u.sha1_ctx, dgst);
	return 1;
}

static const DIGEST sha1_digest_object = {
	OID_sha1,
	SHA1_DIGEST_SIZE,
	SHA1_BLOCK_SIZE,
	sizeof(SHA1_CTX),
	sha1_digest_init,
	sha1_digest_update,
	sha1_digest_finish,
};

const DIGEST *DIGEST_sha1(void)
{
        return &sha1_digest_object;
}
#endif // ENABLE SHA1

#ifdef ENABLE_SHA2
#include <gmssl/sha2.h>

static int sha224_digest_init(DIGEST_CTX *ctx)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	sha224_init(&ctx->u.sha224_ctx);
	return 1;
}

static int sha224_digest_update(DIGEST_CTX *ctx, const uint8_t *in, size_t inlen)
{
	if (!ctx || (!in && inlen != 0)) {
		error_print();
		return -1;
	}
	sha224_update(&ctx->u.sha224_ctx, in, inlen);
	return 1;
}

static int sha224_digest_finish(DIGEST_CTX *ctx, uint8_t *dgst)
{
	if (!ctx || !dgst) {
		error_print();
		return -1;
	}
	sha224_finish(&ctx->u.sha224_ctx, dgst);
	return 1;
}

static const DIGEST sha224_digest_object = {
	OID_sha224,
	SHA224_DIGEST_SIZE,
	SHA224_BLOCK_SIZE,
	sizeof(SHA224_CTX),
	sha224_digest_init,
	sha224_digest_update,
	sha224_digest_finish,
};

const DIGEST *DIGEST_sha224(void)
{
        return &sha224_digest_object;
}

static int sha256_digest_init(DIGEST_CTX *ctx)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	sha256_init(&ctx->u.sha256_ctx);
	return 1;
}

static int sha256_digest_update(DIGEST_CTX *ctx, const uint8_t *in, size_t inlen)
{
	if (!ctx || (!in && inlen != 0)) {
		error_print();
		return -1;
	}
	sha256_update(&ctx->u.sha256_ctx, in, inlen);
	return 1;
}

static int sha256_digest_finish(DIGEST_CTX *ctx, uint8_t *dgst)
{
	if (!ctx || !dgst) {
		error_print();
		return -1;
	}
	sha256_finish(&ctx->u.sha256_ctx, dgst);
	return 1;
}

static const DIGEST sha256_digest_object = {
	OID_sha256,
	SHA256_DIGEST_SIZE,
	SHA256_BLOCK_SIZE,
	sizeof(SHA256_CTX),
	sha256_digest_init,
	sha256_digest_update,
	sha256_digest_finish,
};

const DIGEST *DIGEST_sha256(void)
{
        return &sha256_digest_object;
}


static int sha384_digest_init(DIGEST_CTX *ctx)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	sha384_init(&ctx->u.sha384_ctx);
	return 1;
}

static int sha384_digest_update(DIGEST_CTX *ctx, const uint8_t *in, size_t inlen)
{
	if (!ctx || (!in && inlen != 0)) {
		error_print();
		return -1;
	}
	sha384_update(&ctx->u.sha384_ctx, in, inlen);
	return 1;
}

static int sha384_digest_finish(DIGEST_CTX *ctx, uint8_t *dgst)
{
	if (!ctx || !dgst) {
		error_print();
		return -1;
	}
	sha384_finish(&ctx->u.sha384_ctx, dgst);
	return 1;
}

static const DIGEST sha384_digest_object = {
	OID_sha384,
	SHA384_DIGEST_SIZE,
	SHA384_BLOCK_SIZE,
	sizeof(SHA384_CTX),
	sha384_digest_init,
	sha384_digest_update,
	sha384_digest_finish,
};

const DIGEST *DIGEST_sha384(void)
{
        return &sha384_digest_object;
}


static int sha512_digest_init(DIGEST_CTX *ctx)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	sha512_init(&ctx->u.sha512_ctx);
	return 1;
}

static int sha512_224_digest_init(DIGEST_CTX *ctx)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	sha512_224_init(&ctx->u.sha512_ctx);
	return 1;
}

static int sha512_256_digest_init(DIGEST_CTX *ctx)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	sha512_256_init(&ctx->u.sha512_ctx);
	return 1;
}

static int sha512_digest_update(DIGEST_CTX *ctx, const uint8_t *in, size_t inlen)
{
	if (!ctx || (!in && inlen != 0)) {
		error_print();
		return -1;
	}
	sha512_update(&ctx->u.sha512_ctx, in, inlen);
	return 1;
}

static int sha512_digest_finish(DIGEST_CTX *ctx, uint8_t *dgst)
{
	if (!ctx || !dgst) {
		error_print();
		return -1;
	}
	sha512_finish(&ctx->u.sha512_ctx, dgst);
	return 1;
}

static int sha512_224_digest_finish(DIGEST_CTX *ctx, uint8_t *dgst)
{
	if (!ctx || !dgst) {
		error_print();
		return -1;
	}
	sha512_224_finish(&ctx->u.sha512_ctx, dgst);
	return 1;
}

static int sha512_256_digest_finish(DIGEST_CTX *ctx, uint8_t *dgst)
{
	if (!ctx || !dgst) {
		error_print();
		return -1;
	}
	sha512_256_finish(&ctx->u.sha512_ctx, dgst);
	return 1;
}


static const DIGEST sha512_digest_object = {
	OID_sha512,
	SHA512_DIGEST_SIZE,
	SHA512_BLOCK_SIZE,
	sizeof(SHA512_CTX),
	sha512_digest_init,
	sha512_digest_update,
	sha512_digest_finish,
};

const DIGEST *DIGEST_sha512(void)
{
        return &sha512_digest_object;
}

static const DIGEST sha512_224_digest_object = {
	OID_sha512_224,
	SHA224_DIGEST_SIZE,
	SHA512_BLOCK_SIZE,
	sizeof(SHA512_CTX),
	sha512_224_digest_init,
	sha512_digest_update,
	sha512_224_digest_finish,
};

const DIGEST *DIGEST_sha512_224(void)
{
        return &sha512_224_digest_object;
}

static const DIGEST sha512_256_digest_object = {
	OID_sha512_256,
	SHA256_DIGEST_SIZE,
	SHA512_BLOCK_SIZE,
	sizeof(SHA512_CTX),
	sha512_256_digest_init,
	sha512_digest_update,
	sha512_256_digest_finish,
};

const DIGEST *DIGEST_sha512_256(void)
{
        return &sha512_256_digest_object;
}
#endif // ENABLE_SHA2
