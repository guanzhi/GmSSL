/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
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


typedef struct {
	int oid;
	char *short_name;
	char *display_name;
} DIGEST_TABLE;

DIGEST_TABLE digest_table[] = {
	{ OID_sm3, "sm3", "SM3" },
#ifdef ENABLE_BROKEN_CRYPTO
	{ OID_md5, "md5", "MD5" },
	{ OID_sha1, "sha1", "SHA-1" },
#endif
	{ OID_sha224, "sha224", "SHA-224" },
	{ OID_sha256, "sha256", "SHA-256" },
	{ OID_sha384, "sha384", "SHA-384" },
	{ OID_sha512, "sha512", "SHA-512" },
};

const char *digest_name(const DIGEST *digest)
{
	int i;
	for (i = 0; i < sizeof(digest_table)/sizeof(digest_table[0]); i++) {
		if (digest->oid == digest_table[i].oid) {
			return digest_table[i].short_name;
		}
	}
	return NULL;
}

int digest_init(DIGEST_CTX *ctx, const DIGEST *algor)
{
	memset(ctx, 0, sizeof(DIGEST_CTX));
	if (algor == NULL) {
		error_print();
		return -1;
	}
	ctx->digest = algor;
	ctx->digest->init(ctx);
	return 1;
}

int digest_update(DIGEST_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (data == NULL || datalen == 0) {
		return 0;
	}
	ctx->digest->update(ctx, data, datalen);
	return 1;
}

int digest_finish(DIGEST_CTX *ctx, uint8_t *dgst, size_t *dgstlen)
{
	if (dgst == NULL || dgstlen == NULL) {
		error_print();
		return -1;
	}
	ctx->digest->finish(ctx, dgst);
	*dgstlen = ctx->digest->digest_size;
	return 1;
}

int digest(const DIGEST *digest, const uint8_t *data, size_t datalen,
	uint8_t *dgst, size_t *dgstlen)
{
	DIGEST_CTX ctx;
	if (digest_init(&ctx, digest) != 1
		|| digest_update(&ctx, data, datalen) < 0
		|| digest_finish(&ctx, dgst, dgstlen) != 1) {
		error_print();
		return -1;
	}
	memset(&ctx, 0, sizeof(DIGEST_CTX));
	return 1;
}

const DIGEST *digest_from_name(const char *name)
{
	if (!strcmp(name, "sm3") || !strcmp(name, "SM3")) {
		return DIGEST_sm3();
#ifdef ENABLE_BROKEN_CRYPTO
	} else if (!strcmp(name, "md5") || !strcmp(name, "MD5")) {
		return DIGEST_md5();
	} else if (!strcmp(name, "sha1") || !strcmp(name, "SHA1")) {
		return DIGEST_sha1();
#endif
	} else if (!strcmp(name, "sha224") || !strcmp(name, "SHA224")) {
		return DIGEST_sha224();
	} else if (!strcmp(name, "sha256") || !strcmp(name, "SHA256")) {
		return DIGEST_sha256();
	} else if (!strcmp(name, "sha384") || !strcmp(name, "SHA384")) {
		return DIGEST_sha384();
	} else if (!strcmp(name, "sha512") || !strcmp(name, "SHA512")) {
		return DIGEST_sha512();
	} else if (!strcmp(name, "sha512-224") || !strcmp(name, "SHA512-224")) {
		return DIGEST_sha512_224();
	} else if (!strcmp(name, "sha512-256") || !strcmp(name, "SHA512-256")) {
		return DIGEST_sha512_256();
	}
	return NULL;
}

static int sm3_digest_init(DIGEST_CTX *ctx)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	sm3_init(&ctx->u.sm3_ctx);
	return 1;
}

static int sm3_digest_update(DIGEST_CTX *ctx, const uint8_t *in, size_t inlen)
{
	if (!ctx || (!in && inlen != 0)) {
		error_print();
		return -1;
	}
	sm3_update(&ctx->u.sm3_ctx, in, inlen);
	return 1;
}

static int sm3_digest_finish(DIGEST_CTX *ctx, uint8_t *dgst)
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
	sm3_digest_init,
	sm3_digest_update,
	sm3_digest_finish,
};

const DIGEST *DIGEST_sm3(void)
{
        return &sm3_digest_object;
}

#ifdef ENABLE_BROKEN_CRYPTO

#include <gmssl/md5.h>

static int md5_digest_init(DIGEST_CTX *ctx)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	md5_init(&ctx->u.md5_ctx);
	return 1;
}

static int md5_digest_update(DIGEST_CTX *ctx, const uint8_t *in, size_t inlen)
{
	if (!ctx || (!in && inlen != 0)) {
		error_print();
		return -1;
	}
	md5_update(&ctx->u.md5_ctx, in, inlen);
	return 1;
}

static int md5_digest_finish(DIGEST_CTX *ctx, uint8_t *dgst)
{
	if (!ctx || !dgst) {
		error_print();
		return -1;
	}
	md5_finish(&ctx->u.md5_ctx, dgst);
	return 1;
}

static const DIGEST md5_digest_object = {
	OID_md5,
	MD5_DIGEST_SIZE,
	MD5_BLOCK_SIZE,
	sizeof(MD5_CTX),
	md5_digest_init,
	md5_digest_update,
	md5_digest_finish,
};

const DIGEST *DIGEST_md5(void)
{
        return &md5_digest_object;
}


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
#endif

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


static int sha512_224_digest_finish(DIGEST_CTX *ctx, uint8_t *dgst)
{
	uint8_t buf[SHA512_DIGEST_SIZE];
	if (!ctx || !dgst) {
		error_print();
		return -1;
	}
	sha512_finish(&ctx->u.sha512_ctx, buf);
	memcpy(dgst, buf, SHA224_DIGEST_SIZE);
	memset(buf, 0, sizeof(buf));
	return 1;
}

static const DIGEST sha512_224_digest_object = {
	OID_sha512_224,
	SHA224_DIGEST_SIZE,
	SHA512_BLOCK_SIZE,
	sizeof(SHA512_CTX),
	sha512_digest_init,
	sha512_digest_update,
	sha512_224_digest_finish,
};

const DIGEST *DIGEST_sha512_224(void)
{
        return &sha512_224_digest_object;
}


static int sha512_256_digest_finish(DIGEST_CTX *ctx, uint8_t *dgst)
{
	uint8_t buf[SHA512_DIGEST_SIZE];
	if (!ctx || !dgst) {
		error_print();
		return -1;
	}
	sha512_finish(&ctx->u.sha512_ctx, buf);
	memcpy(dgst, buf, SHA256_DIGEST_SIZE);
	memset(buf, 0, sizeof(buf));
	return 1;
}


static const DIGEST sha512_256_digest_object = {
	OID_sha512_256,
	SHA256_DIGEST_SIZE,
	SHA512_BLOCK_SIZE,
	sizeof(SHA512_CTX),
	sha512_digest_init,
	sha512_digest_update,
	sha512_256_digest_finish,
};

const DIGEST *DIGEST_sha512_256(void)
{
        return &sha512_256_digest_object;
}
