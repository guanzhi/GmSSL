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
#include <gmssl/mem.h>
#include <gmssl/sm2.h>
#include <gmssl/sm2_z256.h>
#include <gmssl/sm3.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>


int sm2_sign_init(SM2_SIGN_CTX *ctx, const SM2_KEY *key, const char *id, size_t idlen)
{
	size_t i;

	if (!ctx || !key) {
		error_print();
		return -1;
	}
	ctx->key = *key;

	// d' = (d + 1)^-1 (mod n)
	sm2_z256_from_bytes(ctx->sign_key, key->private_key);
	sm2_z256_modn_add(ctx->sign_key, ctx->sign_key, sm2_z256_one());
	sm2_z256_modn_inv(ctx->sign_key, ctx->sign_key);

	sm3_init(&ctx->sm3_ctx);

	if (id) {
		uint8_t z[SM3_DIGEST_SIZE];
		if (idlen <= 0 || idlen > SM2_MAX_ID_LENGTH) {
			error_print();
			return -1;
		}
		sm2_compute_z(z, &key->public_key, id, idlen);
		sm3_update(&ctx->sm3_ctx, z, sizeof(z));
	}

	ctx->inited_sm3_ctx = ctx->sm3_ctx;

	// pre compute (k, x = [k]G.x)
	for (i = 0; i < 32; i++) {
		if (sm2_do_sign_pre_compute(ctx->pre_comp[i].k, ctx->pre_comp[i].x1) != 1) {
			error_print();
			return -1;
		}
	}
	ctx->num_pre_comp = 32;

	return 1;
}

int sm2_sign_ctx_reset(SM2_SIGN_CTX *ctx)
{
	ctx->sm3_ctx = ctx->inited_sm3_ctx;
	return 1;
}

int sm2_sign_update(SM2_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (data && datalen > 0) {
		sm3_update(&ctx->sm3_ctx, data, datalen);
	}
	return 1;
}

int sm2_sign_finish(SM2_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen)
{
	uint8_t dgst[SM3_DIGEST_SIZE];
	SM2_SIGNATURE signature;

	if (!ctx || !sig || !siglen) {
		error_print();
		return -1;
	}
	sm3_finish(&ctx->sm3_ctx, dgst);

	if (ctx->num_pre_comp == 0) {
		size_t i;
		for (i = 0; i < 32; i++) {
			if (sm2_do_sign_pre_compute(ctx->pre_comp[i].k, ctx->pre_comp[i].x1) != 1) {
				error_print();
				return -1;
			}
		}
		ctx->num_pre_comp = 32;
	}

	ctx->num_pre_comp--;
	if (sm2_do_sign_fast_ex(ctx->sign_key,
		ctx->pre_comp[ctx->num_pre_comp].k, ctx->pre_comp[ctx->num_pre_comp].x1,
		dgst, &signature) != 1) {
		error_print();
		return -1;
	}

	*siglen = 0;
	if (sm2_signature_to_der(&signature, &sig, siglen) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int sm2_sign_finish_fixlen(SM2_SIGN_CTX *ctx, size_t siglen, uint8_t *sig)
{
	uint8_t dgst[SM3_DIGEST_SIZE];

	if (!ctx || !sig || !siglen) {
		error_print();
		return -1;
	}
	sm3_finish(&ctx->sm3_ctx, dgst);
	if (sm2_sign_fixlen(&ctx->key, dgst, siglen, sig) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_verify_init(SM2_SIGN_CTX *ctx, const SM2_KEY *key, const char *id, size_t idlen)
{
	if (!ctx || !key) {
		error_print();
		return -1;
	}
	memset(ctx, 0, sizeof(*ctx));
	ctx->key.public_key = key->public_key;

	sm2_z256_point_from_bytes((SM2_Z256_POINT *)&ctx->public_key, (const uint8_t *)&key->public_key);

	sm3_init(&ctx->sm3_ctx);

	if (id) {
		uint8_t z[SM3_DIGEST_SIZE];
		if (idlen <= 0 || idlen > SM2_MAX_ID_LENGTH) {
			error_print();
			return -1;
		}
		sm2_compute_z(z, &key->public_key, id, idlen);
		sm3_update(&ctx->sm3_ctx, z, sizeof(z));
	}

	ctx->inited_sm3_ctx = ctx->sm3_ctx;

	return 1;
}

int sm2_verify_update(SM2_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (data && datalen > 0) {
		sm3_update(&ctx->sm3_ctx, data, datalen);
	}
	return 1;
}

int sm2_verify_finish(SM2_SIGN_CTX *ctx, const uint8_t *sig, size_t siglen)
{
	uint8_t dgst[SM3_DIGEST_SIZE];

	if (!ctx || !sig) {
		error_print();
		return -1;
	}
	sm3_finish(&ctx->sm3_ctx, dgst);
	if (sm2_verify(&ctx->key, dgst, sig, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_encrypt_init(SM2_ENC_CTX *ctx, const SM2_KEY *sm2_key)
{
	if (!ctx || !sm2_key) {
		error_print();
		return -1;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->sm2_key = *sm2_key;

	return 1;
}

int sm2_encrypt_update(SM2_ENC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	if (!ctx || !outlen) {
		error_print();
		return -1;
	}

	if (ctx->buf_size > SM2_MAX_PLAINTEXT_SIZE) {
		error_print();
		return -1;
	}

	if (!out) {
		*outlen = 0;
		return 1;
	}

	if (in) {
		if (inlen > SM2_MAX_PLAINTEXT_SIZE - ctx->buf_size) {
			error_print();
			return -1;
		}

		memcpy(ctx->buf + ctx->buf_size, in, inlen);
		ctx->buf_size += inlen;
	}

	*outlen = 0;
	return 1;
}

int sm2_encrypt_finish(SM2_ENC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	if (!ctx || !outlen) {
		error_print();
		return -1;
	}

	if (ctx->buf_size > SM2_MAX_PLAINTEXT_SIZE) {
		error_print();
		return -1;
	}

	if (!out) {
		*outlen = SM2_MAX_CIPHERTEXT_SIZE;
		return 1;
	}

	if (ctx->buf_size) {
		if (in) {
			if (inlen > SM2_MAX_PLAINTEXT_SIZE - ctx->buf_size) {
				error_print();
				return -1;
			}
			memcpy(ctx->buf + ctx->buf_size, in, inlen);
			ctx->buf_size += inlen;
		}
		if (sm2_encrypt(&ctx->sm2_key, ctx->buf, ctx->buf_size, out, outlen) != 1) {
			error_print();
			return -1;
		}
	} else {
		if (!in || !inlen || inlen > SM2_MAX_PLAINTEXT_SIZE) {
			error_print();
			return -1;
		}
		if (sm2_encrypt(&ctx->sm2_key, in, inlen, out, outlen) != 1) {
			error_print();
			return -1;
		}
	}

	return 1;
}


int sm2_decrypt_init(SM2_ENC_CTX *ctx, const SM2_KEY *sm2_key)
{
	if (!ctx || !sm2_key) {
		error_print();
		return -1;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->sm2_key = *sm2_key;

	return 1;
}

int sm2_decrypt_update(SM2_ENC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	if (!ctx || !outlen) {
		error_print();
		return -1;
	}

	if (ctx->buf_size > SM2_MAX_CIPHERTEXT_SIZE) {
		error_print();
		return -1;
	}

	if (!out) {
		*outlen = 0;
		return 1;
	}

	if (in) {
		if (inlen > SM2_MAX_CIPHERTEXT_SIZE - ctx->buf_size) {
			error_print();
			return -1;
		}

		memcpy(ctx->buf + ctx->buf_size, in, inlen);
		ctx->buf_size += inlen;
	}

	*outlen = 0;
	return 1;
}

int sm2_decrypt_finish(SM2_ENC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	if (!ctx || !outlen) {
		error_print();
		return -1;
	}

	if (ctx->buf_size > SM2_MAX_CIPHERTEXT_SIZE) {
		error_print();
		return -1;
	}

	if (!out) {
		*outlen = SM2_MAX_PLAINTEXT_SIZE;
		return 1;
	}

	if (ctx->buf_size) {
		if (in) {
			if (inlen > SM2_MAX_CIPHERTEXT_SIZE - ctx->buf_size) {
				error_print();
				return -1;
			}
			memcpy(ctx->buf + ctx->buf_size, in, inlen);
			ctx->buf_size += inlen;
		}
		if (sm2_decrypt(&ctx->sm2_key, ctx->buf, ctx->buf_size, out, outlen) != 1) {
			error_print();
			return -1;
		}
	} else {
		if (!in || !inlen || inlen > SM2_MAX_CIPHERTEXT_SIZE) {
			error_print();
			return -1;
		}
		if (sm2_decrypt(&ctx->sm2_key, in, inlen, out, outlen) != 1) {
			error_print();
			return -1;
		}
	}

	return 1;
}
