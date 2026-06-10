/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdint.h>
#include <string.h>
#include <gmssl/mem.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>
#include <gmssl/pbkdf2.h>


int pbkdf2_hmac_genkey(const DIGEST *digest,
	const char *pass, size_t passlen, const uint8_t *salt, size_t saltlen,
	size_t iter, size_t outlen, uint8_t *out)
{
	int ret = -1;
	HMAC_CTX ctx;
	HMAC_CTX ctx_tmpl;
	uint8_t iter_be[4];
	uint8_t tmp_block[DIGEST_MAX_SIZE];
	uint8_t key_block[DIGEST_MAX_SIZE];
	uint32_t block_index = 1;
	size_t digest_size;
	size_t block_count;

	if (!digest || !iter || !outlen || !out) {
		error_print();
		return -1;
	}
	if (digest->digest_size > HMAC_MAX_SIZE
		|| !digest->digest_size) {
		error_print();
		return -1;
	}
	if (!pass && passlen) {
		error_print();
		return -1;
	}
	if (!salt && saltlen) {
		error_print();
		return -1;
	}

	digest_size = digest->digest_size;

	block_count = outlen / digest_size;
	if (outlen % digest_size) {
		block_count++;
	}
	if (block_count > UINT32_MAX) {
		error_print();
		return -1;
	}

	if (hmac_init(&ctx_tmpl, digest, (const uint8_t *)pass, passlen) != 1) {
		error_print();
		return -1;
	}

	while (outlen) {
		size_t maclen;
		size_t i;

		PUTU32(iter_be, block_index);
		block_index++;

		ctx = ctx_tmpl;
		if (hmac_update(&ctx, salt, saltlen) < 0
			|| hmac_update(&ctx, iter_be, sizeof(iter_be)) != 1
			|| hmac_finish(&ctx, tmp_block, &maclen) != 1) {
			error_print();
			goto end;
		}
		memcpy(key_block, tmp_block, digest_size);

		for (i = 1; i < iter; i++) {
			ctx = ctx_tmpl;
			if (hmac_update(&ctx, tmp_block, digest_size) != 1
				|| hmac_finish(&ctx, tmp_block, &maclen) != 1) {
				error_print();
				goto end;
			}
			memxor(key_block, tmp_block, digest_size);
		}

		if (outlen < digest_size) {
			memcpy(out, key_block, outlen);
			out += outlen;
			outlen = 0;
		} else {
			memcpy(out, key_block, digest_size);
			out += digest_size;
			outlen -= digest_size;
		}
	}

	ret = 1;

end:
	gmssl_secure_clear(&ctx, sizeof(ctx));
	gmssl_secure_clear(&ctx_tmpl, sizeof(ctx_tmpl));
	gmssl_secure_clear(key_block, sizeof(key_block));
	gmssl_secure_clear(tmp_block, sizeof(tmp_block));
	return ret;
}
