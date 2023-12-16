/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/rand.h>
#include <gmssl/aead.h>


int main(int argc, char **argv)
{
	int ret = -1;
	uint8_t key[SM4_CTR_SM3_HMAC_KEY_SIZE];
	uint8_t iv[SM4_CTR_SM3_HMAC_IV_SIZE];
	SM4_CTR_SM3_HMAC_CTX ctx;
	uint8_t aad[] = "Additianal Authenticated Data, authenticated only, not encrypted";
	uint8_t m1[] = "Plaintext part 1, to be encrypted and authenticated.";
	size_t m1len = sizeof(m1) - 1;
	uint8_t m2[] = "Plaintext part 2, to be encrypted and authenticated.";

	uint8_t c[256];
	uint8_t d[256];
	uint8_t *p;
	size_t clen, dlen, len;

	if (rand_bytes(key, sizeof(key)) != 1
		|| rand_bytes(iv, sizeof(iv)) != 1) {
		fprintf(stderr, "rand_bytes() error\n");
		goto end;
	}

	// encrypt

	if (sm4_ctr_sm3_hmac_encrypt_init(&ctx, key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad)) != 1) {
		fprintf(stderr, "sm4_ctr_sm3_hmac_encrypt_init() error\n");
		goto end;
	}

	p = c;
	clen = 0;

	if (sm4_ctr_sm3_hmac_encrypt_update(&ctx, m1, sizeof(m1)-1, p, &len) != 1) {
		fprintf(stderr, "sm4_ctr_sm3_hmac_encrypt_update() error\n");
		goto end;
	}
	p += len;
	clen += len;

	if (sm4_ctr_sm3_hmac_encrypt_update(&ctx, m2, sizeof(m2), p, &len) != 1) {
		fprintf(stderr, "sm4_ctr_sm3_hmac_encrypt_update() error\n");
		goto end;
	}
	p += len;
	clen += len;

	if (sm4_ctr_sm3_hmac_encrypt_finish(&ctx, p, &len) != 1) {
		fprintf(stderr, "sm4_ctr_sm3_hmac_encrypt_finish() error\n");
		goto end;
	}
	clen += len;

	// decrypt

	if (sm4_ctr_sm3_hmac_decrypt_init(&ctx, key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad)) != 1) {
		fprintf(stderr, "sm4_ctr_sm3_hmac_decrypt_init() error\n");
		goto end;
	}

	p = d;
	dlen = 0;

	if (sm4_ctr_sm3_hmac_decrypt_update(&ctx, c, clen, p, &len) != 1) {
		fprintf(stderr, "sm4_ctr_sm3_hmac_decrypt_update() error\n");
		goto end;
	}
	p += len;
	dlen += len;

	if (sm4_ctr_sm3_hmac_decrypt_finish(&ctx, p, &len) != 1) {
		fprintf(stderr, "sm4_ctr_sm3_hmac_decrypt_finish() error\n");
		goto end;
	}
	dlen += len;

	printf("Decrypted: %s\n", (char *)d);

	ret = 0;

end:
	gmssl_secure_clear(key, sizeof(key));
	gmssl_secure_clear(&ctx, sizeof(ctx));
	return ret;
}
