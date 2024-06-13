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
#include <assert.h>
#include <time.h>
#include <gmssl/hex.h>
#include <gmssl/sm4.h>
#include <gmssl/error.h>
#include <gmssl/rand.h>


static int test_sm4_gcm(void)
{
	// gcm test vectors from rfc 8998 A.1
	const char *hex_key =	"0123456789ABCDEFFEDCBA9876543210";
	const char *hex_iv  =	"00001234567800000000ABCD";
	const char *hex_aad =	"FEEDFACEDEADBEEFFEEDFACEDEADBEEF"
				"ABADDAD2";
	const char *hex_in =	"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"
				"CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD"
				"EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF"
				"EEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA";
	const char *hex_out =	"17F399F08C67D5EE19D0DC9969C4BB7D"
				"5FD46FD3756489069157B282BB200735"
				"D82710CA5C22F0CCFA7CBF93D496AC15"
				"A56834CBCF98C397B4024A2691233B8D";
	const char *hex_tag =	"83DE3541E4C2B58177E065A9BF7B62EC";

	SM4_KEY sm4_key;
	uint8_t key[16];
	uint8_t iv[12];
	uint8_t aad[20];
	uint8_t in[64];
	uint8_t out[64];
	uint8_t tag[16];
	size_t keylen, ivlen, aadlen, inlen, outlen, taglen;

	uint8_t buf[64];
	uint8_t mac[16];

	hex_to_bytes(hex_key, strlen(hex_key), key, &keylen);
	hex_to_bytes(hex_iv, strlen(hex_iv), iv, &ivlen);
	hex_to_bytes(hex_aad, strlen(hex_aad), aad, &aadlen);
	hex_to_bytes(hex_in, strlen(hex_in), in, &inlen);
	hex_to_bytes(hex_out, strlen(hex_out), out, &outlen);
	hex_to_bytes(hex_tag, strlen(hex_tag), tag, &taglen);

	memset(buf, 0, sizeof(buf));
	memset(mac, 0, sizeof(mac));

	sm4_set_encrypt_key(&sm4_key, key);

	// test gcm encrypt
	sm4_gcm_encrypt(&sm4_key, iv, ivlen, aad, aadlen, in, inlen, buf, taglen, mac);
	if (memcmp(buf, out, outlen) != 0) {
		error_print();
		return -1;
	}
	if (memcmp(mac, tag, taglen) != 0) {
		error_print();
		return -1;
	}

	// test gcm decrypt
	memset(buf, 0, sizeof(buf));
	sm4_gcm_decrypt(&sm4_key, iv, ivlen, aad, aadlen, out, outlen, tag, taglen, buf);
	if (memcmp(buf, in, inlen) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_gcm_gbt36624_1(void)
{
	// gcm test vectors from GB/T 36624-2018 C.5
	const char *hex_key = "00000000000000000000000000000000";
	const char *hex_iv  = "000000000000000000000000";
	const char *hex_aad = "";
	const char *hex_in  = "";
	const char *hex_out = "";
	const char *hex_tag = "232F0CFE308B49EA6FC88229B5DC858D";

	SM4_KEY sm4_key;
	uint8_t key[16];
	uint8_t iv[12];
	uint8_t aad[20];
	uint8_t in[64];
	uint8_t out[64];
	uint8_t tag[16];
	size_t keylen, ivlen, aadlen, inlen, outlen, taglen;

	uint8_t buf[64];
	uint8_t mac[16];

	hex_to_bytes(hex_key, strlen(hex_key), key, &keylen);
	hex_to_bytes(hex_iv, strlen(hex_iv), iv, &ivlen);
	hex_to_bytes(hex_aad, strlen(hex_aad), aad, &aadlen);
	hex_to_bytes(hex_in, strlen(hex_in), in, &inlen);
	hex_to_bytes(hex_out, strlen(hex_out), out, &outlen);
	hex_to_bytes(hex_tag, strlen(hex_tag), tag, &taglen);

	memset(buf, 0, sizeof(buf));
	memset(mac, 0, sizeof(mac));

	sm4_set_encrypt_key(&sm4_key, key);

	// test gcm encrypt
	sm4_gcm_encrypt(&sm4_key, iv, ivlen, aad, aadlen, in, inlen, buf, taglen, mac);
	if (memcmp(buf, out, outlen) != 0) {
		error_print();
		return -1;
	}
	if (memcmp(mac, tag, taglen) != 0) {
		error_print();
		return -1;
	}

	// test gcm decrypt
	memset(buf, 0, sizeof(buf));
	sm4_gcm_decrypt(&sm4_key, iv, ivlen, aad, aadlen, out, outlen, tag, taglen, buf);
	if (memcmp(buf, in, inlen) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_gcm_gbt36624_2(void)
{
	// gcm test vectors from GB/T 36624-2018 C.5
	const char *hex_key = "00000000000000000000000000000000";
	const char *hex_iv  = "000000000000000000000000";
	const char *hex_aad = "";
	const char *hex_in  = "00000000000000000000000000000000";
	const char *hex_out = "7DE2AA7F1110188218063BE1BFEB6D89";
	const char *hex_tag = "B851B5F39493752BE508F1BB4482C557";

	SM4_KEY sm4_key;
	uint8_t key[16];
	uint8_t iv[12];
	uint8_t aad[20];
	uint8_t in[64];
	uint8_t out[64];
	uint8_t tag[16];
	size_t keylen, ivlen, aadlen, inlen, outlen, taglen;

	uint8_t buf[64];
	uint8_t mac[16];

	hex_to_bytes(hex_key, strlen(hex_key), key, &keylen);
	hex_to_bytes(hex_iv, strlen(hex_iv), iv, &ivlen);
	hex_to_bytes(hex_aad, strlen(hex_aad), aad, &aadlen);
	hex_to_bytes(hex_in, strlen(hex_in), in, &inlen);
	hex_to_bytes(hex_out, strlen(hex_out), out, &outlen);
	hex_to_bytes(hex_tag, strlen(hex_tag), tag, &taglen);

	memset(buf, 0, sizeof(buf));
	memset(mac, 0, sizeof(mac));

	sm4_set_encrypt_key(&sm4_key, key);

	// test gcm encrypt
	sm4_gcm_encrypt(&sm4_key, iv, ivlen, aad, aadlen, in, inlen, buf, taglen, mac);
	if (memcmp(buf, out, outlen) != 0) {
		error_print();
		return -1;
	}
	if (memcmp(mac, tag, taglen) != 0) {
		error_print();
		return -1;
	}

	// test gcm decrypt
	memset(buf, 0, sizeof(buf));
	sm4_gcm_decrypt(&sm4_key, iv, ivlen, aad, aadlen, out, outlen, tag, taglen, buf);
	if (memcmp(buf, in, inlen) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_gcm_ctx(void)
{
	SM4_GCM_CTX aead_ctx;
	uint8_t key[16];
	uint8_t iv[16];
	uint8_t aad[29];
	uint8_t plain[71];
	size_t plainlen = sizeof(plain);
	uint8_t cipher[256];
	size_t cipherlen = 0;
	uint8_t buf[256];
	size_t buflen = 0;

	size_t lens[] = { 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 };
	uint8_t *in = plain;
	uint8_t *out = cipher;
	size_t inlen, outlen;
	size_t i;

	rand_bytes(key, sizeof(key));
	rand_bytes(iv, sizeof(iv));
	rand_bytes(aad, sizeof(aad));
	rand_bytes(plain, plainlen);

	if (sm4_gcm_encrypt_init(&aead_ctx, key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad), GHASH_SIZE) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; plainlen; i++) {
		assert(i < sizeof(lens)/sizeof(lens[0]));

		inlen = plainlen < lens[i] ? plainlen  : lens[i];
		if (sm4_gcm_encrypt_update(&aead_ctx, in, inlen, out, &outlen) != 1) {
			error_print();
			return -1;
		}
		in += inlen;
		plainlen -= inlen;
		out += outlen;
		cipherlen += outlen;
	}
	if (sm4_gcm_encrypt_finish(&aead_ctx, out, &outlen) != 1) {
		error_print();
		return -1;
	}
	out += outlen;
	cipherlen += outlen;

	format_bytes(stdout, 0, 4, "plaintext ", plain, sizeof(plain));
	format_bytes(stdout, 0, 4, "ciphertext", cipher, cipherlen);

	{
		SM4_KEY sm4_key;
		uint8_t tmp[256];
		size_t tmplen;

		sm4_set_encrypt_key(&sm4_key, key);

		if (sm4_gcm_encrypt(&sm4_key, iv, sizeof(iv), aad, sizeof(aad), plain, sizeof(plain),
			tmp, GHASH_SIZE, tmp + sizeof(plain)) != 1) {
			error_print();
			return -1;
		}
		tmplen = sizeof(plain) + GHASH_SIZE;

		format_bytes(stdout, 0, 4, "ciphertext", tmp, tmplen);

		if (cipherlen != tmplen
			|| memcmp(cipher, tmp, tmplen) != 0) {
			error_print();
			return -1;
		}
	}

	in = cipher;
	out = buf;

	if (sm4_gcm_decrypt_init(&aead_ctx, key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad), GHASH_SIZE) != 1) {
		error_print();
		return -1;
	}
	for (i = sizeof(lens)/sizeof(lens[0]) - 1; cipherlen; i--) {
		inlen = cipherlen < lens[i] ? cipherlen : lens[i];

		if (sm4_gcm_decrypt_update(&aead_ctx, in, inlen, out, &outlen) != 1) {
			error_print();
			return -1;
		}
		in += inlen;
		cipherlen -= inlen;
		out += outlen;
		buflen += outlen;

	}
	if (sm4_gcm_decrypt_finish(&aead_ctx, out, &outlen) != 1) {
		error_print();
		return -1;
	}
	out += outlen;
	buflen += outlen;

	format_bytes(stdout, 0, 4, "plaintext ", buf, buflen);

	if (buflen != sizeof(plain)) {
		error_print();
		return -1;
	}
	if (memcmp(buf, plain, sizeof(plain)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int speed_sm4_gcm_encrypt(void)
{
	SM4_KEY sm4_key;
	uint8_t key[16] = {0};
	uint8_t iv[12];
	uint8_t aad[16];
	uint8_t tag[16];
	uint32_t buf[1024];
	clock_t begin, end;
	double seconds;
	int i;

	sm4_set_encrypt_key(&sm4_key, key);

	for (i = 0; i < 4096; i++) {
		sm4_gcm_encrypt(&sm4_key, iv, sizeof(iv), aad, sizeof(aad), (uint8_t *)buf, sizeof(buf), (uint8_t *)buf, 16, tag);
	}
	begin = clock();
	for (i = 0; i < 4096; i++) {
		sm4_gcm_encrypt(&sm4_key, iv, sizeof(iv), aad, sizeof(aad), (uint8_t *)buf, sizeof(buf), (uint8_t *)buf, 16, tag);
	}
	end = clock();

	seconds = (double)(end - begin)/ CLOCKS_PER_SEC;
	fprintf(stderr, "%s: %f MiB per second\n", __FUNCTION__, 16/seconds);

	return 1;
}

int main(void)
{
	if (test_sm4_gcm() != 1) goto err;
	if (test_sm4_gcm_gbt36624_1() != 1) goto err;
	if (test_sm4_gcm_gbt36624_2() != 1) goto err;
	if (test_sm4_gcm_ctx() != 1) goto err;
#if ENABLE_TEST_SPEED
	if (speed_sm4_gcm_encrypt() != 1) goto err;
#endif
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
