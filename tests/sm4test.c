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
#include <gmssl/hex.h>
#include <gmssl/sm4.h>
#include <gmssl/error.h>
#include <gmssl/rand.h>


static int test_sm4(void)
{
	const uint8_t user_key[16] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	};
	const uint32_t rk[32] = {
		0xf12186f9, 0x41662b61, 0x5a6ab19a, 0x7ba92077,
		0x367360f4, 0x776a0c61, 0xb6bb89b3, 0x24763151,
		0xa520307c, 0xb7584dbd, 0xc30753ed, 0x7ee55b57,
		0x6988608c, 0x30d895b7, 0x44ba14af, 0x104495a1,
		0xd120b428, 0x73b55fa3, 0xcc874966, 0x92244439,
		0xe89e641f, 0x98ca015a, 0xc7159060, 0x99e1fd2e,
		0xb79bd80c, 0x1d2115b0, 0x0e228aeb, 0xf1780c81,
		0x428d3654, 0x62293496, 0x01cf72e5, 0x9124a012,
	};
	const uint8_t plaintext[16] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	};
	const uint8_t ciphertext[16] = {
		0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
		0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
	};
	const uint8_t ciphertext1m[16] = {
		0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f,
		0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66,
	};

	SM4_KEY key;
	unsigned char buf[16];
	int i;

	/* test key scheduling */
	sm4_set_encrypt_key(&key, user_key);

	if (memcmp(key.rk, rk, sizeof(rk)) != 0) {
		fprintf(stderr, "sm4 key scheduling not passed!\n");
		return -1;
	}

	/* test encrypt once */
	sm4_encrypt(&key, plaintext, buf);
	if (memcmp(buf, ciphertext, sizeof(ciphertext)) != 0) {
		fprintf(stderr, "sm4 encrypt not pass!\n");
		return -1;
	}

	/* test encrypt 1000000 times */
	memcpy(buf, plaintext, sizeof(plaintext));
	for (i = 0; i < 1000000; i++) {
		sm4_encrypt(&key, buf, buf);
	}
	if (memcmp(buf, ciphertext1m, sizeof(ciphertext1m)) != 0) {
		fprintf(stderr, "sm4 encrypt 1000000 times not pass!\n");
		return -1;
	}

	/* test decrypt */
	memset(&key, 0, sizeof(key));
	memset(buf, 0, sizeof(buf));
	sm4_set_decrypt_key(&key, user_key);
	sm4_decrypt(&key, ciphertext, buf);
	if (memcmp(buf, plaintext, sizeof(plaintext)) != 0) {
		fprintf(stderr, "sm4 decrypt not pass!\n");
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_cbc(void)
{
	SM4_KEY sm4_key;
	uint8_t key[16] = {0};
	uint8_t iv[16] = {0};
	uint8_t buf1[32] = {0};
	uint8_t buf2[32] = {0};
	uint8_t buf3[32] = {0};

	sm4_set_encrypt_key(&sm4_key, key);
	sm4_cbc_encrypt(&sm4_key, iv, buf1, 2, buf2);
	sm4_set_decrypt_key(&sm4_key, key);
	sm4_cbc_decrypt(&sm4_key, iv, buf2, 2, buf3);

	if (memcmp(buf1, buf3, sizeof(buf3)) != 0) {
		fprintf(stderr, "%s %d: error\n", __FILE__, __LINE__);
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_cbc_padding(void)
{
	SM4_KEY enc_key;
	SM4_KEY dec_key;
	uint8_t key[16] = {0};
	uint8_t iv[16] = {0};
	uint8_t buf1[64];
	uint8_t buf2[128];
	uint8_t buf3[128];
	size_t len1, len2, len3;

	sm4_set_encrypt_key(&enc_key, key);
	sm4_set_decrypt_key(&dec_key, key);

	len1 = 0;
	sm4_cbc_padding_encrypt(&enc_key, iv, buf1, len1, buf2, &len2);
	sm4_cbc_padding_decrypt(&dec_key, iv, buf2, len2, buf3, &len3);
	if (len1 != len3 || memcmp(buf1, buf3, len3) != 0) {
		fprintf(stderr, "%s %d: error\n", __FILE__, __LINE__);
		return -1;
	}

	len1 = 7;
	sm4_cbc_padding_encrypt(&enc_key, iv, buf1, len1, buf2, &len2);
	sm4_cbc_padding_decrypt(&dec_key, iv, buf2, len2, buf3, &len3);
	if (len1 != len3 || memcmp(buf1, buf3, len3) != 0) {
		fprintf(stderr, "%s %d: error\n", __FILE__, __LINE__);
		return -1;
	}

	len1 = 16;
	sm4_cbc_padding_encrypt(&enc_key, iv, buf1, len1, buf2, &len2);
	sm4_cbc_padding_decrypt(&dec_key, iv, buf2, len2, buf3, &len3);
	if (len1 != len3 || memcmp(buf1, buf3, len3) != 0) {
		fprintf(stderr, "%s %d: error\n", __FILE__, __LINE__);
		return -1;
	}

	len1 = 33;
	sm4_cbc_padding_encrypt(&enc_key, iv, buf1, len1, buf2, &len2);
	sm4_cbc_padding_decrypt(&dec_key, iv, buf2, len2, buf3, &len3);
	if (len1 != len3 || memcmp(buf1, buf3, len3) != 0) {
		fprintf(stderr, "%s %d: error\n", __FILE__, __LINE__);
		return -1;
	}

	len1 = sizeof(buf1);
	sm4_cbc_padding_encrypt(&enc_key, iv, buf1, len1, buf2, &len2);
	sm4_cbc_padding_decrypt(&dec_key, iv, buf2, len2, buf3, &len3);
	if (len1 != len3 || memcmp(buf1, buf3, len3) != 0) {
		fprintf(stderr, "%s %d: error\n", __FILE__, __LINE__);
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_ctr(void)
{
	SM4_KEY sm4_key;
	uint8_t key[16] = {0};
	uint8_t ctr[16];
	uint8_t buf1[30] = {0};
	uint8_t buf2[30] = {0};
	uint8_t buf3[30] = {0};

	sm4_set_encrypt_key(&sm4_key, key);
	memset(ctr, 0, sizeof(ctr));
	sm4_ctr_encrypt(&sm4_key, ctr, buf1, sizeof(buf1), buf2);

	memset(ctr, 0, sizeof(ctr));
	sm4_ctr_decrypt(&sm4_key, ctr, buf2, sizeof(buf2), buf3);

	if (memcmp(buf1, buf3, sizeof(buf3)) != 0) {
		fprintf(stderr, "%s %d: error\n", __FILE__, __LINE__);
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_ctr_with_carray(void)
{
	const char *hex_key =	"0123456789ABCDEFFEDCBA9876543210";
	const char *hex_ctr =	"0000000000000000000000000000FFFF";
	const char *hex_in  =	"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"
				"CCCCCCCCCCCCCCCCDDDDDDDDDDDD";
	const char *hex_out =	"7EA678F9F0CBE2000917C63D4E77B4C8"
				"6E4E8532B0046E4AC1E97DA8B831";

	SM4_KEY sm4_key;
	uint8_t key[16] = {0};
	uint8_t ctr[16];
	uint8_t buf1[30] = {0};
	uint8_t buf2[30] = {0};
	uint8_t buf3[30] = {0};

	size_t keylen, ctrlen, inlen, outlen;

	hex_to_bytes(hex_key, strlen(hex_key), key, &keylen);
	hex_to_bytes(hex_ctr, strlen(hex_ctr), ctr, &ctrlen);
	hex_to_bytes(hex_in, strlen(hex_in), buf1, &inlen);
	hex_to_bytes(hex_out, strlen(hex_out), buf3, &outlen);

	sm4_set_encrypt_key(&sm4_key, key);

	sm4_ctr_encrypt(&sm4_key, ctr, buf1, sizeof(buf1), buf2);

	if (memcmp(buf2, buf3, sizeof(buf3)) != 0) {
		error_print();
		return -1;
	}

	hex_to_bytes(hex_ctr, strlen(hex_ctr), ctr, &ctrlen);
	sm4_ctr_decrypt(&sm4_key, ctr, buf3, sizeof(buf3), buf2);

	if (memcmp(buf2, buf1, sizeof(buf1)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

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

static int test_sm4_cbc_update(void)
{
	SM4_KEY sm4_key;
	SM4_CBC_CTX enc_ctx;
	SM4_CBC_CTX dec_ctx;

	uint8_t key[16];
	uint8_t iv[16];
	uint8_t mbuf[16 * 10];
	uint8_t cbuf[16 * 11];
	uint8_t pbuf[16 * 11];
	size_t mlen = 0;
	size_t clen = 0;
	size_t plen = 0;

	uint8_t *in;
	uint8_t *out;
	size_t len;
	size_t lens[] = { 1,5,17,80 };
	int i;

	rand_bytes(key, sizeof(key));
	rand_bytes(iv, sizeof(iv));



	// first test

	mlen = 16;
	rand_bytes(mbuf, mlen);

	if (sm4_cbc_encrypt_init(&enc_ctx, key, iv) != 1
		|| sm4_cbc_encrypt_update(&enc_ctx, mbuf, mlen, cbuf, &clen) != 1
		|| sm4_cbc_encrypt_finish(&enc_ctx, cbuf + clen, &len) != 1) {
		error_print();
		return -1;
	}
	clen += len;

	// check ciphertext
	sm4_set_encrypt_key(&sm4_key, key);
	sm4_cbc_padding_encrypt(&sm4_key, iv, mbuf, mlen, pbuf, &plen);
	if (clen != plen || memcmp(cbuf, pbuf, plen) != 0) {
		error_print();
		return -1;
	}

	// check decrypt
	if (sm4_cbc_decrypt_init(&dec_ctx, key, iv) != 1
		|| sm4_cbc_decrypt_update(&dec_ctx, cbuf, clen, pbuf, &plen) != 1
		|| sm4_cbc_decrypt_finish(&dec_ctx, pbuf + plen, &len) != 1) {
		error_print();
		return -1;
	}
	plen += len;
	if (plen != mlen || memcmp(pbuf, mbuf, mlen) != 0) {
		error_print();
		return -1;
	}


	// second test

	rand_bytes(mbuf, sizeof(mbuf));

	if (sm4_cbc_encrypt_init(&enc_ctx, key, iv) != 1) {
		error_print();
		return -1;
	}
	in = mbuf;
	out = cbuf;
	mlen = 0;
	clen = 0;
	for (i = 0; i < sizeof(lens)/sizeof(lens[0]); i++) {
		if (sm4_cbc_encrypt_update(&enc_ctx, in, lens[i], out, &len) != 1) {
			error_print();
			return -1;
		}
		in += lens[i];
		mlen += lens[i];
		out += len;
		clen += len;

	}
	if (sm4_cbc_encrypt_finish(&enc_ctx, out, &len) != 1) {
		error_print();
		return -1;
	}
	clen += len;

	// check ciphertest
	sm4_cbc_padding_encrypt(&sm4_key, iv, mbuf, mlen, pbuf, &plen);
	if (plen != clen || memcmp(pbuf, cbuf, clen) != 0) {
		error_print();
		return -1;
	}

	// check decrypt
	if (sm4_cbc_decrypt_init(&dec_ctx, key, iv) != 1) {
		error_print();
		return -1;
	}
	plen = 0;
	in = cbuf;
	out = pbuf;
	for (i = 0; i < sizeof(lens)/sizeof(lens[0]); i++) {
		if (sm4_cbc_decrypt_update(&dec_ctx, in, lens[i], out, &len) != 1) {
			error_print();
			return -1;
		}
		in += lens[i];
		clen -= lens[i];
		out += len;
		plen += len;
	}
	if (sm4_cbc_decrypt_update(&dec_ctx, in, clen, out, &len) != 1) {
		error_print();
		return -1;
	}
	out += len;
	plen += len;
	if (sm4_cbc_decrypt_finish(&dec_ctx, out, &len) != 1) {
		error_print();
		return -1;
	}
	plen += len;

	if (plen != mlen || memcmp(pbuf, mbuf, mlen) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_ctr_update(void)
{
	SM4_KEY sm4_key;
	SM4_CTR_CTX enc_ctx;
	SM4_CTR_CTX dec_ctx;

	uint8_t key[16];
	uint8_t iv[16];
	uint8_t ctr[16];
	uint8_t mbuf[16 * 10];
	uint8_t cbuf[16 * 11];
	uint8_t pbuf[16 * 11];
	size_t mlen = 0;
	size_t clen = 0;
	size_t plen = 0;

	uint8_t *in;
	uint8_t *out;
	size_t len;
	size_t lens[] = { 1,5,17,80 };
	int i;

	rand_bytes(key, sizeof(key));
	rand_bytes(iv, sizeof(iv));

	// first test

	mlen = 16;
	rand_bytes(mbuf, mlen);
	memcpy(ctr, iv, sizeof(iv));
	if (sm4_ctr_encrypt_init(&enc_ctx, key, ctr) != 1
		|| sm4_ctr_encrypt_update(&enc_ctx, mbuf, mlen, cbuf, &clen) != 1
		|| sm4_ctr_encrypt_finish(&enc_ctx, cbuf + clen, &len) != 1) {
		error_print();
		return -1;
	}
	clen += len;

	// check ciphertext
	sm4_set_encrypt_key(&sm4_key, key);
	sm4_ctr_encrypt(&sm4_key, ctr, mbuf, mlen, pbuf); // 注意：sm4_ctr_encrypt() 会修改ctr的值
	memcpy(ctr, iv, sizeof(iv));
	if (memcmp(cbuf, pbuf, clen) != 0) {
		error_print();
		return -1;
	}

	// check decrypt
	if (sm4_ctr_decrypt_init(&dec_ctx, key, ctr) != 1
		|| sm4_ctr_decrypt_update(&dec_ctx, cbuf, clen, pbuf, &plen) != 1
		|| sm4_ctr_decrypt_finish(&dec_ctx, pbuf + plen, &len) != 1) {
		error_print();
		return -1;
	}
	plen += len;

	if (plen != mlen || memcmp(pbuf, mbuf, mlen) != 0) {
		error_print();
		return -1;
	}


	// second test

	rand_bytes(mbuf, sizeof(mbuf));

	if (sm4_ctr_encrypt_init(&enc_ctx, key, ctr) != 1) {
		error_print();
		return -1;
	}
	in = mbuf;
	out = cbuf;
	mlen = 0;
	clen = 0;
	for (i = 0; i < sizeof(lens)/sizeof(lens[0]); i++) {
		if (sm4_ctr_encrypt_update(&enc_ctx, in, lens[i], out, &len) != 1) {
			error_print();
			return -1;
		}
		in += lens[i];
		mlen += lens[i];
		out += len;
		clen += len;

	}
	if (sm4_ctr_encrypt_finish(&enc_ctx, out, &len) != 1) {
		error_print();
		return -1;
	}
	clen += len;

	// check ciphertest
	sm4_ctr_encrypt(&sm4_key, ctr, mbuf, mlen, pbuf);
	memcpy(ctr, iv, sizeof(iv));
	if (memcmp(pbuf, cbuf, mlen) != 0) {
		error_print();
		return -1;
	}

	// check decrypt
	if (sm4_ctr_decrypt_init(&dec_ctx, key, ctr) != 1) {
		error_print();
		return -1;
	}
	plen = 0;
	in = cbuf;
	out = pbuf;
	for (i = 0; i < sizeof(lens)/sizeof(lens[0]); i++) {
		if (sm4_ctr_decrypt_update(&dec_ctx, in, lens[i], out, &len) != 1) {
			error_print();
			return -1;
		}
		in += lens[i];
		clen -= lens[i];
		out += len;
		plen += len;
	}
	if (sm4_ctr_decrypt_update(&dec_ctx, in, clen, out, &len) != 1) {
		error_print();
		return -1;
	}
	out += len;
	plen += len;
	if (sm4_ctr_decrypt_finish(&dec_ctx, out, &len) != 1) {
		error_print();
		return -1;
	}
	plen += len;

	if (plen != mlen || memcmp(pbuf, mbuf, mlen) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_sm4() != 1) goto err;
	if (test_sm4_cbc() != 1) goto err;
	if (test_sm4_cbc_padding() != 1) goto err;
	if (test_sm4_ctr() != 1) goto err;
	if (test_sm4_gcm() != 1) goto err;
	if (test_sm4_gcm_gbt36624_1() != 1) goto err;
	if (test_sm4_gcm_gbt36624_2() != 1) goto err;
	if (test_sm4_cbc_update() != 1) goto err;
	if (test_sm4_ctr_update() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
