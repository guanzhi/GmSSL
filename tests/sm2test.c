/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm2.h>


// SM2还需要大量的测试覆盖
/*
void sm2_point_to_compressed_octets(const SM2_POINT *P, uint8_t out[33]);
void sm2_point_to_uncompressed_octets(const SM2_POINT *P, uint8_t out[65]);
int sm2_point_from_octets(SM2_POINT *P, const uint8_t *in, size_t inlen);
int sm2_point_from_x(SM2_POINT *P, const uint8_t x[32]);
int sm2_point_from_xy(SM2_POINT *P, const uint8_t x[32], const uint8_t y[32]);
int sm2_point_is_on_curve(const SM2_POINT *P);
*/

static int test_sm2_point(void)
{
	SM2_POINT P;
	uint8_t k[32] = {0};
	uint8_t buf[65] = {0};
	int i;

	k[31] = 2;

	printf("k = "); for (i = 0; i < 32; i++) printf("%02x", k[i]); printf("\n");

	sm2_point_mul_generator(&P, k);

	printf("k * G :\n");
	sm2_point_print(stdout, &P, 0, 2);

	sm2_point_to_compressed_octets(&P, buf);
	for (i = 0; i < 33; i++) printf("%02x", buf[i]); printf("\n");

	memset(buf, 0, sizeof(buf));
	sm2_point_to_uncompressed_octets(&P, buf);
	for (i = 0; i < 65; i++) printf("%02x", buf[i]); printf("\n");

	memset(&P, 0, sizeof(SM2_POINT));
	/*
	i = sm2_point_from_x(&P, buf + 1);
	printf("sm2_point_from_x: %d\n", i);
	*/

	sm2_point_from_octets(&P, buf, 65);

	i = sm2_point_is_on_curve(&P);
	printf("point_is_on_curve: %d\n", i);

	return 1;
}


static int test_sm2_do_encrypt(void)
{
	SM2_KEY key;
	uint8_t plaintext[] = "Hello World!";
	uint8_t cipherbuf[SM2_CIPHERTEXT_SIZE(sizeof(plaintext))] = {0};
	SM2_CIPHERTEXT *ciphertext = (SM2_CIPHERTEXT *)cipherbuf;
	uint8_t plainbuf[sizeof(cipherbuf)] = {0};
	size_t plainlen = 0;
	int r = 0;

	sm2_keygen(&key);

	sm2_do_encrypt(&key, plaintext, sizeof(plaintext), ciphertext);

	printf("ciphertext:\n");
	sm2_ciphertext_print(stdout, ciphertext, 0, 2);

	sm2_do_decrypt(&key, ciphertext, plainbuf, &plainlen);

	printf("plaintext = %s\n", (char *)plainbuf);
	return r;
}

static int test_sm2_sign(void)
{
	SM2_KEY key;
	SM2_SIGN_CTX ctx;
	uint8_t msg[] = "Hello World!";
	uint8_t sig[128] = {0};
	size_t siglen = sizeof(sig);
	int i;
	int r;

	sm2_keygen(&key);
	sm2_key_print(stdout, &key, 0, 0);

	sm2_sign_init(&ctx, &key, SM2_DEFAULT_ID);
	sm2_sign_update(&ctx, msg, sizeof(msg));
	sm2_sign_finish(&ctx, sig, &siglen);

	printf("signature:\n");
	sm2_print_signature(stdout, sig, siglen, 0, 2);

	sm2_verify_init(&ctx, &key, SM2_DEFAULT_ID);
	sm2_verify_update(&ctx, msg, sizeof(msg));
	r = sm2_verify_finish(&ctx, sig, siglen);
	printf("verify %s\n", r > 0 ? "success" : "failed");

	return 0;
}

int main(void)
{
	sm2_algo_selftest();

	//test_sm2_point();
	//test_sm2_sign();
	test_sm2_do_encrypt();

	return 0;
}
