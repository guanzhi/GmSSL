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
#include <gmssl/sm4.h>
#include <gmssl/rand.h>

static int test_sm4_cbc(void)
{
	SM4_KEY sm4_key;
	uint8_t key[16] = {0};
	uint8_t iv[16];

	uint8_t buf1[2]  = {0};
	uint8_t buf2[32] = {0};
	uint8_t buf3[47] = {0};
	uint8_t buf4[96] = {0};
	uint8_t buf5[96];
	int i;

	sm4_set_encrypt_key(&sm4_key, key);
	sm4_cbc_encrypt(&sm4_key, iv, buf2, 2, buf4);

	for (i = 0; i < 32; i++) {
		printf("%02x", buf4[i]);
	}
	printf("\n");
	return 1;
}

static int test_sm4_cbc_padding(void)
{
	SM4_KEY enc_key;
	SM4_KEY dec_key;
	uint8_t key[16] = {0};
	uint8_t iv[16] = {0};
	uint8_t in[64];
	uint8_t out[128];
	uint8_t buf[128];
	size_t len1, len2, i;

	for (i = 0; i < sizeof(in); i++) {
		in[i] = i;
	}

	sm4_set_encrypt_key(&enc_key, key);
	sm4_set_decrypt_key(&dec_key, key);

	sm4_cbc_padding_encrypt(&enc_key, iv, in, 33, out, &len1);
	printf("c = (%zu) ", len1); for (i = 0; i < len1; i++) printf("%02x", out[i]); printf("\n");

	sm4_cbc_padding_decrypt(&dec_key, iv, out, len1, buf, &len2);
	printf("m = (%zu) ", len2); for (i = 0; i < len2; i++) printf("%02x", buf[i]); printf("\n");


	return 1;
}



int main(void)
{
	test_sm4_cbc();
	test_sm4_cbc_padding();
	return 1;
}
