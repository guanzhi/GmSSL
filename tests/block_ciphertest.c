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
#include <gmssl/block_cipher.h>


int block_cipher_sm4_test(void)
{
	static char *iv_hex[] = {
		"A9993E364706816ABA3E25717850C26C9CD0D89D",
		"A9993E364706816ABA3E25717850C26C9CD0D89D",
	};

	// 提供256比特的密钥长度
	static char *key_hex[] = {
	};

	static char *plaintext_hex[] = {
	};

	static char *ciphertext_hex[] = {
	};

	const BLOCK_CIPEHR *cipher;
	BLOCK_CIPHER_KEY cipher_key;
	uint8_t key[32];
	uint8_t iv[16];
	uint8_t plaintext[16 * 3];
	uint8_t ciphertext[16 * 4];
	uint8_t buf[16 * 4];

	for (i = 0; i < NUM_TESTS; i++) {
		hex2bin(key_hex, strlen(key_hex), key);
		hex2bin(iv_hex, strlen(iv_hex), iv);
		hex2bin(plaintext_hex, strlen(plaintext_hex), plaintext);
		hex2bin(ciphertext_hex, strlen(ciphertext_hex), ciphertext);

		block_cipher_set_encrypt_key(&cipher_key, cipher, key, 16, iv);
		block_cipher_cbc_encrypt(&cipher_key, iv, plaintext, 3, buf);

		if (memcmp(buf, 16 * 3, ciphertext) != 0) {
		}
	}

	return 0;
}
