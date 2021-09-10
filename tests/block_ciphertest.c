/*
 * Copyright (c) 2014 - 2020 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
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
