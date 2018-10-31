/* ====================================================================
 * Copyright (c) 2014 - 2018 The GmSSL Project. All rights reserved.
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
 * ====================================================================
 */
/*
 * This sm4 demo use the native sm3_init/update/final APIs
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sms4.h>
#include <openssl/is_gmssl.h>


int main(int argc, char **argv)
{
	sms4_key_t sms4;
	unsigned char key[SMS4_KEY_LENGTH] = {0};
	unsigned char block[SMS4_BLOCK_SIZE] = {0};
	int i;

#if USE_RANDOM
	if (!RAND_bytes(key, sizeof(key))
		|| !RAND_bytes(block, sizeof(block))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
#endif

	printf("key              = ");
	for (i = 0; i < sizeof(key); i++) {
		printf("%02X", key[i]);
	}
	printf("\n");

	printf("plaintext block  = ");
	for (i = 0; i < sizeof(block); i++) {
		printf("%02X", block[i]);
	}
	printf("\n");

	/* expand key for encryption */
	sms4_set_encrypt_key(&sms4, key);

	/* encrypt a block */
	sms4_encrypt(block, block, &sms4);

	printf("ciphertext block = ");
	for (i = 0; i < sizeof(block); i++) {
		printf("%02X", block[i]);
	}
	printf("\n");

	/* expand key for decryption */
	sms4_set_decrypt_key(&sms4, key);

	/* decrypt a block */
	sms4_decrypt(block, block, &sms4);

	printf("decrypted block  = ");
	for (i = 0; i < sizeof(block); i++) {
		printf("%02X", block[i]);
	}
	printf("\n");

	return 0;
}
