/* ====================================================================
 * Copyright (c) 2014 - 2017 The GmSSL Project.  All rights reserved.
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



/* ======================
* test unit for serpent-256
* Odzhan
*========================
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/e_os2.h>

#include "../e_os.h"

#ifdef OPENSSL_NO_SERPENT
int main(int argc, char **argv)
{
	printf("No Serpent support\n");
	return 0;
}
#else

#include <ctype.h>
#include <openssl/serpent.h>

char *plain[] =
{ "3DA46FFA6F4D6F30CD258333E5A61369" };

char *keys[] =
{ "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
};

char *cipher[] =
{ "00112233445566778899AABBCCDDEEFF" };

size_t hex2bin(void *bin, char hex[]) {
	size_t len, i;
	int x;
	uint8_t *p = (uint8_t*)bin;

	len = strlen(hex);

	if ((len & 1) != 0) {
		return 0;
	}

	for (i = 0; i<len; i++) {
		if (isxdigit((int)hex[i]) == 0) {
			return 0;
		}
	}

	for (i = 0; i<len / 2; i++) {
		sscanf(&hex[i * 2], "%2x", &x);
		p[i] = (uint8_t)x;
	}
	return len / 2;
}

void dump_hex(char *s, uint8_t bin[], int len)
{
	int i;
	printf("\n%s=", s);
	for (i = 0; i<len; i++) {
		printf("%02x", bin[i]);
	}
}

int main(void)
{
	uint8_t ct1[32], pt1[32], pt2[32], key[64];
	int klen, plen, clen, i, j;
	serpent_key_t skey;
	serpent_blk ct2;
	uint32_t *p;

	printf("\nserpent-256 test\n");

	for (i = 0; i<sizeof(keys) / sizeof(char*); i++) {
		clen = hex2bin(ct1, cipher[i]);
		plen = hex2bin(pt1, plain[i]);
		klen = hex2bin(key, keys[i]);

		/* set key */
		memset(&skey, 0, sizeof(skey));
		p = (uint32_t*)&skey.x[0][0];

		serpent_set_encrypt_key(&skey, key);
		printf("\nkey=");

		for (j = 0; j<sizeof(skey) / sizeof(serpent_subkey_t) * 4; j++) {
			if ((j % 8) == 0) 
				putchar('\n');
			printf("%08X ", p[j]);
		}

		/* encrypt */
		memcpy(ct2.b, pt1, SERPENT_BLOCK_SIZE);

		printf("\n\n");
		dump_hex("plaintext", ct2.b, 16);

		serpent_encrypt(pt1,ct2.b, &skey);

		dump_hex("ciphertext", ct2.b, 16);

		if (memcmp(ct1, ct2.b, clen) == 0) {
			printf("\nEncryption OK");
			serpent_decrypt(ct2.b,pt1, &skey);
			if (memcmp(pt1, ct2.b, plen) == 0) {
				printf("\nDecryption OK");
				dump_hex("plaintext", ct2.b, 16);
			}
			else {
				printf("\nDecryption failed");
			}
		}
		else {
			printf("\nEncryption failed");
		}
	}
	return 0;
}
#endif
