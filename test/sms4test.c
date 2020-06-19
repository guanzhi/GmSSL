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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../e_os.h"

#ifdef OPENSSL_NO_SMS4
int main(int argc, char **argv)
{
	printf("NO SMS4 support\n");
	return 0;
}
#else
# include <openssl/evp.h>
# include <openssl/sms4.h>
# include <openssl/rand.h>

# ifdef SMS4_AVX2
void sms4_avx2_ecb_encrypt_blocks(const unsigned char *in,
	unsigned char *out, size_t blocks, const sms4_key_t *key);
void sms4_avx2_ctr32_encrypt_blocks(const unsigned char *in,
	unsigned char *out, size_t blocks, const sms4_key_t *key,
	const unsigned char iv[16]);
# endif

static int test_ecb(int avx)
{
	sms4_key_t key;
	unsigned char user_key[16] = {0};
	/* 2 rounds avx-512 and 2 rounds x86 */
	unsigned char in[(16 * 2 + 2) * 16] = {0};
	unsigned char out1[sizeof(in)] = {0};
	unsigned char out2[sizeof(in)] = {0};
	int i;

	RAND_bytes(user_key, sizeof(user_key));
	RAND_bytes(in, sizeof(in));

	sms4_set_encrypt_key(&key, user_key);
	for (i = 0; i < sizeof(in)/SMS4_BLOCK_SIZE; i++) {
		sms4_encrypt(in + 16*i, out1 + 16*i, &key);
	}

	switch (avx) {
# ifdef SMS4_AVX2
	case 2:
		sms4_avx2_ecb_encrypt_blocks(in, out2, sizeof(in)/SMS4_BLOCK_SIZE, &key);
		break;
# endif
	default:
		printf("avx shuold be in {2}\n");
		return 0;
	}

	if (memcmp(out1, out2, sizeof(out1)) != 0) {
		return 0;
	}
	return 1;
}

static void xor_block(unsigned char *out, const unsigned char *in)
{
	int i;
	for (i = 0; i < 16; i++) {
		out[i] ^= in[i];
	}
}

static int test_ctr32(int avx)
{
	sms4_key_t key;
	unsigned char user_key[16] = {0};
	unsigned char iv[16] = {0};
	unsigned char ctr1[16];
	unsigned char ctr2[16];
	/* 2 rounds avx-512 and 2 rounds x86 */
	unsigned char in[(16 * 2 + 2) * 16] = {0};
	unsigned char out1[sizeof(in)];
	unsigned char out2[sizeof(in)];
	int i;

	RAND_bytes(user_key, sizeof(user_key));
	RAND_bytes(iv, sizeof(iv) - 1);
	RAND_bytes(in, sizeof(in));

	sms4_set_encrypt_key(&key, user_key);
	memcpy(ctr1, iv, sizeof(iv));
	memcpy(ctr2, iv, sizeof(iv));

	for (i = 0; i < sizeof(in)/16; i++) {
		sms4_encrypt(ctr1, out1 + 16 * i, &key);
		xor_block(out1 + 16 * i, in + 16 * i);
		ctr1[15]++;
	}

	switch (avx) {
# ifdef SMS4_AVX2
	case 2:
		sms4_avx2_ctr32_encrypt_blocks(in, out2, sizeof(in)/16, &key, ctr2);
		break;
# endif
	case 0:
		sms4_ctr32_encrypt_blocks(in, out2, sizeof(in)/16, &key, ctr2);
		break;
	default:
		printf("avx should be in {0, 2}\n");
		return 0;
	}

	if (memcmp(out1, out2, sizeof(out1)) != 0) {
		return 0;
	}
	return 1;
}

static int test_ede(void)
{
	sms4_key_t key;
	sms4_ede_key_t ede_key;
	unsigned char user_key[48];
	unsigned char in[16];
	unsigned char out1[16];
	unsigned char out2[16];

	RAND_bytes(in, sizeof(in));

	RAND_bytes(user_key, 16);
	memcpy(user_key + 16, user_key, 16);
	memcpy(user_key + 32, user_key, 16);
	sms4_set_encrypt_key(&key, user_key);
	sms4_encrypt(in, out1, &key);
	sms4_ede_set_encrypt_key(&ede_key, user_key);
	sms4_ede_encrypt(in, out2, &ede_key);
	if (memcmp(out1, out2, 16) != 0) {
		return 0;
	}

	RAND_bytes(user_key, sizeof(user_key));
	sms4_ede_set_encrypt_key(&ede_key, user_key);
	sms4_ede_encrypt(in, out1, &ede_key);
	sms4_ede_set_decrypt_key(&ede_key, user_key);
	sms4_ede_decrypt(out1, out2, &ede_key);
	if (memcmp(in, out2, 16) != 0) {
		return 0;
	}

	return 1;
}


int main(int argc, char **argv)
{
	int err = 0;
	int i;
	sms4_key_t key;
	unsigned char buf[16];

	unsigned char user_key[16] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	};

	uint32_t rk[32] = {
		0xf12186f9, 0x41662b61, 0x5a6ab19a, 0x7ba92077,
		0x367360f4, 0x776a0c61, 0xb6bb89b3, 0x24763151,
		0xa520307c, 0xb7584dbd, 0xc30753ed, 0x7ee55b57,
		0x6988608c, 0x30d895b7, 0x44ba14af, 0x104495a1,
		0xd120b428, 0x73b55fa3, 0xcc874966, 0x92244439,
		0xe89e641f, 0x98ca015a, 0xc7159060, 0x99e1fd2e,
		0xb79bd80c, 0x1d2115b0, 0x0e228aeb, 0xf1780c81,
		0x428d3654, 0x62293496, 0x01cf72e5, 0x9124a012,
	};

	unsigned char plaintext[16] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	};

	unsigned char ciphertext1[16] = {
		0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
		0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
	};

	unsigned char ciphertext2[16] = {
		0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f,
		0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66,
	};

	/* test key scheduling */
	sms4_set_encrypt_key(&key, user_key);

	if (memcmp(key.rk, rk, sizeof(rk)) != 0) {
		printf("sms4 key scheduling not passed!\n");
		err++;
		goto end;
	}
	printf("sms4 key scheduling passed!\n");

	/* test encrypt once */
	sms4_encrypt(plaintext, buf, &key);

	if (memcmp(buf, ciphertext1, sizeof(ciphertext1)) != 0) {
		printf("sms4 encrypt not pass!\n");
		err++;
		goto end;
	}
	printf("sms4 encrypt pass!\n");

	/* test encrypt 1000000 times */
	memcpy(buf, plaintext, sizeof(plaintext));
	for (i = 0; i < 1000000; i++) {
		sms4_encrypt(buf, buf, &key);
	}

	if (memcmp(buf, ciphertext2, sizeof(ciphertext2)) != 0) {
		printf("sms4 encrypt 1000000 times not pass!\n");
		err++;
		goto end;
	}
	printf("sms4 encrypt 1000000 times pass!\n");

	/* test ctr32 */
	if (!test_ctr32(0)) {
		printf("sms4 ctr32 not pass!\n");
		err++;
	} else
		printf("sms4 ctr32 pass!\n");

	/* test ede */
	if (!test_ede()) {
		printf("sms4 ede not pass!\n");
		err++;
	} else
		printf("sms4 ede pass!\n");


# ifdef SMS4_AVX2
	/* test ecb in avx2 */
	if (!test_ecb(2)) {
		printf("sms4 ecb in avx2 not pass!\n");
		err++;
	} else
		printf("sms4 ecb in avx2 pass!\n");

	/* test ctr32 in avx2 */
	if (!test_ctr32(2)) {
		printf("sms4 ctr32 in avx2 not pass!\n");
		err++;
	} else
		printf("sms4 ctr32 in avx2 pass!\n");
# endif

	if (err == 0)
		printf("sms4 all test vectors pass!\n");
	else
end:
		printf("some test vector failed\n");

	return err;
}
#endif
