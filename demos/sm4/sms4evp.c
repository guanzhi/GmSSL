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
 * This sm4 demo use the EVP API.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sms4.h>
#include <openssl/is_gmssl.h>

static void print_buf(const char *s, const unsigned char *buf, size_t buflen)
{
	int i;
	printf("%s = ", s);
	for (i = 0; i < buflen; i++) {
		printf("%02X", buf[i]);
	}
	printf("\n");
}

int main(int argc, char **argv)
{
	int ret = -1;
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *cipher = EVP_sms4_cbc();
	unsigned char key[SMS4_KEY_LENGTH] = {0};
	unsigned char iv[SMS4_IV_LENGTH] = {0};
	unsigned char msg[MSG_LEN];
	unsigned char cbuf[sizeof(msg) + SMS4_BLOCK_SIZE];
	unsigned char pbuf[sizeof(cbuf)];
	unsigned int clen, plen;
	int len;

	/* generate random key/iv/msg */
	if (!RAND_bytes(key, sizeof(key))
		|| !RAND_bytes(iv, sizeof(iv))
		|| !RAND_bytes(msg, sizeof(msg))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	print_buf("key", key, sizeof(key));
	print_buf("iv", iv, sizeof(iv));
	print_buf("msg", msg, sizeof(msg));

	/* create encrypt/decrypt context */
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		ERR_print_errors_fp(stderr);
		goto end;
	}


	/* encrypt */
	if (!EVP_EncryptInit(ctx, cipher, key, iv)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	clen = 0;

	if (!EVP_EncryptUpdate(ctx, cbuf, &len, msg, sizeof(msg))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	clen += len;

	if (!EVP_EncryptFinal(ctx, cbuf + len, &len)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	clen += len;

	print_buf("ciphertext", cbuf, clen);

	/* decrypt */
	if (!EVP_DecryptInit(ctx, cipher, key, iv)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	plen = 0;

	if (!EVP_DecryptUpdate(ctx, pbuf, &len, cbuf, clen)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	plen += len;

	if (!EVP_DecryptFinal(ctx, pbuf + len, &len)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	plen += len;

	print_buf("decrypted", pbuf, plen);

	ret = 0;

end:
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}
