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
#include <ctype.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ffx.h>
#include <openssl/e_os2.h>
#include "../modes/modes_lcl.h"


static uint32_t modulo[] = {
		1,
		10,
		100,
		1000,
		10000,
		100000,
		1000000,
		10000000,
		100000000,
		1000000000,
		1000000000,
};

struct FFX_CTX_st {
	EVP_CIPHER_CTX *cctx;
	int flag;
};

FFX_CTX *FFX_CTX_new(void)
{
	FFX_CTX *ret = NULL;
	ret = OPENSSL_zalloc(sizeof(*ret));
	return ret;
}

void FFX_CTX_free(FFX_CTX *ctx)
{
	if (ctx) {
		EVP_CIPHER_CTX_free(ctx->cctx);
	}
	OPENSSL_free(ctx);
}

int FFX_init(FFX_CTX *ctx, const EVP_CIPHER *cipher, const unsigned char *key,
	int flag)
{
	int ret = 0;
	EVP_CIPHER_CTX *cctx = NULL;

	if (!ctx || !cipher || !key) {
		FFXerr(FFX_F_FFX_INIT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (EVP_CIPHER_mode(cipher) != EVP_CIPH_ECB_MODE) {
		FFXerr(FFX_F_FFX_INIT, FFX_R_INVALID_CIPHER_MODE);
		return 0;
	}
	if (EVP_CIPHER_block_size(cipher) != 16) {
		FFXerr(FFX_F_FFX_INIT, FFX_R_INVALID_BLOCK_SIZE);
		return 0;
	}

	if (!ctx->cctx) {
		if (!(cctx = EVP_CIPHER_CTX_new())) {
			FFXerr(FFX_F_FFX_INIT, ERR_R_MALLOC_FAILURE);
			goto end;
		}
		ctx->cctx = cctx;
		cctx = NULL;
	}
	ctx->flag = flag;

	if (!EVP_EncryptInit_ex(ctx->cctx, cipher, NULL, key, NULL)) {
		FFXerr(FFX_F_FFX_INIT, FFX_R_ENCRYPT_INIT_FAILURE);
		goto end;
	}

	ret = 1;
end:
	EVP_CIPHER_CTX_free(cctx);
	return ret;
}

int FFX_encrypt(FFX_CTX *ctx, const char *in, char *out, size_t iolen,
	unsigned char *tweak, size_t tweaklen)
{
	int llen, rlen;
	uint32_t lval, rval;
	unsigned char pblock[16] = {
		0x01, 0x02, 0x01, 0x0a, 0x00, 0x00, 0x0a, 0xff,
		0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00};
	unsigned char qblock[16];
	char lbuf[FFX_MAX_DIGITS/2 + 2];
	uint64_t yval;
	size_t i;

	if (!ctx || !in || !out || !tweak) {
		FFXerr(FFX_F_FFX_ENCRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (iolen < FFX_MIN_DIGITS || iolen > FFX_MAX_DIGITS) {
		FFXerr(FFX_F_FFX_ENCRYPT, FFX_R_INVALID_INPUT_LENGTH);
		return 0;
	}

	for (i = 0; i < iolen; i++) {
		if (!isdigit(in[i])) {
			FFXerr(FFX_F_FFX_ENCRYPT, FFX_R_INVALID_INPUT_DIGIT);
			return 0;
		}
	}
	llen = iolen / 2;
	rlen = iolen - llen;

	if (tweaklen < FFX_MIN_TWEAKLEN || tweaklen > FFX_MAX_TWEAKLEN) {
		FFXerr(FFX_F_FFX_ENCRYPT, FFX_R_INVALID_TWEAK_LENGTH);
		return 0;
	}

	memcpy(lbuf, in, llen);
	lbuf[llen] = 0;
	lval = atoi(lbuf);
	rval = atoi(in + llen);

	pblock[7] = llen & 0xff;
	pblock[8] = iolen & 0xff;
	pblock[12] = tweaklen & 0xff;

	if (!EVP_Cipher(ctx->cctx, pblock, pblock,
		EVP_CIPHER_CTX_block_size(ctx->cctx))) {
		FFXerr(FFX_F_FFX_ENCRYPT, ERR_R_EVP_LIB);
		return 0;
	}

	memset(qblock, 0, sizeof(qblock));
	memcpy(qblock, tweak, tweaklen);

	for (i = 0; i < FFX_NUM_ROUNDS; i += 2) {

		unsigned char rblock[16];
		size_t j;

		qblock[11] = i & 0xff;
		memcpy(qblock + 12, &rval, sizeof(rval));
		for (j = 0; j < sizeof(rblock); j++) {
			rblock[j] = pblock[j] ^ qblock[j];
		}
		if (!EVP_Cipher(ctx->cctx, rblock, rblock,
			EVP_CIPHER_CTX_block_size(ctx->cctx))) {
			FFXerr(FFX_F_FFX_ENCRYPT, ERR_R_EVP_LIB);
			return 0;
		}

		yval = *((uint64_t *)rblock) % modulo[llen];
		lval = (lval + yval) % modulo[llen];

		qblock[11] = (i + 1) & 0xff;
		memcpy(qblock + 12, &lval, sizeof(lval));
		for (j = 0; j < sizeof(rblock); j++) {
			rblock[j] = pblock[j] ^ qblock[j];
		}
		if (!EVP_Cipher(ctx->cctx, rblock, rblock,
			EVP_CIPHER_CTX_block_size(ctx->cctx))) {
			FFXerr(FFX_F_FFX_ENCRYPT, ERR_R_EVP_LIB);
			return 0;
		}
		yval = *((uint64_t *)rblock) % modulo[rlen];
		rval = (rval + yval) % modulo[rlen];
	}

	memset(out, '0', iolen);
	sprintf(lbuf, "%d", rval);
	memcpy(out + rlen - strlen(lbuf), lbuf, strlen(lbuf));
	sprintf(lbuf, "%d", lval);
	strcpy(out + iolen - strlen(lbuf), lbuf);

	return 1;
}

int FFX_decrypt(FFX_CTX *ctx, const char *in, char *out, size_t iolen,
	unsigned char *tweak, size_t tweaklen)
{
	int llen, rlen;
	uint32_t lval, rval;
	unsigned char pblock[16] = {
		0x01, 0x02, 0x01, 0x0a, 0x00, 0x00, 0x0a, 0xff,
		0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00};
	unsigned char qblock[16];
	char lbuf[FFX_MAX_DIGITS/2 + 2];
	uint64_t yval;
	size_t i;

	if (!ctx || !in || !out || !tweak) {
		FFXerr(FFX_F_FFX_DECRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (iolen < FFX_MIN_DIGITS || iolen > FFX_MAX_DIGITS) {
		FFXerr(FFX_F_FFX_DECRYPT, FFX_R_INVALID_INPUT_LENGTH);
		return 0;
	}

	for (i = 0; i < iolen; i++) {
		if (!isdigit(in[i])) {
			FFXerr(FFX_F_FFX_DECRYPT, FFX_R_INVALID_INPUT_DIGIT);
			return 0;
		}
	}
	rlen = iolen / 2;
	llen = iolen - rlen;


	if (tweaklen < FFX_MIN_TWEAKLEN || tweaklen > FFX_MAX_TWEAKLEN) {
		FFXerr(FFX_F_FFX_DECRYPT, FFX_R_INVALID_TWEAK_LENGTH);
		return 0;
	}

	memcpy(lbuf, in, llen);
	lbuf[llen] = 0;
	lval = atoi(lbuf);
	rval = atoi(in + llen);

	pblock[7] = rlen & 0xff;
	pblock[8] = iolen & 0xff;
	pblock[12] = tweaklen & 0xff;

	if (!EVP_Cipher(ctx->cctx, pblock, pblock,
		EVP_CIPHER_CTX_block_size(ctx->cctx))) {
		FFXerr(FFX_F_FFX_DECRYPT, ERR_R_EVP_LIB);
		return 0;
	}

	memset(qblock, 0, sizeof(qblock));
	memcpy(qblock, tweak, tweaklen);

	for (i = FFX_NUM_ROUNDS - 1; i > 0; i -= 2) {

		unsigned char rblock[16];
		size_t j;

		qblock[11] = i & 0xff;
		memcpy(qblock + 12, &rval, sizeof(rval));
		for (j = 0; j < sizeof(rblock); j++) {
			rblock[j] = pblock[j] ^ qblock[j];
		}
		if (!EVP_Cipher(ctx->cctx, rblock, rblock,
			EVP_CIPHER_CTX_block_size(ctx->cctx))) {
			FFXerr(FFX_F_FFX_DECRYPT, ERR_R_EVP_LIB);
			return 0;
		}

		yval = *((uint64_t *)rblock) % modulo[llen];
		lval = (lval >= yval) ? (lval - yval) : lval + modulo[llen] - yval;

		qblock[11] = (i - 1) & 0xff;
		memcpy(qblock + 12, &lval, sizeof(lval));
		for (j = 0; j < sizeof(rblock); j++) {
			rblock[j] = pblock[j] ^ qblock[j];
		}
		if (!EVP_Cipher(ctx->cctx, rblock, rblock,
			EVP_CIPHER_CTX_block_size(ctx->cctx))) {
			FFXerr(FFX_F_FFX_DECRYPT, ERR_R_EVP_LIB);
			return 0;
		}

		yval = *((uint64_t *)rblock) % modulo[rlen];
		rval = (rval >= yval) ? (rval - yval) : rval + modulo[rlen] - yval;
	}

	memset(out, '0', iolen);
	sprintf(lbuf, "%d", rval);
	memcpy(out + rlen - strlen(lbuf), lbuf, strlen(lbuf));
	sprintf(lbuf, "%d", lval);
	strcpy(out + iolen - strlen(lbuf), lbuf);

	return 1;
}

static int luhn_table[10] = {0, 2, 4, 6, 8, 1, 3, 5, 7, 9};

int FFX_compute_luhn(const char *in, size_t inlen)
{
	int r = 0;
	int i;

	for (i = inlen - 1; i >= 0; i--) {
		int a;
		if (!isdigit(in[i])) {
			return -2;
		}
		a = in[i] - '0';
		if (i % 2 != inlen % 2)
			a = luhn_table[a];
		r += a;
	}

	r = ((r * 9) % 10) + '0';
	return r;
}

