/* ====================================================================
 * Copyright (c) 2015 The GmSSL Project.  All rights reserved.
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
 *
 */
/*
 * Format-Preserve Encryption
 * implementation of NIST 800-38G FF1 schemes
 * 
 * FPE is used to encrypt strings such as credit card numbers and phone numbers
 * the ciphertext is still in valid format, for example:
 *	 FPE_encrypt("13810631266") == "98723498792"
 * the output is still 11 digits
 */


#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include "ffx.h"

#define FFX_MIN_DIGITS	   		 6
#define FFX_MAX_DIGITS	  		18
#define FFX_MIN_TWEAKLEN	  	 4
#define FFX_MAX_TWEAKLEN	  	11 
#define FFX_NUM_ROUNDS	  		10


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

int FFX_init(FFX_CTX *ctx, int flag, const unsigned char *key, int keybits)
{
	ctx->flag = flag;

	if (AES_set_encrypt_key(key, keybits, &ctx->key) < 0) {
		fprintf(stderr, "error: %s: %s: %d\n", __FUNCTION__, __FILE__, __LINE__);
		return -1;
	}

	return 0;
}

void FFX_cleanup(FFX_CTX *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
}

int FFX_encrypt(FFX_CTX *ctx, const char *in, size_t inlen,
	const unsigned char *tweak, size_t tweaklen, char *out)
{
	int llen, rlen;
	uint32_t lval, rval;
	unsigned char pblock[16] = {
		0x01, 0x02, 0x01, 0x0a, 0x00, 0x00, 0x0a, 0xff,
		0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00};
	unsigned char qblock[16];
	char lbuf[FFX_MAX_DIGITS/2 + 2];
	uint64_t yval;
	int i;

	assert(out);
	assert(in);
	assert(tweak);

	if (inlen > strlen(in) || 
		inlen < FFX_MIN_DIGITS || inlen > FFX_MAX_DIGITS) {
		fprintf(stderr, "%s: invalid digits length\n", __FUNCTION__);
		return -1;
	}
	for (i = 0; i < inlen; i++) {
		if (!isdigit(in[i])) {
			fprintf(stderr, "%s: invalid digits format\n", __FUNCTION__);
			return -1;
		}
	}
	llen = inlen / 2;
	rlen = inlen - llen;


	if (tweaklen < FFX_MIN_TWEAKLEN || tweaklen > FFX_MAX_TWEAKLEN) {
		fprintf(stderr, "%s: invalid tweak length\n", __FUNCTION__);
		return -1;
	}

	memcpy(lbuf, in, llen);
	lbuf[llen] = 0;
	lval = atoi(lbuf);
	rval = atoi(in + llen);

	pblock[7] = llen & 0xff;
	pblock[8] = inlen & 0xff;
	pblock[12] = tweaklen & 0xff;

	AES_encrypt(pblock, pblock, &ctx->key);

	memset(qblock, 0, sizeof(qblock));
	memcpy(qblock, tweak, tweaklen);
	
	for (i = 0; i < FFX_NUM_ROUNDS; i += 2) {
	
		unsigned char rblock[16];
		int j;

		qblock[11] = i & 0xff;
		memcpy(qblock + 12, &rval, sizeof(rval));
		for (j = 0; j < sizeof(rblock); j++) {
			rblock[j] = pblock[j] ^ qblock[j];
		}
		AES_encrypt(rblock, rblock, &ctx->key);
		yval = *((uint64_t *)rblock) % modulo[llen];
		lval = (lval + yval) % modulo[llen];
		
		qblock[11] = (i + 1) & 0xff;
		memcpy(qblock + 12, &lval, sizeof(lval));
		for (j = 0; j < sizeof(rblock); j++) {
			rblock[j] = pblock[j] ^ qblock[j];
		}
		AES_encrypt(rblock, rblock, &ctx->key);
		yval = *((uint64_t *)rblock) % modulo[rlen];
		rval = (rval + yval) % modulo[rlen];
	}

	memset(out, '0', inlen);
	sprintf(lbuf, "%d", rval);
	memcpy(out + rlen - strlen(lbuf), lbuf, strlen(lbuf));
	sprintf(lbuf, "%d", lval);
	strcpy(out + inlen - strlen(lbuf), lbuf);

	return 0;
}

int FFX_decrypt(FFX_CTX *ctx, const char *in, size_t inlen,
	const unsigned char *tweak, size_t tweaklen, char *out)
{
	int llen, rlen;
	uint32_t lval, rval;
	unsigned char pblock[16] = {
		0x01, 0x02, 0x01, 0x0a, 0x00, 0x00, 0x0a, 0xff,
		0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00};
	unsigned char qblock[16];
	char lbuf[FFX_MAX_DIGITS/2 + 2];
	uint64_t yval;
	int i;

	assert(out);
	assert(in);
	assert(tweak);

	if (inlen > strlen(in) ||
		inlen < FFX_MIN_DIGITS || inlen > FFX_MAX_DIGITS) {
		fprintf(stderr, "%s: invalid digits length\n", __FUNCTION__);
		return -1;
	}
	for (i = 0; i < inlen; i++) {
		if (!isdigit(in[i])) {
			fprintf(stderr, "%s: invalid digits format\n", __FUNCTION__);
			return -1;
		}
	}
	rlen = inlen / 2;
	llen = inlen - rlen;

	if (tweaklen < FFX_MIN_TWEAKLEN || tweaklen > FFX_MAX_TWEAKLEN) {
		fprintf(stderr, "%s: invalid tweak length\n", __FUNCTION__);
		return -1;
	}

	memcpy(lbuf, in, llen);
	lbuf[llen] = 0;
	lval = atoi(lbuf);
	rval = atoi(in + llen);

	pblock[7] = rlen & 0xff;
	pblock[8] = inlen & 0xff;
	pblock[12] = tweaklen & 0xff;

	AES_encrypt(pblock, pblock, &ctx->key);

	memset(qblock, 0, sizeof(qblock));
	memcpy(qblock, tweak, tweaklen);
	
	for (i = FFX_NUM_ROUNDS - 1; i > 0; i -= 2) {
	
		unsigned char rblock[16];
		int j;

		qblock[11] = i & 0xff;
		memcpy(qblock + 12, &rval, sizeof(rval));
		for (j = 0; j < sizeof(rblock); j++) {
			rblock[j] = pblock[j] ^ qblock[j];
		}
		AES_encrypt(rblock, rblock, &ctx->key);
		yval = *((uint64_t *)rblock) % modulo[llen];
		lval = (lval >= yval) ? (lval - yval) : lval + modulo[llen] - yval;
		
		qblock[11] = (i - 1) & 0xff;
		memcpy(qblock + 12, &lval, sizeof(lval));
		for (j = 0; j < sizeof(rblock); j++) {
			rblock[j] = pblock[j] ^ qblock[j];
		}
		AES_encrypt(rblock, rblock, &ctx->key);
		yval = *((uint64_t *)rblock) % modulo[rlen];
		rval = (rval >= yval) ? (rval - yval) : rval + modulo[rlen] - yval;
	}

	memset(out, '0', inlen);
	sprintf(lbuf, "%d", rval);
	memcpy(out + rlen - strlen(lbuf), lbuf, strlen(lbuf));
	sprintf(lbuf, "%d", lval);
	strcpy(out + inlen - strlen(lbuf), lbuf);

	return 0;
}

static int test()
{
	char buf[100];
	char buf2[100];
	unsigned char key[32] = {0};
	unsigned char tweak[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
	FFX_CTX ctx;
	int r;

	ERR_load_crypto_strings();

	if (FFX_init(&ctx, 0, key, sizeof(key) * 8) < 0) {
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "%s: %d\n", __FILE__, __LINE__);
		return -1;
	}

	char *in = "99999999999999999";
	r = FFX_encrypt(&ctx, in, strlen(in), tweak, sizeof(tweak), buf);

	if (r < 0) {
		printf("failed\n");
		return -1;
	}

	printf("%s\n", buf);
	printf("\n");

	r = FFX_decrypt(&ctx, buf, strlen(buf), tweak, sizeof(tweak), buf2);
	printf("%s\n", buf2);

	return 0;
}

static int luhn_table[10] = {0, 2, 4, 6, 8, 1, 3, 5, 7, 9};

/*
 * 7992739871, checksum = 3
 */

int FFX_compute_luhn(const char *in, size_t inlen)
{
	int r = 0;
	int i;

	for (i = inlen - 1; i >= 0; i--) {
		int a;
		if (!isdigit(in[i])) {
			fprintf(stderr, "%s: invalid digit string\n", __FUNCTION__);
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

#if 0
int luhn_test()
{
	char *digits = "7992739871";
	int r = compute_luhn(digits, strlen(digits));
	printf("%c", r);
	return 0;
}
#endif



