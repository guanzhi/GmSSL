/* demo/gmssl/sm2.c */
/* ====================================================================
 * Copyright (c) 2015-2016 The GmSSL Project.  All rights reserved.
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

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/sm2.h>

#define NUM_PKEYS	4

int main()
{
	int ret = -1;
	int verbose = 0;
	BIO *out = NULL;

	int id = EVP_PKEY_SM2;
	const EVP_MD *md = EVP_sm3();
	ENGINE *engine = NULL;

	EVP_PKEY_CTX *pkctx = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_MD_CTX *mdctx = NULL;
	EVP_CIPHER_CTX *cpctx = NULL;

	unsigned char dgst[EVP_MAX_MD_SIZE] = "hello world";
	size_t dgstlen = 32;
	unsigned char sig[256];
	size_t siglen = sizeof(sig);

	unsigned char msg[] = "hello world this is the message";
	size_t msglen = sizeof(msg);
	unsigned char cbuf[512];
	size_t cbuflen = sizeof(cbuf);
	unsigned char mbuf[512];
	size_t mbuflen = sizeof(mbuf);

	int len;
	unsigned int ulen;

	ERR_load_crypto_strings();

	out = BIO_new_fp(stdout, BIO_NOCLOSE);

	if (!(pkctx = EVP_PKEY_CTX_new_id(id, engine))) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_PKEY_keygen_init(pkctx)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_PKEY_keygen(pkctx, &pkey)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	EVP_PKEY_CTX_free(pkctx);

	if (0) {
		EVP_PKEY_print_public(out, pkey, 4, NULL);
		BIO_printf(out, "\n");
		EVP_PKEY_print_private(out, pkey, 4, NULL);
		BIO_printf(out, "\n");
	}

	if (!(pkctx = EVP_PKEY_CTX_new(pkey, engine))) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	/* EVP_PKEY_sign() */

	if (!EVP_PKEY_sign_init(pkctx)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	bzero(sig, sizeof(sig));
	siglen = sizeof(sig);
	dgstlen = 32;

	if (!EVP_PKEY_sign(pkctx, sig, &siglen, dgst, dgstlen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (verbose) {
		size_t i;
		printf("signature (%zu bytes) = ", siglen);
		for (i = 0; i < siglen; i++) {
			printf("%02X", sig[i]);
		}
		printf("\n");
	}

	if (!EVP_PKEY_verify_init(pkctx)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (EVP_PKEY_verify(pkctx, sig, siglen, dgst, dgstlen) != SM2_VERIFY_SUCCESS) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (verbose) {
		printf("signature verification success!\n");
	}

	/* EVP_PKEY_encrypt() */

	if (!EVP_PKEY_encrypt_init(pkctx)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	cbuflen = sizeof(cbuf);
	if (!EVP_PKEY_encrypt(pkctx, cbuf, &cbuflen, msg, msglen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (verbose) {
		size_t i;
		printf("ciphertext (%zu bytes) = ", cbuflen);
		for (i = 0; i < cbuflen; i++) {
			printf("%02X", cbuf[i]);
		}
		printf("\n");
	}

	if (!EVP_PKEY_decrypt_init(pkctx)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	bzero(mbuf, sizeof(mbuf));
	mbuflen = sizeof(mbuf);
	if (!EVP_PKEY_decrypt(pkctx, mbuf, &mbuflen, cbuf, cbuflen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (verbose) {
		printf("original  message = %s\n", msg);
		printf("decrypted message = %s\n", mbuf);
	}


	/* EVP_PKEY_encrypt_old */


	if ((len = EVP_PKEY_encrypt_old(cbuf, msg, (int)msglen, pkey)) <= 0) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (verbose) {
		int i;
		printf("ciphertext (%d bytes) = ", len);
		for (i = 0; i < len; i++) {
			printf("%02X", cbuf[i]);
		}
		printf("\n");
	}

	bzero(mbuf, sizeof(mbuf));
	if ((len = EVP_PKEY_decrypt_old(mbuf, cbuf, len, pkey)) <= 0) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (verbose) {
		printf("original  message = %s\n", msg);
		printf("decrypted message = %s\n", mbuf);
	}

	if (!(mdctx = EVP_MD_CTX_create())) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	
	/* EVP_SignInit_ex/Update/Final_ex */

	if (!EVP_SignInit_ex(mdctx, EVP_sm3(), engine)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_SignUpdate(mdctx, msg, msglen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_SignFinal(mdctx, sig, &ulen, pkey)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}
	siglen = ulen;

	if (verbose) {
		size_t i;
		printf("signature (%zu bytes) = ", siglen);
		for (i = 0; i < siglen; i++) {
			printf("%02X", sig[i]);
		}
		printf("\n");
	}

	if (!EVP_VerifyInit_ex(mdctx, EVP_sm3(), engine)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_VerifyUpdate(mdctx, msg, msglen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (EVP_VerifyFinal(mdctx, sig, ulen, pkey) != SM2_VERIFY_SUCCESS) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}


	/* EVP_DigestSignInit/Update/Final() */
	// FIXME: return values might be different, not just 1 or 0
	if (!EVP_DigestSignInit(mdctx, &pkctx, md, engine, pkey)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_DigestSignUpdate(mdctx, msg, msglen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	siglen = sizeof(sig);
	if (!EVP_DigestSignFinal(mdctx, sig, &siglen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	pkctx = NULL;	
	if (!EVP_DigestVerifyInit(mdctx, &pkctx, md, engine, pkey)) {
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_DigestVerifyUpdate(mdctx, msg, msglen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_DigestVerifyFinal(mdctx, sig, siglen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}


	/* EVP_SealInit/Update/Final() EVP_OpenInit/Update/Final() */
	/*
	EVP_PKEY *pk[NUM_PKEYS] = {0};
	unsigned char iv[16];
	unsigned char ek[NUM_PKEYS][256];
	int eklen[NUM_PKEYS];

	RAND_pseudo_bytes(iv, sizeof(iv));

	int i;
	for (i = 0; i < NUM_PKEYS; i++) {
	}

	if (!(cpctx = EVP_CIPHER_CTX_new())) {
		goto end;
	}

	if (!EVP_SealInit(cpctx, cipher, ek, &ekl, iv, pubk, npubk)) {
		goto end;
	}

	if (!EVP_SealUpdate(cpctx, msg, msglen)) {
		goto end;
	}

	if (!EVP_SealFinal(cpctx, cbuf, (int *)&cbuflen)) {
		goto end;
	}
	*/

	printf("test success!\n");
	ret = 1;
end:
	ERR_print_errors_fp(stderr);
	return ret;
}

