/* ====================================================================
 * Copyright (c) 2014 - 2016 The GmSSL Project.  All rights reserved.
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

#ifdef OPENSSL_NO_SM2
int main(int argc, char **argv)
{
	printf("No SM2 support\n");
	return 0;
}
#else

# include <openssl/ec.h>
# include <openssl/bn.h>
# include <openssl/evp.h>
# include <openssl/rand.h>
# include <openssl/engine.h>
# include <openssl/sm2.h>

static EVP_PKEY *genpkey(int curve_nid, BIO *out, int verbose)
{
	int ok = 0;
	EVP_PKEY *ret = NULL;
	EVP_PKEY_CTX *pkctx = NULL;

	if (!(pkctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_PKEY_keygen_init(pkctx)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkctx, curve_nid)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_PKEY_keygen(pkctx, &ret)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (verbose > 1) {
		EVP_PKEY_print_private(out, ret, 4, NULL);
		BIO_printf(out, "\n");
	}

	ok = 1;
end:
	if (!ok && ret) {
		EVP_PKEY_free(ret);
		ret = NULL;
	}
	EVP_PKEY_CTX_free(pkctx);
	return ret;
}

static int test_evp_pkey_sign(EVP_PKEY *pkey, int do_sm2, int verbose)
{
	int ret = 0;
	EVP_PKEY_CTX *pkctx = NULL;
	int type = do_sm2 ? NID_sm_scheme : NID_secg_scheme;
	unsigned char dgst[EVP_MAX_MD_SIZE] = "hello world";
	size_t dgstlen;
	unsigned char sig[256];
	size_t siglen;


	if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	/* EVP_PKEY_sign() */

	if (!EVP_PKEY_sign_init(pkctx)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_PKEY_CTX_set_ec_sign_type(pkctx, type)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	dgstlen = 32;
	memset(sig, 0, sizeof(sig));
	siglen = sizeof(sig);
	if (!EVP_PKEY_sign(pkctx, sig, &siglen, dgst, dgstlen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (verbose > 1) {
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

	if (!EVP_PKEY_CTX_set_ec_sign_type(pkctx, type)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (1 != EVP_PKEY_verify(pkctx, sig, siglen, dgst, dgstlen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (verbose) {
		printf("%s(%s) passed\n", __FUNCTION__, OBJ_nid2sn(type));
	}

	ret = 1;
end:
	EVP_PKEY_CTX_free(pkctx);
	return ret;
}

static int test_evp_pkey_encrypt(EVP_PKEY *pkey, int do_sm2, int verbose)
{
	int ret = 0;
	EVP_PKEY_CTX *pkctx = NULL;
	int type = do_sm2 ? NID_sm_scheme : NID_secg_scheme;
	unsigned char msg[] = "hello world this is the message";
	size_t msglen = sizeof(msg);
	unsigned char cbuf[512];
	size_t cbuflen = sizeof(cbuf);
	unsigned char mbuf[512];
	size_t mbuflen = sizeof(mbuf);

	if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	/* EVP_PKEY_encrypt() */

	if (!EVP_PKEY_encrypt_init(pkctx)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_PKEY_CTX_set_ec_enc_type(pkctx, type)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

					
	/* we need to set the sm2 encrypt params (hash = sm3) */
									

	cbuflen = sizeof(cbuf);
	if (!EVP_PKEY_encrypt(pkctx, cbuf, &cbuflen, msg, msglen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (verbose > 1) {
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

	if (!EVP_PKEY_CTX_set_ec_enc_type(pkctx, type)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	memset(mbuf, 0, sizeof(mbuf));
	mbuflen = sizeof(mbuf);
	if (!EVP_PKEY_decrypt(pkctx, mbuf, &mbuflen, cbuf, cbuflen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (verbose > 1) {
		printf("original  message = %s\n", msg);
		printf("decrypted message = %s\n", mbuf);
	}

	if (verbose) {
		printf("%s(%s) passed\n", __FUNCTION__, OBJ_nid2sn(type));
	}

	ret = 1;
end:
	ERR_print_errors_fp(stderr);
	EVP_PKEY_CTX_free(pkctx);
	return ret;
}

static int test_evp_pkey_encrypt_old(EVP_PKEY *pkey, int verbose)
{
	int ret = 0;
	unsigned char msg[] = "hello world this is the message";
	size_t msglen = sizeof(msg);
	unsigned char cbuf[512];
	unsigned char mbuf[512];

	int len;

	if ((len = EVP_PKEY_encrypt_old(cbuf, msg, (int)msglen, pkey)) <= 0) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (verbose > 1) {
		int i;
		printf("ciphertext (%d bytes) = ", len);
		for (i = 0; i < len; i++) {
			printf("%02X", cbuf[i]);
		}
		printf("\n");
	}

	memset(mbuf, 0, sizeof(mbuf));
	if ((len = EVP_PKEY_decrypt_old(mbuf, cbuf, len, pkey)) <= 0) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (verbose > 1) {
		printf("original  message = %s\n", msg);
		printf("decrypted message = %s\n", mbuf);
	}

	if (verbose) {
		printf("%s() passed!\n", __FUNCTION__);
	}

	ret = 1;
end:
	return ret;
}

static int test_evp_sign(EVP_PKEY *pkey, const EVP_MD *md, int verbose)
{
	int ret = 0;
	EVP_MD_CTX *mdctx = NULL;
	unsigned char msg[] = "hello world this is the message";
	size_t msglen = sizeof(msg);
	unsigned char sig[256];
	unsigned int siglen = (unsigned int)sizeof(sig);

	if (!(mdctx = EVP_MD_CTX_create())) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_SignInit_ex(mdctx, md, NULL)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_SignUpdate(mdctx, msg, msglen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_SignFinal(mdctx, sig, &siglen, pkey)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (verbose > 1) {
		size_t i;
		printf("signature (%u bytes) = ", siglen);
		for (i = 0; i < siglen; i++) {
			printf("%02X", sig[i]);
		}
		printf("\n");
	}

	if (!EVP_VerifyInit_ex(mdctx, md, NULL)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_VerifyUpdate(mdctx, msg, msglen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (1 != EVP_VerifyFinal(mdctx, sig, siglen, pkey)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (verbose) {
		printf("%s() passed\n", __FUNCTION__);
	}

	ret = 1;

end:
	EVP_MD_CTX_destroy(mdctx);
	return ret;
}

static int test_evp_digestsign(EVP_PKEY *pkey, int do_sm2, const EVP_MD *md, int verbose)
{
	int ret = 0;
	EVP_MD_CTX *mdctx = NULL;
	EVP_PKEY_CTX *pkctx;
	int type = do_sm2 ? NID_sm_scheme : NID_secg_scheme;
	unsigned char msg[] = "hello world this is the message";
	size_t msglen = sizeof(msg);
	unsigned char sig[256];
	size_t siglen = (unsigned int)sizeof(sig);


	unsigned char z[EVP_MAX_MD_SIZE];

	if (!(mdctx = EVP_MD_CTX_create())) {
		goto end;
	}

	pkctx = NULL;
	if (!EVP_DigestSignInit(mdctx, &pkctx, md, NULL, pkey)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_PKEY_CTX_set_ec_sign_type(pkctx, type)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	/*
	if (!EVP_PKEY_CTX_set_pre_update(pkctx, z, 32)) {
		goto end;
	}
	*/

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
	if (!EVP_DigestVerifyInit(mdctx, &pkctx, md, NULL, pkey)) {
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_PKEY_CTX_set_ec_sign_type(pkctx, type)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	/*
	if (!EVP_PKEY_CTX_set_pre_update(pkctx, z, 32)) {
		goto end;
	}
	*/

	if (!EVP_DigestVerifyUpdate(mdctx, msg, msglen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_DigestVerifyFinal(mdctx, sig, siglen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (verbose) {
		printf("%s() passed\n", __FUNCTION__);
	}

	ret = 1;
end:
	EVP_MD_CTX_destroy(mdctx);
	return ret;
}

#define NUM_PKEYS	3
#define MAX_PKEY_SIZE	1024

static int test_evp_seal(int curve_id, const EVP_CIPHER *cipher, BIO *out, int verbose)
{
	int ret = 0;
	EVP_PKEY *pkey[NUM_PKEYS] = {0};
	EVP_CIPHER_CTX *cctx = NULL;
	unsigned char iv[16];
	unsigned char *ek[NUM_PKEYS] = {0};
	int ekl[NUM_PKEYS];
	unsigned char msg1[] = "Hello ";
	unsigned char msg2[] = "World!";
	unsigned char cbuf[256];
	unsigned char mbuf[256];
	unsigned char *p;
	int len, clen, mlen, i;


	for (i = 0; i < NUM_PKEYS; i++) {
		if (!(pkey[i] = genpkey(curve_id, out, verbose))) {
			fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
			goto end;
		}
		ekl[i] = MAX_PKEY_SIZE;
		ek[i] = OPENSSL_malloc(ekl[i]);
	}
	RAND_bytes(iv, sizeof(iv));

	if (!(cctx = EVP_CIPHER_CTX_new())) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if ((i = EVP_SealInit(cctx, cipher, ek, ekl, iv, pkey, NUM_PKEYS)) != NUM_PKEYS) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (verbose > 1) {
		for (i = 0; i < NUM_PKEYS; i++) {
			int j;
			BIO_printf(out, "ek[%d] (%d-byte) = ", i, ekl[i]);
			for (j = 0; j < ekl[i]; j++) {
				BIO_printf(out, "%02X", ek[i][j]);
			}
			BIO_printf(out, "\n");
		}
	}

	p = cbuf;
	len = sizeof(cbuf);
	if (!EVP_SealUpdate(cctx, p, &len, msg1, sizeof(msg1)-1)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}
	p += len;

	len = sizeof(cbuf) - (p - cbuf);
	if (!EVP_SealUpdate(cctx, p, &len, msg2, sizeof(msg2)-1)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}
	p += len;

	len = sizeof(cbuf) - (p - cbuf);
	if (!EVP_SealFinal(cctx, p, &len)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}
	p += len;

	clen = p - cbuf;

	if (verbose > 1) {
		BIO_printf(out, "ciphertext (%d-byte) = ", clen);
		for (i = 0; i < clen; i++) {
			BIO_printf(out, "%02X", cbuf[i]);
		}
		BIO_printf(out, "\n");
	}

	if (!EVP_OpenInit(cctx, cipher, ek[1], ekl[1], iv, pkey[1])) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	memset(mbuf, 0, sizeof(mbuf));
	p = mbuf;
	len = sizeof(mbuf);

	if (!EVP_OpenUpdate(cctx, p, &len, cbuf, clen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}
	p += len;
	len = sizeof(mbuf) - len;

	if (!EVP_OpenFinal(cctx, p, &len)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}
	p += len;

	mlen = p - mbuf;

	if (verbose > 1) {
		BIO_printf(out, "message = %s%s\n", (char *)msg1, (char *)msg2);
		BIO_printf(out, "message = %s\n", (char *)mbuf);
	}

	if (verbose) {
		BIO_printf(out, "%s() passed!\n", __FUNCTION__);
	}

	ret = 1;

end:
	EVP_CIPHER_CTX_free(cctx);
	for (i = 0; i < NUM_PKEYS; i++) {
		EVP_PKEY_free(pkey[i]);
		OPENSSL_free(ek[i]);
	}
	return ret;
}

int main(int argc, char **argv)
{
	int err = 0;
	int verbose = 2;
	EVP_PKEY *pkey = NULL;
	int curve_id = NID_sm2p256v1;
	const EVP_MD *md = EVP_sm3();
	const EVP_CIPHER *cipher = EVP_sms4_cbc();
	BIO *out = NULL;

	out = BIO_new_fp(stderr, BIO_NOCLOSE);

	if (!(pkey = genpkey(curve_id, out, verbose))) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	//if (!test_evp_pkey_sign(pkey, 1, 0)) err++;
	//if (!test_evp_pkey_sign(pkey, 0, 0)) err++;
	if (!test_evp_pkey_encrypt(pkey, 1, verbose)) err++;
	//if (!test_evp_pkey_encrypt(pkey, 0, verbose)) err++;
	//if (!test_evp_pkey_encrypt_old(pkey, verbose)) err++;
	//if (!test_evp_sign(pkey, md, 0)) err++;
	//if (!test_evp_seal(curve_id, cipher, out, verbose)) err++;
	//if (!test_evp_digestsign(pkey, 1, md, verbose)) err++;

end:
	EVP_PKEY_free(pkey);
	EXIT(err);
}
#endif
