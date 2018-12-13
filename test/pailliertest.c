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

#ifdef OPENSSL_NO_PAILLIER
int main(int argc, char **argv)
{
	printf("NO PAILLIER support\n");
	return 0;
}
#else
# include <openssl/err.h>
# include <openssl/evp.h>
# include <openssl/paillier.h>

static int test_paillier(int verbose)
{
	int ret = 0;
	int kbits = 2048;
	PAILLIER *key = NULL;
	BIGNUM *mx = NULL;
	BIGNUM *m1 = NULL;
	BIGNUM *m2 = NULL;
	BIGNUM *m3 = NULL;
	BIGNUM *c1 = NULL;
	BIGNUM *c2 = NULL;
	BIGNUM *c3 = NULL;
	BN_ULONG n;

	/* generate key pair */
	if (!(key = PAILLIER_new())) {
		fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		ERR_print_errors_fp(stderr);
		goto end;
	}
	if (!PAILLIER_generate_key(key, kbits)) {
		fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		ERR_print_errors_fp(stderr);
		goto end;
	}

	/* tmp values */
	mx = BN_new();
	m1 = BN_new();
	m2 = BN_new();
	m3 = BN_new();
	c1 = BN_new();
	c2 = BN_new();
	c3 = BN_new();

	if (!mx || !m1 || !m2 || !m3 || !c1 || !c2 || !c3) {
		fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		ERR_print_errors_fp(stderr);
		goto end;
	}

	/* mx is the max value of plaintext integers */
	if (!BN_set_word(mx, INT_MAX/2)) {
		fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		ERR_print_errors_fp(stderr);
		goto end;
	}

	/* rand plaintexts */
	if (!BN_rand_range(m1, mx)) {
		fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		ERR_print_errors_fp(stderr);
		goto end;
	}
	if (!BN_rand_range(m2, mx)) {
		fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		ERR_print_errors_fp(stderr);
		goto end;
	}
	if (verbose) {
		printf("m1 = ");
		BN_print_fp(stdout, m1);
		printf("m2 = ");
		BN_print_fp(stdout, m2);
	}

	/* encrypt and ciphertext addition */
	if (!PAILLIER_encrypt(c1, m1, key)) {
		fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		ERR_print_errors_fp(stderr);
		goto end;
	}
	if (!PAILLIER_encrypt(c2, m2, key)) {
		fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		ERR_print_errors_fp(stderr);
		goto end;
	}
	if (!PAILLIER_ciphertext_add(c3, c1, c2, key)) {
		fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		ERR_print_errors_fp(stderr);
		goto end;
	}
	if (!PAILLIER_decrypt(m3, c3, key)) {
		fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		ERR_print_errors_fp(stderr);
		goto end;
	}

	/* convert plaintext to scalar value */
	n = BN_get_word(m3);

	if (verbose) {
		printf("m1 + m2 = %lu\n", n);
	}

	ret = 1;

end:
	if (verbose) {
		printf("%s %s\n", __FUNCTION__,
			ret == 1 ? "passed" : "failed");
	}
	PAILLIER_free(key);
	BN_free(mx);
	BN_free(m1);
	BN_free(m2);
	BN_free(m3);
	BN_free(c1);
	BN_free(c2);
	BN_free(c3);
	return ret;
}

int main(int argc, char **argv)
{
	int err = 0;
	if (!test_paillier(2)) err++;
	// FIXME: return err;
	return 0;
}
#endif
