/* crypto/ecies/eciestest.c */
/* ====================================================================
 * Copyright (c) 2007 - 2015 The GmSSL Project.  All rights reserved.
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
#include <stdlib.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "ecies.h"

int ecies_test_ECIESParameters(void)
{
	int ret = 0;

	ECIES_PARAMS buffer;
	ECIES_PARAMS *param = &buffer;
	unsigned char *der = NULL;
	int derlen;
	unsigned char *p;
	const unsigned char *cp;

	param->kdf_md = EVP_sha1();
	param->sym_cipher = NULL;
	param->mac_md = EVP_sha1();

	derlen = i2d_ECIESParameters(param, NULL);
	if (derlen <= 0) {
		fprintf(stderr, "test i2d_ECIESParameters failed test suite 1\n");
		goto end;
	}
	der = OPENSSL_malloc(derlen);
	OPENSSL_assert(der);
	p = der;
	derlen = i2d_ECIESParameters(param, &p);

	param = NULL;
	cp = der;
	param = d2i_ECIESParameters(NULL, &cp, derlen);
	if (!param) {
		fprintf(stderr, "test d2i_ECIESParameters faild\n");
		goto end;
	}
	OPENSSL_free(param);

	param = NULL;
	cp = der;
	d2i_ECIESParameters(&param, &cp, derlen);
	if (!param) {
		fprintf(stderr, "test failed\n");
		goto end;
	}
	
	ret = 1;

end:
	return ret;	
}

void ecies_test(void)
{
	int r;
	EC_GROUP *ec_group = NULL;
	EC_KEY *ec_key = NULL;
	ECIES_PARAMS params;
	ECIES_PARAMS *param2 = NULL;
	ECIES_CIPHERTEXT_VALUE *cv = NULL;
	unsigned char buffer1[1024];
	unsigned char buffer2[1024];
	unsigned char buffer3[1024];
	unsigned char *der = NULL;
	int derlen;
	unsigned char *p;
	const unsigned char *cp;

	ec_key = EC_KEY_new_by_curve_name(OBJ_sn2nid("secp192k1"));
	OPENSSL_assert(ec_key);
	r = EC_KEY_generate_key(ec_key);
	assert(r);

	/* set ECIESParameters */
	params.kdf_md = EVP_sha1();
	params.sym_cipher = EVP_aes_128_cbc();
	params.mac_md = EVP_sha1();

	derlen = i2d_ECIESParameters(&params, NULL);
	printf("ECIESParameters DER length = %d\n", derlen);
	
	memset(buffer1, 0, sizeof(buffer1));
	strcpy((char *)buffer1, "hello");
	cv = ECIES_do_encrypt(&params, buffer1, strlen(buffer1) + 1, ec_key);
	assert(cv);

	memset(buffer3, 0, sizeof(buffer3));
	if (!ECIES_do_decrypt(cv, &params, buffer3, &derlen, ec_key)) {
		ERR_print_errors_fp(stderr);
		return;
	}

	printf("decrypted plaintext length = %d\n", derlen);
	printf("%s\n", buffer3);

	derlen = i2d_ECIES_CIPHERTEXT_VALUE(cv, NULL);
	printf("ECIES Test: ECIES_CIPHERTEXT_VALUE DER encoding length = %d\n", derlen);
	der = OPENSSL_malloc(derlen);
	assert(der);
	p = der;
	i2d_ECIES_CIPHERTEXT_VALUE(cv, &p);
	
	ECIES_CIPHERTEXT_VALUE_free(cv);
	cv = NULL;

	cp = der;
	cv = d2i_ECIES_CIPHERTEXT_VALUE(NULL, &cp, derlen);
	assert(cv);

	ecies_test_ECIESParameters();

}

int main(int argc, char **argv)
{
	ecies_test();
	return 0;
}

