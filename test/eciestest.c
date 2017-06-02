/* ====================================================================
 * Copyright (c) 2007 - 2016 The GmSSL Project.  All rights reserved.
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

#ifdef OPENSSL_NO_ECIES
int main(int argc, char **argv)
{
	printf("NO ECIES support\n");
	return 0;
}
#else
# include <assert.h>
# include <openssl/evp.h>
# include <openssl/err.h>
# include <openssl/ecies.h>

static int ECIES_test(int verbose)
{
	int ret = 0;
	EC_KEY *ec_key = NULL;
	unsigned char mbuf[] = "message to be encrypted";
	size_t mlen = sizeof(mbuf);
	unsigned char *cbuf = NULL;
	unsigned char *pbuf = NULL;
	size_t clen, plen;

	/* generate key pair */
	if (!(ec_key = EC_KEY_new_by_curve_name(NID_secp192k1))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	if (!EC_KEY_generate_key(ec_key)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	/* estimate output buffer size */
	if (!ECIES_encrypt_with_recommended(mbuf, sizeof(mbuf), NULL, &clen, ec_key)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	/* prepare buffer */
	if (!(cbuf = OPENSSL_malloc(clen))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	/* encrypt */
	if (!ECIES_encrypt_with_recommended(mbuf, sizeof(mbuf), cbuf, &clen, ec_key)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (verbose) {
		printf("plaintext = %s\n", (char *)mbuf);
	}

	if (verbose) {
		int i;
		printf("ciphertext = ");
		for (i = 0; i < clen; i++) {
			printf("%02X", cbuf[i]);
		}
		printf("\n");
	}

	/* estimate output buffer size */
	if (!ECIES_decrypt_with_recommended(cbuf, clen, NULL, &plen, ec_key)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	/* prepare buffer */
	if (!(pbuf = OPENSSL_zalloc(plen))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	/* decrypt */
	if (!ECIES_decrypt_with_recommended(cbuf, clen, pbuf, &plen, ec_key)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (verbose) {
		printf("plaintext = %s\n", pbuf);
	}

	/* compare plaintext, and set result */
	if (plen == mlen && memcmp(mbuf, pbuf, mlen) == 0) {
		ret = 1;
	}

	if (verbose) {
		printf("%s() %s\n", __FUNCTION__,
			ret == 1 ? "passed" : "failed");
	}

end:
	EC_KEY_free(ec_key);
	OPENSSL_free(cbuf);
	OPENSSL_free(pbuf);
	return ret;
}

int main(int argc, char **argv)
{
	int verbose = 2;
	if (!ECIES_test(verbose)) {
		printf("test failed\n");
		return 1;
	} else {
		printf("test ok\n");
		return 0;
	}
}
#endif
