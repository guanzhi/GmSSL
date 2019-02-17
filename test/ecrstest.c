/* ====================================================================
 * Copyright (c) 2014 - 2019 The GmSSL Project.  All rights reserved.
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

#ifdef OPENSSL_NO_ECRS
int main(int argc, char **argv)
{
	printf("No ECRS support\n");
	return 0;
}
#else
# include <openssl/evp.h>
# include <openssl/err.h>
# include <openssl/ecrs.h>
# include <openssl/objects.h>

# define NUM_KEYS 5

int main(int argc, char **argv)
{
	int err = 1;
	STACK_OF(EC_KEY) *keys = NULL;
	EC_KEY *ec_key = NULL;
	int type = NID_sm3;
	unsigned char dgst[32];
	unsigned char sig[(NUM_KEYS + 1) * 80];
	unsigned int siglen = sizeof(sig);
	int i;

	if (!(keys = sk_EC_KEY_new(NULL))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	for (i = 0; i < NUM_KEYS; i++) {
		if (!(ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1))) {
			ERR_print_errors_fp(stderr);
			goto end;
		}
		if (!EC_KEY_generate_key(ec_key)) {
			ERR_print_errors_fp(stderr);
			goto end;
		}
		sk_EC_KEY_push(keys, ec_key);
		ec_key = NULL;
	}

	if (!ECRS_sign(type, dgst, sizeof(dgst), sig, &siglen, keys,
		sk_EC_KEY_value(keys, 0))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (1 != ECRS_verify(type, dgst, sizeof(dgst), sig, siglen, keys)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	err = 0;

end:
	sk_EC_KEY_free(keys);
	EC_KEY_free(ec_key);
	EXIT(err);
}
#endif
