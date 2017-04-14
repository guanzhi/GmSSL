/* ====================================================================
 * Copyright (c) 2016 The GmSSL Project.  All rights reserved.
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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include "../bn/bn_lcl.h"

int BN_hash_to_range(const EVP_MD *md, BIGNUM **bn,
	const void *s, size_t slen, const BIGNUM *range, BN_CTX *bn_ctx)
{
	int ret = 0;
	BIGNUM *r = NULL;
	BIGNUM *a = NULL;
	unsigned char *buf = NULL;
	size_t buflen, mdlen;
	int nbytes, rounds, i;

	if (!s || slen <= 0 || !md || !range) {
		BNerr(BN_F_BN_HASH_TO_RANGE, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(*bn)) {
		if (!(r = BN_new())) {
			BNerr(BN_F_BN_HASH_TO_RANGE, ERR_R_MALLOC_FAILURE);
			return 0;
		}
	} else {
		r = *bn;
		BN_zero(r);
	}

	mdlen = EVP_MD_size(md);
	buflen = mdlen + slen;
	if (!(buf = OPENSSL_malloc(buflen))) {
		BNerr(BN_F_BN_HASH_TO_RANGE, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	memset(buf, 0, mdlen);
	memcpy(buf + mdlen, s, slen);

	a = BN_new();
	if (!a) {
		BNerr(BN_F_BN_HASH_TO_RANGE, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	nbytes = BN_num_bytes(range);
	rounds = (nbytes + mdlen - 1)/mdlen;

	if (!bn_expand(r, rounds * mdlen * 8)) {
		BNerr(BN_F_BN_HASH_TO_RANGE, ERR_R_BN_LIB);
		goto end;
	}

	for (i = 0; i < rounds; i++) {
		if (!EVP_Digest(buf, buflen, buf, (unsigned int *)&mdlen, md, NULL)) {
			BNerr(BN_F_BN_HASH_TO_RANGE, ERR_R_EVP_LIB);
			goto end;
		}
		if (!BN_bin2bn(buf, mdlen, a)) {
			BNerr(BN_F_BN_HASH_TO_RANGE, ERR_R_BN_LIB);
			goto end;
		}
		if (!BN_lshift(r, r, mdlen * 8)) {
			BNerr(BN_F_BN_HASH_TO_RANGE, ERR_R_BN_LIB);
			goto end;
		}
		if (!BN_uadd(r, r, a)) {
			goto end;
		}
	}

	if (!BN_mod(r, r, range, bn_ctx)) {
		BNerr(BN_F_BN_HASH_TO_RANGE, ERR_R_BN_LIB);
		goto end;
	}

	*bn = r;
	ret = 1;
end:
	if (!ret && !(*bn)) {
		BN_free(r);
	}
	BN_free(a);
	OPENSSL_free(buf);
	return ret;
}
