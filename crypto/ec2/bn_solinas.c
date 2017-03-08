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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/bn_solinas.h>
#include "../bn/bn_lcl.h"

/*
 * generate the solinas prime tables,
 * use it for fast check of solinas
 */

static BN_SOLINAS BN_solinas_table[] = {
	{ 192, 16, -1, -1 },
	{ 192, 64, -1, -1 },
	{ 224, 96, -1,  1 },
	{ 256, 168, -1, 1 },
	{ 384, 80, -1,  1 },
	{ 512, 32, -1,  1 },
	{ 512, 32, -1, -1 },
	{ 1024, 424, -1, -1 },
	{ 1024, 856, -1, 1 },
};

/*
 * solinas = 2^a + s * 2^b + c, where s, c in {1, -1}
 * solinas looks like:
 *   2^a + 2^b + 1 = 10000100001
 *   2^a - 2^b + 1 =  1111100001
 *   2^a + 2^b - 1 = 10000011111
 *   2^a - 2^b - 1 =  1111011111
 * so:
 *   n = len(bits(solinas))
 *   c = bits(solinas)[1] == 0 ? 1 : -1
 *   s = bits(solinas)[n-2] == 0 ? 1 : -1
 *   a = bits(solinas)[n-2] == 0 ? n-1 : n-2
 *   b = len(bits(solinas - 2^a - s*2^b - c)) - 1
 *
 * examples:
 *   0xfffffffffffffffffffffffffffbffff
 *   0xffffffffffffffffffffffeffffffffffff
 *   0xfffffffffbfffffffffffffffffffffffff
 */


int BN_bn2solinas(const BIGNUM *bn, BN_SOLINAS *solinas)
{
	int ret = 0;
	BIGNUM *tmp = NULL;
	int nbits;
	int i;

	if (!solinas || !bn) {
		BNerr(BN_F_BN_BN2SOLINAS, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!BN_copy(tmp, bn)) {
		goto end;
	}

	if ((nbits = BN_num_bits(bn) - 1) < 1) {
		BNerr(BN_F_BN_BN2SOLINAS, BN_R_INVALID_SOLINAS);
		goto end;
	}

	solinas->c = BN_is_bit_set(bn, 1) ? 1 : -1;
	if (BN_is_bit_set(bn, nbits - 1)) {
		solinas->s = -1;
		solinas->a = nbits;
	} else {
		solinas->s = 1;
		solinas->a = nbits - 1;
	}

	for (i = 1; i < nbits; i++) {
	}

end:
	return ret;
}

int BN_solinas2bn(const BN_SOLINAS *solinas, BIGNUM *bn)
{
	int ret = 0;
#if 0
	BIGNUM *tmp = NULL;
	if (b <= 0 || a <= b || (s != 1 && s != -1) ||
		(c != 1 && c != -1)) {
		BNerr(BN_F_BN_SOLINAS2BN, BN_R_INVALID_SOLINAS_PARAMETERS);
		return 0;
	}

	if (!(tmp = BN_new())) {
		BNerr(BN_F_BN_SOLINAS2BN, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	BN_one(tmp);

	if (!BN_lshift(solinas, tmp, a)) {
		BNerr(BN_F_BN_SOLINAS2BN, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_lshift(tmp, tmp, b)) {
		BNerr(BN_F_BN_SOLINAS2BN, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_add_word(tmp, c)) {
		BNerr(BN_F_BN_SOLINAS2BN, ERR_R_BN_LIB);
		goto end;
	}
	if (s > 0) {
		if (!BN_add(solinas, solinas, tmp)) {
			BNerr(BN_F_BN_SOLINAS2BN, ERR_R_BN_LIB);
			goto end;
		}
	} else {
		if (!BN_sub(solinas, solinas, tmp)) {
			BNerr(BN_F_BN_SOLINAS2BN, ERR_R_BN_LIB);
			goto end;
		}
	}

	/* check if solinas is a prime */

	ret = 1;
end:
	BN_free(tmp);
#endif
	return ret;
}

int BN_generate_solinas(BIGNUM *ret, BN_SOLINAS *solinas, BN_GENCB *cb)
{
	return 0;
}

int BN_is_solinas(const BIGNUM *a)
{
	return 0;
}

