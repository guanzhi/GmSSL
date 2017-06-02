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
/*
 * Solinas Prime (prime number with low weight)
 */

#ifndef HEADER_BN_SOLINAS_H
#define HEADER_BN_SOLINAS_H

#include <openssl/bn.h>

#ifdef __cplusplus
extern "C" {
#endif

/* solinas prime = 2^a + s * 2^b + c */
typedef struct {
	int a;
	int b;
	int s;
	int c;
} BN_SOLINAS;

int BN_bn2solinas(const BIGNUM *bn, BN_SOLINAS *solinas);
int BN_solinas2bn(const BN_SOLINAS *solinas, BIGNUM *bn);
int BN_is_solinas(const BIGNUM *bn);

/*
 * the following Solinas primes are from
 * "Solinas primes of small weight for fixed sizes"
 * https://eprint.iacr.org/2010/058.pdf
 *
 * 2^192 - 2^16  - 1
 * 2^192 - 2^64  - 1
 * 2^224 - 2^96  + 1
 * 2^256 - 2^168 + 1
 * 2^384 - 2^80  + 1
 * 2^512 - 2^32  + 1
 * 2^512 - 2^32  - 1
 * 2^1024 - 2^424 - 1
 * 2^1024 - 2^856 + 1
 */


#ifdef __cplusplus
}
#endif
#endif
