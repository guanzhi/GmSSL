/*
 * Copyright (c) 2014 - 2020 The GmSSL Project.  All rights reserved.
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
 */


/*
   PBKDF2 (P, S, c, dkLen)

   Options:        PRF        underlying pseudorandom function (hLen
                              denotes the length in octets of the
                              pseudorandom function output)

   Input:          P          password, an octet string
                   S          salt, an octet string
                   c          iteration count, a positive integer
                   dkLen      intended length in octets of the derived
                              key, a positive integer, at most
                              (2^32 - 1) * hLen

   Output:         DK         derived key, a dkLen-octet string

   Steps:

      1. If dkLen > (2^32 - 1) * hLen, output "derived key too long" and
         stop.

      2. Let l be the number of hLen-octet blocks in the derived key,
         rounding up, and let r be the number of octets in the last
         block:

                   l = CEIL (dkLen / hLen) ,
                   r = dkLen - (l - 1) * hLen .

         Here, CEIL (x) is the "ceiling" function, i.e. the smallest
         integer greater than, or equal to, x.

      3. For each block of the derived key apply the function F defined
         below to the password P, the salt S, the iteration count c, and
         the block index to compute the block:

                   T_1 = F (P, S, c, 1) ,
                   T_2 = F (P, S, c, 2) ,
                   ...
                   T_l = F (P, S, c, l) ,

         where the function F is defined as the exclusive-or sum of the
         first c iterates of the underlying pseudorandom function PRF
         applied to the password P and the concatenation of the salt S
         and the block index i:

                   F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c

         where

                   U_1 = PRF (P, S || INT (i)) ,
                   U_2 = PRF (P, U_1) ,
                   ...
                   U_c = PRF (P, U_{c-1}) .

         Here, INT (i) is a four-octet encoding of the integer i, most
         significant octet first.

      4. Concatenate the blocks and extract the first dkLen octets to
         produce a derived key DK:

                   DK = T_1 || T_2 ||  ...  || T_l<0..r-1>

      5. Output the derived key DK.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmssl/asn1.h>
#include <gmssl/hmac.h>
#include <gmssl/digest.h>
#include <gmssl/error.h>
#include <gmssl/oid.h>
#include "endian.h"
#include "mem.h"

int pbkdf2_genkey(const DIGEST *digest,
	const char *pass, size_t passlen,
	const uint8_t *salt, size_t saltlen, size_t count,
	size_t outlen, uint8_t *out)
{
	HMAC_CTX ctx;
	HMAC_CTX ctx_tmpl;
	uint32_t iter = 1;
	uint8_t iter_be[4];
	uint8_t tmp_block[64];
	uint8_t key_block[64];
	size_t len;

	hmac_init(&ctx_tmpl, digest, (uint8_t *)pass, passlen);

	while (outlen > 0) {
		size_t i;

		PUTU32(iter_be, iter);
		iter++;

		ctx = ctx_tmpl;
		hmac_update(&ctx, salt, saltlen);
		hmac_update(&ctx, iter_be, sizeof(iter_be));
		hmac_finish(&ctx, tmp_block, &len);
		memcpy(key_block, tmp_block, len);

		for (i = 1; i < count; i++) {
			ctx = ctx_tmpl;
			hmac_update(&ctx, tmp_block, len);
			hmac_finish(&ctx, tmp_block, &len);
			memxor(key_block, tmp_block, len);
		}

		if (outlen < len) {
			memcpy(out, key_block, outlen);
			out += outlen;
			outlen = 0;
		} else {
			memcpy(out, key_block, len);
			out += len;
			outlen -= len;
		}
	}

	memset(&ctx, 0, sizeof(ctx));
	memset(key_block, 0, sizeof(key_block));
	memset(tmp_block, 0, sizeof(key_block));
	return 1;
}
