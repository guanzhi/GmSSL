/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
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
#include <gmssl/endian.h>
#include <gmssl/mem.h>

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

int pbkdf2_hmac_sm3_genkey(
	const char *pass, size_t passlen,
	const uint8_t *salt, size_t saltlen, size_t count,
	size_t outlen, uint8_t *out)
{
	SM3_HMAC_CTX ctx;
	SM3_HMAC_CTX ctx_tmpl;
	uint32_t iter = 1;
	uint8_t iter_be[4];
	uint8_t tmp_block[SM3_DIGEST_SIZE];
	uint8_t key_block[SM3_DIGEST_SIZE];
	// TODO: a bug in 3.0.0 is fixied. How to update release version 3.0.0 ? A test is also required!

	sm3_hmac_init(&ctx_tmpl, (uint8_t *)pass, passlen);

	while (outlen > 0) {
		size_t i;

		PUTU32(iter_be, iter);
		iter++;

		ctx = ctx_tmpl;
		sm3_hmac_update(&ctx, salt, saltlen);
		sm3_hmac_update(&ctx, iter_be, sizeof(iter_be));
		sm3_hmac_finish(&ctx, tmp_block);
		memcpy(key_block, tmp_block, SM3_DIGEST_SIZE);

		for (i = 1; i < count; i++) {
			ctx = ctx_tmpl;
			sm3_hmac_update(&ctx, tmp_block, SM3_DIGEST_SIZE);
			sm3_hmac_finish(&ctx, tmp_block);
			memxor(key_block, tmp_block, SM3_DIGEST_SIZE);
		}

		if (outlen < SM3_DIGEST_SIZE) {
			memcpy(out, key_block, outlen);
			out += outlen;
			outlen = 0;
		} else {
			memcpy(out, key_block, SM3_DIGEST_SIZE);
			out += SM3_DIGEST_SIZE;
			outlen -= SM3_DIGEST_SIZE;
		}
	}

	memset(&ctx, 0, sizeof(ctx));
	memset(key_block, 0, sizeof(key_block));
	memset(tmp_block, 0, sizeof(key_block));
	return 1;
}
