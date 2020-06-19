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

#include <string.h>
#include <openssl/ec.h>
#include <openssl/sm2.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>
#include "../ec/ec_lcl.h"
#include "sm2_lcl.h"


ASN1_SEQUENCE(SM2CiphertextValue) = {
	ASN1_SIMPLE(SM2CiphertextValue, xCoordinate, BIGNUM),
	ASN1_SIMPLE(SM2CiphertextValue, yCoordinate, BIGNUM),
	ASN1_SIMPLE(SM2CiphertextValue, hash, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SM2CiphertextValue, ciphertext, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(SM2CiphertextValue)
IMPLEMENT_ASN1_FUNCTIONS(SM2CiphertextValue)
IMPLEMENT_ASN1_DUP_FUNCTION(SM2CiphertextValue)

int SM2_ciphertext_size(const EC_KEY *ec_key, size_t inlen)
{
	int ret;
	const EC_GROUP *group = NULL;
	ASN1_OCTET_STRING s;
	int len = 0, i;

	if (inlen > SM2_MAX_PLAINTEXT_LENGTH) {
		SM2err(SM2_F_SM2_CIPHERTEXT_SIZE, SM2_R_PLAINTEXT_TOO_LONG);
		return 0;
	}

	if (ec_key) {
		group = EC_KEY_get0_group(ec_key);
	}

	if (group) {
		ASN1_INTEGER a;
		unsigned char buf[4] = {0xff};

		/* ASN1_INTEGER xCoordinate, yCoordinate */
		if (!(i = EC_GROUP_order_bits(group))) {
			SM2err(SM2_F_SM2_CIPHERTEXT_SIZE, ERR_R_EC_LIB);
			return 0;
		}
		a.length = (i + 7)/8;
		a.data = buf;
		a.type = V_ASN1_INTEGER;
		i = i2d_ASN1_INTEGER(&a, NULL);
		len = i + i;

		/* ASN1_OCTET_STRING hash 32 */
		s.length = SM3_DIGEST_LENGTH;
		s.data = NULL;
		s.type = V_ASN1_OCTET_STRING;
		i = i2d_ASN1_OCTET_STRING(&s, NULL);
		len += i;

	} else {
		len += 104;
	}

	/* ASN1_OCTET_STRING ciphertext inlen */
	s.length = inlen;
	s.data = NULL;
	s.type = V_ASN1_OCTET_STRING;
	i = i2d_ASN1_OCTET_STRING(&s, NULL);
	len += i;

	ret = ASN1_object_size(1, len, V_ASN1_SEQUENCE);
	return ret;
}

int i2d_SM2CiphertextValue_bio(BIO *bp, SM2CiphertextValue *a)
{
	return ASN1_item_i2d_bio(ASN1_ITEM_rptr(SM2CiphertextValue), bp, a);
}

SM2CiphertextValue *d2i_SM2CiphertextValue_bio(BIO *bp, SM2CiphertextValue **a)
{
	return ASN1_item_d2i_bio(ASN1_ITEM_rptr(SM2CiphertextValue), bp, a);
}

#ifndef OPENSSL_NO_STDIO
SM2CiphertextValue *d2i_SM2CiphertextValue_fp(FILE *fp, SM2CiphertextValue **a)
{
	return ASN1_item_d2i_fp(ASN1_ITEM_rptr(SM2CiphertextValue), fp, a);
}

int i2d_SM2CiphertextValue_fp(FILE *fp, SM2CiphertextValue *a)
{
	return ASN1_item_i2d_fp(ASN1_ITEM_rptr(SM2CiphertextValue), fp, a);
}
#endif
