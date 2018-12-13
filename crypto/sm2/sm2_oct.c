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
#include "sm2_lcl.h"


int i2o_SM2CiphertextValue(const EC_GROUP *group, const SM2CiphertextValue *cv,
	unsigned char **pout)
{
	int ret = 0, outlen = 0, nbytes;
	EC_POINT *point = NULL;
	BN_CTX *bn_ctx = NULL;
	unsigned char *buf;
	unsigned char *p;
	size_t siz;

	if (!group || !cv || !pout) {
		SM2err(SM2_F_I2O_SM2CIPHERTEXTVALUE,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	nbytes = (EC_GROUP_get_degree(group) + 7)/8;

	if (!cv->xCoordinate || BN_num_bytes(cv->xCoordinate) > nbytes
		|| !cv->yCoordinate || BN_num_bytes(cv->yCoordinate) > nbytes
		|| ASN1_STRING_length(cv->hash) <= 0
		|| ASN1_STRING_length(cv->hash) > EVP_MAX_MD_SIZE
		|| ASN1_STRING_length(cv->ciphertext) <= 0) {
		SM2err(SM2_F_I2O_SM2CIPHERTEXTVALUE, SM2_R_INVALID_CIPHERTEXT);
		return 0;
	}

	/* prepare buffer */
	if (*pout) {
		p = *pout;

	} else {
		size_t buflen = 1 + nbytes * 2
			+ ASN1_STRING_length(cv->ciphertext)
			+ ASN1_STRING_length(cv->hash);

		if (!(buf = OPENSSL_malloc(buflen))) {
			SM2err(SM2_F_I2O_SM2CIPHERTEXTVALUE,
				ERR_R_MALLOC_FAILURE);
			return 0;
		}

		p = buf;
	}

	/* encode x, y */
	if (!(point = EC_POINT_new(group)) || !(bn_ctx = BN_CTX_new())) {
		SM2err(SM2_F_I2O_SM2CIPHERTEXTVALUE, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_set_affine_coordinates_GFp(group, point,
			cv->xCoordinate, cv->yCoordinate, bn_ctx)) {
			goto end;
		}
	} else {
		if (!EC_POINT_set_affine_coordinates_GF2m(group, point,
			cv->xCoordinate, cv->yCoordinate, bn_ctx)) {
			goto end;
		}
	}

	if (!(siz = EC_POINT_point2oct(group, point,
		POINT_CONVERSION_UNCOMPRESSED, p, 1 + 2 * nbytes, bn_ctx))) {
		SM2err(SM2_F_I2O_SM2CIPHERTEXTVALUE, ERR_R_EC_LIB);
		goto end;
	}
	OPENSSL_assert(siz == 1 + 2 * nbytes);
	p += siz;
	outlen += siz;

	/* encode ciphertext */
	memcpy(p, ASN1_STRING_get0_data(cv->ciphertext),
		ASN1_STRING_length(cv->ciphertext));
	p += ASN1_STRING_length(cv->ciphertext);
	outlen += ASN1_STRING_length(cv->ciphertext);

	/* encode hash */
	memcpy(p, ASN1_STRING_get0_data(cv->hash),
		ASN1_STRING_length(cv->hash));
	p += ASN1_STRING_length(cv->hash);
	outlen += ASN1_STRING_length(cv->hash);

	/* output */
	if (*pout) {
		*pout = p;
	} else {
		*pout = buf;
		buf = NULL;
	}
	ret = outlen;

end:
	EC_POINT_free(point);
	BN_CTX_free(bn_ctx);
	return ret;
}

SM2CiphertextValue *o2i_SM2CiphertextValue(const EC_GROUP *group,
	const EVP_MD *md, SM2CiphertextValue **pout,
	const unsigned char **pin, long len)
{
	SM2CiphertextValue *ret = NULL;
	SM2CiphertextValue *cv = NULL;
	BN_CTX *bn_ctx = NULL;
	EC_POINT *point = NULL;
	const unsigned char *p;
	int nbytes;

	if (!group || !pin) {
		SM2err(SM2_F_O2I_SM2CIPHERTEXTVALUE,
			ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	nbytes = (EC_GROUP_get_degree(group) + 7)/8;

	if (len <= 1 + nbytes * 2 + EVP_MD_size(md)) {
		SM2err(SM2_F_O2I_SM2CIPHERTEXTVALUE,
			SM2_R_INVALID_CIPHERTEXT);
		return NULL;
	}

	if (pout && *pout) {
		cv = *pout;
	} else {
		if (!(cv = SM2CiphertextValue_new())) {
			SM2err(SM2_F_O2I_SM2CIPHERTEXTVALUE,
				ERR_R_MALLOC_FAILURE);
			goto end;
		}
	}

	if (!(point = EC_POINT_new(group))
		|| !(bn_ctx = BN_CTX_new())) {
		SM2err(SM2_F_O2I_SM2CIPHERTEXTVALUE,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}

	p = *pin;

	/* set (x, y) */
	if (!EC_POINT_oct2point(group, point, p, 1 + nbytes * 2, bn_ctx)) {
		SM2err(SM2_F_O2I_SM2CIPHERTEXTVALUE,
			SM2_R_INVALID_CIPHERTEXT);
		goto end;
	}
	p += 1 + nbytes * 2;
	len -= 1 + nbytes * 2;

	if (!cv->xCoordinate) {
		if (!(cv->xCoordinate = BN_new())) {
			SM2err(SM2_F_O2I_SM2CIPHERTEXTVALUE,
				ERR_R_MALLOC_FAILURE);
			goto end;
		}
	}
	if (!cv->yCoordinate) {
		if (!(cv->yCoordinate = BN_new())) {
			SM2err(SM2_F_O2I_SM2CIPHERTEXTVALUE,
				ERR_R_MALLOC_FAILURE);
			goto end;
		}
	}

	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_get_affine_coordinates_GFp(group, point,
			cv->xCoordinate, cv->yCoordinate, bn_ctx)) {
			SM2err(SM2_F_O2I_SM2CIPHERTEXTVALUE, ERR_R_EC_LIB);
			goto end;
		}
	} else {
		if (!EC_POINT_get_affine_coordinates_GF2m(group, point,
			cv->xCoordinate, cv->yCoordinate, bn_ctx)) {
			SM2err(SM2_F_O2I_SM2CIPHERTEXTVALUE, ERR_R_EC_LIB);
			goto end;
		}
	}

	/* set ciphertext */
	if (!cv->ciphertext) {
		if (!(cv->ciphertext = ASN1_OCTET_STRING_new())) {
			SM2err(SM2_F_O2I_SM2CIPHERTEXTVALUE,
				ERR_R_MALLOC_FAILURE);
			goto end;
		}
	}

	if (!ASN1_OCTET_STRING_set(cv->ciphertext, p, len - EVP_MD_size(md))) {
		SM2err(SM2_F_O2I_SM2CIPHERTEXTVALUE, ERR_R_ASN1_LIB);
		goto end;
	}
	p += len - EVP_MD_size(md);

	/* set hash */
	if (!cv->hash) {
		if (!(cv->hash = ASN1_OCTET_STRING_new())) {
			SM2err(SM2_F_O2I_SM2CIPHERTEXTVALUE,
				ERR_R_MALLOC_FAILURE);
			goto end;
		}
	}

	if (!ASN1_OCTET_STRING_set(cv->hash, p, EVP_MD_size(md))) {
		SM2err(SM2_F_O2I_SM2CIPHERTEXTVALUE, ERR_R_ASN1_LIB);
		goto end;
	}
	p += EVP_MD_size(md);

	/* set result */
	*pin = p;
	ret = cv;
	cv = NULL;

end:
	if ((cv != *pout) && (!ret))
		SM2CiphertextValue_free(cv);

	EC_POINT_free(point);
	BN_CTX_free(bn_ctx);
	return ret;
}
