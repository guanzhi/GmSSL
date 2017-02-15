/* ====================================================================
 * Copyright (c) 2015 - 2016 The GmSSL Project.  All rights reserved.
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
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sm2.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#define EC_MAX_NBYTES  ((OPENSSL_ECC_MAX_FIELD_BITS + 7)/8)


int SM2_get_public_key_data(EC_KEY *ec_key, unsigned char *out, size_t *outlen)
{
	int ret = 0;
	const EC_GROUP *group;
	BN_CTX *bn_ctx = NULL;
	BIGNUM *p = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	int nbytes;
	size_t len;

	if (!ec_key || !outlen) {
		ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (!(group = EC_KEY_get0_group(ec_key))) {
		ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	/* degree is the bit length of field element, not the order of subgroup */
	nbytes = (EC_GROUP_get_degree(group) + 7)/8;
	len = nbytes * 6;

	if (!out) {
		*outlen = len;
		return 1;
	}
	if (*outlen < len) {
		ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA, EC_R_BUFFER_TOO_SMALL);
		return 0;
	}

	memset(out, 0, len);

	p = BN_new();
	x = BN_new();
	y = BN_new();
	bn_ctx = BN_CTX_new();
	if (!bn_ctx || !p || !x || !y) {
		ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA,  ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* get curve coefficients */
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
		if (!EC_GROUP_get_curve_GFp(group, p, x, y, bn_ctx)) {
			ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA, ERR_R_EC_LIB);
			goto end;
		}
	} else {
		if (!EC_GROUP_get_curve_GF2m(group, p, x, y, bn_ctx)) {
			ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA, ERR_R_EC_LIB);
			goto end;
		}
	}

	BN_bn2bin(x, out + nbytes - BN_num_bytes(x));
	out += nbytes;

	BN_bn2bin(y, out + nbytes - BN_num_bytes(y));
	out += nbytes;

	/* get curve generator coordinates */
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_get_affine_coordinates_GFp(group,
			EC_GROUP_get0_generator(group), x, y, bn_ctx)) {
			ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA, ERR_R_EC_LIB);
			goto end;
		}
	} else {
		if (!EC_POINT_get_affine_coordinates_GF2m(group,
			EC_GROUP_get0_generator(group), x, y, bn_ctx)) {
			ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA, ERR_R_EC_LIB);
			goto end;
		}
	}

	if (!BN_bn2bin(x, out + nbytes - BN_num_bytes(x))) {
		ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA, ERR_R_BN_LIB);
		goto end;
	}
	out += nbytes;

	if (!BN_bn2bin(y, out + nbytes - BN_num_bytes(y))) {
		ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA, ERR_R_BN_LIB);
		goto end;
	}
	out += nbytes;


	/* get pub_key coorindates */
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_get_affine_coordinates_GFp(group,
			EC_KEY_get0_public_key(ec_key), x, y, bn_ctx)) {
			ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA, ERR_R_EC_LIB);
			goto end;
		}
	} else {
		if (!EC_POINT_get_affine_coordinates_GF2m(group,
			EC_KEY_get0_public_key(ec_key), x, y, bn_ctx)) {
			ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA, ERR_R_EC_LIB);
			goto end;
		}
	}

	if (!BN_bn2bin(x, out + nbytes - BN_num_bytes(x))) {
		ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA, ERR_R_BN_LIB);
		goto end;
	}
	out += nbytes;

	if (!BN_bn2bin(y, out + nbytes - BN_num_bytes(y))) {
		ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA, ERR_R_BN_LIB);
		goto end;
	}

	*outlen = len;
	ret = 1;

end:
	BN_free(p);
	BN_free(x);
	BN_free(y);
	BN_CTX_free(bn_ctx);
	return ret;
}

int SM2_compute_id_digest(const EVP_MD *md, const char *id, size_t idlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	int ret = 0;
	EVP_MD_CTX *md_ctx = NULL;
	unsigned char idbits[2];
	unsigned char buf[SM2_MAX_PKEY_DATA_LENGTH];
	unsigned int len;
	size_t size;

	if (!md || !id || idlen <= 0 || !outlen || !ec_key) {
		ECerr(EC_F_SM2_COMPUTE_ID_DIGEST, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	/*
	 * check compatibility with the GM/T 0003.2-2012 standard
	 * digest length must be 256-bit/32-byte
	 * id length should be less than SM2_MAX_ID_LENGTH
	 */
	if (EVP_MD_size(md) != SM2_ID_DIGEST_LENGTH) {
		ECerr(EC_F_SM2_COMPUTE_ID_DIGEST, EC_R_INVALID_DIGEST_ALGOR);
		return 0;
	}
	if (strlen(id) != idlen) {
		ECerr(EC_F_SM2_COMPUTE_ID_DIGEST, EC_R_INVALID_SM2_ID);
		return 0;
	}
	if (idlen > SM2_MAX_ID_LENGTH || idlen <= 0) {
		ECerr(EC_F_SM2_COMPUTE_ID_DIGEST, EC_R_INVALID_ID_LENGTH);
		return 0;
	}

	if (!out) {
		*outlen = EVP_MD_size(md);
		return 1;
	}
	if (*outlen < EVP_MD_size(md)) {
		ECerr(EC_F_SM2_COMPUTE_ID_DIGEST, EC_R_BUFFER_TOO_SMALL);
		return 0;
	}

	/* prepare */
	if (!(md_ctx = EVP_MD_CTX_new())) {
		ECerr(EC_F_SM2_COMPUTE_ID_DIGEST, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	/* get public key data from ec_key */
	size = sizeof(buf);
	if (!SM2_get_public_key_data(ec_key, buf, &size)) {
		ECerr(EC_F_SM2_COMPUTE_ID_DIGEST, EC_R_GET_PUBLIC_KEY_DATA_FAILURE);
		goto end;
	}

	/* 2-byte id length in bits */
	idbits[0] = ((idlen * 8) >> 8) % 256;
	idbits[1] = (idlen * 8) % 256;

	/* compute digest of (idbits, id, pkeydata) */
	if (!EVP_DigestInit_ex(md_ctx, md, NULL)) {
		ECerr(EC_F_SM2_COMPUTE_ID_DIGEST, ERR_R_EVP_LIB);
		goto end;
	}
	if (!EVP_DigestUpdate(md_ctx, idbits, sizeof(idbits))) {
		ECerr(EC_F_SM2_COMPUTE_ID_DIGEST, ERR_R_EVP_LIB);
		goto end;
	}
	if (!EVP_DigestUpdate(md_ctx, id, idlen)) {
		ECerr(EC_F_SM2_COMPUTE_ID_DIGEST, ERR_R_EVP_LIB);
		goto end;
	}
	if (!EVP_DigestUpdate(md_ctx, buf, size)) {
		ECerr(EC_F_SM2_COMPUTE_ID_DIGEST, ERR_R_EVP_LIB);
		goto end;
	}
	len = EVP_MD_size(md);
	if (!EVP_DigestFinal_ex(md_ctx, out, &len)) {
		ECerr(EC_F_SM2_COMPUTE_ID_DIGEST, ERR_R_EVP_LIB);
		goto end;
	}

	*outlen = len;
	ret = 1;

end:
	EVP_MD_CTX_free(md_ctx);
        return ret;
}

/*
 * Generate GM/T 0003.2-2012 message digest for SM2 signature scheme.
 * Return dgst = msg_md( id_md(id, ec_key) || msg )
 */
int SM2_compute_message_digest(const EVP_MD *id_md, const EVP_MD *msg_md,
	const unsigned char *msg, size_t msglen, const char *id, size_t idlen,
	unsigned char *out, size_t *outlen,
	EC_KEY *ec_key)
{
	int ret = 0;
	EVP_MD_CTX *md_ctx;
	unsigned char buf[EVP_MAX_MD_SIZE];
	size_t len;

	if (!id_md || !msg_md || !msg || msglen <= 0 || !id || idlen <= 0 || !ec_key) {
		ECerr(EC_F_SM2_COMPUTE_MESSAGE_DIGEST, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(md_ctx = EVP_MD_CTX_new())) {
		ECerr(EC_F_SM2_COMPUTE_MESSAGE_DIGEST, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	len = sizeof(buf);
	if (!SM2_compute_id_digest(id_md, id, idlen, buf, &len, ec_key)) {
		ECerr(EC_F_SM2_COMPUTE_MESSAGE_DIGEST, ERR_R_EC_LIB);
		goto end;
	}

	if (!EVP_DigestInit_ex(md_ctx, msg_md, NULL)) {
		ECerr(EC_F_SM2_COMPUTE_MESSAGE_DIGEST, ERR_R_EVP_LIB);
		goto end;
	}
	if (!EVP_DigestUpdate(md_ctx, buf, len)) {
		ECerr(EC_F_SM2_COMPUTE_MESSAGE_DIGEST, ERR_R_EVP_LIB);
		goto end;
	}
	printf("zid(%d)=", len); for (int i=0; i<len; i++) printf("%02x", buf[i]); printf("\n");

	if (!EVP_DigestUpdate(md_ctx, msg, msglen)) {
		ECerr(EC_F_SM2_COMPUTE_MESSAGE_DIGEST, ERR_R_EVP_LIB);
		goto end;
	}
	printf("msg="); for (int i=0; i<len; i++) printf("%02x", msg[i]); printf("\n");

	len = sizeof(buf);
	if (!EVP_DigestFinal_ex(md_ctx, out, &len)) {
		ECerr(EC_F_SM2_COMPUTE_MESSAGE_DIGEST, ERR_R_EVP_LIB);
		goto end;
	}

	*outlen = len;
	ret = 1;

end:
	EVP_MD_CTX_free(md_ctx);
	return ret;
}

