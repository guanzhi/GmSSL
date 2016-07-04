/* crypto/sm2/sm2_lib.c */
/* ====================================================================
 * Copyright (c) 2015 The GmSSL Project.  All rights reserved.
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
 *
 */


#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sm2.h>

#define EC_MAX_NBYTES	((OPENSSL_ECC_MAX_FIELD_BITS + 7)/8)



static void *sm2_data_dup(void *data) {
	if (data)
		return OPENSSL_strdup((const char *)data);
	else	return NULL;
}

static void sm2_data_free(void *data) {
	if (data)
		OPENSSL_free(data);
}

int SM2_set_id(EC_KEY *ec_key, const char *id)
{
	char *pid;

	if (strlen(id) > SM2_MAX_ID_LENGTH) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		return 0;
	}

	if ((pid = EC_KEY_get_key_method_data(ec_key, sm2_data_dup,
		sm2_data_free, sm2_data_free)) != NULL) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		return 0;
	}

	if (!(pid = OPENSSL_strdup(id))) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		return 0;
	}

	if (EC_KEY_insert_key_method_data(ec_key, pid, sm2_data_dup,
		sm2_data_free, sm2_data_free)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		//ERR_print_errors_fp(stderr);
		//OPENSSL_free(pid);
		return 0;
	}

	return 1;
}

char *SM2_get0_id(EC_KEY *ec_key)
{
	return (char *)EC_KEY_get_key_method_data(ec_key, sm2_data_dup,
		sm2_data_free, sm2_data_free);
}

/*
 * pkdata = a || b || G.x || G.y || P.x || P.y
 */
int sm2_get_public_key_data(unsigned char *buf, EC_KEY *ec_key)
{
	int ret = -1;
	const EC_GROUP *ec_group = EC_KEY_get0_group(ec_key);
	const EC_POINT *point;
	int nbytes;
	unsigned char oct[EC_MAX_NBYTES * 2 + 1];
	BN_CTX *bn_ctx = NULL;
	BIGNUM *p = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	size_t len;

	if (!ec_key || !buf) {
		return 0;
	}
	nbytes = (EC_GROUP_get_degree(EC_KEY_get0_group(ec_key)) + 7)/8;
	memset(buf, 0, nbytes * 6);

	bn_ctx = BN_CTX_new();
	p = BN_new();
	x = BN_new();
	y = BN_new();
	if (!bn_ctx || !p || !x || !y) {
		goto err;
	}

	if (EC_METHOD_get_field_type(EC_GROUP_method_of(ec_group)) == NID_X9_62_prime_field) {
		if (!EC_GROUP_get_curve_GFp(ec_group, p, x, y, bn_ctx)) {
			goto err;
		}
	} else {
		if (!EC_GROUP_get_curve_GF2m(ec_group, p, x, y, bn_ctx)) {
			goto err;
		}
	}


	buf += nbytes;
	BN_bn2bin(x, buf - BN_num_bytes(x));
	buf += nbytes;
	BN_bn2bin(y, buf - BN_num_bytes(y));

	/* get curve generator coordinates */
	if (!(point = EC_GROUP_get0_generator(ec_group))) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto err;
	}
	if (!(len = EC_POINT_point2oct(ec_group, point,
		POINT_CONVERSION_UNCOMPRESSED, oct, sizeof(oct), bn_ctx))) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto err;
	}
	//OPENSSL_assert(len == 32 * 2 + 1); 
	memcpy(buf, oct + 1, len - 1);
	buf += len - 1;

	/* get pub_key coorindates */
	if (!(point = EC_KEY_get0_public_key(ec_key))) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto err;
	}
	if (!(len = EC_POINT_point2oct(ec_group, point,
		POINT_CONVERSION_UNCOMPRESSED, oct, sizeof(oct), bn_ctx))) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto err;
	}
	//OPENSSL_assert(len == 32 * 2 + 1); 
	memcpy(buf, oct + 1, len - 1);
	buf += len - 1;

	ret = (nbytes * 6);

err:
	if (bn_ctx) BN_CTX_free(bn_ctx);
	if (p) BN_free(p);
	if (x) BN_free(x);
	if (y) BN_free(y);

	return ret;
}

int SM2_compute_id_digest_ex(const EVP_MD *md,
	unsigned char *dgst, size_t dgstlen,
	const char *id, size_t idlen, EC_KEY *ec_key)
{
	SM2err(SM2_F_SM2_COMPUTE_ID_DIGEST_EX, ERR_R_SM2_LIB);
	return 0;
}

//TODO: review this function again.
int SM2_compute_id_digest(const EVP_MD *md, unsigned char *dgst,
	unsigned int *dgstlen, EC_KEY *ec_key)
{
        int ret = 0;
        EVP_MD_CTX *md_ctx = NULL;
        unsigned char pkdata[EC_MAX_NBYTES * 6];
	unsigned char idbits[2];
	int pkdatalen;
	char *id;

	if ((pkdatalen = sm2_get_public_key_data(pkdata, ec_key)) < 0) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto err;
	}

	if (!(id = SM2_get0_id(ec_key))) {
		id = SM2_DEFAULT_ID;
	}


	idbits[0] = ((strlen(id) * 8) >> 8) % 256;
	idbits[1] = (strlen(id) * 8) % 256;


	if (!(md_ctx = EVP_MD_CTX_create())) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto err;
	}
	if (!EVP_DigestInit_ex(md_ctx, md, NULL)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		ERR_print_errors_fp(stderr);
		goto err;
	}
	if (!EVP_DigestUpdate(md_ctx, idbits, sizeof(idbits))) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto err;
	}
	if (!EVP_DigestUpdate(md_ctx, id, strlen(id))) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto err;
	}
	if (!EVP_DigestUpdate(md_ctx, pkdata, pkdatalen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto err;
	}
	if (!EVP_DigestFinal_ex(md_ctx, dgst, dgstlen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto err;
	}

	ret = 1;

err:
	if (md_ctx) EVP_MD_CTX_destroy(md_ctx);
        return ret;
}

int SM2_compute_message_digest(const EVP_MD *id_md, const EVP_MD *msg_md,
	const void *msg, size_t msglen, unsigned char *dgst,
	unsigned int *dgstlen, EC_KEY *ec_key)
{
	int ret = 0;
	EVP_MD_CTX md_ctx;
	unsigned char buf[EVP_MAX_MD_SIZE];
	unsigned int len;

	EVP_MD_CTX_init(&md_ctx);

	if (!EVP_DigestInit_ex(&md_ctx, msg_md, NULL)) {
		goto err;
	}

	if (!SM2_compute_id_digest(id_md, buf, &len, ec_key)) {
		goto err;
	}

	if (!EVP_DigestUpdate(&md_ctx, buf, len)) {
		goto err;
	}

	if (!EVP_DigestUpdate(&md_ctx, msg, msglen)) {
		goto err;
	}

	if (!EVP_DigestFinal_ex(&md_ctx, dgst, &len)) {
		goto err;
	}

	*dgstlen = len;
	ret = 1;
err:
	EVP_MD_CTX_cleanup(&md_ctx);
	return ret;
}

int SM2_digest(const void *msg, size_t msglen, unsigned char *dgst,
	unsigned int *dgstlen, EC_KEY *ec_key)
{
	const EVP_MD *id_md = EVP_sm3();
	const EVP_MD *msg_md = EVP_sm3();

	return SM2_compute_message_digest(id_md, msg_md,
		msg, msglen, dgst, dgstlen, ec_key);
}

