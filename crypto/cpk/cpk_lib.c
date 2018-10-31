/* ====================================================================
 * Copyright (c) 2007 - 2018 The GmSSL Project.  All rights reserved.
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

#include <string.h>
#include <assert.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/cpk.h>
#include "../x509/x509_lcl.h"
#include "cpk_lcl.h"

static EC_KEY *X509_ALGOR_get1_EC_KEY(X509_ALGOR *algor);
static int extract_ec_params(CPK_MASTER_SECRET *master, CPK_PUBLIC_PARAMS *param);
static EC_KEY *extract_ec_priv_key(CPK_MASTER_SECRET *master, const char *id);
static EC_KEY *extract_ec_pub_key(CPK_PUBLIC_PARAMS *param, const char *id);


CPK_MASTER_SECRET *CPK_MASTER_SECRET_create(const char *domain_id, int curve, int map)
{
	CPK_MASTER_SECRET *ret = NULL;
	CPK_MASTER_SECRET *master = NULL;
	EC_KEY *ec_key = NULL;
	EVP_PKEY *pkey = NULL;
	X509_PUBKEY *pubkey = NULL;
	const BIGNUM *order;
	int order_bytes;
	int num_factors;
	unsigned char *secret_buf = NULL;
	size_t secret_len;
	unsigned char *p;
	BIGNUM *bn = NULL;
	int i;

	/* check domain_id */
	if (!(master = CPK_MASTER_SECRET_new())) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* set version */
	master->version = CPK_VERSION;

	/* set domain_id */
	if (!domain_id) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, ERR_R_PASSED_NULL_PARAMETER);
		goto end;
	}

	if (strlen(domain_id) <= 0 || strlen(domain_id) > CPK_MAX_ID_LENGTH) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, CPK_R_INVALID_ID_LENGTH);
		goto end;
	}

	if (!X509_NAME_add_entry_by_NID(master->id, NID_organizationName,
		MBSTRING_UTF8, (unsigned char *)domain_id, -1, -1, 0)) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, ERR_R_X509_LIB);
		goto end;
	}

	/* set pkey algor */
	if (!(ec_key = EC_KEY_new_by_curve_name(curve))) {
		//CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, CPK_R_INVALID_CURVE);
		CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, ERR_R_CPK_LIB);
		goto end;
	}

	if (!(pkey = EVP_PKEY_new())
		|| !EVP_PKEY_set1_EC_KEY(pkey, ec_key)) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, ERR_R_EVP_LIB);
		goto end;
	}
	if (!(pubkey = X509_PUBKEY_new())
		|| !X509_PUBKEY_set(&pubkey, pkey)
		|| !X509_PUBKEY_get0_param(NULL, NULL, NULL, &master->pkey_algor, pubkey)) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, ERR_R_X509_LIB);
		goto end;
	}

	/* get order and order_bytes */
	if (!(order = EC_GROUP_get0_order(EC_KEY_get0_group(ec_key)))
		|| !(order_bytes = BN_num_bytes(order))) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, ERR_R_CPK_LIB);
		goto end;
	}

	/* set map algor */
	X509_ALGOR_free(master->map_algor);
	if (!(master->map_algor = CPK_MAP_new(map))) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, ERR_R_CPK_LIB);
		goto end;
	}

	/* get num_factors */
	if ((num_factors = CPK_MAP_num_factors(master->map_algor)) <= 0) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, CPK_R_INVALID_MAP_ALGOR);
		goto end;
	}

	/* set random secret_factors */
	secret_len = order_bytes * num_factors;
	if (!(secret_buf = OPENSSL_zalloc(secret_len))) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	p = secret_buf;

	if (!(bn = BN_new())) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	for (i = 0; i < num_factors; i++) {
		do {
			if (!BN_rand_range(bn, order)) {
				CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE,
					ERR_R_BN_LIB);
				goto end;
			}
		} while (BN_is_zero(bn));

		if (!BN_bn2bin(bn, p + order_bytes - BN_num_bytes(bn))) {
			CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, ERR_R_BN_LIB);
			goto end;
		}
		p += order_bytes;
	}

	if (!ASN1_STRING_set(master->secret_factors, secret_buf, secret_len)) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_CREATE, ERR_R_ASN1_LIB);
		goto end;
	}

	ret = master;
	master = NULL;

end:
	CPK_MASTER_SECRET_free(master);
	EC_KEY_free(ec_key);
	EVP_PKEY_free(pkey);
	X509_PUBKEY_free(pubkey);
	OPENSSL_clear_free(secret_buf, secret_len);
	BN_free(bn);
	return ret;
}

CPK_PUBLIC_PARAMS *CPK_MASTER_SECRET_extract_public_params(CPK_MASTER_SECRET *master)
{
	CPK_PUBLIC_PARAMS *ret = NULL;
	CPK_PUBLIC_PARAMS *param = NULL;
	int pkey_type;

	OPENSSL_assert(master->pkey_algor->algorithm);

	pkey_type = OBJ_obj2nid(master->pkey_algor->algorithm);


	if (!(param = CPK_PUBLIC_PARAMS_new())) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PUBLIC_PARAMS,
			ERR_R_MALLOC_FAILURE);
		goto err;
	}

	param->version = master->version;

	X509_NAME_free(param->id);
	if (!(param->id = X509_NAME_dup(master->id))) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PUBLIC_PARAMS,
			ERR_R_MALLOC_FAILURE);
		goto err;
	}

	X509_ALGOR_free(param->pkey_algor);
	if (!(param->pkey_algor = X509_ALGOR_dup(master->pkey_algor))) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PUBLIC_PARAMS,
			ERR_R_MALLOC_FAILURE);
		goto err;
	}

	X509_ALGOR_free(param->map_algor);
	if (!(param->map_algor = X509_ALGOR_dup(master->map_algor))) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PUBLIC_PARAMS,
			ERR_R_MALLOC_FAILURE);
		goto err;
	}


	switch (pkey_type) {
	case EVP_PKEY_EC:
		if (!extract_ec_params(master, param)) {
			CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PUBLIC_PARAMS,
				ERR_R_CPK_LIB);
			goto err;
		}
		break;

	default:
		CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PUBLIC_PARAMS, CPK_R_INVALID_PKEY_TYPE);
		goto err;
	}

	ret = param;
	param = NULL;

err:
	CPK_PUBLIC_PARAMS_free(param);
	return ret;
}

EVP_PKEY *CPK_MASTER_SECRET_extract_private_key(
	CPK_MASTER_SECRET *master, const char *id)
{
	EVP_PKEY *ret = NULL;
	EVP_PKEY *pkey = NULL;
	int pkey_type;

	if (!(pkey = EVP_PKEY_new())) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PRIVATE_KEY,
			ERR_R_MALLOC_FAILURE);
		goto err;
	}

	pkey_type = OBJ_obj2nid(master->pkey_algor->algorithm);

	if (pkey_type == EVP_PKEY_EC) {
		EC_KEY *ec_key;
		if (!(ec_key = extract_ec_priv_key(master, id))) {
			CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PRIVATE_KEY,
				ERR_R_CPK_LIB);
			goto err;
		}
		if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
			EC_KEY_free(ec_key);
			CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PRIVATE_KEY,
				ERR_R_EVP_LIB);
			goto err;
		}

	} else {
		CPKerr(CPK_F_CPK_MASTER_SECRET_EXTRACT_PRIVATE_KEY,
			CPK_R_INVALID_PKEY_TYPE);
		goto err;
	}

	ret = pkey;
	pkey = NULL;

err:
	EVP_PKEY_free(pkey);
	return ret;
}

EVP_PKEY *CPK_PUBLIC_PARAMS_extract_public_key(CPK_PUBLIC_PARAMS *param,
	const char *id)
{
	EVP_PKEY *ret = NULL;
	EVP_PKEY *pkey = NULL;
	int pkey_type;

	if (!(pkey = EVP_PKEY_new())) {
		CPKerr(CPK_F_CPK_PUBLIC_PARAMS_EXTRACT_PUBLIC_KEY,
			ERR_R_MALLOC_FAILURE);
		goto err;
	}

	pkey_type = OBJ_obj2nid(param->pkey_algor->algorithm);


	if (pkey_type == EVP_PKEY_EC) {
		EC_KEY *ec_key = NULL;
		if (!(ec_key = extract_ec_pub_key(param, id))) {
			CPKerr(CPK_F_CPK_PUBLIC_PARAMS_EXTRACT_PUBLIC_KEY,
				ERR_R_CPK_LIB);
			goto err;
		}
		if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
			EC_KEY_free(ec_key);
			CPKerr(CPK_F_CPK_PUBLIC_PARAMS_EXTRACT_PUBLIC_KEY,
				ERR_R_EVP_LIB);
			goto err;
		}

	} else {
		CPKerr(CPK_F_CPK_PUBLIC_PARAMS_EXTRACT_PUBLIC_KEY,
			CPK_R_INVALID_PKEY_TYPE);
		goto err;
	}

	ret = pkey;
	pkey = NULL;

err:
	EVP_PKEY_free(pkey);
	return ret;
}

char *CPK_MASTER_SECRET_get_name(CPK_MASTER_SECRET *master, char *buf, int size)
{
	return X509_NAME_oneline(master->id, buf, size);
}

char *CPK_PUBLIC_PARAMS_get_name(CPK_PUBLIC_PARAMS *params, char *buf, int size)
{
	return X509_NAME_oneline(params->id, buf, size);
}

int CPK_MASTER_SECRET_validate_public_params(CPK_MASTER_SECRET *master,
	CPK_PUBLIC_PARAMS *params)
{
	int ret = 0;
	CPK_PUBLIC_PARAMS *tmp = NULL;

	if (!(tmp = CPK_MASTER_SECRET_extract_public_params(master))) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_VALIDATE_PUBLIC_PARAMS, ERR_R_CPK_LIB);
		goto err;
	}
	if (tmp->version != params->version) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_VALIDATE_PUBLIC_PARAMS, ERR_R_CPK_LIB);
		goto err;
	}
	if (X509_NAME_cmp(tmp->id, params->id)) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_VALIDATE_PUBLIC_PARAMS, ERR_R_CPK_LIB);
		goto err;
	}

	/*
	 * two ASN_OBJECT * with different address may have same NID
	 * thus we can not check with:
	 * tmp->pkey_algor->algorithm != params->pkey_algor->algorithm
	 */
	if (OBJ_obj2nid(tmp->pkey_algor->algorithm) !=
	    OBJ_obj2nid(params->pkey_algor->algorithm)) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_VALIDATE_PUBLIC_PARAMS, ERR_R_CPK_LIB);
		goto err;
	}
	// FIXME: pkey_algor->parameters
	if (OBJ_obj2nid(tmp->map_algor->algorithm) !=
	    OBJ_obj2nid(params->map_algor->algorithm)) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_VALIDATE_PUBLIC_PARAMS, ERR_R_CPK_LIB);
		goto err;
	}
	if (ASN1_STRING_cmp(tmp->public_factors, params->public_factors)) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_VALIDATE_PUBLIC_PARAMS, ERR_R_CPK_LIB);
		goto err;
	}

	ret = 1;
err:
	CPK_PUBLIC_PARAMS_free(tmp);
	return ret;
}

int CPK_PUBLIC_PARAMS_validate_private_key(CPK_PUBLIC_PARAMS *params,
	const char *id, const EVP_PKEY *priv_key)
{
	int ret = -3;
	EVP_PKEY *pub_key = NULL;

	if (!(pub_key = CPK_PUBLIC_PARAMS_extract_public_key(params, id))) {
		CPKerr(CPK_F_CPK_PUBLIC_PARAMS_VALIDATE_PRIVATE_KEY,
			ERR_R_EVP_LIB);
		goto err;
	}
	ret = EVP_PKEY_cmp(pub_key, priv_key);
err:
	EVP_PKEY_free(pub_key);
	return ret;
}


static EC_KEY *X509_ALGOR_get1_EC_KEY(X509_ALGOR *algor)
{
	EC_KEY *ec_key = NULL;
	int ptype;
	const void *pval;
	const unsigned char *p;

	X509_ALGOR_get0(NULL, &ptype, &pval, algor);

	if (ptype == V_ASN1_SEQUENCE) {
		ASN1_OCTET_STRING *pstr = (ASN1_OCTET_STRING *)pval;
		p = pstr->data;
		if (!(ec_key = d2i_ECParameters(NULL, &p, pstr->length))) {
			CPKerr(CPK_F_X509_ALGOR_GET1_EC_KEY, ERR_R_EC_LIB);
			return NULL;
		}

	} else if (ptype == V_ASN1_OBJECT) {
		ASN1_OBJECT *poid = (ASN1_OBJECT *)pval;
		EC_GROUP *group;
		if (!(ec_key = EC_KEY_new())) {
			CPKerr(CPK_F_X509_ALGOR_GET1_EC_KEY, ERR_R_MALLOC_FAILURE);
			return NULL;
		}
		if (!(group = EC_GROUP_new_by_curve_name(OBJ_obj2nid(poid)))) {
			EC_KEY_free(ec_key);
			CPKerr(CPK_F_X509_ALGOR_GET1_EC_KEY, ERR_R_EC_LIB);
			return NULL;
		}
		EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
		if (!EC_KEY_set_group(ec_key, group)) {
			EC_GROUP_free(group);
			EC_KEY_free(ec_key);
			CPKerr(CPK_F_X509_ALGOR_GET1_EC_KEY, ERR_R_EC_LIB);
			return NULL;
		}
		EC_GROUP_free(group);

	} else {
		CPKerr(CPK_F_X509_ALGOR_GET1_EC_KEY, CPK_R_BAD_DATA);
		return NULL;
	}
	return ec_key;
}

static int extract_ec_params(CPK_MASTER_SECRET *master, CPK_PUBLIC_PARAMS *param)
{
	int ret = 0;
	EC_KEY *ec_key = NULL;
	const EC_GROUP *ec_group;
	BIGNUM *bn = BN_new();
	BIGNUM *order = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	EC_POINT *pt = NULL;
	int i, bn_size, pt_size, num_factors;
	const unsigned char *bn_ptr;
	unsigned char *pt_ptr;

	if (!bn || !order || !ctx) {
		CPKerr(CPK_F_EXTRACT_EC_PARAMS, ERR_R_CPK_LIB);
		goto err;
	}

	if (!(ec_key = X509_ALGOR_get1_EC_KEY(master->pkey_algor))) {
		CPKerr(CPK_F_EXTRACT_EC_PARAMS, ERR_R_CPK_LIB);
		goto err;
	}
	ec_group = EC_KEY_get0_group(ec_key);
	if (!(EC_GROUP_get_order(ec_group, order, ctx))) {
		CPKerr(CPK_F_EXTRACT_EC_PARAMS, ERR_R_CPK_LIB);
		goto err;
	}
	bn_size = BN_num_bytes(order);
	pt_size = bn_size + 1;

	if ((num_factors = CPK_MAP_num_factors(master->map_algor)) <= 0) {
		CPKerr(CPK_F_EXTRACT_EC_PARAMS, ERR_R_CPK_LIB);
		goto err;
	}
	if (ASN1_STRING_length(master->secret_factors) != bn_size * num_factors) {
		CPKerr(CPK_F_EXTRACT_EC_PARAMS, ERR_R_CPK_LIB);
		goto err;
	}
	if (!ASN1_STRING_set(param->public_factors, NULL, pt_size * num_factors)) {
		CPKerr(CPK_F_EXTRACT_EC_PARAMS, ERR_R_CPK_LIB);
		goto err;
	}

	bn_ptr = ASN1_STRING_get0_data(master->secret_factors);
	pt_ptr = ASN1_STRING_get0_data(param->public_factors);
	memset(pt_ptr, 0, ASN1_STRING_length(param->public_factors));

	if (!(pt = EC_POINT_new(ec_group))) {
		CPKerr(CPK_F_EXTRACT_EC_PARAMS, ERR_R_CPK_LIB);
		goto err;
	}
	for (i = 0; i < num_factors; i++) {
		if (!BN_bin2bn(bn_ptr, bn_size, bn)) {
			CPKerr(CPK_F_EXTRACT_EC_PARAMS, ERR_R_CPK_LIB);
			goto err;
		}
		if (BN_is_zero(bn) || BN_cmp(bn, order) >= 0) {
			CPKerr(CPK_F_EXTRACT_EC_PARAMS, ERR_R_CPK_LIB);
			goto err;
		}
		if (!EC_POINT_mul(ec_group, pt, bn, NULL, NULL, ctx)) {
			CPKerr(CPK_F_EXTRACT_EC_PARAMS, ERR_R_CPK_LIB);
			goto err;
		}

		if (!EC_POINT_point2oct(ec_group, pt,
			POINT_CONVERSION_COMPRESSED, pt_ptr, pt_size, ctx)) {
			CPKerr(CPK_F_EXTRACT_EC_PARAMS, ERR_R_CPK_LIB);
			goto err;
		}
		bn_ptr += bn_size;
		pt_ptr += pt_size;
	}

	ret = 1;
err:
	EC_KEY_free(ec_key);
	BN_free(bn);
	BN_free(order);
	BN_CTX_free(ctx);
	EC_POINT_free(pt);
	return ret;
}

static EC_KEY *extract_ec_priv_key(CPK_MASTER_SECRET *master, const char *id)
{
	EC_KEY *ret = NULL;
	EC_KEY *ec_key = NULL;
	const EC_GROUP *ec_group;
	EC_POINT *pub_key = NULL;
	BIGNUM *priv_key = BN_new();
	BIGNUM *order = BN_new();
	BIGNUM *bn = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	int *index = NULL;
	int i, num_indexes, bn_size;


	if (!priv_key || !bn || !order || !ctx) {
		CPKerr(CPK_F_EXTRACT_EC_PRIV_KEY, ERR_R_CPK_LIB);
		goto err;
	}

	if (!(ec_key = X509_ALGOR_get1_EC_KEY(master->pkey_algor))) {
		CPKerr(CPK_F_EXTRACT_EC_PRIV_KEY, ERR_R_CPK_LIB);
		goto err;
	}
	ec_group = EC_KEY_get0_group(ec_key);
	if (!(pub_key = EC_POINT_new(ec_group))) {
		CPKerr(CPK_F_EXTRACT_EC_PRIV_KEY, ERR_R_CPK_LIB);
		goto err;
	}

	if ((num_indexes = CPK_MAP_num_indexes(master->map_algor)) <= 0) {
		CPKerr(CPK_F_EXTRACT_EC_PRIV_KEY, ERR_R_CPK_LIB);
		goto err;
	}
	if (!(index = OPENSSL_malloc(sizeof(int) * num_indexes))) {
		CPKerr(CPK_F_EXTRACT_EC_PRIV_KEY, ERR_R_CPK_LIB);
		goto err;
	}
	if (!CPK_MAP_str2index(master->map_algor, id, index)) {
		CPKerr(CPK_F_EXTRACT_EC_PRIV_KEY, ERR_R_CPK_LIB);
		goto err;
	}

	BN_zero(priv_key);
	if (!(EC_GROUP_get_order(EC_KEY_get0_group(ec_key), order, ctx))) {
		CPKerr(CPK_F_EXTRACT_EC_PRIV_KEY, ERR_R_CPK_LIB);
		goto err;
	}
	bn_size = BN_num_bytes(order);

	for (i = 0; i < num_indexes; i++) {
		const unsigned char *p =
			ASN1_STRING_get0_data(master->secret_factors) +
			bn_size * index[i];

		if (!BN_bin2bn(p, bn_size, bn)) {
			CPKerr(CPK_F_EXTRACT_EC_PRIV_KEY, ERR_R_CPK_LIB);
			goto err;
		}
		if (BN_is_zero(bn) || BN_cmp(bn, order) >= 0) {
			CPKerr(CPK_F_EXTRACT_EC_PRIV_KEY, ERR_R_CPK_LIB);
			goto err;
		}
		if (!BN_mod_add(priv_key, priv_key, bn, order, ctx)) {
			CPKerr(CPK_F_EXTRACT_EC_PRIV_KEY, ERR_R_CPK_LIB);
			goto err;
		}
	}
	if (!EC_KEY_set_private_key(ec_key, priv_key)) {
		CPKerr(CPK_F_EXTRACT_EC_PRIV_KEY, ERR_R_CPK_LIB);
		goto err;
	}

	if (!EC_POINT_mul(ec_group, pub_key, priv_key, NULL, NULL, ctx)) {
		CPKerr(CPK_F_EXTRACT_EC_PRIV_KEY, ERR_R_CPK_LIB);
		goto err;
	}
	if (!EC_KEY_set_public_key(ec_key, pub_key)) {
		CPKerr(CPK_F_EXTRACT_EC_PRIV_KEY, ERR_R_CPK_LIB);
		goto err;
	}

	ret = ec_key;
	ec_key = NULL;

err:
	EC_KEY_free(ec_key);
	BN_free(priv_key);
	EC_POINT_free(pub_key);
	BN_free(order);
	BN_free(bn);
	BN_CTX_free(ctx);
	OPENSSL_free(index);
	return ret;
}

static EC_KEY *extract_ec_pub_key(CPK_PUBLIC_PARAMS *param, const char *id)
{
	EC_KEY *ret = NULL;
	EC_KEY *ec_key = NULL;
	const EC_GROUP *ec_group;
	EC_POINT *pub_key = NULL;
	EC_POINT *pt = NULL;
	BIGNUM *order = BN_new();
	BIGNUM *bn = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	int *index = NULL;
	int i, bn_size, pt_size, num_indexes, num_factors;

	if (!(ec_key = X509_ALGOR_get1_EC_KEY(param->pkey_algor))) {
		CPKerr(CPK_F_EXTRACT_EC_PUB_KEY, ERR_R_CPK_LIB);
		goto err;
	}
	ec_group = EC_KEY_get0_group(ec_key);

	if (!(pub_key = EC_POINT_new(ec_group))) {
		CPKerr(CPK_F_EXTRACT_EC_PUB_KEY, ERR_R_CPK_LIB);
		goto err;
	}
	if (!(pt = EC_POINT_new(ec_group))) {
		CPKerr(CPK_F_EXTRACT_EC_PUB_KEY, ERR_R_CPK_LIB);
		goto err;
	}
	if (!EC_GROUP_get_order(ec_group, order, ctx)) {
		CPKerr(CPK_F_EXTRACT_EC_PUB_KEY, ERR_R_CPK_LIB);
		goto err;
	}
	bn_size = BN_num_bytes(order);
	pt_size = bn_size + 1;

	if ((num_factors = CPK_MAP_num_factors(param->map_algor)) <= 0) {
		CPKerr(CPK_F_EXTRACT_EC_PUB_KEY, ERR_R_CPK_LIB);
		goto err;
	}
	if (ASN1_STRING_length(param->public_factors) != pt_size * num_factors) {
		CPKerr(CPK_F_EXTRACT_EC_PUB_KEY, ERR_R_CPK_LIB);
		goto err;
	}

	if ((num_indexes = CPK_MAP_num_indexes(param->map_algor)) <= 0) {
		CPKerr(CPK_F_EXTRACT_EC_PUB_KEY, ERR_R_CPK_LIB);
		goto err;
	}
	if (!(index = OPENSSL_malloc(sizeof(int) * num_indexes))) {
		CPKerr(CPK_F_EXTRACT_EC_PUB_KEY, ERR_R_CPK_LIB);
		goto err;
	}
	if (!CPK_MAP_str2index(param->map_algor, id, index)) {
		CPKerr(CPK_F_EXTRACT_EC_PUB_KEY, ERR_R_CPK_LIB);
		goto err;
	}

	if (!EC_POINT_set_to_infinity(ec_group, pub_key)) {
		CPKerr(CPK_F_EXTRACT_EC_PUB_KEY, ERR_R_CPK_LIB);
		goto err;
	}
	for (i = 0; i < num_indexes; i++) {
		const unsigned char *p =
			ASN1_STRING_get0_data(param->public_factors) +
			pt_size * index[i];

		if (!EC_POINT_oct2point(ec_group, pt, p, pt_size, ctx)) {
			CPKerr(CPK_F_EXTRACT_EC_PUB_KEY, ERR_R_CPK_LIB);
			goto err;
		}

		if (!EC_POINT_add(ec_group, pub_key, pub_key, pt, ctx)) {
			CPKerr(CPK_F_EXTRACT_EC_PUB_KEY, ERR_R_CPK_LIB);
			goto err;
		}
	}

	if (!EC_KEY_set_public_key(ec_key, pub_key)) {
		CPKerr(CPK_F_EXTRACT_EC_PUB_KEY, ERR_R_CPK_LIB);
		goto err;
	}

	ret = ec_key;
	ec_key = NULL;

err:
	EC_KEY_free(ec_key);
	EC_POINT_free(pub_key);
	BN_free(order);
	BN_free(bn);
	BN_CTX_free(ctx);
	OPENSSL_free(index);
	return ret;
}
