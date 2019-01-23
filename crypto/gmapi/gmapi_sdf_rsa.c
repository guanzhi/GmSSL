/* ====================================================================
 * Copyright (c) 2015-2016 The GmSSL Project.  All rights reserved.
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
#include "internal/cryptlib.h"

#if !defined(OPENSSL_NO_SDF) && !defined(OPENSSL_NO_RSA)
# include <openssl/err.h>
# include <openssl/rsa.h>
# include <openssl/sdf.h>
# include <openssl/gmapi.h>

RSA *RSA_new_from_RSArefPublicKey(const RSArefPublicKey *ref)
{
	RSA *ret = NULL;
	RSA *rsa = NULL;

	if (!ref) {
		GMAPIerr(GMAPI_F_RSA_NEW_FROM_RSAREFPUBLICKEY,
			ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	if (!(rsa = RSA_new())) {
		GMAPIerr(GMAPI_F_RSA_NEW_FROM_RSAREFPUBLICKEY,
			ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	if (!RSA_set_RSArefPublicKey(rsa, ref)) {
		GMAPIerr(GMAPI_F_RSA_NEW_FROM_RSAREFPUBLICKEY,
			GMAPI_R_INVALID_RSA_PUBLIC_KEY);
		goto end;
	}

	ret = rsa;
	rsa = NULL;

end:
	RSA_free(rsa);
	return ret;
}

int RSA_set_RSArefPublicKey(RSA *rsa, const RSArefPublicKey *ref)
{
	int ret = 0;
	BIGNUM *n = NULL;
	BIGNUM *e = NULL;

	if (!rsa || !ref) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAREFPUBLICKEY,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if ((ref->bits < OPENSSL_RSA_FIPS_MIN_MODULUS_BITS) ||
		(ref->bits > sizeof(ref->m) * 8) || (ref->bits % 8 != 0)) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAREFPUBLICKEY,
			GMAPI_R_INVALID_RSA_KEY_LENGTH);
		return 0;
	}

	if (!(n = BN_bin2bn(ref->m, sizeof(ref->m), NULL))) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAREFPUBLICKEY, ERR_R_BN_LIB);
		goto end;
	}

	if (!(e = BN_bin2bn(ref->e, sizeof(ref->e), NULL))) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAREFPUBLICKEY, ERR_R_BN_LIB);
		goto end;
	}

	if (!RSA_set0_key(rsa, n, e, NULL)) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAREFPUBLICKEY, ERR_R_RSA_LIB);
		goto end;
	}
	n = NULL;
	e = NULL;

	if (1 != RSA_check_key(rsa)) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAREFPUBLICKEY,
			GMAPI_R_INVALID_RSA_PUBLIC_KEY);
		goto end;
	}

	ret = 1;

end:
	BN_free(n);
	BN_free(e);
	return ret;
}

int RSA_get_RSArefPublicKey(RSA *rsa, RSArefPublicKey *ref)
{
	const BIGNUM *n;
	const BIGNUM *e;

	if (!rsa || !ref) {
		GMAPIerr(GMAPI_F_RSA_GET_RSAREFPUBLICKEY,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	RSA_get0_key(rsa, &n, &e, NULL);

	if (!n || !e) {
		GMAPIerr(GMAPI_F_RSA_GET_RSAREFPUBLICKEY,
			GMAPI_R_INVALID_RSA_PUBLIC_KEY);
		return 0;
	}
	if (RSA_bits(rsa) % 8 != 0 || RSA_bits(rsa) > sizeof(ref->m) * 8) {
		GMAPIerr(GMAPI_F_RSA_GET_RSAREFPUBLICKEY,
			GMAPI_R_INVALID_RSA_PUBLIC_KEY);
		return 0;
	}

	memset(ref, 0, sizeof(RSArefPublicKey));
	ref->bits = RSA_bits(rsa);

	if (BN_bn2bin(n, ref->m + sizeof(ref->m) - BN_num_bytes(n)) <= 0) {
		GMAPIerr(GMAPI_F_RSA_GET_RSAREFPUBLICKEY,
			GMAPI_R_ENCODE_RSA_PUBLIC_KEY_FAILED);
		return 0;
	}

	if (BN_bn2bin(e, ref->e + sizeof(ref->e) - BN_num_bytes(e)) <= 0) {
		GMAPIerr(GMAPI_F_RSA_GET_RSAREFPUBLICKEY,
			GMAPI_R_ENCODE_RSA_PUBLIC_KEY_FAILED);
		return 0;
	}

	return 1;
}

RSA *RSA_new_from_RSArefPrivateKey(const RSArefPrivateKey *ref)
{
	RSA *ret = NULL;
	RSA *rsa = NULL;

	if (!ref) {
		GMAPIerr(GMAPI_F_RSA_NEW_FROM_RSAREFPRIVATEKEY,
			ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	if (!(rsa = RSA_new())) {
		GMAPIerr(GMAPI_F_RSA_NEW_FROM_RSAREFPRIVATEKEY,
			ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	if (!RSA_set_RSArefPrivateKey(rsa, ref)) {
		GMAPIerr(GMAPI_F_RSA_NEW_FROM_RSAREFPRIVATEKEY,
			GMAPI_R_INVALID_RSA_PRIVATE_KEY);
		goto end;
	}

	ret = rsa;
	rsa = NULL;

end:
	RSA_free(rsa);
	return ret;
}


int RSA_set_RSArefPrivateKey(RSA *rsa, const RSArefPrivateKey *ref)
{
	int ret = 0;
	BIGNUM *n = NULL;
	BIGNUM *e = NULL;
	BIGNUM *d = NULL;
	BIGNUM *p = NULL;
	BIGNUM *q = NULL;
	BIGNUM *dmp1 = NULL;
	BIGNUM *dmq1 = NULL;
	BIGNUM *iqmp = NULL;

	if (!rsa || !ref) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAREFPRIVATEKEY,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (ref->bits < OPENSSL_RSA_FIPS_MIN_MODULUS_BITS
		|| ref->bits > sizeof(ref->m) *8
		|| ref->bits % 8 != 0
		|| ref->bits % 16 != 0) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAREFPRIVATEKEY,
			GMAPI_R_INVALID_KEY_LENGTH);
		return 0;
	}

	if (!(n = BN_bin2bn(ref->m, sizeof(ref->m), NULL))
		|| !(e = BN_bin2bn(ref->e, sizeof(ref->e), NULL))
		|| !(d = BN_bin2bn(ref->d, sizeof(ref->d), NULL))
		|| !(p = BN_bin2bn(ref->prime[0], sizeof(ref->prime[0]), NULL))
		|| !(q = BN_bin2bn(ref->prime[1], sizeof(ref->prime[1]), NULL))
		|| !(dmp1 = BN_bin2bn(ref->pexp[0], sizeof(ref->pexp[0]), NULL))
		|| !(dmq1 = BN_bin2bn(ref->pexp[1], sizeof(ref->pexp[1]), NULL))
		|| !(iqmp = BN_bin2bn(ref->coef, sizeof(ref->coef), NULL))) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAREFPRIVATEKEY, ERR_R_BN_LIB);
		goto end;
	}

	if (!RSA_set0_key(rsa, n, e, d)) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAREFPRIVATEKEY,
			GMAPI_R_INVALID_RSA_PRIVATE_KEY);
		goto end;
	}
	n = NULL;
	e = NULL;
	d = NULL;

	if (!RSA_set0_factors(rsa, p, q)) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAREFPRIVATEKEY,
			GMAPI_R_INVALID_RSA_PRIVATE_KEY);
		goto end;
	}
	p = NULL;
	q = NULL;

	if (!RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp)) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAREFPRIVATEKEY,
			GMAPI_R_INVALID_RSA_PRIVATE_KEY);
		goto end;
	}
	dmp1 = NULL;
	dmq1 = NULL;
	iqmp = NULL;

	ret = 1;

end:
	BN_free(n);
	BN_free(e);
	BN_free(d);
	BN_free(p);
	BN_free(q);
	BN_free(dmp1);
	BN_free(dmq1);
	BN_free(iqmp);
	return ret;
}

int RSA_get_RSArefPrivateKey(RSA *rsa, RSArefPrivateKey *ref)
{
	const BIGNUM *n;
	const BIGNUM *e;
	const BIGNUM *d;
	const BIGNUM *p;
	const BIGNUM *q;
	const BIGNUM *dmp1;
	const BIGNUM *dmq1;
	const BIGNUM *iqmp;

	if (!rsa || !ref) {
		GMAPIerr(GMAPI_F_RSA_GET_RSAREFPRIVATEKEY,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (RSA_bits(rsa) % 8 != 0 || RSA_bits(rsa) > sizeof(ref->m) * 8) {
		GMAPIerr(GMAPI_F_RSA_GET_RSAREFPRIVATEKEY,
			GMAPI_R_INVALID_RSA_PRIVATE_KEY);
		return 0;
	}

	RSA_get0_key(rsa, &n, &e, &d);
	RSA_get0_factors(rsa, &p, &q);
	RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);

	if (!n || !e || !d) {
		GMAPIerr(GMAPI_F_RSA_GET_RSAREFPRIVATEKEY,
			GMAPI_R_INVALID_RSA_PRIVATE_KEY);
		return 0;
	}

	memset(ref, 0, sizeof(RSArefPrivateKey));

	ref->bits = RSA_bits(rsa);

	if (BN_bn2bin(n, ref->m + sizeof(ref->m) - BN_num_bytes(n)) <= 0) {
		GMAPIerr(GMAPI_F_RSA_GET_RSAREFPRIVATEKEY,
			GMAPI_R_INVALID_RSA_PRIVATE_KEY);
		return 0;
	}

	if (BN_bn2bin(e, ref->e + sizeof(ref->e) - BN_num_bytes(e)) <= 0) {
		GMAPIerr(GMAPI_F_RSA_GET_RSAREFPRIVATEKEY,
			GMAPI_R_INVALID_RSA_PRIVATE_KEY);
		return 0;
	}

	if (BN_bn2bin(d, ref->d + sizeof(ref->d) - BN_num_bytes(d)) <= 0) {
		GMAPIerr(GMAPI_F_RSA_GET_RSAREFPRIVATEKEY,
			GMAPI_R_INVALID_RSA_PRIVATE_KEY);
		return 0;
	}

	if (p && BN_bn2bin(p, ref->prime[0] + sizeof(ref->prime[0]) -
		BN_num_bytes(p)) < 0) {
		GMAPIerr(GMAPI_F_RSA_GET_RSAREFPRIVATEKEY,
			GMAPI_R_INVALID_RSA_PRIVATE_KEY);
		return 0;
	}

	if (q && BN_bn2bin(q, ref->prime[1] + sizeof(ref->prime[1]) -
		BN_num_bytes(q)) < 0) {
		GMAPIerr(GMAPI_F_RSA_GET_RSAREFPRIVATEKEY,
			GMAPI_R_INVALID_RSA_PRIVATE_KEY);
		return 0;
	}

	if (dmp1 && BN_bn2bin(dmp1, ref->pexp[0] + sizeof(ref->pexp[0]) -
		BN_num_bytes(dmp1)) < 0) {
		GMAPIerr(GMAPI_F_RSA_GET_RSAREFPRIVATEKEY,
			GMAPI_R_INVALID_RSA_PRIVATE_KEY);
		return 0;
	}

	if (dmq1 && BN_bn2bin(dmq1, ref->pexp[1] + sizeof(ref->pexp[1]) -
		BN_num_bytes(dmq1)) < 0) {
		GMAPIerr(GMAPI_F_RSA_GET_RSAREFPRIVATEKEY,
			GMAPI_R_INVALID_RSA_PRIVATE_KEY);
		return 0;
	}

	if (iqmp && BN_bn2bin(iqmp, ref->coef + sizeof(ref->coef) -
		BN_num_bytes(iqmp)) < 0) {
		GMAPIerr(GMAPI_F_RSA_GET_RSAREFPRIVATEKEY,
			GMAPI_R_INVALID_RSA_PRIVATE_KEY);
		return 0;
	}

	return 1;
}
#endif
