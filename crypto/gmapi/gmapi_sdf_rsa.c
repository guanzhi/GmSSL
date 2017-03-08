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

/* convert RSA between native and SDF types, never include skf.h */
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/gmapi.h>
#include <openssl/rsa.h>
#include <openssl/sdf.h>
#include "../rsa/rsa_locl.h" //FIXME


RSA *RSA_new_from_RSArefPublicKey(const RSArefPublicKey *ref)
{
	RSA *ret;
	if (!(ret = RSA_new())) {
		GMAPIerr(GMAPI_F_RSA_NEW_FROM_RSAREFPUBLICKEY, ERR_R_RSA_LIB);
		return NULL;
	}
	if (!RSA_set_RSArefPublicKey(ret, ref)) {
		GMAPIerr(GMAPI_F_RSA_NEW_FROM_RSAREFPUBLICKEY,
			GMAPI_R_INVALID_RSA_PUBLIC_KEY);
		RSA_free(ret);
		return NULL;
	}
	return ret;
}

int RSA_set_RSArefPublicKey(RSA *rsa, const RSArefPublicKey *ref)
{
	if (!rsa || !ref) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAREFPUBLICKEY,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if ((ref->bits < 1024) || (ref->bits > RSAref_MAX_LEN*8) ||
		(ref->bits % 8 != 0)) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAREFPUBLICKEY,
			GMAPI_R_INVALID_RSA_KEY_LENGTH);
		return 0;
	}
	if (!(rsa->n = BN_bin2bn(ref->m, ref->bits/8, rsa->n))) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAREFPUBLICKEY,
			GMAPI_R_INVALID_RSA_PUBLIC_KEY);
		return 0;
	}
	if (!(rsa->e = BN_bin2bn(ref->e, RSAref_MAX_LEN, rsa->e))) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAREFPUBLICKEY,
			GMAPI_R_INVALID_RSA_PUBLIC_KEY);
		return 0;
	}
	if (!RSA_check_key(rsa)) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAREFPUBLICKEY,
			GMAPI_R_INVALID_RSA_PUBLIC_KEY);
		return 0;
	}
	return 1;
}

int RSA_get_RSArefPublicKey(RSA *rsa, RSArefPublicKey *ref)
{
	int nbytes;
	if (!rsa || !ref) {
		GMAPIerr(GMAPI_F_RSA_GET_RSAREFPUBLICKEY,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (!rsa->n || !rsa->e) {
		GMAPIerr(GMAPI_F_RSA_GET_RSAREFPUBLICKEY,
			GMAPI_R_INVALID_RSA_PUBLIC_KEY);
		return 0;
	}
	nbytes = BN_num_bytes(rsa->n);
	if (!BN_bn2bin(rsa->n, ref->m) || !BN_bn2bin(rsa->e,
		ref->e + MAX_RSA_EXPONENT_LEN - BN_num_bytes(rsa->e))) {
		GMAPIerr(GMAPI_F_RSA_GET_RSAREFPUBLICKEY,
			GMAPI_R_ENCODE_RSA_PUBLIC_KEY_FAILED);
		return 0;
	}
	return 1;
}

RSA *RSA_new_from_RSArefPrivateKey(const RSArefPrivateKey *ref)
{
	RSA *ret;
	if (!(ret = RSA_new())) {
		GMAPIerr(GMAPI_F_RSA_NEW_FROM_RSAREFPRIVATEKEY, ERR_R_RSA_LIB);
		return NULL;
	}
	if (!RSA_set_RSArefPrivateKey(ret, ref)) {
		GMAPIerr(GMAPI_F_RSA_NEW_FROM_RSAREFPRIVATEKEY,
			GMAPI_R_INVALID_RSA_PRIVATE_KEY);
		RSA_free(ret);
		return NULL;
	}
	return ret;
}


int RSA_set_RSArefPrivateKey(RSA *rsa, const RSArefPrivateKey *ref)
{
	int nbytes;
	if (!rsa || !ref) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAREFPRIVATEKEY,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if ((ref->bits < 1024) || (ref->bits > RSAref_MAX_LEN*8) ||
		(ref->bits % 8 != 0) || (ref->bits % 16 != 0)) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAREFPRIVATEKEY,
			GMAPI_R_INVALID_KEY_LENGTH);
		return 0;
	}
	nbytes = ref->bits/8;
	if (!(rsa->n = BN_bin2bn(ref->m, nbytes, rsa->n)) ||
		!(rsa->e = BN_bin2bn(ref->e, MAX_RSA_EXPONENT_LEN, rsa->e)) ||
		!(rsa->d = BN_bin2bn(ref->d, nbytes, rsa->d)) ||
		!(rsa->p = BN_bin2bn(ref->prime[0], nbytes/2, rsa->p)) ||
		!(rsa->q = BN_bin2bn(ref->prime[1], nbytes/2, rsa->q)) ||
		!(rsa->dmp1 = BN_bin2bn(ref->pexp[0], nbytes/2, rsa->dmp1)) ||
		!(rsa->dmq1 = BN_bin2bn(ref->pexp[1], nbytes/2, rsa->dmq1)) ||
		!(rsa->iqmp = BN_bin2bn(ref->coef, nbytes/2, rsa->iqmp))) {
		GMAPIerr(GMAPI_F_RSA_SET_RSAREFPRIVATEKEY,
			GMAPI_R_INVALID_RSA_PRIVATE_KEY);
		return 0;
	}
	return 1;
}

int RSA_get_RSArefPrivateKey(RSA *rsa, RSArefPrivateKey *ref)
{
	int nbytes;
	if (!rsa || !ref) {
		GMAPIerr(GMAPI_F_RSA_GET_RSAREFPRIVATEKEY,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (!rsa->n || !rsa->e || !rsa->d || !rsa->p || !rsa->q ||
		!rsa->dmp1 || !rsa->dmq1 || !rsa->iqmp) {
		GMAPIerr(GMAPI_F_RSA_GET_RSAREFPRIVATEKEY,
			GMAPI_R_INVALID_RSA_PRIVATE_KEY);
		return 0;
	}

	memset(ref, 0, sizeof(*ref));
	ref->bits = BN_num_bits(rsa->n);

	nbytes = BN_num_bytes(rsa->n);
	if (!BN_bn2bin(rsa->n, ref->m) ||
		!BN_bn2bin(rsa->e, ref->e + MAX_RSA_EXPONENT_LEN - BN_num_bytes(rsa->e)) ||
		!BN_bn2bin(rsa->d, ref->d + nbytes - BN_num_bytes(rsa->d)) ||
		!BN_bn2bin(rsa->p, (unsigned char *)&(ref->prime[0]) + nbytes/2 - BN_num_bytes(rsa->p)) ||
		!BN_bn2bin(rsa->q, (unsigned char *)&(ref->prime[1]) + nbytes/2 - BN_num_bytes(rsa->q)) ||
		!BN_bn2bin(rsa->dmp1, (unsigned char *)&(ref->pexp[0]) + nbytes/2 - BN_num_bytes(rsa->dmp1)) ||
		!BN_bn2bin(rsa->dmq1, (unsigned char *)&(ref->pexp[1]) + nbytes/2 - BN_num_bytes(rsa->dmq1)) ||
		!BN_bn2bin(rsa->iqmp, ref->coef + nbytes/2 - BN_num_bytes(rsa->iqmp))) {
		GMAPIerr(GMAPI_F_RSA_GET_RSAREFPRIVATEKEY,
			GMAPI_R_INVALID_RSA_PRIVATE_KEY);
		return 0;
	}

	return 1;
}
