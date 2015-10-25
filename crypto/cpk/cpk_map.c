/* crypto/cpk/cpk_map.c */
/* ====================================================================
 * Copyright (c) 2007 - 2015 The GmSSL Project.  All rights reserved.
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
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "cpk.h"

X509_ALGOR *CPK_MAP_new_default()
{
	X509_ALGOR *algor = NULL;
	const EVP_MD *md = EVP_sha1();
	
	if (md != EVP_sha1() && md != EVP_sha384()) {
		CPKerr(CPK_F_CPK_MAP_NEW_DEFAULT, CPK_R_BAD_ARGUMENT);
		goto end;
	}
	if (!(algor = X509_ALGOR_new())) {
		CPKerr(CPK_F_CPK_MAP_NEW_DEFAULT, ERR_R_X509_LIB);
		goto end;
	}
	if (!X509_ALGOR_set0(algor, OBJ_nid2obj(EVP_MD_nid(md)), 
		V_ASN1_UNDEF, NULL)) {
		X509_ALGOR_free(algor);
		algor = NULL;
		CPKerr(CPK_F_CPK_MAP_NEW_DEFAULT, ERR_R_X509_LIB);
		goto end;
	}
end:
	return algor;
}

int CPK_MAP_is_valid(const X509_ALGOR *algor)
{
	OPENSSL_assert(algor);
	OPENSSL_assert(algor->algorithm);
	switch (OBJ_obj2nid(algor->algorithm)) {
	case NID_sha1:
	case NID_sha384:
		return 1;
	}
	return 0;
}

int CPK_MAP_num_subset(const X509_ALGOR *algor)
{
	OPENSSL_assert(algor);
	OPENSSL_assert(algor->algorithm);
	switch (OBJ_obj2nid(algor->algorithm)) {
	case NID_sha1:
		return 32;
	case NID_sha384:
		return 4096;
	}
	return -1;
}

int CPK_MAP_num_factors(const X509_ALGOR *algor)
{
	return 1024;
}

int CPK_MAP_num_indexes(const X509_ALGOR *algor)
{
	return 32;
}

int CPK_MAP_num_index(const X509_ALGOR *algor)
{
	OPENSSL_assert(algor);
	OPENSSL_assert(algor->algorithm);
	switch (OBJ_obj2nid(algor->algorithm)) {
	case NID_sha1:
		return 32;
	case NID_sha384:
		return 32;
	}
	return -1;
}

int CPK_MAP_str2index(const X509_ALGOR *algor, const char *str, int *index)
{
	int ret = 0;
	const EVP_MD *md;
	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned int dgstlen;
	BIGNUM *bn = NULL;
	int i, num_index, num_subset;
	
	OPENSSL_assert(algor);
	OPENSSL_assert(algor->algorithm);
	OPENSSL_assert(str);
	OPENSSL_assert(strlen(str) > 0);
	
	if (!CPK_MAP_is_valid(algor)) {
		CPKerr(CPK_F_CPK_MAP_STR2INDEX, CPK_R_INVALID_MAP_ALGOR);
		goto err;
	}
	if (!index) {
		ret = CPK_MAP_num_index(algor);
		goto err;
	}
	if (!(md = EVP_get_digestbyobj(algor->algorithm))) {
		CPKerr(CPK_F_CPK_MAP_STR2INDEX, ERR_R_EVP_LIB);
		goto err;
	}
	if (!EVP_Digest(str, strlen(str), dgst, &dgstlen, md, NULL)) {
		CPKerr(CPK_F_CPK_MAP_STR2INDEX, ERR_R_EVP_LIB);
		return 0;
	}
	if (!(bn = BN_new())) {
		CPKerr(CPK_F_CPK_MAP_STR2INDEX, ERR_R_BN_LIB);
		goto err;
	}
	if (!BN_bin2bn(dgst, dgstlen, bn)) {
		CPKerr(CPK_F_CPK_MAP_STR2INDEX, ERR_R_BN_LIB);
		goto err;
	}
	num_index = CPK_MAP_num_index(algor);
	num_subset = CPK_MAP_num_subset(algor);
	
	for (i = 0; i < num_index; i++) {
		int r = BN_mod_word(bn, num_subset);
		index[i] = num_subset * i + r;
	}
	ret = num_index;
err:	
	if (bn) BN_free(bn);
	return ret;
}

