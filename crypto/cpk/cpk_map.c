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
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/cpk.h>
#include "cpk_lcl.h"
#include "../../e_os.h"

/* Currently we only support fixed 32 indexes
 * this means EC_POINT_add() called 32 times */
#define CPK_NUM_INDEXES	32

typedef struct {
	int map_nid;
	int md_nid;
} CPK_MAP_TABLE;

static CPK_MAP_TABLE map_table[] = {
	{NID_cpk_map_sm3, NID_sm3},
	{NID_cpk_map_sha1, NID_sha1},
	{NID_cpk_map_sha256, NID_sha256},
	{NID_cpk_map_sha384, NID_sha384},
	{NID_cpk_map_sha512, NID_sha512}
};

static const EVP_MD *cpk_map2md(int type)
{
	int i;
	for (i = 0; i < OSSL_NELEM(map_table); i++) {
		if (map_table[i].map_nid == type) {
			return EVP_get_digestbynid(map_table[i].md_nid);
		}
	}
	return NULL;
}

static const EVP_MD *CPK_MAP_get_md(const X509_ALGOR *algor)
{
	const EVP_MD *md;
	if (!algor->algorithm) {
		CPKerr(CPK_F_CPK_MAP_GET_MD, CPK_R_INVALID_ARGUMENT);
		return NULL;
	}
	if (!(md = cpk_map2md(OBJ_obj2nid(algor->algorithm)))) {
		CPKerr(CPK_F_CPK_MAP_GET_MD, ERR_R_CPK_LIB);
		return NULL;
	}
	return md;
}

X509_ALGOR *CPK_MAP_new(int type)
{
	X509_ALGOR *ret = NULL;
	X509_ALGOR *algor = NULL;

	if (!cpk_map2md(type)) {
		CPKerr(CPK_F_CPK_MAP_NEW, CPK_R_INVALID_MAP_ALGOR);
		return NULL;
	}
	if (!(algor = X509_ALGOR_new())) {
		CPKerr(CPK_F_CPK_MAP_NEW, ERR_R_X509_LIB);
		goto end;
	}
	if (!X509_ALGOR_set0(algor, OBJ_nid2obj(type), V_ASN1_UNDEF, NULL)) {
		CPKerr(CPK_F_CPK_MAP_NEW, ERR_R_X509_LIB);
		goto end;
	}

	ret = algor;
	algor = NULL;

end:
	X509_ALGOR_free(algor);
	return ret;
}

X509_ALGOR *CPK_MAP_new_default(void)
{
	return CPK_MAP_new(NID_cpk_map_sha1);
}

int CPK_MAP_is_valid(const X509_ALGOR *algor)
{
	return CPK_MAP_get_md(algor) != NULL;
}

int CPK_MAP_num_indexes(const X509_ALGOR *algor)
{
	if (!CPK_MAP_is_valid(algor)) {
		CPKerr(CPK_F_CPK_MAP_NUM_INDEXES, CPK_R_INVALID_MAP_ALGOR);
		return 0;
	}
	/* current only use fixed num_indexes */
	return CPK_NUM_INDEXES;
}

int CPK_MAP_num_subset(const X509_ALGOR *algor)
{
	const EVP_MD *md;
	if (!(md = CPK_MAP_get_md(algor))) {
		CPKerr(CPK_F_CPK_MAP_NUM_SUBSET, ERR_R_CPK_LIB);
		return 0;
	}
	return 1 << ((EVP_MD_size(md) * 8) / CPK_MAP_num_indexes(algor));
}

int CPK_MAP_num_factors(const X509_ALGOR *algor)
{
	int num_indexes;
	int num_subset;
	if (!(num_indexes = CPK_MAP_num_indexes(algor))) {
		CPKerr(CPK_F_CPK_MAP_NUM_FACTORS, ERR_R_CPK_LIB);
		return 0;
	}
	if (!(num_subset = CPK_MAP_num_subset(algor))) {
		CPKerr(CPK_F_CPK_MAP_NUM_FACTORS, ERR_R_CPK_LIB);
		return 0;
	}
	return num_indexes * num_subset;
}

int CPK_MAP_str2index(const X509_ALGOR *algor, const char *str, int *index)
{
	int ret = 0;
	const EVP_MD *md;
	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned int dgstlen;
	BIGNUM *bn = NULL;
	int i;
	int num_indexes, num_subset;

	OPENSSL_assert(algor);
	OPENSSL_assert(algor->algorithm);
	OPENSSL_assert(str);
	OPENSSL_assert(strlen(str) > 0);

	if (!(md = CPK_MAP_get_md(algor))
		|| !(num_indexes = CPK_MAP_num_indexes(algor))
		|| !(num_subset = CPK_MAP_num_subset(algor))) {
		CPKerr(CPK_F_CPK_MAP_STR2INDEX, CPK_R_INVALID_MAP_ALGOR);
		return 0;
	}

	if (!index) {
		return CPK_MAP_num_indexes(algor);
	}

	if (!EVP_Digest(str, strlen(str), dgst, &dgstlen, md, NULL)) {
		CPKerr(CPK_F_CPK_MAP_STR2INDEX, ERR_R_EVP_LIB);
		return 0;
	}
	if (!(bn = BN_new())) {
		CPKerr(CPK_F_CPK_MAP_STR2INDEX, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!BN_bin2bn(dgst, dgstlen, bn)) {
		CPKerr(CPK_F_CPK_MAP_STR2INDEX, ERR_R_BN_LIB);
		goto end;
	}

	for (i = 0; i < num_indexes; i++) {
		int r = BN_mod_word(bn, num_subset);
		BN_div_word(bn, num_subset);
		index[i] = num_subset * i + r;
	}

	ret = num_indexes;
end:
	BN_free(bn);
	return ret;
}
