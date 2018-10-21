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
#include <openssl/bio.h>
#include <openssl/cpk.h>
#include <openssl/objects.h>
#include "cpk_lcl.h"

int CPK_MASTER_SECRET_print(BIO *out, CPK_MASTER_SECRET *master,
	int indent, unsigned long flags)
{
	char name[1024] = {0};
	int num_factors;
	const unsigned char *p;
	int i, len;

	if (!X509_NAME_oneline(master->id, name, sizeof(name))) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_PRINT, ERR_R_CPK_LIB);
		return 0;
	}

	BIO_printf(out, "CPK_MASTER_SECRET\n");
	BIO_printf(out, "  Version          : %ld\n", master->version);
	BIO_printf(out, "  Domain-ID        : %s\n", name);
	BIO_printf(out, "  Public-Key-Algor : %s\n", OBJ_nid2sn(OBJ_obj2nid(master->pkey_algor->algorithm)));
	BIO_printf(out, "  Map-Algor        : %s\n", OBJ_nid2sn(OBJ_obj2nid(master->map_algor->algorithm)));
	BIO_printf(out, "  Secret-Factors   :\n");

	if ((num_factors = CPK_MAP_num_factors(master->map_algor)) <= 0) {
		fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		return 0;
	}
	p = ASN1_STRING_get0_data(master->secret_factors);

	len = ASN1_STRING_length(master->secret_factors)/num_factors;
	if (ASN1_STRING_length(master->secret_factors) % num_factors) {
		CPKerr(CPK_F_CPK_MASTER_SECRET_PRINT, ERR_R_CPK_LIB);
		return 0;
	}

	for (i = 0; i < num_factors; i++) {
		int j;
		printf("    %-8d ", i);
		for (j = 0; j < len; j++) {
			BIO_printf(out, "%02X", p[j]);
		}
		printf("\n");
		p += len;
	}

	return 1;
}

int CPK_PUBLIC_PARAMS_print(BIO *out, CPK_PUBLIC_PARAMS *params,
	int indent, unsigned long flags)
{
	char name[1024] = {0};
	int num_factors;
	const unsigned char *p;
	int len, i;

	if (!X509_NAME_oneline(params->id, name, sizeof(name))) {
		CPKerr(CPK_F_CPK_PUBLIC_PARAMS_PRINT, ERR_R_CPK_LIB);
		return 0;
	}

	BIO_printf(out, "CPK_PUBLIC_PARAMS\n");
	BIO_printf(out, "  Version          : %ld\n", params->version);
	BIO_printf(out, "  Domain-ID        : %s\n", name);
	BIO_printf(out, "  Public-Key-Algor : %s\n", OBJ_nid2sn(OBJ_obj2nid(params->pkey_algor->algorithm)));
	BIO_printf(out, "  Map-Algor        : %s\n", OBJ_nid2sn(OBJ_obj2nid(params->map_algor->algorithm)));
	BIO_printf(out, "  Secret-Factors   :\n");

	if ((num_factors = CPK_MAP_num_factors(params->map_algor)) <= 0) {
		fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		return 0;
	}
	p = ASN1_STRING_get0_data(params->public_factors);

	len = ASN1_STRING_length(params->public_factors)/num_factors;
	if (ASN1_STRING_length(params->public_factors) % num_factors) {
		CPKerr(CPK_F_CPK_PUBLIC_PARAMS_PRINT, ERR_R_CPK_LIB);
		return 0;
	}

	for (i = 0; i < num_factors; i++) {
		int j;
		printf("    %-8d ", i);
		for (j = 0; j < len; j++) {
			BIO_printf(out, "%02X", p[j]);
		}
		printf("\n");
		p += len;
	}

	return 1;
}
