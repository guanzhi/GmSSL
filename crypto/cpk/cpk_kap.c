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

#include <openssl/evp.h>
#include <openssl/ecdh.h>
#include <openssl/objects.h>
#include <openssl/cpk.h>
#include "cpk_lcl.h"

int CPK_PUBLIC_PARAMS_compute_share_key(CPK_PUBLIC_PARAMS *params,
	void *out, size_t outlen, const char *id, EVP_PKEY *priv_key,
	void *(*kdf)(const void *in, size_t inlen, void *out, size_t *outlen))
{
	int ret = 0;
	EVP_PKEY *pub_key = NULL;
	int pkey_type = OBJ_obj2nid(params->pkey_algor->algorithm);

	OPENSSL_assert(kdf != NULL);

	printf("%d\n", __LINE__);
	if (EVP_PKEY_id(priv_key) != pkey_type) {
		CPKerr(CPK_F_CPK_PUBLIC_PARAMS_COMPUTE_SHARE_KEY,
			ERR_R_MALLOC_FAILURE); //FIXME: ERR_R_XXX
		goto err;
	}
	if (!(pub_key = CPK_PUBLIC_PARAMS_extract_public_key(params, id))) {
		CPKerr(CPK_F_CPK_PUBLIC_PARAMS_COMPUTE_SHARE_KEY,
			ERR_R_MALLOC_FAILURE); //FIXME: ERR_R_XXX
		goto err;
	}
	if (pkey_type == EVP_PKEY_EC) {

		if (!ECDH_compute_key(out, outlen,
			EC_KEY_get0_public_key((EC_KEY *)EVP_PKEY_get0(pub_key)),
			(EC_KEY *)EVP_PKEY_get0(priv_key), kdf)) {
			CPKerr(CPK_F_CPK_PUBLIC_PARAMS_COMPUTE_SHARE_KEY,
				ERR_R_MALLOC_FAILURE); //FIXME: ERR_R_XXX
			goto err;
		}
	} else if (pkey_type == EVP_PKEY_DH) {
		// not supported yet
		goto err;	
	}

	
	ret = 1;
err:
	return ret;
}

