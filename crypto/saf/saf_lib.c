/* ====================================================================
 * Copyright (c) 2016 The GmSSL Project.  All rights reserved.
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
#include <openssl/gmsaf.h>
#include "saf_lcl.h"


EVP_PKEY *SAF_load_private_key(SAF_APP *app, const char *container, int flags)
{
	EVP_PKEY *ret = NULL;
	EVP_PKEY *pkey = NULL;
	char key_id[1024];

	if (!app->engine) {
		SAFerr(SAF_F_SAF_LOAD_PRIVATE_KEY, SAF_R_INVALID_APP);
		return NULL;
	}

	/*		
	snprintf(key_id, sizeof(key_id), "%s.%s", container,
		((flags & EVP_PKT_SIGN) ? "sign" : "enc"));
	*/

	if (!(pkey = ENGINE_load_private_key(app->engine, key_id, NULL, NULL))) {
		SAFerr(SAF_F_SAF_LOAD_PRIVATE_KEY, SAF_R_LOAD_PRIVATE_KEY_FAILURE);
		goto end;
	}

	if (EVP_PKEY_base_id(pkey) !=
		((flags & EVP_PK_EC) ? EVP_PKEY_EC : EVP_PKEY_RSA)) {
		SAFerr(SAF_F_SAF_LOAD_PRIVATE_KEY, SAF_R_INVALID_PKEY_TYPE);
		goto end;
	}

	ret = pkey;
	pkey = NULL;
end:
	EVP_PKEY_free(pkey);
	return ret;
}

EVP_PKEY *SAF_load_public_key(SAF_APP *app, const char *container, int flags)
{
	EVP_PKEY *ret = NULL;
	EVP_PKEY *pkey = NULL;
	char key_id[1024];

	if (!app->engine) {
		SAFerr(SAF_F_SAF_LOAD_PUBLIC_KEY, SAF_R_INVALID_APP);
		return NULL;
	}

	/*				
	snprintf(key_id, sizeof(key_id), "%s.%s", container,
		((flags & EVP_PKT_SIGN) ? "sign" : "enc"));
	*/

	if (!(pkey = ENGINE_load_public_key(app->engine, key_id, NULL, NULL))) {
		SAFerr(SAF_F_SAF_LOAD_PUBLIC_KEY, SAF_R_LOAD_PUBLIC_KEY_FAILURE);
		goto end;
	}

	if (EVP_PKEY_base_id(pkey) !=
		((flags & EVP_PK_EC) ? EVP_PKEY_EC : EVP_PKEY_RSA)) {
		SAFerr(SAF_F_SAF_LOAD_PUBLIC_KEY, SAF_R_INVALID_PKEY_TYPE);
		goto end;
	}

	ret = pkey;
	pkey = NULL;
end:
	EVP_PKEY_free(pkey);
	return ret;
}
