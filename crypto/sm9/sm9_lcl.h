/* crypto/sm9/sm9_lcl.h */
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
 *
 */

#ifndef HEADER_SM9_LCL_H
#define HEADER_SM9_LCL_H

#include "sm9.h"

#ifdef __cplusplus
extern "C" {
#endif

struct sm9_public_params_st {
	char *id;
	void *data;
};

struct sm9_master_secret_st {
	char *id;
	void *data;
};

struct sm9_method_st {
	int type;
	char *name;
	int (*setup)(SM9_PUBLIC_PARAMS **params, SM9_MASTER_SECRET **master);
	void (*public_params_free)(SM9_PUBLIC_PARAMS *a);
	void (*master_secret_free)(SM9_MASTER_SECRET *a);
	int (*public_params_encode)(SM9_PUBLIC_PARAMS *a, unsigned char *out);
	int (*master_secret_encode)(SM9_MASTER_SECRET *a, unsigned char *out);
	SM9_PUBLIC_PARAMS *(*public_params_decode)(SM9_PUBLIC_PARAMS **a, const unsigned char **in, long len);
	SM9_MASTER_SECRET *(*master_secret_decode)(SM9_MASTER_SECRET **a, const unsigned char **in, long len);
	EVP_PKEY *(*extract_private_key)(SM9_MASTER_SECRET *master,
		const char *id, size_t idlen, EVP_PKEY **pkey);
	int (*encrypt)(SM9_PUBLIC_PARAMS *params,
		const unsigned char *in, size_t inlen,
		unsigned char *out, size_t *outlen,
		const char *id, size_t idlen);
	int (*decrypt)(SM9_PUBLIC_PARAMS *params,
		const unsigned char *in, size_t inlen,
		unsigned char *out, size_t *outlen,
		EVP_PKEY *pkey);
};

#ifdef __cplusplus
}
#endif
#endif

