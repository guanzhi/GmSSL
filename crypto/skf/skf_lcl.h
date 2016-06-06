/* crypto/skf/skf_lcl.h */
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

#ifndef HEADER_SKF_LCL_H
#define HEADER_SKF_LCL_H

#include <openssl/evp.h>
#include <openssl/cmac.h>
#include <openssl/cbcmac.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SKF_HANDLE_MAGIC 	0x31323334
#define SKF_HASH_HANDLE		1
#define SKF_MAC_HANDLE		2
#define SKF_KEY_HANDLE		10
#define SKF_CIPHER_HANDLE	11

struct SKF_HANDLE {
	unsigned int magic;
	int type;
	int algid;
	unsigned int keylen;
	unsigned char key[EVP_MAX_KEY_LENGTH];
	union {
		EVP_MD_CTX *md_ctx;
		CBCMAC_CTX *cbcmac_ctx;
		EVP_CIPHER_CTX *cipher_ctx;
	} u;
	struct SKF_HANDLE *next;
	struct SKF_HANDLE *prev;
};

typedef struct SKF_HANDLE SKF_HANDLE;

EVP_MD_CTX *SKF_HANDLE_get_md_ctx(HANDLE hHash);
CBCMAC_CTX *SKF_HANDLE_get_cbcmac_ctx(HANDLE hMac);
const EVP_CIPHER *SKF_HANDLE_get_cipher(HANDLE hKey, BLOCKCIPHERPARAM *param);
EVP_CIPHER_CTX *SKF_HANDLE_get_cipher_ctx(HANDLE hKey);
unsigned char *SKF_HANDLE_get_key(HANDLE hKey);




#ifdef  __cplusplus
}
#endif
#endif
