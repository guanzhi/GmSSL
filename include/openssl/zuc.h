/* ====================================================================
 * Copyright (c) 2015 - 2018 The GmSSL Project.  All rights reserved.
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

#ifndef HEADER_ZUC_H
#define HEADER_ZUC_H

#include <openssl/opensslconf.h>
# ifndef OPENSSL_NO_ZUC

# include <stdlib.h>
# include <openssl/e_os2.h>

# define ZUC_IV_LENGTH	16
# define ZUC_KEY_LENGTH	16

typedef uint32_t ZUC_UINT1;
typedef uint32_t ZUC_UINT5;
typedef uint32_t ZUC_UINT15;
typedef uint32_t ZUC_UINT31;
typedef uint32_t ZUC_UINT32;

# ifdef __cplusplus
extern "C" {
# endif


typedef struct zuc_key_st {
	ZUC_UINT31 LFSR[16];
	uint32_t R1;
	uint32_t R2;
} ZUC_KEY;


void ZUC_set_key(ZUC_KEY *key, const unsigned char *user_key, const unsigned char *iv);
void ZUC_generate_keystream(ZUC_KEY *key, size_t nwords, uint32_t *words);
uint32_t ZUC_generate_keyword(ZUC_KEY *key);


# ifdef __cplusplus
}
# endif
# endif
#endif
