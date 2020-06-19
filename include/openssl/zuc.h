/* ====================================================================
 * Copyright (c) 2015 - 2019 The GmSSL Project.  All rights reserved.
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

typedef uint32_t ZUC_BIT;
typedef uint32_t ZUC_UINT5;
typedef uint8_t  ZUC_UINT6;
typedef uint32_t ZUC_UINT15;
typedef uint32_t ZUC_UINT31;
typedef uint32_t ZUC_UINT32;

# ifdef __cplusplus
extern "C" {
# endif


# define ZUC_KEY_LENGTH	16
# define ZUC_IV_LENGTH	16
# define ZUC_MAC_LENGTH 4


typedef struct ZUC_KEY_st {
	ZUC_UINT31 LFSR[16];
	ZUC_UINT32 R1;
	ZUC_UINT32 R2;
} ZUC_KEY;

void ZUC_set_key(ZUC_KEY *key, const unsigned char user_key[16], const unsigned char iv[16]);
void ZUC_generate_keystream(ZUC_KEY *key, size_t nwords, ZUC_UINT32 *words);
ZUC_UINT32 ZUC_generate_keyword(ZUC_KEY *key);

typedef struct ZUC_MAC_CTX_st {
	ZUC_UINT31 LFSR[16];
	ZUC_UINT32 R1;
	ZUC_UINT32 R2;
	ZUC_UINT32 T;
	ZUC_UINT32 K0;
	unsigned char buf[4];
	int buflen;
} ZUC_MAC_CTX;

void ZUC_MAC_init(ZUC_MAC_CTX *ctx, const unsigned char key[16], const unsigned char iv[16]);
void ZUC_MAC_update(ZUC_MAC_CTX *ctx, const unsigned char *data, size_t len);
void ZUC_MAC_final(ZUC_MAC_CTX *ctx, const unsigned char *data, size_t nbits, unsigned char mac[4]);

void ZUC_eea_encrypt(const ZUC_UINT32 *in, ZUC_UINT32 *out, size_t nbits,
	const unsigned char key[16], ZUC_UINT32 count, ZUC_UINT5 bearer,
	ZUC_BIT direction);
ZUC_UINT32 ZUC_eia_generate_mac(const ZUC_UINT32 *data, size_t nbits,
	const unsigned char user_key[16], ZUC_UINT32 count, ZUC_UINT5 bearer,
	ZUC_BIT direction);

# define ZUC256_KEY_LENGTH	32
# define ZUC256_IV_LENGTH	23
# define ZUC256_MAC32_LENGTH	4
# define ZUC256_MAC64_LENGTH	8
# define ZUC256_MAC128_LENGTH	16
# define ZUC256_MIN_MAC_LENGTH	ZUC256_MAC32_LENGTH
# define ZUC256_MAX_MAC_LENGTH	ZUC256_MAC128_LENGTH

typedef ZUC_KEY ZUC256_KEY;

void ZUC256_set_key(ZUC256_KEY *key, const unsigned char user_key[32],
	const unsigned char iv[23]);
#define ZUC256_generate_keystream(k,n,out)	ZUC_generate_keystream(k,n,out)
#define ZUC256_generate_keyword(k)		ZUC_generate_keyword(k)

typedef struct ZUC256_MAC_CTX_st {
	ZUC_UINT31 LFSR[16];
	ZUC_UINT32 R1;
	ZUC_UINT32 R2;
	ZUC_UINT32 T[4];
	ZUC_UINT32 K0[4];
	unsigned char buf[4];
	int buflen;
	int macbits;
} ZUC256_MAC_CTX;

void ZUC256_MAC_init(ZUC256_MAC_CTX *ctx, const unsigned char key[32], const unsigned char iv[23], int macbits);
void ZUC256_MAC_update(ZUC256_MAC_CTX *ctx, const unsigned char *data, size_t len);
void ZUC256_MAC_final(ZUC256_MAC_CTX *ctx, const unsigned char *data, size_t nbits, unsigned char *mac);


# ifdef __cplusplus
}
# endif
# endif
#endif
