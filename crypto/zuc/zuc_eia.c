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

#include <stdlib.h>
#include <string.h>
#include <openssl/zuc.h>
#include <openssl/crypto.h>
#include "modes_lcl.h"

static void zuc_set_eia_iv(unsigned char iv[16], ZUC_UINT32 count, ZUC_UINT5 bearer,
	ZUC_BIT direction)
{
	memset(iv, 0, 16);
	iv[0] = count >> 24;
	iv[1] = iv[9] = count >> 16;
	iv[2] = iv[10] = count >> 8;
	iv[3] = iv[11] = count;
	iv[4] = iv[12] = bearer << 3;
	iv[8] = iv[0] ^ (direction << 7);
	iv[14] = (direction << 7);
}

#if 1
ZUC_UINT32 ZUC_eia_generate_mac(const ZUC_UINT32 *data, size_t nbits,
	const unsigned char key[16], ZUC_UINT32 count, ZUC_UINT5 bearer,
	ZUC_BIT direction)
{
	ZUC_MAC_CTX ctx;
	unsigned char iv[16];
	unsigned char mac[4];
	zuc_set_eia_iv(iv, count, bearer, direction);
	ZUC_MAC_init(&ctx, key, iv);
	ZUC_MAC_final(&ctx, (unsigned char *)data, nbits, mac);
	return GETU32(mac);
}
#else

#define ZUC_MAC_BUF_WORDS 64

#define GET_WORD(p, i)	((i) % 32) \
		? ((*((ZUC_UINT32 *)(p) + (i)/32) << ((i) % 32)) \
			 | (*((ZUC_UINT32 *)(p) + (i)/32 + 1) >> (32 - ((i) % 32)))) \
		: *((ZUC_UINT32 *)(p) + (i)/32)

#define GET_BIT(p, i) \
	(((*((ZUC_UINT32 *)(p) + (i)/32)) & (1 << (31 - ((i) % 32)))) ? 1 : 0)

ZUC_UINT32 ZUC_eia_generate_mac(const ZUC_UINT32 *data, size_t nbits,
	const unsigned char user_key[16], ZUC_UINT32 count, ZUC_UINT5 bearer,
	ZUC_BIT direction)
{
	ZUC_UINT32 T = 0;
	ZUC_KEY key;
	unsigned char iv[16];
	ZUC_UINT32 buf[ZUC_MAC_BUF_WORDS + 2];
	size_t nwords = (nbits + 31)/32;
	size_t i;
	size_t num = ZUC_MAC_BUF_WORDS;


	ZUC_set_eia_iv(iv, count, bearer, direction);
	ZUC_set_key(&key, user_key, iv);

	if (nwords <= ZUC_MAC_BUF_WORDS) {
		ZUC_generate_keystream(&key, nwords + 2, buf);
		for (i = 0; i < nbits; i++) {
			if (GET_BIT(data, i)) {
				T ^= GET_WORD(buf, i);
			}
		}
		T ^= GET_WORD(buf, i);
		T ^= buf[nwords + 1];
		return T;

	} else {

		ZUC_generate_keystream(&key, ZUC_MAC_BUF_WORDS + 1, buf);
		for (i = 0; i < ZUC_MAC_BUF_WORDS * 32; i++) {
			if (GET_BIT(data, i)) {
				T ^= GET_WORD(buf, i);
			}
		}
		data += ZUC_MAC_BUF_WORDS;
		nwords -= ZUC_MAC_BUF_WORDS;
		nbits -= ZUC_MAC_BUF_WORDS * 32;
	}

	while (nwords > ZUC_MAC_BUF_WORDS) {
		buf[0] = buf[ZUC_MAC_BUF_WORDS];
		ZUC_generate_keystream(&key, ZUC_MAC_BUF_WORDS, buf + 1);
		for (i = 0; i < ZUC_MAC_BUF_WORDS * 32; i ++) {
			if (GET_BIT(data, i)) {
				T ^= GET_WORD(buf, i);
			}
		}
		data += num;
		nwords -= num;
		nbits -= ZUC_MAC_BUF_WORDS * 32;
	}

	buf[0] = buf[ZUC_MAC_BUF_WORDS];
	ZUC_generate_keystream(&key, nwords + 1, buf + 1);
	for (i = 0; i < nbits; i++) {
		if (GET_BIT(data, i)) {
			T ^= GET_WORD(buf, i);
		}
	}

	T ^= GET_WORD(buf, i);
	T ^= buf[nwords + 1];

	return T;
}
#endif
