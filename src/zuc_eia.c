/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <stdlib.h>
#include <string.h>
#include <gmssl/zuc.h>
#include "endian.h"

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
ZUC_UINT32 zuc_eia_generate_mac(const ZUC_UINT32 *data, size_t nbits,
	const unsigned char key[16], ZUC_UINT32 count, ZUC_UINT5 bearer,
	ZUC_BIT direction)
{
	ZUC_MAC_CTX ctx;
	unsigned char iv[16];
	unsigned char mac[4];
	zuc_set_eia_iv(iv, count, bearer, direction);
	zuc_mac_init(&ctx, key, iv);
	zuc_mac_finish(&ctx, (unsigned char *)data, nbits, mac);
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
