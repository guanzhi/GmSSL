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
#include <gmssl/zuc.h>

static void zuc_set_eea_key(ZUC_KEY *key, const unsigned char user_key[16],
	ZUC_UINT32 count, ZUC_UINT5 bearer, ZUC_BIT direction)
{
	unsigned char iv[16] = {0};
	iv[0] = iv[8] = count >> 24;
	iv[1] = iv[9] = count >> 16;
	iv[2] = iv[10] = count >> 8;
	iv[3] = iv[11] = count;
	iv[4] = iv[12] = ((bearer << 1) | (direction & 1)) << 2;
	zuc_set_key(key, user_key, iv);
}

void zuc_eea_encrypt(const ZUC_UINT32 *in, ZUC_UINT32 *out, size_t nbits,
	const unsigned char key[16], ZUC_UINT32 count, ZUC_UINT5 bearer,
	ZUC_BIT direction)
{
	ZUC_KEY zuc_key;
	size_t nwords = (nbits + 31)/32;
	size_t i;

	zuc_set_eea_key(&zuc_key, key, count, bearer, direction);
	zuc_generate_keystream(&zuc_key, nwords, out);
	for (i = 0; i < nwords; i++) {
		out[i] ^= in[i];
	}

	if (nbits % 32 != 0) {
		out[nwords - 1] |= (0xffffffff << (32 - (nbits%32)));
	}
}
