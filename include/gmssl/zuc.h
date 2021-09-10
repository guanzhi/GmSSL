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

#ifndef GMSSL_ZUC_H
#define GMSSL_ZUC_H


#include <stdlib.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


# define ZUC_KEY_SIZE	16
# define ZUC_IV_SIZE	16
# define ZUC_MAC_SIZE	4

typedef uint32_t ZUC_BIT;
typedef uint32_t ZUC_UINT5;
typedef uint8_t  ZUC_UINT6;
typedef uint32_t ZUC_UINT15;
typedef uint32_t ZUC_UINT31;
typedef uint32_t ZUC_UINT32;

typedef struct ZUC_KEY_st {
	ZUC_UINT31 LFSR[16];
	ZUC_UINT32 R1;
	ZUC_UINT32 R2;
} ZUC_KEY;

void zuc_set_key(ZUC_KEY *key, const uint8_t user_key[16], const uint8_t iv[16]);
void zuc_generate_keystream(ZUC_KEY *key, size_t nwords, ZUC_UINT32 *words);
ZUC_UINT32 zuc_generate_keyword(ZUC_KEY *key);


typedef struct ZUC_MAC_CTX_st {
	ZUC_UINT31 LFSR[16];
	ZUC_UINT32 R1;
	ZUC_UINT32 R2;
	ZUC_UINT32 T;
	ZUC_UINT32 K0;
	uint8_t buf[4];
	size_t buflen;
} ZUC_MAC_CTX;

void zuc_mac_init(ZUC_MAC_CTX *ctx, const uint8_t key[16], const uint8_t iv[16]);
void zuc_mac_update(ZUC_MAC_CTX *ctx, const uint8_t *data, size_t len);
void zuc_mac_finish(ZUC_MAC_CTX *ctx, const uint8_t *data, size_t nbits, uint8_t mac[4]);

void zuc_eea_encrypt(const ZUC_UINT32 *in, ZUC_UINT32 *out, size_t nbits,
	const uint8_t key[16], ZUC_UINT32 count, ZUC_UINT5 bearer,
	ZUC_BIT direction);
ZUC_UINT32 zuc_eia_generate_mac(const ZUC_UINT32 *data, size_t nbits,
	const uint8_t user_key[16], ZUC_UINT32 count, ZUC_UINT5 bearer,
	ZUC_BIT direction);


# define ZUC256_KEY_SIZE	32
# define ZUC256_IV_SIZE	23
# define ZUC256_MAC32_SIZE	4
# define ZUC256_MAC64_SIZE	8
# define ZUC256_MAC128_SIZE	16
# define ZUC256_MIN_MAC_SIZE	ZUC256_MAC32_SIZE
# define ZUC256_MAX_MAC_SIZE	ZUC256_MAC128_SIZE

typedef ZUC_KEY ZUC256_KEY;

void zuc256_set_key(ZUC256_KEY *key, const uint8_t user_key[32], const uint8_t iv[23]);
#define zuc256_generate_keystream(k,n,out)	zuc_generate_keystream(k,n,out)
#define zuc256_generate_keyword(k)		zuc_generate_keyword(k)


typedef struct ZUC256_MAC_CTX_st {
	ZUC_UINT31 LFSR[16];
	ZUC_UINT32 R1;
	ZUC_UINT32 R2;
	ZUC_UINT32 T[4];
	ZUC_UINT32 K0[4];
	uint8_t buf[4];
	int buflen;
	int macbits;
} ZUC256_MAC_CTX;

void zuc256_mac_init(ZUC256_MAC_CTX *ctx, const uint8_t key[32], const uint8_t iv[23], int macbits);
void zuc256_mac_update(ZUC256_MAC_CTX *ctx, const uint8_t *data, size_t len);
void zuc256_mac_finish(ZUC256_MAC_CTX *ctx, const uint8_t *data, size_t nbits, uint8_t *mac);


#ifdef __cplusplus
}
#endif
#endif
