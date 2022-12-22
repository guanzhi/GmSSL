/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_SM4_CBC_MAC_H
#define GMSSL_SM4_CBC_MAC_H

#include <stdint.h>
#include <gmssl/sm4.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	SM4_KEY key;
	uint8_t iv[16];
	size_t ivlen;
} SM4_CBC_MAC_CTX;

void sm4_cbc_mac_init(SM4_CBC_MAC_CTX *ctx, const uint8_t key[16]);
void sm4_cbc_mac_update(SM4_CBC_MAC_CTX *ctx, const uint8_t *data, size_t datalen);
void sm4_cbc_mac_finish(SM4_CBC_MAC_CTX *ctx, uint8_t mac[16]);


#ifdef __cplusplus
}
#endif
#endif
