/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#ifndef GMSSL_RC4_H
#define GMSSL_RC4_H


#include <string.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


#define RC4_MIN_KEY_BITS	40
#define RC4_STATE_NUM_WORDS	256


typedef struct {
	uint8_t d[RC4_STATE_NUM_WORDS];
} RC4_STATE;

void rc4_init(RC4_STATE *state, const uint8_t *key, size_t keylen);
void rc4_generate_keystream(RC4_STATE *state, size_t outlen, uint8_t *out);


#ifdef __cplusplus
}
#endif
#endif
