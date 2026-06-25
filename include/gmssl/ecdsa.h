/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_ECDSA_H
#define GMSSL_ECDSA_H


#include <stdint.h>
#include <stdlib.h>
#include <gmssl/ec.h>


#ifdef __cplusplus
extern "C" {
#endif


int ecdsa_sign(const EC_KEY *key, const uint8_t *dgst, size_t dgstlen,
	uint8_t *sig, size_t *siglen);
int ecdsa_sign_fixed_len(const EC_KEY *key, const uint8_t *dgst, size_t dgstlen,
	size_t siglen, uint8_t *sig);
int ecdsa_verify(const EC_KEY *key, const uint8_t *dgst, size_t dgstlen,
	const uint8_t *sig, size_t siglen);


#ifdef __cplusplus
}
#endif
#endif
