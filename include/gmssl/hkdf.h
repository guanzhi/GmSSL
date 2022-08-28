/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

// RFC 5869

#ifndef GMSSL_HKDF_H
#define GMSSL_HKDF_H

#include <string.h>
#include <gmssl/digest.h>
#include <gmssl/hmac.h>


#ifdef  __cplusplus
extern "C" {
#endif


int hkdf_extract(const DIGEST *digest, const uint8_t *salt, size_t saltlen,
	const uint8_t *ikm, size_t ikmlen,
	uint8_t *prk, size_t *prklen);

int hkdf_expand(const DIGEST *digest, const uint8_t *prk, size_t prklen,
	const uint8_t *opt_info, size_t opt_infolen,
	size_t L, uint8_t *okm);

int sm3_hkdf_extract(const uint8_t *salt, size_t saltlen,
	const uint8_t *ikm, size_t ikmlen,
	uint8_t *prk, size_t *prklen);

int sm3_hkdf_expand(const uint8_t *prk, size_t prklen,
	const uint8_t *opt_info, size_t opt_infolen,
	size_t L, uint8_t *okm);


#ifdef  __cplusplus
}
#endif
#endif
