/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_PBKDF2_H
#define GMSSL_PBKDF2_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <gmssl/hmac.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
PBKDF2 Public API

	PBKDF2_MIN_ITER
	PBKDF2_DEFAULT_SALT_SIZE
	PBKDF2_MAX_SALT_SIZE

	pbkdf2_hmac_sm3_genkey
*/


#define PBKDF2_MIN_ITER			10000
#define PBKDF2_MAX_ITER			(INT_MAX)
#define PBKDF2_MAX_SALT_SIZE		64
#define PBKDF2_DEFAULT_SALT_SIZE	8


int pbkdf2_genkey(const DIGEST *digest,
	const char *pass, size_t passlen, const uint8_t *salt, size_t saltlen, size_t iter,
	size_t outlen, uint8_t *out);

int pbkdf2_hmac_sm3_genkey(
	const char *pass, size_t passlen, const uint8_t *salt, size_t saltlen, size_t iter,
	size_t outlen, uint8_t *out);


#ifdef __cplusplus
}
#endif
#endif
