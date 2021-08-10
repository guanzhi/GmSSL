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

#ifndef GMSSL_PBKDF2_H
#define GMSSL_PBKDF2_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <gmssl/hmac.h>

#ifdef __cplusplus
extern "C" {
#endif


#define PBKDF2_MIN_ITER			10000
#define PBKDF2_MIN_SALT_SIZE		64
#define PBKDF2_DEFAULT_SALT_SIZE	8


int pbkdf2_genkey(const DIGEST *digest,
	const char *pass, size_t passlen,
	const uint8_t *salt, size_t saltlen,
	size_t count, size_t outlen, uint8_t *out);


#ifdef __cplusplus
}
#endif
#endif
