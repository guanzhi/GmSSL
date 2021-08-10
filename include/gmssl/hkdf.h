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
	const uint8_t *info, size_t infolen,
	size_t L, uint8_t *okm);



#ifdef  __cplusplus
}
#endif
#endif
