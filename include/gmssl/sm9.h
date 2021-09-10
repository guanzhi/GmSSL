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

#ifndef GMSSL_SM9_H
#define GMSSL_SM9_H

#ifdef __cplusplus
extern "C" {
#endif


// set the same value as sm2
#define SM9_MAX_ID_BITS		65535
#define SM9_MAX_ID_SIZE		(SM9_MAX_ID_BITS/8)

typedef struct {
	uint8_t x[32];
	uint8_t y[32];
} SM9_POINT;

typedef struct {
	uint8_t x[64];
	uint8_t y[64];
} SM9_TWIST_POINT;

typedef struct {
	uint8_t ks[32];
	SM9_TWIST_POINT Ppubs; // Ppubs = ks * P2
} SM9_SIGN_MASTER_KEY;

typedef struct {
	SM9_POINT ds;
} SM9_SIGN_KEY;

typedef struct {
	uint8_t h[32];
	SM9_TWIST_POINT S;
} SM9_SIGNATURE;

int sm9_sign_setup(SM9_SIGN_MASTER_KEY *msk);
int sm9_sign_keygen(SM9_SIGN_MASTER_KEY *msk, const char *id, size_t idlen, SM9_POINT *ds);

int sm9_do_sign(SM9_SIGN_KEY *key, const uint8_t dgst[32], SM9_SIGNATURE *sig);
int sm9_do_verify(SM9_SIGN_KEY *key, const uint8_t dgst[32], const SM9_SIGNATURE *sig);



#  ifdef  __cplusplus
}
#  endif
# endif
