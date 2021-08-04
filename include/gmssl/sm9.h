/*
 * Copyright (c) 2016 - 2021 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
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
