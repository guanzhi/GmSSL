/* ====================================================================
 * Copyright (c) 2016 The GmSSL Project.  All rights reserved.
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
 * ====================================================================
 */

#ifndef HEADER_SM9_LCL_H
#define HEADER_SM9_LCL_H

#include <openssl/err.h>
#include <openssl/sm9.h>

/* Curve ID */
#define SM9_CID_TYPE0CURVE	0x10
#define SM9_CID_TYPE1CURVE	0x11
#define SM9_CID_TYPE2CURVE	0x12

/* Pairing ID */
#define SM9_EID_TATE		0x01
#define SM9_EID_WEIL		0x02
#define SM9_EID_ATE		0x03
#define SM9_EID_RATE		0x04

#define SM9_MAX_ID_LENGTH	127

/* not clear what it is */
#define SM9_HID			0xc9

#ifdef __cplusplus
extern "C" {
#endif

struct SM9PublicParameters_st {
	ASN1_OBJECT *curve;
	BIGNUM *p;
	BIGNUM *a;
	BIGNUM *b;
	BIGNUM *beta;
	BIGNUM *order;
	BIGNUM *cofactor;
	BIGNUM *k;
	ASN1_OCTET_STRING *pointP1;
	ASN1_OCTET_STRING *pointP2;
	ASN1_OBJECT *pairing;
	ASN1_OCTET_STRING *pointPpub;
	BIGNUM *g1; /* g1 = e(P1, Ppub) */
	BIGNUM *g2; /* g2 = e(Ppub, P2) */
	ASN1_OBJECT *hashfcn;
};

struct SM9MasterSecret_st {
	BIGNUM *masterSecret;
};

struct SM9PrivateKey_st {
	ASN1_OCTET_STRING *privatePoint;
};

struct SM9Ciphertext_st {
	ASN1_OCTET_STRING *pointC1;
	ASN1_OCTET_STRING *c2;
	ASN1_OCTET_STRING *c3;
};

struct SM9Signature_st {
	BIGNUM *h;
	ASN1_OCTET_STRING *pointS;
};


int SM9_hash1(const EVP_MD *md, BIGNUM **r,
	const char *id, size_t idlen, unsigned char hid,
	const BIGNUM *range, BN_CTX *ctx);

int SM9_hash2(const EVP_MD *md, BIGNUM **r,
	const unsigned char *data, size_t datalen,
	const unsigned char *elem, size_t elemlen,
	const BIGNUM *range, BN_CTX *ctx);

EC_GROUP *EC_GROUP_new_sm9s256t1(void);


#ifdef __cplusplus
}
#endif
#endif
