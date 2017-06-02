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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/ec.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/ec_type1.h>
#include <openssl/ec_hash.h>
#include <openssl/bfibe.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/bn_hash.h>
#include <openssl/bn_gfp2.h>
#include <openssl/kdf.h>

/*
 * the `curve` attribute of BFPublicParameters is the OID present the
 * `type1curve` which is E: y^2 = x^3 + 1 over prime field. It is not an
 * elliptic curve domain parameters composed of (p, a, b, G, n, h).
 * For type-1 curve, a = 0, b = 1.
 * q (i.e. the n in ec params) is the order of generator G, is a prime.
 * When q is a solinas prime, the scalar mulitiplication computation can
 * be reduced.
 * zeta (i.e. h in ec params) = (p + 1)/q. In normall ecc, h is very small
 * such as 1 or 4. But in pairing, the zeta (or h) is very large.
 */
struct BFPublicParameters_st {
	long version;
	ASN1_OBJECT *curve;
	BIGNUM *p;
	BIGNUM *q;
	FpPoint *pointP;
	FpPoint *pointPpub;
	ASN1_OBJECT *hashfcn;
};

struct BFMasterSecret_st {
	long version;
	BIGNUM *masterSecret;
};

struct BFPrivateKeyBlock_st {
	long version;
	FpPoint *privateKey;
};

struct BFCiphertextBlock_st {
	long version;
	FpPoint *u;
	ASN1_OCTET_STRING *v;
	ASN1_OCTET_STRING *w;
};

