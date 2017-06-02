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

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bn_gfp2.h>
#include <openssl/bn_hash.h>
#include <openssl/ec_type1.h>
#include <openssl/bb1ibe.h>
#include "bb1ibe_lcl.h"

ASN1_SEQUENCE(BB1PublicParameters) = {
	ASN1_SIMPLE(BB1PublicParameters, version, LONG),
	ASN1_SIMPLE(BB1PublicParameters, curve, ASN1_OBJECT),
	ASN1_SIMPLE(BB1PublicParameters, p, BIGNUM),
	ASN1_SIMPLE(BB1PublicParameters, q, BIGNUM),
	ASN1_SIMPLE(BB1PublicParameters, pointP, FpPoint),
	ASN1_SIMPLE(BB1PublicParameters, pointP1, FpPoint),
	ASN1_SIMPLE(BB1PublicParameters, pointP2, FpPoint),
	ASN1_SIMPLE(BB1PublicParameters, pointP3, FpPoint),
	ASN1_SIMPLE(BB1PublicParameters, v, FpPoint),
	ASN1_SIMPLE(BB1PublicParameters, hashfcn, ASN1_OBJECT)
} ASN1_SEQUENCE_END(BB1PublicParameters)
IMPLEMENT_ASN1_FUNCTIONS(BB1PublicParameters)
IMPLEMENT_ASN1_DUP_FUNCTION(BB1PublicParameters)

ASN1_SEQUENCE(BB1MasterSecret) = {
	ASN1_SIMPLE(BB1MasterSecret, version, LONG),
	ASN1_SIMPLE(BB1MasterSecret, alpha, BIGNUM),
	ASN1_SIMPLE(BB1MasterSecret, beta, BIGNUM),
	ASN1_SIMPLE(BB1MasterSecret, gamma, BIGNUM)
} ASN1_SEQUENCE_END(BB1MasterSecret)
IMPLEMENT_ASN1_FUNCTIONS(BB1MasterSecret)
IMPLEMENT_ASN1_DUP_FUNCTION(BB1MasterSecret)

ASN1_SEQUENCE(BB1PrivateKeyBlock) = {
	ASN1_SIMPLE(BB1PrivateKeyBlock, version, LONG),
	ASN1_SIMPLE(BB1PrivateKeyBlock, pointD0, FpPoint),
	ASN1_SIMPLE(BB1PrivateKeyBlock, pointD1, FpPoint)
} ASN1_SEQUENCE_END(BB1PrivateKeyBlock)
IMPLEMENT_ASN1_FUNCTIONS(BB1PrivateKeyBlock)
IMPLEMENT_ASN1_DUP_FUNCTION(BB1PrivateKeyBlock)

ASN1_SEQUENCE(BB1CiphertextBlock) = {
	ASN1_SIMPLE(BB1CiphertextBlock, version, LONG),
	ASN1_SIMPLE(BB1CiphertextBlock, pointChi0, FpPoint),
	ASN1_SIMPLE(BB1CiphertextBlock, pointChi1, FpPoint),
	ASN1_SIMPLE(BB1CiphertextBlock, nu, BIGNUM),
	ASN1_SIMPLE(BB1CiphertextBlock, y, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(BB1CiphertextBlock)
IMPLEMENT_ASN1_FUNCTIONS(BB1CiphertextBlock)
IMPLEMENT_ASN1_DUP_FUNCTION(BB1CiphertextBlock)

