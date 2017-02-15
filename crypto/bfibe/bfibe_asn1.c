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
#include "bfibe_lcl.h"

ASN1_SEQUENCE(BFPublicParameters) = {
	ASN1_SIMPLE(BFPublicParameters, version, LONG),
	ASN1_SIMPLE(BFPublicParameters, curve, ASN1_OBJECT),
	ASN1_SIMPLE(BFPublicParameters, p, BIGNUM),
	ASN1_SIMPLE(BFPublicParameters, q, BIGNUM),
	ASN1_SIMPLE(BFPublicParameters, pointP, FpPoint),
	ASN1_SIMPLE(BFPublicParameters, pointPpub, FpPoint),
	ASN1_SIMPLE(BFPublicParameters, hashfcn, ASN1_OBJECT)
} ASN1_SEQUENCE_END(BFPublicParameters)
IMPLEMENT_ASN1_FUNCTIONS(BFPublicParameters)
IMPLEMENT_ASN1_DUP_FUNCTION(BFPublicParameters)

ASN1_SEQUENCE(BFMasterSecret) = {
	ASN1_SIMPLE(BFMasterSecret, version, LONG),
	ASN1_SIMPLE(BFMasterSecret, masterSecret, BIGNUM)
} ASN1_SEQUENCE_END(BFMasterSecret)
IMPLEMENT_ASN1_FUNCTIONS(BFMasterSecret)
IMPLEMENT_ASN1_DUP_FUNCTION(BFMasterSecret)

ASN1_SEQUENCE(BFPrivateKeyBlock) = {
	ASN1_SIMPLE(BFPrivateKeyBlock, version, LONG),
	ASN1_SIMPLE(BFPrivateKeyBlock, privateKey, FpPoint)
} ASN1_SEQUENCE_END(BFPrivateKeyBlock)
IMPLEMENT_ASN1_FUNCTIONS(BFPrivateKeyBlock)
IMPLEMENT_ASN1_DUP_FUNCTION(BFPrivateKeyBlock)

ASN1_SEQUENCE(BFCiphertextBlock) = {
	ASN1_SIMPLE(BFCiphertextBlock, version, LONG),
	ASN1_SIMPLE(BFCiphertextBlock, u, FpPoint),
	ASN1_SIMPLE(BFCiphertextBlock, v, ASN1_OCTET_STRING),
	ASN1_SIMPLE(BFCiphertextBlock, w, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(BFCiphertextBlock)
IMPLEMENT_ASN1_FUNCTIONS(BFCiphertextBlock)
IMPLEMENT_ASN1_DUP_FUNCTION(BFCiphertextBlock)

