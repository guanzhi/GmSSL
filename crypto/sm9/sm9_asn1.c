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

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/sm9.h>
#include "sm9_lcl.h"

ASN1_SEQUENCE(SM9PublicParameters) = {
	ASN1_SIMPLE(SM9PublicParameters, curve, ASN1_OBJECT),
	ASN1_SIMPLE(SM9PublicParameters, p, BIGNUM),
	ASN1_SIMPLE(SM9PublicParameters, a, BIGNUM),
	ASN1_SIMPLE(SM9PublicParameters, b, BIGNUM),
	ASN1_SIMPLE(SM9PublicParameters, beta, BIGNUM),
	ASN1_SIMPLE(SM9PublicParameters, order, BIGNUM),
	ASN1_SIMPLE(SM9PublicParameters, cofactor, BIGNUM),
	ASN1_SIMPLE(SM9PublicParameters, k, BIGNUM),
	ASN1_SIMPLE(SM9PublicParameters, pointP1, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SM9PublicParameters, pointP2, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SM9PublicParameters, pairing, ASN1_OBJECT),
	ASN1_SIMPLE(SM9PublicParameters, pointPpub, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SM9PublicParameters, g1, BIGNUM),
	ASN1_SIMPLE(SM9PublicParameters, g2, BIGNUM),
	ASN1_SIMPLE(SM9PublicParameters, hashfcn, ASN1_OBJECT)
} ASN1_SEQUENCE_END(SM9PublicParameters)
IMPLEMENT_ASN1_FUNCTIONS(SM9PublicParameters)
IMPLEMENT_ASN1_DUP_FUNCTION(SM9PublicParameters)

ASN1_SEQUENCE(SM9MasterSecret) = {
	ASN1_SIMPLE(SM9MasterSecret, masterSecret, BIGNUM)
} ASN1_SEQUENCE_END(SM9MasterSecret)
IMPLEMENT_ASN1_FUNCTIONS(SM9MasterSecret)
IMPLEMENT_ASN1_DUP_FUNCTION(SM9MasterSecret)

ASN1_SEQUENCE(SM9PrivateKey) = {
	ASN1_SIMPLE(SM9PrivateKey, privatePoint, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SM9PrivateKey)
IMPLEMENT_ASN1_FUNCTIONS(SM9PrivateKey)
IMPLEMENT_ASN1_DUP_FUNCTION(SM9PrivateKey)

ASN1_SEQUENCE(SM9PublicKey) = {
	ASN1_SIMPLE(SM9PublicKey, publicPoint, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SM9PublicKey)
IMPLEMENT_ASN1_FUNCTIONS(SM9PublicKey)
IMPLEMENT_ASN1_DUP_FUNCTION(SM9PublicKey)

ASN1_SEQUENCE(SM9Ciphertext) = {
	ASN1_SIMPLE(SM9Ciphertext, pointC1, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SM9Ciphertext, c2, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SM9Ciphertext, c3, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SM9Ciphertext)
IMPLEMENT_ASN1_FUNCTIONS(SM9Ciphertext)
IMPLEMENT_ASN1_DUP_FUNCTION(SM9Ciphertext)

ASN1_SEQUENCE(SM9Signature) = {
	ASN1_SIMPLE(SM9Signature, h, BIGNUM),
	ASN1_SIMPLE(SM9Signature, pointS, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SM9Signature)
IMPLEMENT_ASN1_FUNCTIONS(SM9Signature)
IMPLEMENT_ASN1_DUP_FUNCTION(SM9Signature)

int SM9PublicKey_gmtls_encode(SM9PublicKey *pk, unsigned char key[1024])
{
	return 0;
}
