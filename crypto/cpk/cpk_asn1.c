/* ====================================================================
 * Copyright (c) 2007 - 2016 The GmSSL Project.  All rights reserved.
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

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/cpk.h>
#include "cpk_lcl.h"

ASN1_SEQUENCE(CPK_MASTER_SECRET) = {
	ASN1_SIMPLE(CPK_MASTER_SECRET, version, LONG),
	ASN1_SIMPLE(CPK_MASTER_SECRET, id, X509_NAME),
	ASN1_SIMPLE(CPK_MASTER_SECRET, pkey_algor, X509_ALGOR),
	ASN1_SIMPLE(CPK_MASTER_SECRET, map_algor, X509_ALGOR),
	ASN1_SIMPLE(CPK_MASTER_SECRET, secret_factors, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(CPK_MASTER_SECRET)
IMPLEMENT_ASN1_FUNCTIONS(CPK_MASTER_SECRET)
IMPLEMENT_ASN1_DUP_FUNCTION(CPK_MASTER_SECRET)

ASN1_SEQUENCE(CPK_PUBLIC_PARAMS) = {
	ASN1_SIMPLE(CPK_PUBLIC_PARAMS, version, LONG),
	ASN1_SIMPLE(CPK_PUBLIC_PARAMS, id, X509_NAME),
	ASN1_SIMPLE(CPK_PUBLIC_PARAMS, pkey_algor, X509_ALGOR),
	ASN1_SIMPLE(CPK_PUBLIC_PARAMS, map_algor, X509_ALGOR),
	ASN1_SIMPLE(CPK_PUBLIC_PARAMS, public_factors, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(CPK_PUBLIC_PARAMS)
IMPLEMENT_ASN1_FUNCTIONS(CPK_PUBLIC_PARAMS)
IMPLEMENT_ASN1_DUP_FUNCTION(CPK_PUBLIC_PARAMS)


CPK_MASTER_SECRET *d2i_CPK_MASTER_SECRET_bio(BIO *bp, CPK_MASTER_SECRET **master)
{
	return ASN1_item_d2i_bio(ASN1_ITEM_rptr(CPK_MASTER_SECRET), bp, master);
}

int i2d_CPK_MASTER_SECRET_bio(BIO *bp, CPK_MASTER_SECRET *master)
{
	return ASN1_item_i2d_bio(ASN1_ITEM_rptr(CPK_MASTER_SECRET), bp, master);
}

CPK_PUBLIC_PARAMS *d2i_CPK_PUBLIC_PARAMS_bio(BIO *bp, CPK_PUBLIC_PARAMS **params)
{
	return ASN1_item_d2i_bio(ASN1_ITEM_rptr(CPK_PUBLIC_PARAMS), bp, params);
}

int i2d_CPK_PUBLIC_PARAMS_bio(BIO *bp, CPK_PUBLIC_PARAMS *params)
{
	return ASN1_item_i2d_bio(ASN1_ITEM_rptr(CPK_PUBLIC_PARAMS), bp, params);
}
