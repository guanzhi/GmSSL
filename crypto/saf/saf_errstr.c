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
#include <openssl/gmsaf.h>
#include "../../e_os.h"

static ERR_STRING_DATA saf_errstr[] = {
	{ SAR_Ok,		"Success" },
	{ SAR_UnknownErr,	"Unknown error" },
	{ SAR_NotSupportYetErr,	"Not supported yet error" },
	{ SAR_FileErr,		"File error" },
	{ SAR_ProviderTypeErr,	"Provider type error" },
	{ SAR_LoadProviderErr,	"Load provider error" },
	{ SAR_LoadDevMngApiErr,	"Load Device management API error" },
	{ SAR_AlgoTypeErr,	"Algorithm type error" },
	{ SAR_NameLenErr,	"Name length error" },
	{ SAR_KeyUsageErr,	"Key usage error" },
	{ SAR_ModulusLenErr,	"Modulus length error" },
	{ SAR_NotInitializeErr,	"Not initialized error" },
	{ SAR_ObjErr,		"Object error" },
	{ SAR_MemoryErr,	"Memory error" },
	{ SAR_TimeoutErr,	"Timeout error" },
	{ SAR_IndataLenErr,	"Input data length error" },
	{ SAR_IndataErr,	"Input data error" },
	{ SAR_GenRandErr,	"Generate random error" },
	{ SAR_HashObjErr,	"Hash object error" },
	{ SAR_HashErr,		"Hash error" },
	{ SAR_GenRsaKeyErr,	"Generate RSA key error" },
	{ SAR_RsaModulusLenErr,	"RSA modulus length error" },
	{ SAR_CspImportPubKeyErr,"CSP import public key error" },
	{ SAR_RsaEncErr,	"RSA encryption error" },
	{ SAR_RsaDecErr,	"RSA decryption error" },
	{ SAR_HashNotEqualErr,	"Hash not equal error" },
	{ SAR_KeyNotFoundErr,	"Key not found error" },
	{ SAR_CertNotFoundErr,	"Certificate not found error" },
	{ SAR_NotExportErr,	"Non-exportable error" },
	{ SAR_CertRevokedErr,	"Certificate revoked error" },
	{ SAR_CertNotYetValidErr,"Certificate not yet valid error" },
	{ SAR_CerthashExpiredErr,"Certificate hash expirted error" },
	{ SAR_CertVerifyErr,	"Certificate verification error" },
	{ SAR_CertEncodeErr,	"Certificate encoding error" },
	{ SAR_DecryptPadErr,	"Decryption padding error" },
	{ SAR_MacLenErr,	"MAC length error" },
	{ SAR_KeyInfoTypeErr,	"Key information type error" },
	{ SAR_NotLogin,		"Not login" },
};

const char *SAF_GetErrorString(int err)
{
	int i;
	for (i = 0; i < OSSL_NELEM(saf_errstr); i++) {
		if (err == saf_errstr[i].error) {
			return saf_errstr[i].string;
		}
	}
	return "(undef)";
}

