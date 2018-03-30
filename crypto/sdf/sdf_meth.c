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
#include <openssl/gmsdf.h>
#include <openssl/crypto.h>
#include "internal/dso.h"
#include "internal/sdf_int.h"

#define SDF_METHOD_BIND_FUNCTION_EX(func,name) \
	sdf->func = (SDF_##func##_FuncPtr)DSO_bind_func(sdf->dso, "SDF_"#name)

#define SDF_METHOD_BIND_FUNCTION(func) \
	SDF_METHOD_BIND_FUNCTION_EX(func,func)

SDF_METHOD *SDF_METHOD_load_library(const char *so_path)
{
	SDF_METHOD *ret = NULL;
	SDF_METHOD *sdf = NULL;

	if (!(sdf = OPENSSL_zalloc(sizeof(*sdf)))) {
		SDFerr(SDF_F_SDF_METHOD_LOAD_LIBRARY, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!(sdf->dso = DSO_load(NULL, so_path, NULL, 0))) {
		SDFerr(SDF_F_SDF_METHOD_LOAD_LIBRARY, SDF_R_DSO_LOAD_FAILURE);
		goto end;
	}

	SDF_METHOD_BIND_FUNCTION(OpenDevice);
	SDF_METHOD_BIND_FUNCTION(CloseDevice);
	SDF_METHOD_BIND_FUNCTION(OpenSession);
	SDF_METHOD_BIND_FUNCTION(CloseSession);
	SDF_METHOD_BIND_FUNCTION(GetDeviceInfo);
	SDF_METHOD_BIND_FUNCTION(GenerateRandom);
	SDF_METHOD_BIND_FUNCTION(GetPrivateKeyAccessRight);
	SDF_METHOD_BIND_FUNCTION(ReleasePrivateKeyAccessRight);
	SDF_METHOD_BIND_FUNCTION(ExportSignPublicKey_RSA);
	SDF_METHOD_BIND_FUNCTION(ExportEncPublicKey_RSA);
	SDF_METHOD_BIND_FUNCTION(GenerateKeyPair_RSA);
	SDF_METHOD_BIND_FUNCTION(GenerateKeyWithIPK_RSA);
	SDF_METHOD_BIND_FUNCTION(GenerateKeyWithEPK_RSA);
	SDF_METHOD_BIND_FUNCTION(ImportKeyWithISK_RSA);
	SDF_METHOD_BIND_FUNCTION(ExchangeDigitEnvelopeBaseOnRSA);
	SDF_METHOD_BIND_FUNCTION(ExportSignPublicKey_ECC);
	SDF_METHOD_BIND_FUNCTION(ExportEncPublicKey_ECC);
	SDF_METHOD_BIND_FUNCTION(GenerateKeyPair_ECC);
	SDF_METHOD_BIND_FUNCTION(GenerateKeyWithIPK_ECC);
	SDF_METHOD_BIND_FUNCTION(GenerateKeyWithEPK_ECC);
	SDF_METHOD_BIND_FUNCTION(ImportKeyWithISK_ECC);
	SDF_METHOD_BIND_FUNCTION(GenerateAgreementDataWithECC);
	SDF_METHOD_BIND_FUNCTION(GenerateKeyWithECC);
	SDF_METHOD_BIND_FUNCTION(GenerateAgreementDataAndKeyWithECC);
	SDF_METHOD_BIND_FUNCTION(ExchangeDigitEnvelopeBaseOnECC);
	SDF_METHOD_BIND_FUNCTION(GenerateKeyWithKEK);
	SDF_METHOD_BIND_FUNCTION(ImportKeyWithKEK);
	SDF_METHOD_BIND_FUNCTION(DestroyKey);
	SDF_METHOD_BIND_FUNCTION(ExternalPublicKeyOperation_RSA);
	//SDF_METHOD_BIND_FUNCTION(InternalPublicKeyOperation_RSA);
	SDF_METHOD_BIND_FUNCTION(InternalPrivateKeyOperation_RSA);
	SDF_METHOD_BIND_FUNCTION(ExternalVerify_ECC);
	SDF_METHOD_BIND_FUNCTION(InternalSign_ECC);
	SDF_METHOD_BIND_FUNCTION(InternalVerify_ECC);
	SDF_METHOD_BIND_FUNCTION(ExternalEncrypt_ECC);
	//SDF_METHOD_BIND_FUNCTION(ExternalDecrypt_ECC);
	SDF_METHOD_BIND_FUNCTION(InternalEncrypt_ECC);
	SDF_METHOD_BIND_FUNCTION(InternalDecrypt_ECC);
	SDF_METHOD_BIND_FUNCTION(Encrypt);
	SDF_METHOD_BIND_FUNCTION(Decrypt);
	SDF_METHOD_BIND_FUNCTION(CalculateMAC);
	SDF_METHOD_BIND_FUNCTION(HashInit);
	SDF_METHOD_BIND_FUNCTION(HashUpdate);
	SDF_METHOD_BIND_FUNCTION(HashFinal);
	SDF_METHOD_BIND_FUNCTION_EX(CreateObject,CreateFile);
	SDF_METHOD_BIND_FUNCTION_EX(ReadObject,ReadFile);
	SDF_METHOD_BIND_FUNCTION_EX(WriteObject,WriteFile);
	SDF_METHOD_BIND_FUNCTION_EX(DeleteObject,DeleteFile);

	ret = sdf;
	sdf = NULL;

end:
	SDF_METHOD_free(sdf);
	return ret;
}

void SDF_METHOD_free(SDF_METHOD *meth)
{
	if (meth) DSO_free(meth->dso);
	OPENSSL_free(meth);
}


