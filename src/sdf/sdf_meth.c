/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmssl/dylib.h>
#include "sdf_int.h"

#define SDFerr(a,b)

#define SDF_METHOD_BIND_FUNCTION_EX(func,name) \
	sdf->func = (SDF_##func##_FuncPtr)dylib_get_function(sdf->dso, "SDF_"#name)

#define SDF_METHOD_BIND_FUNCTION(func) \
	SDF_METHOD_BIND_FUNCTION_EX(func,func)

SDF_METHOD *SDF_METHOD_load_library(const char *so_path)
{
	SDF_METHOD *ret = NULL;
	SDF_METHOD *sdf = NULL;

	if (!(sdf = malloc(sizeof(*sdf)))) {
		SDFerr(SDF_F_SDF_METHOD_LOAD_LIBRARY, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	memset(sdf, 0, sizeof(*sdf));

	if (!(sdf->dso = dylib_load_library(so_path))) {
		fprintf(stderr, "%s %d: %s\n", __FILE__, __LINE__, dylib_error_str());
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
	if (meth) dylib_close_library(meth->dso);
	free(meth);
}


