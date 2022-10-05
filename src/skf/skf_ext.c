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
#include <limits.h>
#include "skf_int.h"
#include "skf_ext.h"
#include "skf.h"


#define SKFerr(f,e)

ULONG DEVAPI SKF_NewECCCipher(ULONG ulCipherLen, ECCCIPHERBLOB **cipherBlob)
{
	ECCCIPHERBLOB *ret = NULL;

	if (!(ret = malloc(sizeof(ECCCIPHERBLOB) - 1 + ulCipherLen))) {
		SKFerr(SKF_F_SKF_NEWECCCIPHER, ERR_R_MALLOC_FAILURE);
		return SAR_MEMORYERR;
	}

	ret->CipherLen = ulCipherLen;
	*cipherBlob = ret;
	return SAR_OK;
}

ULONG DEVAPI SKF_NewEnvelopedKey(ULONG ulCipherLen, ENVELOPEDKEYBLOB **envelopedKeyBlob)
{
	ENVELOPEDKEYBLOB *ret = NULL;

	if (!(ret = malloc(sizeof(ENVELOPEDKEYBLOB) - 1 + ulCipherLen))) {
		SKFerr(SKF_F_SKF_NEWENVELOPEDKEY, ERR_R_MALLOC_FAILURE);
		return SAR_MEMORYERR;
	}

	ret->ECCCipherBlob.CipherLen = ulCipherLen;
	*envelopedKeyBlob = ret;
	return SAR_OK;
}

ULONG DEVAPI SKF_OpenDevice(LPSTR devName, BYTE authKey[16], DEVINFO *devInfo, DEVHANDLE *phDev)
{
	ULONG rv;
	DEVHANDLE hDev = NULL;
	HANDLE hKey = NULL;
	ULONG ulTimeOut = 0xffffffff;
	BYTE authRand[16] = {0};
	BYTE authData[16] = {0};
	ULONG authRandLen = SKF_AUTHRAND_LENGTH;
	ULONG authDataLen = sizeof(authData);
	BLOCKCIPHERPARAM encParam = {{0}, 0, 0, 0};

	if ((rv = SKF_ConnectDev((LPSTR)devName, &hDev)) != SAR_OK
		|| (rv = SKF_GetDevInfo(hDev, devInfo)) != SAR_OK
		|| (rv = SKF_LockDev(hDev, ulTimeOut)) != SAR_OK
		|| (rv = SKF_GenRandom(hDev, authRand, authRandLen)) != SAR_OK
		|| (rv = SKF_SetSymmKey(hDev, authKey, devInfo->DevAuthAlgId, &hKey)) != SAR_OK
		|| (rv = SKF_EncryptInit(hKey, encParam)) != SAR_OK
		|| (rv = SKF_Encrypt(hKey, authRand, sizeof(authRand), authData, &authDataLen)) != SAR_OK
		|| (rv =SKF_DevAuth(hDev, authData, authDataLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_OPENDEVICE, ERR_R_SKF_LIB);
		goto end;
	}
	*phDev = hDev;
	hDev = NULL;

end:
	//OPENSSL_cleanse(authRand, sizeof(authRand));
	//OPENSSL_cleanse(authData, sizeof(authData));
	if (hKey && (rv = SKF_CloseHandle(hKey)) != SAR_OK) {
		SKFerr(SKF_F_SKF_OPENDEVICE, ERR_R_SKF_LIB);
	}
	if (hDev  && (rv = SKF_DisConnectDev(hDev)) != SAR_OK) {
		SKFerr(SKF_F_SKF_OPENDEVICE, ERR_R_SKF_LIB);
	}
	return rv;
}

ULONG DEVAPI SKF_CloseDevice(DEVHANDLE hDev)
{
	ULONG rv;
	if ((rv = SKF_UnlockDev(hDev)) != SAR_OK) {
		SKFerr(SKF_F_SKF_CLOSEDEVICE, ERR_R_SKF_LIB);
	}
	if ((rv = SKF_DisConnectDev(hDev)) != SAR_OK) {
		SKFerr(SKF_F_SKF_CLOSEDEVICE, ERR_R_SKF_LIB);
	}
	return rv;
}

#if 0
ULONG DEVAPI SKF_ImportECCPrivateKey(DEVHANDLE hDev, HCONTAINER hContainer,
	EC_KEY *ec_key, ULONG symmAlgId)
{
	int ret = 0;
	ULONG rv;
	ULONG containerType;
	ECCPRIVATEKEYBLOB eccPriKeyBlob;
	BYTE symmKey[16];
	HANDLE hSymmKey = NULL;
	BLOCKCIPHERPARAM encParam;
	ULONG encedPriKeyLen;
	SKF_PUBLICKEYBLOB signPubKeyBlob;
	ULONG signPubKeyLen = sizeof(signPubKeyBlob);
	ENVELOPEDKEYBLOB envelopedKeyBlob;

	/* check container type */
	if ((rv = SKF_GetContainerType(hContainer, &containerType)) != SAR_OK) {
		SKFerr(SKF_F_SKF_IMPORTECCPRIVATEKEY, ERR_R_SKF_LIB);
		return rv;
	}
	if (containerType != SKF_CONTAINER_TYPE_ECC) {
		SKFerr(SKF_F_SKF_IMPORTECCPRIVATEKEY, SKF_R_CONTAINER_TYPE_NOT_MATCH);
		return SAR_FAIL;
	}

	/* get private key and public key */
	if (!EC_KEY_get_ECCPRIVATEKEYBLOB(ec_key, &eccPriKeyBlob)
		|| !EC_KEY_get_ECCPUBLICKEYBLOB(ec_key, &(envelopedKeyBlob.PubKey))) {
		SKFerr(SKF_F_SKF_IMPORTECCPRIVATEKEY, ERR_R_GMAPI_LIB);
		rv = SAR_FAIL;
		goto end;
	}

	/* set Version, ulSymmAlgID, ulBits */
	envelopedKeyBlob.Version = SKF_ENVELOPEDKEYBLOB_VERSION;
	envelopedKeyBlob.ulSymmAlgID = symmAlgId;
	envelopedKeyBlob.ulBits = eccPriKeyBlob.BitLen;

	/* encrypt private key with random generated symmkey */
	if (!rand_bytes(symmKey, sizeof(symmKey))) {
		SKFerr(SKF_F_SKF_IMPORTECCPRIVATEKEY, ERR_R_SKF_LIB);
		rv = SAR_FAIL;
		goto end;
	}
	if ((rv = SKF_SetSymmKey(hDev, symmKey, symmAlgId, &hSymmKey)) != SAR_OK) {
		SKFerr(SKF_F_SKF_IMPORTECCPRIVATEKEY, ERR_R_SKF_LIB);
		goto end;
	}
	encParam.IVLen = 0;
	encParam.PaddingType = SKF_NO_PADDING;
	if ((rv = SKF_EncryptInit(hSymmKey, encParam)) != SAR_OK) {
		SKFerr(SKF_F_SKF_IMPORTECCPRIVATEKEY, ERR_R_SKF_LIB);
		goto end;
	}
	encedPriKeyLen = sizeof(envelopedKeyBlob.cbEncryptedPriKey);
	if ((rv = SKF_Encrypt(hSymmKey,
		eccPriKeyBlob.PrivateKey, sizeof(eccPriKeyBlob.PrivateKey),
		(BYTE *)&(envelopedKeyBlob.cbEncryptedPriKey), &encedPriKeyLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_IMPORTECCPRIVATEKEY, ERR_R_SKF_LIB);
		goto end;
	}
	if (encedPriKeyLen != sizeof(eccPriKeyBlob.PrivateKey)) {
		SKFerr(SKF_F_SKF_IMPORTECCPRIVATEKEY, ERR_R_SKF_LIB);
		rv = SAR_FAIL;
		goto end;
	}

	/* encrypt symmKey */
	if ((rv = SKF_ExportPublicKey(hContainer, TRUE,
		(BYTE *)&signPubKeyBlob, &signPubKeyLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_IMPORTECCPRIVATEKEY, ERR_R_SKF_LIB);
		goto end;
	}
	if (signPubKeyLen != sizeof(ECCPUBLICKEYBLOB)) {
		SKFerr(SKF_F_SKF_IMPORTECCPRIVATEKEY, ERR_R_SKF_LIB);
		rv = SAR_FAIL;
		goto end;
	}
	if ((rv = SKF_ExtECCEncrypt(hDev, (ECCPUBLICKEYBLOB *)&signPubKeyBlob,
		symmKey, sizeof(symmKey), &(envelopedKeyBlob.ECCCipherBlob))) != SAR_OK) {
		SKFerr(SKF_F_SKF_IMPORTECCPRIVATEKEY, ERR_R_SKF_LIB);
		goto end;
	}

	ret = 1;
end:
	OPENSSL_cleanse(&eccPriKeyBlob, sizeof(eccPriKeyBlob));
	OPENSSL_cleanse(symmKey, sizeof(symmKey));
	if (hSymmKey && SKF_CloseHandle(hSymmKey) != SAR_OK) {
		SKFerr(SKF_F_SKF_IMPORTECCPRIVATEKEY, ERR_R_SKF_LIB);
		ret = 0;
	}
	return ret;
}

ULONG DEVAPI SKF_ImportRSAPrivateKey(DEVHANDLE hDev, HCONTAINER hContainer,
	RSA *rsa, ULONG symmAlgId)
{
	ULONG rv;
	ULONG containerType;
	RSAPRIVATEKEYBLOB rsaPriKeyBlob;
	unsigned char symmKey[16];
	RSAPUBLICKEYBLOB rsaPubKeyBlob;
	ULONG rsaPubKeyLen = sizeof(rsaPubKeyBlob);
	BYTE wrappedKey[MAX_RSA_MODULUS_LEN];
	ULONG wrappedKeyLen = sizeof(wrappedKey);
	EVP_CIPHER_CTX *cctx = NULL;
	unsigned char *p;
	int len;
	BYTE encedPriKey[sizeof(RSAPRIVATEKEYBLOB) + 16*2];
	ULONG encedPriKeyLen = sizeof(encedPriKey);


	if ((rv = SKF_GetContainerType(hContainer, &containerType)) != SAR_OK) {
		SKFerr(SKF_F_SKF_IMPORTRSAPRIVATEKEY, ERR_R_SKF_LIB);
		return rv;
	}
	if (containerType != SKF_CONTAINER_TYPE_RSA) {
		SKFerr(SKF_F_SKF_IMPORTRSAPRIVATEKEY, ERR_R_SKF_LIB);
		return SAR_FAIL;
	}

	if (!RSA_get_RSAPRIVATEKEYBLOB(rsa, &rsaPriKeyBlob)) {
		SKFerr(SKF_F_SKF_IMPORTRSAPRIVATEKEY, ERR_R_SKF_LIB);
		goto end;
	}

	/* generate symmkey */
	/* wrap symmkey with signing public key */
	if (!rand_bytes(symmKey, sizeof(symmKey))) {
		SKFerr(SKF_F_SKF_IMPORTRSAPRIVATEKEY, ERR_R_SKF_LIB);
		goto end;
	}
	if ((rv = SKF_ExportPublicKey(hContainer, SGD_TRUE,
		(BYTE *)&rsaPubKeyBlob, &rsaPubKeyLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_IMPORTRSAPRIVATEKEY, ERR_R_SKF_LIB);
		goto end;
	}
	if (!(rsa = RSA_new_from_RSAPUBLICKEYBLOB(&rsaPubKeyBlob))) {
		SKFerr(SKF_F_SKF_IMPORTRSAPRIVATEKEY, ERR_R_SKF_LIB);
		goto end;
	}
	if ((len = RSA_public_encrypt(sizeof(symmKey), symmKey, wrappedKey,
		rsa, RSA_PKCS1_PADDING)) != rsaPriKeyBlob.BitLen / 8) {
		goto end;
	}
	wrappedKeyLen = (ULONG)len;

	/* encrypt private key with symmkey in ECB mode */
	if (!(cctx = EVP_CIPHER_CTX_new())) {
		SKFerr(SKF_F_SKF_IMPORTRSAPRIVATEKEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!EVP_EncryptInit_ex(cctx, EVP_sms4_ecb(), NULL, symmKey, NULL)) {
		SKFerr(SKF_F_SKF_IMPORTRSAPRIVATEKEY, ERR_R_EVP_LIB);
		goto end;
	}
	p = encedPriKey;
	if (!EVP_EncryptUpdate(cctx, p, &len, (unsigned char *)&rsaPriKeyBlob,
		sizeof(RSAPRIVATEKEYBLOB))) {
		SKFerr(SKF_F_SKF_IMPORTRSAPRIVATEKEY, ERR_R_EVP_LIB);
		goto end;
	}
	p += len;
	if (!EVP_EncryptFinal_ex(cctx, p, &len)) {
		SKFerr(SKF_F_SKF_IMPORTRSAPRIVATEKEY, ERR_R_EVP_LIB);
		goto end;
	}
	p += len;
	encedPriKeyLen = p - encedPriKey;

	/* import */
	if ((rv = SKF_ImportRSAKeyPair(hContainer, symmAlgId, wrappedKey, wrappedKeyLen,
		encedPriKey, encedPriKeyLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_IMPORTRSAPRIVATEKEY, ERR_R_SKF_LIB);
		goto end;
	}

end:
	OPENSSL_cleanse(&rsaPriKeyBlob, sizeof(rsaPriKeyBlob));
	OPENSSL_cleanse(symmKey, sizeof(symmKey));
	OPENSSL_cleanse(wrappedKey, sizeof(wrappedKey));
	EVP_CIPHER_CTX_free(cctx);
	return rv;
}

ULONG DEVAPI SKF_ImportPrivateKey(DEVHANDLE hDev, HCONTAINER hContainer,
	EVP_PKEY *pkey, ULONG symmAlgId)
{
	ULONG rv;
	switch (EVP_PKEY_id(pkey)) {
	case EVP_PKEY_EC:
		if ((rv = SKF_ImportECCPrivateKey(hDev, hContainer,
			EVP_PKEY_get0_EC_KEY(pkey), symmAlgId)) != SAR_OK) {
			SKFerr(SKF_F_SKF_IMPORTPRIVATEKEY, ERR_R_SKF_LIB);
			return rv;
		}
		break;
	case EVP_PKEY_RSA:
		if ((rv = SKF_ImportRSAPrivateKey(hDev, hContainer,
			EVP_PKEY_get0_RSA(pkey), symmAlgId)) != SAR_OK) {
			SKFerr(SKF_F_SKF_IMPORTPRIVATEKEY, ERR_R_SKF_LIB);
			return rv;
		}
		break;
	default:
		SKFerr(SKF_F_SKF_IMPORTPRIVATEKEY,
			SKF_R_UNSUPPORTED_PRIVATE_KEY_TYPE);
		return SAR_FAIL;
	}
	return SAR_OK;
}

ULONG DEVAPI SKF_ExportECCPublicKey(HCONTAINER hContainer, BOOL bSign, EC_KEY **ec_key)
{
	ULONG rv;
	ULONG containerType;
	BYTE pubKeyBlob[sizeof(SKF_PUBLICKEYBLOB)];
	ECCPUBLICKEYBLOB *pubKey = (ECCPUBLICKEYBLOB *)pubKeyBlob;
	ULONG pubKeyLen = sizeof(SKF_PUBLICKEYBLOB);

	if ((rv = SKF_GetContainerType(hContainer, &containerType)) != SAR_OK) {
		SKFerr(SKF_F_SKF_EXPORTECCPUBLICKEY, ERR_R_SKF_LIB);
		return rv;
	}
	if (containerType != SKF_CONTAINER_TYPE_ECC) {
		SKFerr(SKF_F_SKF_EXPORTECCPUBLICKEY, SKF_R_CONTAINER_TYPE_NOT_MATCH);
		return SAR_FAIL;
	}

	if ((rv = SKF_ExportPublicKey(hContainer, bSign,
		pubKeyBlob, &pubKeyLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_EXPORTECCPUBLICKEY, ERR_R_SKF_LIB);
		return rv;
	}
	if (pubKeyLen != sizeof(ECCPUBLICKEYBLOB)) {
		SKFerr(SKF_F_SKF_EXPORTECCPUBLICKEY, ERR_R_SKF_LIB);
		return SAR_FAIL;
	}

	if (!(*ec_key = EC_KEY_new_from_ECCPUBLICKEYBLOB(pubKey))) {
		SKFerr(SKF_F_SKF_EXPORTECCPUBLICKEY, SKF_R_INVALID_ECC_PUBLIC_KEY);
		return SAR_FAIL;
	}
	return SAR_OK;
}

ULONG DEVAPI SKF_ExportRSAPublicKey(HCONTAINER hContainer, BOOL bSign, RSA **rsa)
{
	ULONG rv;
	ULONG containerType;
	BYTE pubKeyBlob[sizeof(SKF_PUBLICKEYBLOB)];
	RSAPUBLICKEYBLOB *pubKey = (RSAPUBLICKEYBLOB *)pubKeyBlob;
	ULONG pubKeyLen = sizeof(SKF_PUBLICKEYBLOB);

	if ((rv = SKF_GetContainerType(hContainer, &containerType)) != SAR_OK) {
		SKFerr(SKF_F_SKF_EXPORTRSAPUBLICKEY, ERR_R_SKF_LIB);
		return rv;
	}
	if (containerType != SKF_CONTAINER_TYPE_RSA) {
		SKFerr(SKF_F_SKF_EXPORTRSAPUBLICKEY, SKF_R_CONTAINER_TYPE_NOT_MATCH);
		return SAR_FAIL;
	}

	if ((rv = SKF_ExportPublicKey(hContainer, bSign,
		pubKeyBlob, &pubKeyLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_EXPORTRSAPUBLICKEY, ERR_R_SKF_LIB);
		return rv;
	}
	if (pubKeyLen != sizeof(RSAPUBLICKEYBLOB)) {
		SKFerr(SKF_F_SKF_EXPORTRSAPUBLICKEY, ERR_R_SKF_LIB);
		return SAR_FAIL;
	}

	if (!(*rsa = RSA_new_from_RSAPUBLICKEYBLOB(pubKey))) {
		SKFerr(SKF_F_SKF_EXPORTRSAPUBLICKEY, SKF_R_INVALID_RSA_PUBLIC_KEY);
		return SAR_FAIL;
	}
	return SAR_OK;
}

ULONG DEVAPI SKF_ExportEVPPublicKey(HCONTAINER hContainer, BOOL bSign, EVP_PKEY **pp)
{
	ULONG rv;
	ULONG containerType;
	EVP_PKEY *pkey = NULL;

	if ((rv = SKF_GetContainerType(hContainer, &containerType)) != SAR_OK) {
		SKFerr(SKF_F_SKF_EXPORTEVPPUBLICKEY, ERR_R_SKF_LIB);
		return rv;
	}

	if (!(pkey = EVP_PKEY_new())) {
		SKFerr(SKF_F_SKF_EXPORTEVPPUBLICKEY, ERR_R_MALLOC_FAILURE);
		return SAR_MEMORYERR;
	}

	if (containerType == SKF_CONTAINER_TYPE_ECC) {
		EC_KEY *ec_key = NULL;
		if ((rv = SKF_ExportECCPublicKey(hContainer, bSign,
			&ec_key)) != SAR_OK) {
			SKFerr(SKF_F_SKF_EXPORTEVPPUBLICKEY, ERR_R_SKF_LIB);
			goto end;
		}
		if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
			EC_KEY_free(ec_key);
			rv = SAR_FAIL;
			goto end;
		}

	} else if (containerType == SKF_CONTAINER_TYPE_RSA) {
		RSA *rsa = NULL;
		if ((rv = SKF_ExportRSAPublicKey(hContainer, bSign,
			&rsa)) != SAR_OK) {
			SKFerr(SKF_F_SKF_EXPORTEVPPUBLICKEY, ERR_R_SKF_LIB);
			goto end;
		}
		if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
			RSA_free(rsa);
			rv = SAR_FAIL;
			goto end;
		}

	} else {
		SKFerr(SKF_F_SKF_EXPORTEVPPUBLICKEY, SKF_R_INVALID_CONTAINER_TYPE);
		rv = SAR_FAIL;
		goto end;
	}

	*pp = pkey;
	pkey = NULL;
	rv = SAR_OK;

end:
	EVP_PKEY_free(pkey);
	return rv;
}
#endif

/*
ULONG DEVAPI SKF_ImportX509Certificate(HCONTAINER hContainer, BOOL bSign, X509 *x509)
{
	int ret = 0;
	ULONG containerType;
	unsigned char *cert = NULL;
	unsigned char *p;
	int len;

	if (SKF_GetContainerType(hContainer, &containerType) != SAR_OK) {
		return 0;
	}
	if (containerType == SKF_CONTAINER_TYPE_UNDEF) {
		return 0;
	}

	switch (EVP_PKEY_id(X509_get0_pubkey(x509))) {
	case  EVP_PKEY_EC:
		if (containerType != SKF_CONTAINER_TYPE_ECC) {
			goto end;
		}
		if (!EC_KEY_is_sm2p256v1(EVP_PKEY_get0_EC_KEY(X509_get0_pubkey(x509)))) {
			goto end;
		}
		break;

	case EVP_PKEY_RSA:
		if (containerType != SKF_CONTAINER_TYPE_RSA) {
			goto end;
		}
		break;
	default:
		goto end;
	}

	if (X509_get_key_usage(x509) & (KU_DIGITAL_SIGNATURE|
		KU_NON_REPUDIATION|KU_KEY_CERT_SIGN|KU_CRL_SIGN)) {
		bSign = SGD_TRUE;
	} else if (X509_get_key_usage(x509) & (KU_KEY_ENCIPHERMENT|
		KU_DATA_ENCIPHERMENT|KU_KEY_AGREEMENT|KU_ENCIPHER_ONLY)) {
		bSign = SGD_FALSE;
	} else {
		goto end;
	}

	if ((len = i2d_X509(x509, NULL)) <= 0
		|| !(p = cert = malloc(len))
		|| (len = i2d_X509(x509, &p)) <= 0) {
		goto end;
	}

	if (SKF_ImportCertificate(hContainer, bSign, cert, (ULONG)len) != SAR_OK) {
		goto end;
	}

	ret = 1;
end:
	X509_free(x509);
	OPENSSL_free(cert);
	return ret;
}

ULONG DEVAPI SKF_ImportX509CertificateByKeyUsage(HCONTAINER hContainer, X509 *x509)
{
	ULONG rv;
	BOOL bSign;

	if (X509_get_key_usage(x509) & (KU_DIGITAL_SIGNATURE|
		KU_NON_REPUDIATION|KU_KEY_CERT_SIGN|KU_CRL_SIGN)) {
		bSign = SGD_TRUE;
	} else if (X509_get_key_usage(x509) & (KU_KEY_ENCIPHERMENT|
		KU_DATA_ENCIPHERMENT|KU_KEY_AGREEMENT|KU_ENCIPHER_ONLY)) {
		bSign = SGD_FALSE;
	} else {
		SKFerr(SKF_F_SKF_IMPORTX509CERTIFICATEBYKEYUSAGE,
			SKF_R_UNKNOWN_CERTIFICATE_KEYUSAGE);
		return SAR_FAIL;
	}

	if ((rv = SKF_ImportX509Certificate(hContainer, bSign, x509)) != SAR_OK) {
		SKFerr(SKF_F_SKF_IMPORTX509CERTIFICATEBYKEYUSAGE, ERR_R_SKF_LIB);
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ExportX509Certificate(HCONTAINER hContainer, BOOL bSign, X509 **px509)
{
	ULONG rv = SAR_FAIL;
	BYTE *pbCert = NULL;
	ULONG ulCertLen;
	const unsigned char *p;
	X509 *x509 = NULL;

	ulCertLen = SKF_MAX_CERTIFICATE_SIZE;
	if (!(pbCert = malloc(ulCertLen))) {
		SKFerr(SKF_F_SKF_EXPORTX509CERTIFICATE, ERR_R_MALLOC_FAILURE);
		rv = SAR_MEMORYERR;
		goto end;
	}
	if ((rv = SKF_ExportCertificate(hContainer, bSign,
		pbCert, &ulCertLen)) != SAR_OK) {
		SKFerr(SKF_F_SKF_EXPORTX509CERTIFICATE, ERR_R_SKF_LIB);
		goto end;
	}

	p = pbCert;
	if (!(x509 = d2i_X509(NULL, &p, (long)ulCertLen))) {
		SKFerr(SKF_F_SKF_EXPORTX509CERTIFICATE,
			SKF_R_PARSE_CERTIFICATE_FAILURE);
		goto end;
	}
	if (p - pbCert != ulCertLen) {
		SKFerr(SKF_F_SKF_EXPORTX509CERTIFICATE,
			SKF_R_PARSE_CERTIFICATE_FAILURE);
		goto end;
	}

	*px509 = x509;
	x509 = NULL;
	rv = SAR_OK;

end:
	OPENSSL_free(pbCert);
	X509_free(x509);
	return rv;
}
*/
