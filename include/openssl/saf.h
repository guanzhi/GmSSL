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

#ifndef HEADER_SAF_H
#define HEADER_SAF_H

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_SAF

#include <openssl/sgd.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct SGD_USR_CERT_ENUMLIST_ {
	unsigned int certCount;
	unsigned char *certificate[SGD_MAX_COUNT];
	unsigned int certificateLen[SGD_MAX_COUNT];
	unsigned char *containerName[SGD_MAX_COUNT];
	unsigned int containterNameLen[SGD_MAX_COUNT];
	unsigned int keyUsage[SGD_MAX_COUNT];
} SGD_USR_CERT_ENUMLIST;

typedef struct SGD_KEYCONTAINERINFO_ENUMLIST_ {
	unsigned int keyPairCount;
	unsigned char *containerName[SGD_MAX_COUNT];
	unsigned int conatinerNameLen[SGD_MAX_COUNT];
	unsigned int keyUsage[SGD_MAX_COUNT];
	unsigned int keyType[SGD_MAX_COUNT];
} SGD_KEYCONTAINERINFO_ENUMLIST;

typedef struct {
	unsigned char dn_c[SGD_MAX_NAME_SIZE];
	unsigned char dn_c_len[1];
	unsigned char dn_s[SGD_MAX_NAME_SIZE];
	unsigned char dn_s_len[1];
	unsigned char dn_l[SGD_MAX_NAME_SIZE];
	unsigned char dn_l_len[1];
	unsigned char dn_o[5][SGD_MAX_NAME_SIZE];
	unsigned int  dn_o_len[5];
	unsigned char dn_ou[5][SGD_MAX_NAME_SIZE];
	unsigned int  dn_ou_len[5];
	unsigned char dn_cn[2][SGD_MAX_NAME_SIZE];
	unsigned int  dn_cn_len[2];
	unsigned char dn_email[2][SGD_MAX_NAME_SIZE];
	unsigned int  dn_email_len[2];
} SGD_NAME_INFO;

int SAF_Initialize(
	void **phAppHandle,
	char *pubCfgFilePath);

int SAF_Finalize(
	void *hAppHandle);

int SAF_GetVersion(
	unsigned int *puiVersion);

int SAF_Login(
	void *hAppHandle,
	unsigned int uiUsrType,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned char *pucPin,
	unsigned int uiPinLen,
	unsigned int *puiRemainCount);

int SAF_ChangePin(
	void *hAppHandle,
	unsigned int uiUsrType,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned char *pucOldPin,
	unsigned int uiOldPinLen,
	unsigned char *pucNewPin,
	unsigned int uiNewPinLen,
	unsigned int *puiRemainCount);

int SAF_Logout(
	void *hAppHandle,
	unsigned int uiUsrType);

int SAF_AddTrustedRootCaCertificate(
	void *hAppHandle,
	unsigned char *pucCertificate,
	unsigned int uiCertificateLen);

int SAF_GetRootCaCertificateCount(
	void *hAppHandle,
	unsigned int *puiCount);

int SAF_GetRootCaCertificate(
	void *hAppHandle,
	unsigned int uiIndex,
	unsigned char *pucCertificate,
	unsigned int *puiCertificateLen);

int SAF_RemoveRootCaCertificate(
	void *hAppHandle,
	unsigned int uiIndex);

int SAF_AddCaCertificate(
	void *hAppHandle,
	unsigned char *pucCertificate,
	unsigned int uiCertificateLen);

int SAF_GetCaCertificateCount(
	void *hAppHandle,
	unsigned int *puiCount);

int SAF_GetCaCertificate(
	void *hAppHandle,
	unsigned int uiIndex,
	unsigned char *pucCertificate,
	unsigned int *puiCertificateLen);

int SAF_RemoveCaCertificate(
	void *hAppHandle,
	unsigned int uiIndex);

int SAF_AddCrl(
	void *hAppHandle,
	unsigned char *pucDerCrl,
	unsigned int uiDerCrlLen);

int SAF_VerifyCertificate(
	void *hAppHandle,
	unsigned char *pucUsrCertificate,
	unsigned int uiUsrCertificateLen);

int SAF_VerifyCertificateByCrl(
	void *hAppHandle,
	unsigned char *pucUsrCertificate,
	unsigned int uiUsrCertificateLen,
	unsigned char *pucDerCrl,
	unsigned int uiDerCrlLen);

int SAF_GetCertificateStateByOCSP(
	void *hAppHandle,
	unsigned char *pcOcspHostURL,
	unsigned int uiOcspHostURLLen,
	unsigned char *pucUsrCertificate,
	unsigned int uiUsrCertificateLen,
	unsigned char *pucCACertificate,
	unsigned int uiCACertficateLen);

int SAF_GetCertFromLdap(
	void *hAppHandle,
	char *pcLdapHostURL,
	unsigned int uiLdapHostURLLen,
	unsigned char *pucQueryDN,
	unsigned int uiQueryDNLen,
	unsigned char *pucOutCert,
	unsigned int *puiOutCertLen);

int SAF_GetCrlFromLdap(
	void *hAppHandle,
	char *pcLdapHostURL,
	unsigned int uiLdapHostURLLen,
	unsigned char *pucCertificate,
	unsigned int uiCertificateLen,
	unsigned char *pucCrlData,
	unsigned int *puiCrlDataLen);

int SAF_GetCertificateInfo(
	void *hAppHandle,
	unsigned char *pucCertificate,
	unsigned int uiCertificateLen,
	unsigned int uiInfoType,
	unsigned char *pucInfo,
	unsigned int *puiInfoLen);

int SAF_GetExtTypeInfo(
	void *hAppHandle,
	unsigned char *pucDerCert,
	unsigned int uiDerCertLen,
	unsigned int uiInfoType,
	unsigned char *pucPriOid,
	unsigned int uiPriOidLen,
	unsigned char *pucInfo,
	unsigned int *puiInfoLen);

int SAF_EnumCertificates(
	void *hAppHandle,
	SGD_USR_CERT_ENUMLIST *usrCerts);

int SAF_EnumKeyContainerInfo(
	void *hAppHandle,
	SGD_KEYCONTAINERINFO_ENUMLIST *keyContainerInfo);

int SAF_EnumCertificatesFree(
	void *hAppHandle,
	SGD_USR_CERT_ENUMLIST *usrCerts);

int SAF_EnumKeyContainerInfoFree(
	void *hAppHandle,
	SGD_KEYCONTAINERINFO_ENUMLIST *keyContainerInfo);

int SAF_Base64_Encode(
	unsigned char *pucInData,
	unsigned int puiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

int SAF_Base64_Decode(
	unsigned char *pucInData,
	unsigned int puiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

int SAF_Base64_CreateBase64Obj(
	void **phBase64Obj);

int SAF_Base64_DestroyBase64Obj(
	void *hBase64Obj);

int SAF_Base64_EncodeUpdate(
	void *hBase64Obj,
	unsigned char *pucInData,
	unsigned int puiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

int SAF_Base64_EncodeFinal(
	void *hBase64Obj,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

int SAF_Base64_DecodeUpdate(
	void *hBase64Obj,
	unsigned char *pucInData,
	unsigned int puiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

int SAF_Base64_DecodeFinal(
	void *hBase64Obj,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

int SAF_GenRandom(
	unsigned int uiRandLen,
	unsigned char *pucRand);

int SAF_Hash(
	unsigned int uiAlgoType,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucPublicKey,
	unsigned int uiPublicKeyLen,
	unsigned char *pubID,
	unsigned int ulIDLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

int SAF_CreateHashObj(void **phHashObj,
	unsigned int uiAlgoType,
	unsigned char *pucPublicKey,
	unsigned int uiPublicKeyLen,
	unsigned char *pucID,
	unsigned int ulIDLen);

int SAF_DestroyHashObj(
	void *phHashObj);

int SAF_HashUpdate(
	void *phHashObj,
	const unsigned char *pucInData,
	unsigned int uiInDataLen);

int SAF_HashFinal(
	void *phHashObj,
	unsigned char *pucOutData,
	unsigned int *uiOutDataLen);

int SAF_GenRsaKeyPair(
	void *hAppHandle,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiKeyBits,
	unsigned int uiKeyUsage,
	unsigned int uiExportFlag);

int SAF_GetRsaPublicKey(
	void *hAppHandle,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiKeyUsage,
	unsigned char *pucPublicKey,
	unsigned int *puiPublicKeyLen);

int SAF_RsaSign(
	void *hAppHandle,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiHashAlgoType,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucSignature,
	unsigned int *puiSignatureLen);

int SAF_RsaSignFile(
	void *hAppHandle,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiHashAlgoType,
	unsigned char *pucFileName,
	unsigned char *pucSignature,
	unsigned int *puiSignatureLen);

int SAF_RsaVerifySign(
	unsigned int uiHashAlgoType,
	unsigned char *pucPublicKey,
	unsigned int uiPublicKeyLen,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucSignature,
	unsigned int uiSignatureLen);

int SAF_RsaVerifySignFile(
	unsigned int uiHashAlgoType,
	unsigned char *pucPublicKey,
	unsigned int uiPublicKeyLen,
	unsigned char *pucFileName,
	unsigned char *pucSignature,
	unsigned int uiSignatureLen);

int SAF_VerifySignByCert(
	unsigned int uiHashAlgoType,
	unsigned char *pucCertificate,
	unsigned int uiCertificateLen,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucSignature,
	unsigned int uiSignatureLen);

int SAF_GenEccKeyPair(
	void *hAppHandle,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiKeyBits,
	unsigned int uiKeyUsage,
	unsigned int uiExportFlag);

int SAF_GetEccPublicKey(
	void *hAppHandle,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiKeyUsage,
	unsigned char *pucPublicKey,
	unsigned int *puiPublicKeyLen);

int SAF_EccSign(
	void *hAppHandle,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiAlgorithmID,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucSignData,
	unsigned int *puiSignDataLen);

int SAF_EccVerifySign(
	unsigned char *pucPublicKey,
	unsigned int uiPublicKeyLen,
	unsigned int uiAlgorithmID,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucSignData,
	unsigned int uiSignDataLen);

int SAF_EccPublicKeyEnc(
	unsigned char *pucPublicKey,
	unsigned int uiPublicKeyLen,
	unsigned int uiAlgorithmID,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

int SAF_EccPublicKeyEncByCert(
	unsigned char *pucCertificate,
	unsigned int uiCertificateLen,
	unsigned int uiAlgorithmID,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

int SAF_EccVerifySignByCert(
	unsigned int uiAlgorithmID,
	unsigned char *pucCertificate,
	unsigned int uiCertificateLen,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucSignData,
	unsigned int uiSignDataLen);

int SAF_CreateSymmKeyObj(
	void *hAppHandle,
	void **phSymmKeyObj,
	unsigned char *pucContainerName,
	unsigned int uiContainerLen,
	unsigned char *pucIV,
	unsigned int uiIVLen,
	unsigned int uiEncOrDec,
	unsigned int uiCryptoAlgID);

int SAF_GenerateKeyWithEPK(
	void *hSymmKeyObj,
	unsigned char *pucPublicKey,
	unsigned int uiPublicKeyLen,
	unsigned char *pucSymmKey,
	unsigned int *puiSymmKeyLen,
	void **phKeyHandle);

int SAF_ImportEncedKey(
	void *hSymmKeyObj,
	unsigned char *pucSymmKey,
	unsigned int uiSymmKeyLen,
	void **phKeyHandle);

int SAF_GenerateAgreementDataWithECC(
	void *hSymmKeyObj,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiKeyBits,
	unsigned char *pucSponsorID,
	unsigned int uiSponsorIDLength,
	unsigned char *pucSponsorPublicKey,
	unsigned int *puiSponsorPublicKeyLen,
	unsigned char *pucSponsorTmpPublicKey,
	unsigned int *puiSponsorTmpPublicKeyLen,
	void **phAgreementHandle);

int SAF_GenerateKeyWithECC(
	void *phAgreementHandle,
	unsigned char *pucResponseID,
	unsigned int uiResponseIDLength,
	unsigned char *pucResponsePublicKey,
	unsigned int uiResponsePublicKeyLen,
	unsigned char *pucResponseTmpPublicKey,
	unsigned int uiResponseTmpPublicKeyLen,
	void **phKeyHandle);

int SAF_GenerateAgreementDataAdnKeyWithECC(
	void *hSymmKeyObj,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiKeyBits,
	unsigned char *pucResponseID,
	unsigned int uiResponseIDLength,
	unsigned char *pucSponsorID,
	unsigned int uiSponsorIDLength,
	unsigned char *pucSponsorPublicKey,
	unsigned int *puiSponsorPublicKeyLen,
	unsigned char *pucSponsorTmpPublicKey,
	unsigned int *puiSponsorTmpPublicKeyLen,
	unsigned char *pucResponsePublicKey,
	unsigned int uiResponsePublicKeyLen,
	unsigned char *pucResponseTmpPublicKey,
	unsigned int uiResponseTmpPublicKeyLen,
	void **phKeyHandle);

int SAF_DestroySymmAlgoObj(
	void *hSymmKeyObj);

int SAF_DestroyKeyHandle(
	void *hKeyHandle);

int SAF_SymmEncrypt(
	void *hKeyHandle,
	const unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

int SAF_SymmEncryptUpdate(
	void *hKeyHandle,
	const unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

int SAF_SymmEncryptFinal(
	void *hKeyHandle,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

int SAF_SymmDecrypt(
	void *hKeyHandle,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

int SAF_SymmDecryptUpdate(
	void *hKeyHandle,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

int SAF_SymmDecryptFinal(
	void *hKeyHandle,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

int SAF_Mac(
	void *hKeyHandle,
	const unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

int SAF_MacUpdate(
	void *hKeyHandle,
	const unsigned char *pucInData,
	unsigned int uiInDataLen);

int SAF_MacFinal(
	void *hKeyHandle,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

int SAF_Pkcs7_EncodeData(
	void *hAppHandle,
	unsigned char *pucSignContainerName,
	unsigned int uiSignContainerNameLen,
	unsigned char *pucSignerCertificate,
	unsigned int uiSignerCertificateLen,
	unsigned int uiDigestAlgorithm,
	unsigned char *pucEncCertificate,
	unsigned int uiEncCertificateLen,
	unsigned int uiSymmAlgorithm,
	unsigned char *pucData,
	unsigned int uiDataLen,
	unsigned char *pucDerP7Data,
	unsigned int *puiDerP7DataLen);

int SAF_Pkcs7_DecodeData(
	void *hAppHandle,
	unsigned char *pucDecContainerName,
	unsigned int uiDecContainerNameLen,
	unsigned char *pucDerP7Data,
	unsigned int uiDerP7DataLen,
	unsigned char *pucData,
	unsigned int *puiDataLen,
	unsigned char *pucSignerCertificate,
	unsigned int *puiSignerCertificateLen,
	unsigned int *puiDigestAlgorithm);

int SAF_Pkcs7_EncodeSignedData(
	void *hAppHandle,
	unsigned char *pucSignContainerName,
	unsigned int uiSignContainerNameLen,
	unsigned int uiSignKeyUsage,
	unsigned char *pucSignerCertificate,
	unsigned int uiSignerCertificateLen,
	unsigned int uiDigestAlgorithm,
	unsigned char *pucData,
	unsigned int uiDataLen,
	unsigned char *pucDerP7Data,
	unsigned int *puiDerP7DataLen);

int SAF_Pkcs7_DecodeSignedData(
	void *hAppHandle,
	unsigned char *pucDerP7SignedData,
	unsigned int uiDerP7SignedDataLen,
	unsigned int *puiDigestAlgorithm,
	unsigned char *pucSignerCertificate,
	unsigned int *puiSignerCertificateLen,
	unsigned char *pucData,
	unsigned int *puiDataLen,
	unsigned char *pucSig,
	unsigned int *puiSigLen);

int SAF_Pkcs7_EncodeEnvelopedData(
	void *hAppHandle,
	unsigned char *pucData,
	unsigned int uiDataLen,
	unsigned char *pucEncCertificate,
	unsigned int uiEncCertificateLen,
	unsigned int uiSymmAlgorithm,
	unsigned char *pucDerP7EnvelopedData,
	unsigned int *puiDerP7EnvelopedDataLen);

int SAF_Pkcs7_DecodeEnvelopedData(
	void *hAppHandle,
	unsigned char *pucDecContainerName,
	unsigned int uiDecContainerNameLen,
	unsigned char *pucDerP7EnvelopedData,
	unsigned int uiDerP7EnvelopedDataLen,
	unsigned char *pucData,
	unsigned int *puiDataLen);

int SAF_Pkcs7_EncodeDigestedData(
	void *hAppHandle,
	unsigned int uiDigestAlgorithm,
	unsigned char *pucData,
	unsigned int uiDataLen,
	unsigned char *pucDerP7DigestedData,
	unsigned int *puiDerP7DigestedDataLen);

int SAF_Pkcs7_DecodeDigestedData(
	void *hAppHandle,
	unsigned char *pucDerP7DigestedData,
	unsigned int uiDerP7DigestedDataLen,
	unsigned int *puiDigestAlgorithm,
	unsigned char *pucData,
	unsigned int *puiDataLen,
	unsigned char *pucDigest,
	unsigned int *puiDigestLen);

int SAF_SM2_EncodeSignedAndEnvelopedData(
	void *hAppHandle,
	unsigned char *pucSignContainerName,
	unsigned int uiSignContainerNameLen,
	unsigned char *pucSignerCertificate,
	unsigned int uiSignerCertificateLen,
	unsigned int uiDigestAlgorithm,
	unsigned char *pucEncCertificate,
	unsigned int uiEncCertificateLen,
	unsigned int uiSymmAlgorithm,
	unsigned char *pucData,
	unsigned int uiDataLen,
	unsigned char *pucDerSignedAndEnvelopedData,
	unsigned int *puiDerSignedAndEnvelopedDataLen);

int SAF_SM2_DecodeSignedAndEnvelopedData(
	void *hAppHandle,
	unsigned char *pucDerContainerName,
	unsigned int uiDerContainerNameLen,
	unsigned char *pucDerSignedAndEnvelopedData,
	unsigned int uiDerSignedAndEnvelopedDataLen,
	unsigned char *pucData,
	unsigned int *puiDataLen,
	unsigned char *pucSignerCertificate,
	unsigned int *puiSignerCertificateLen,
	unsigned int *puiDigestAlgorithm);

int SAF_SM2_EncodeSignedData(
	void *hAppHandle,
	unsigned char *pucSignContainerName,
	unsigned int uiSignContainerNameLen,
	unsigned int uiSignKeyUsage,
	unsigned char *pucSignerCertificate,
	unsigned int uiSignerCertificateLen,
	unsigned int uiDigestAlgorithm,
	unsigned char *pucData,
	unsigned int uiDataLen,
	unsigned char *pucDerSignedData,
	unsigned int *puiDerSignedDataLen);

int SAF_SM2_DecodeSignedData(
	void *hAppHandle,
	unsigned char *pucDerSignedData,
	unsigned int uiDerSignedDataLen,
	unsigned int *puiDigestAlgorithm,
	unsigned char *pucSignerCertificate,
	unsigned int *puiSignerCertificateLen,
	unsigned char *pucData,
	unsigned int *puiDataLen,
	unsigned char *pucSign,
	unsigned int *puiSignLen);

int SAF_SM2_EncodeEnvelopedData(
	void *hAppHandle,
	unsigned char *pucData,
	unsigned int uiDataLen,
	unsigned char *pucEncCertificate,
	unsigned int uiEncCertificateLen,
	unsigned int uiSymmAlgorithm,
	unsigned char *pucDerEnvelopedData,
	unsigned int *puiDerEnvelopedDataLen);

int SAF_SM2_DecodeEnvelopedData(
	void *hAppHandle,
	unsigned char *pucDecContainerName,
	unsigned int uiDecContainerNameLen,
	unsigned char *pucDerEnvelopedData,
	unsigned int uiDerEnvelopedDataLen,
	unsigned char *pucData,
	unsigned int *puiDataLen);


#define SAR_Ok			0x00000000
#define SAR_UnknownErr		0x02000001
#define SAR_NotSupportYetErr	0x02000002
#define SAR_FileErr		0x02000003
#define SAR_ProviderTypeErr	0x02000004
#define SAR_LoadProviderErr	0x02000005
#define SAR_LoadDevMngApiErr	0x02000006
#define SAR_AlgoTypeErr		0x02000007
#define SAR_NameLenErr		0x02000008
#define SAR_KeyUsageErr		0x02000009
#define SAR_ModulusLenErr	0x02000010
#define SAR_NotInitializeErr	0x02000011
#define SAR_ObjErr		0x02000012
#define SAR_MemoryErr		0x02000100
#define SAR_TimeoutErr		0x02000101
#define SAR_IndataLenErr	0x02000200
#define SAR_IndataErr		0x02000201
#define SAR_GenRandErr		0x02000300
#define SAR_HashObjErr		0x02000301
#define SAR_HashErr		0x02000302
#define SAR_GenRsaKeyErr	0x02000303
#define SAR_RsaModulusLenErr	0x02000304
#define SAR_CspImportPubKeyErr	0x02000305
#define SAR_RsaEncErr		0x02000306
#define SAR_RsaDecErr		0x02000307
#define SAR_HashNotEqualErr	0x02000308
#define SAR_KeyNotFoundErr	0x02000309
#define SAR_CertNotFoundErr	0x02000310
#define SAR_NotExportErr	0x02000311
#define SAR_CertRevokedErr	0x02000316
#define SAR_CertNotYetValidErr	0x02000317
#define SAR_CerthashExpiredErr	0x02000318
#define SAR_CertVerifyErr	0x02000319
#define SAR_CertEncodeErr	0x02000320
#define SAR_DecryptPadErr	0x02000400
#define SAR_MacLenErr		0x02000401
#define SAR_KeyInfoTypeErr	0x02000402
#define SAR_NotLogin		0x02000403


#ifdef __cplusplus
}
#endif
#endif
#endif
