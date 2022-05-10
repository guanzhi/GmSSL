/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/gmsdf.h>

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_SDF,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_SDF,0,reason)

static ERR_STRING_DATA SDF_str_functs[] = {
    {ERR_FUNC(SDF_F_SANSEC_DECODE_ECCCIPHER), "sansec_decode_ecccipher"},
    {ERR_FUNC(SDF_F_SANSEC_ENCODE_ECCCIPHER), "sansec_encode_ecccipher"},
    {ERR_FUNC(SDF_F_SDF_CALCULATEMAC), "SDF_CalculateMAC"},
    {ERR_FUNC(SDF_F_SDF_CLOSEDEVICE), "SDF_CloseDevice"},
    {ERR_FUNC(SDF_F_SDF_CLOSESESSION), "SDF_CloseSession"},
    {ERR_FUNC(SDF_F_SDF_CREATEFILE), "SDF_CreateFile"},
    {ERR_FUNC(SDF_F_SDF_DECRYPT), "SDF_Decrypt"},
    {ERR_FUNC(SDF_F_SDF_DELETEFILE), "SDF_DeleteFile"},
    {ERR_FUNC(SDF_F_SDF_DESTROYKEY), "SDF_DestroyKey"},
    {ERR_FUNC(SDF_F_SDF_ENCRYPT), "SDF_Encrypt"},
    {ERR_FUNC(SDF_F_SDF_EXCHANGEDIGITENVELOPEBASEONECC),
     "SDF_ExchangeDigitEnvelopeBaseOnECC"},
    {ERR_FUNC(SDF_F_SDF_EXCHANGEDIGITENVELOPEBASEONRSA),
     "SDF_ExchangeDigitEnvelopeBaseOnRSA"},
    {ERR_FUNC(SDF_F_SDF_EXPORTENCPUBLICKEY_ECC),
     "SDF_ExportEncPublicKey_ECC"},
    {ERR_FUNC(SDF_F_SDF_EXPORTENCPUBLICKEY_RSA),
     "SDF_ExportEncPublicKey_RSA"},
    {ERR_FUNC(SDF_F_SDF_EXPORTSIGNPUBLICKEY_ECC),
     "SDF_ExportSignPublicKey_ECC"},
    {ERR_FUNC(SDF_F_SDF_EXPORTSIGNPUBLICKEY_RSA),
     "SDF_ExportSignPublicKey_RSA"},
    {ERR_FUNC(SDF_F_SDF_EXTERNALENCRYPT_ECC), "SDF_ExternalEncrypt_ECC"},
    {ERR_FUNC(SDF_F_SDF_EXTERNALPUBLICKEYOPERATION_RSA),
     "SDF_ExternalPublicKeyOperation_RSA"},
    {ERR_FUNC(SDF_F_SDF_EXTERNALVERIFY_ECC), "SDF_ExternalVerify_ECC"},
    {ERR_FUNC(SDF_F_SDF_GENERATEAGREEMENTDATAANDKEYWITHECC),
     "SDF_GenerateAgreementDataAndKeyWithECC"},
    {ERR_FUNC(SDF_F_SDF_GENERATEAGREEMENTDATAWITHECC),
     "SDF_GenerateAgreementDataWithECC"},
    {ERR_FUNC(SDF_F_SDF_GENERATEKEYPAIR_ECC), "SDF_GenerateKeyPair_ECC"},
    {ERR_FUNC(SDF_F_SDF_GENERATEKEYPAIR_RSA), "SDF_GenerateKeyPair_RSA"},
    {ERR_FUNC(SDF_F_SDF_GENERATEKEYWITHECC), "SDF_GenerateKeyWithECC"},
    {ERR_FUNC(SDF_F_SDF_GENERATEKEYWITHEPK_ECC),
     "SDF_GenerateKeyWithEPK_ECC"},
    {ERR_FUNC(SDF_F_SDF_GENERATEKEYWITHEPK_RSA),
     "SDF_GenerateKeyWithEPK_RSA"},
    {ERR_FUNC(SDF_F_SDF_GENERATEKEYWITHIPK_ECC),
     "SDF_GenerateKeyWithIPK_ECC"},
    {ERR_FUNC(SDF_F_SDF_GENERATEKEYWITHIPK_RSA),
     "SDF_GenerateKeyWithIPK_RSA"},
    {ERR_FUNC(SDF_F_SDF_GENERATEKEYWITHKEK), "SDF_GenerateKeyWithKEK"},
    {ERR_FUNC(SDF_F_SDF_GENERATERANDOM), "SDF_GenerateRandom"},
    {ERR_FUNC(SDF_F_SDF_GETDEVICEINFO), "SDF_GetDeviceInfo"},
    {ERR_FUNC(SDF_F_SDF_GETPRIVATEKEYACCESSRIGHT),
     "SDF_GetPrivateKeyAccessRight"},
    {ERR_FUNC(SDF_F_SDF_HASHFINAL), "SDF_HashFinal"},
    {ERR_FUNC(SDF_F_SDF_HASHINIT), "SDF_HashInit"},
    {ERR_FUNC(SDF_F_SDF_HASHUPDATE), "SDF_HashUpdate"},
    {ERR_FUNC(SDF_F_SDF_IMPORTKEY), "SDF_ImportKey"},
    {ERR_FUNC(SDF_F_SDF_IMPORTKEYWITHISK_ECC), "SDF_ImportKeyWithISK_ECC"},
    {ERR_FUNC(SDF_F_SDF_IMPORTKEYWITHISK_RSA), "SDF_ImportKeyWithISK_RSA"},
    {ERR_FUNC(SDF_F_SDF_IMPORTKEYWITHKEK), "SDF_ImportKeyWithKEK"},
    {ERR_FUNC(SDF_F_SDF_INTERNALDECRYPT_ECC), "SDF_InternalDecrypt_ECC"},
    {ERR_FUNC(SDF_F_SDF_INTERNALENCRYPT_ECC), "SDF_InternalEncrypt_ECC"},
    {ERR_FUNC(SDF_F_SDF_INTERNALPRIVATEKEYOPERATION_RSA),
     "SDF_InternalPrivateKeyOperation_RSA"},
    {ERR_FUNC(SDF_F_SDF_INTERNALPUBLICKEYOPERATION_RSA),
     "SDF_InternalPublicKeyOperation_RSA"},
    {ERR_FUNC(SDF_F_SDF_INTERNALSIGN_ECC), "SDF_InternalSign_ECC"},
    {ERR_FUNC(SDF_F_SDF_INTERNALVERIFY_ECC), "SDF_InternalVerify_ECC"},
    {ERR_FUNC(SDF_F_SDF_LOADLIBRARY), "SDF_LoadLibrary"},
    {ERR_FUNC(SDF_F_SDF_METHOD_LOAD_LIBRARY), "SDF_METHOD_load_library"},
    {ERR_FUNC(SDF_F_SDF_NEWECCCIPHER), "SDF_NewECCCipher"},
    {ERR_FUNC(SDF_F_SDF_OPENDEVICE), "SDF_OpenDevice"},
    {ERR_FUNC(SDF_F_SDF_OPENSESSION), "SDF_OpenSession"},
    {ERR_FUNC(SDF_F_SDF_READFILE), "SDF_ReadFile"},
    {ERR_FUNC(SDF_F_SDF_RELEASEPRIVATEKEYACCESSRIGHT),
     "SDF_ReleasePrivateKeyAccessRight"},
    {ERR_FUNC(SDF_F_SDF_WRITEFILE), "SDF_WriteFile"},
    {0, NULL}
};

static ERR_STRING_DATA SDF_str_reasons[] = {
    {ERR_REASON(SDF_R_ALGORITHM_MODE_NOT_SUPPORTED),
     "algorithm mode not supported"},
    {ERR_REASON(SDF_R_ALGORITHM_NOT_SUPPORTED), "algorithm not supported"},
    {ERR_REASON(SDF_R_BUFFER_TOO_SMALL), "buffer too small"},
    {ERR_REASON(SDF_R_COMMUNICATION_FAILURE), "communication failure"},
    {ERR_REASON(SDF_R_DSO_LOAD_FAILURE), "dso load failure"},
    {ERR_REASON(SDF_R_ENCRYPT_DATA_ERROR), "encrypt data error"},
    {ERR_REASON(SDF_R_ERROR), "error"},
    {ERR_REASON(SDF_R_FILE_ALREADY_EXIST), "file already exist"},
    {ERR_REASON(SDF_R_FILE_NOT_EXIST), "file not exist"},
    {ERR_REASON(SDF_R_HARDWARE_ERROR), "hardware error"},
    {ERR_REASON(SDF_R_INVALID_FILE_OFFSET), "invalid file offset"},
    {ERR_REASON(SDF_R_INVALID_FILE_SIZE), "invalid file size"},
    {ERR_REASON(SDF_R_INVALID_INPUT_ARGUMENT), "invalid input argument"},
    {ERR_REASON(SDF_R_INVALID_KEY), "invalid key"},
    {ERR_REASON(SDF_R_INVALID_KEY_TYPE), "invalid key type"},
    {ERR_REASON(SDF_R_INVALID_OUTPUT_ARGUMENT), "invalid output argument"},
    {ERR_REASON(SDF_R_INVALID_SANSEC_ECCCIPHER_LENGTH),
     "invalid sansec ecccipher length"},
    {ERR_REASON(SDF_R_INVALID_SM2_CIPHERTEXT_LENGTH),
     "invalid sm2 ciphertext length"},
    {ERR_REASON(SDF_R_KEY_NOT_EXIST), "key not exist"},
    {ERR_REASON(SDF_R_LOAD_LIBRARY_FAILURE), "load library failure"},
    {ERR_REASON(SDF_R_MAC_ERROR), "mac error"},
    {ERR_REASON(SDF_R_MULTI_STEP_OPERATION_ERROR),
     "multi step operation error"},
    {ERR_REASON(SDF_R_NOT_IMPLEMENTED), "not implemented"},
    {ERR_REASON(SDF_R_NOT_INITIALIZED), "not initialized"},
    {ERR_REASON(SDF_R_NOT_SUPPORTED_CIPHER_ALGOR),
     "not supported cipher algor"},
    {ERR_REASON(SDF_R_NOT_SUPPORTED_DIGEST_ALGOR),
     "not supported digest algor"},
    {ERR_REASON(SDF_R_NOT_SUPPORTED_ECC_ALGOR), "not supported ecc algor"},
    {ERR_REASON(SDF_R_NOT_SUPPORTED_PKEY_ALGOR), "not supported pkey algor"},
    {ERR_REASON(SDF_R_NO_PRIVATE_KEY_ACCESS_RIGHT),
     "no private key access right"},
    {ERR_REASON(SDF_R_OPEN_DEVICE_FAILURE), "open device failure"},
    {ERR_REASON(SDF_R_OPEN_SESSION_FAILURE), "open session failure"},
    {ERR_REASON(SDF_R_OPERATION_NOT_SUPPORTED), "operation not supported"},
    {ERR_REASON(SDF_R_PRIVATE_KEY_OPERATION_FAILURE),
     "private key operation failure"},
    {ERR_REASON(SDF_R_PRKERR), "prkerr"},
    {ERR_REASON(SDF_R_PUBLIC_KEY_OPERATION_FAILURE),
     "public key operation failure"},
    {ERR_REASON(SDF_R_RANDOM_GENERATION_ERROR), "random generation error"},
    {ERR_REASON(SDF_R_SANSEC_BASE), "sansec base"},
    {ERR_REASON(SDF_R_SANSEC_CARD_ALGOR_NOT_SUPPORTED),
     "sansec card algor not supported"},
    {ERR_REASON(SDF_R_SANSEC_CARD_ALG_MODE_NOT_SUPPORTED),
     "sansec card alg mode not supported"},
    {ERR_REASON(SDF_R_SANSEC_CARD_BASE), "sansec card base"},
    {ERR_REASON(SDF_R_SANSEC_CARD_BUFFER_TOO_SMALL),
     "sansec card buffer too small"},
    {ERR_REASON(SDF_R_SANSEC_CARD_COMMMUCATION_FAILED),
     "sansec card commmucation failed"},
    {ERR_REASON(SDF_R_SANSEC_CARD_CRYPTO_NOT_INITED),
     "sansec card crypto not inited"},
    {ERR_REASON(SDF_R_SANSEC_CARD_DATA_PADDING_ERROR),
     "sansec card data padding error"},
    {ERR_REASON(SDF_R_SANSEC_CARD_DATA_SIZE), "sansec card data size"},
    {ERR_REASON(SDF_R_SANSEC_CARD_DEVICE_STATUS_ERROR),
     "sansec card device status error"},
    {ERR_REASON(SDF_R_SANSEC_CARD_DEVICE_STATUS_ERROR_05),
     "sansec card device status error 05"},
    {ERR_REASON(SDF_R_SANSEC_CARD_FILE_NOT_EXIST),
     "sansec card file not exist"},
    {ERR_REASON(SDF_R_SANSEC_CARD_FILE_OFFSET_ERROR),
     "sansec card file offset error"},
    {ERR_REASON(SDF_R_SANSEC_CARD_FILE_SIZE_ERROR),
     "sansec card file size error"},
    {ERR_REASON(SDF_R_SANSEC_CARD_HARDWARE_FAILURE),
     "sansec card hardware failure"},
    {ERR_REASON(SDF_R_SANSEC_CARD_KEY_ERROR), "sansec card key error"},
    {ERR_REASON(SDF_R_SANSEC_CARD_KEY_NOT_EXIST),
     "sansec card key not exist"},
    {ERR_REASON(SDF_R_SANSEC_CARD_KEY_TYPE_ERROR),
     "sansec card key type error"},
    {ERR_REASON(SDF_R_SANSEC_CARD_LOGIN_ERROR), "sansec card login error"},
    {ERR_REASON(SDF_R_SANSEC_CARD_LOGIN_ERROR_05),
     "sansec card login error 05"},
    {ERR_REASON(SDF_R_SANSEC_CARD_MANAGEMENT_DENYED),
     "sansec card management denyed"},
    {ERR_REASON(SDF_R_SANSEC_CARD_MANAGEMENT_DENYED_05),
     "sansec card management denyed 05"},
    {ERR_REASON(SDF_R_SANSEC_CARD_NOT_SUPPORTED),
     "sansec card not supported"},
    {ERR_REASON(SDF_R_SANSEC_CARD_OPEN_DEVICE_FAILED),
     "sansec card open device failed"},
    {ERR_REASON(SDF_R_SANSEC_CARD_OPEN_SESSION_FAILED),
     "sansec card open session failed"},
    {ERR_REASON(SDF_R_SANSEC_CARD_OPERATION_DENYED),
     "sansec card operation denyed"},
    {ERR_REASON(SDF_R_SANSEC_CARD_OPERATION_DENYED_05),
     "sansec card operation denyed 05"},
    {ERR_REASON(SDF_R_SANSEC_CARD_PARAMENT_ERROR),
     "sansec card parament error"},
    {ERR_REASON(SDF_R_SANSEC_CARD_PARAMENT_ERROR_05),
     "sansec card parament error 05"},
    {ERR_REASON(SDF_R_SANSEC_CARD_PRIVATE_KEY_ACCESS_DENYED),
     "sansec card private key access denyed"},
    {ERR_REASON(SDF_R_SANSEC_CARD_PRIVATE_KEY_OPERATION_ERROR),
     "sansec card private key operation error"},
    {ERR_REASON(SDF_R_SANSEC_CARD_PUBLIC_KEY_OPERATION_ERROR),
     "sansec card public key operation error"},
    {ERR_REASON(SDF_R_SANSEC_CARD_READER_BASE), "sansec card reader base"},
    {ERR_REASON(SDF_R_SANSEC_CARD_READER_CARD_INSERT),
     "sansec card reader card insert"},
    {ERR_REASON(SDF_R_SANSEC_CARD_READER_CARD_INSERT_TYPE),
     "sansec card reader card insert type"},
    {ERR_REASON(SDF_R_SANSEC_CARD_READER_NO_CARD),
     "sansec card reader no card"},
    {ERR_REASON(SDF_R_SANSEC_CARD_READER_PIN_ERROR),
     "sansec card reader pin error"},
    {ERR_REASON(SDF_R_SANSEC_CARD_SIGN_ERROR), "sansec card sign error"},
    {ERR_REASON(SDF_R_SANSEC_CARD_STEP_ERROR), "sansec card step error"},
    {ERR_REASON(SDF_R_SANSEC_CARD_SYMMETRIC_ALGOR_ERROR),
     "sansec card symmetric algor error"},
    {ERR_REASON(SDF_R_SANSEC_CARD_UNKNOW_ERROR), "sansec card unknow error"},
    {ERR_REASON(SDF_R_SANSEC_CARD_USERID_ERROR), "sansec card userid error"},
    {ERR_REASON(SDF_R_SANSEC_CARD_USERID_ERROR_05),
     "sansec card userid error 05"},
    {ERR_REASON(SDF_R_SANSEC_CARD_VERIFY_ERROR), "sansec card verify error"},
    {ERR_REASON(SDF_R_SANSEC_CONFIG_ERROR), "sansec config error"},
    {ERR_REASON(SDF_R_SANSEC_CONNECT_ERROR), "sansec connect error"},
    {ERR_REASON(SDF_R_SANSEC_FILE_ALREADY_EXIST),
     "sansec file already exist"},
    {ERR_REASON(SDF_R_SANSEC_INVALID_AUTHENCODE),
     "sansec invalid authencode"},
    {ERR_REASON(SDF_R_SANSEC_INVALID_COMMAND), "sansec invalid command"},
    {ERR_REASON(SDF_R_SANSEC_INVALID_PARAMETERS),
     "sansec invalid parameters"},
    {ERR_REASON(SDF_R_SANSEC_INVALID_USER), "sansec invalid user"},
    {ERR_REASON(SDF_R_SANSEC_NO_AVAILABLE_CSM), "sansec no available csm"},
    {ERR_REASON(SDF_R_SANSEC_NO_AVAILABLE_HSM), "sansec no available hsm"},
    {ERR_REASON(SDF_R_SANSEC_PROTOCOL_VERSION_ERROR),
     "sansec protocol version error"},
    {ERR_REASON(SDF_R_SANSEC_SEM_TIMEOUT), "sansec sem timeout"},
    {ERR_REASON(SDF_R_SANSEC_SET_SOCKET_OPTION_ERROR),
     "sansec set socket option error"},
    {ERR_REASON(SDF_R_SANSEC_SOCKET_RECV_0), "sansec socket recv 0"},
    {ERR_REASON(SDF_R_SANSEC_SOCKET_RECV_ERROR), "sansec socket recv error"},
    {ERR_REASON(SDF_R_SANSEC_SOCKET_SEND_ERROR), "sansec socket send error"},
    {ERR_REASON(SDF_R_SANSEC_SOCKET_TIMEOUT), "sansec socket timeout"},
    {ERR_REASON(SDF_R_SANSEC_SYNC_ERROR), "sansec sync error"},
    {ERR_REASON(SDF_R_SANSEC_SYNC_LOGIN_ERROR), "sansec sync login error"},
    {ERR_REASON(SDF_R_SIGNING_FAILURE), "signing failure"},
    {ERR_REASON(SDF_R_SUCCESS), "success"},
    {ERR_REASON(SDF_R_SYMMETRIC_OPERATION_FAILURE),
     "symmetric operation failure"},
    {ERR_REASON(SDF_R_UNNOWN_ERROR), "unnown error"},
    {ERR_REASON(SDF_R_VERIFICATION_FAILURE), "verification failure"},
    {ERR_REASON(SDF_R_WRITE_FILE_FAILURE), "write file failure"},
    {0, NULL}
};

#endif

int ERR_load_SDF_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(SDF_str_functs[0].error) == NULL) {
        ERR_load_strings(0, SDF_str_functs);
        ERR_load_strings(0, SDF_str_reasons);
    }
#endif
    return 1;
}