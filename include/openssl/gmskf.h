/* ====================================================================
 * Copyright (c) 2015 - 2016 The GmSSL Project.  All rights reserved.
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

#ifndef HEADER_GMSKF_H
#define HEADER_GMSKF_H

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_SKF

#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/sgd.h>
#include <openssl/skf.h>

#define SKF_NO_PADDING		0
#define SKF_PKCS5_PADDING	1

#define SKF_DEV_STATE_ABSENT	0x00000000
#define SKF_DEV_STATE_PRESENT	0x00000001
#define SKF_DEV_STATE_UNKNOW	0x00000010

#define SKF_CONTAINER_TYPE_UNDEF	0
#define SKF_CONTAINER_TYPE_RSA		1
#define SKF_CONTAINER_TYPE_ECC		2

#define SKF_ENVELOPEDKEYBLOB_VERSION	1
#define SKF_AUTHKEY_LENGTH		16
#define SKF_AUTHRAND_LENGTH		16
#define SKF_MAX_FILE_SIZE		(256*1024)
#define SKF_MAX_CERTIFICATE_SIZE	(8*1024)


#define SKF_DEFAULT_ADMIN_PIN_RETRY_COUNT	6
#define SKF_DEFAULT_USER_PIN_RETRY_COUNT	6

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	union {
		ECCPUBLICKEYBLOB ecc;
		RSAPUBLICKEYBLOB rsa;
	} u;
} SKF_PUBLICKEYBLOB;
#define SKF_MAX_PUBLICKEYBOLB_LENGTH sizeof(SKF_PUBLICKEYBLOB)

typedef struct {
	char *name;
	unsigned char *buf;
	int offset;
	int length;
} SKF_FILE_OP_PARAMS;


ULONG DEVAPI SKF_LoadLibrary(LPSTR so_path, LPSTR vendor);
ULONG DEVAPI SKF_UnloadLibrary(void);
ULONG DEVAPI SKF_OpenDevice(LPSTR devName, BYTE authKey[16], DEVINFO *devInfo, DEVHANDLE *phDev);
ULONG DEVAPI SKF_CloseDevice(DEVHANDLE hDev);
ULONG DEVAPI SKF_GetDevStateName(ULONG ulDevState, LPSTR *szName);
ULONG DEVAPI SKF_GetContainerTypeName(ULONG ulContainerType, LPSTR *szName);
ULONG DEVAPI SKF_GetAlgorName(ULONG ulAlgID, LPSTR *szName);
ULONG DEVAPI SKF_PrintDevInfo(BIO *out, DEVINFO *devInfo);
ULONG DEVAPI SKF_PrintRSAPublicKey(BIO *out, RSAPUBLICKEYBLOB *blob);
ULONG DEVAPI SKF_PrintRSAPrivateKey(BIO *out, RSAPRIVATEKEYBLOB *blob);
ULONG DEVAPI SKF_PrintECCPublicKey(BIO *out, ECCPUBLICKEYBLOB *blob);
ULONG DEVAPI SKF_PrintECCPrivateKey(BIO *out, ECCPRIVATEKEYBLOB *blob);
ULONG DEVAPI SKF_PrintECCCipher(BIO *out, ECCCIPHERBLOB *blob);
ULONG DEVAPI SKF_PrintECCSignature(BIO *out, ECCSIGNATUREBLOB *blob);
ULONG DEVAPI SKF_GetErrorString(ULONG ulError, LPSTR *szErrorStr);
ULONG DEVAPI SKF_NewECCCipher(ULONG ulCipherLen, ECCCIPHERBLOB **cipherBlob);
ULONG DEVAPI SKF_NewEnvelopedKey(ULONG ulCipherLen, ENVELOPEDKEYBLOB **envelopedKeyBlob);
ULONG DEVAPI SKF_ImportECCPrivateKey(DEVHANDLE hDev, HCONTAINER hContainer, EC_KEY *ec_key, ULONG symmAlgId);
ULONG DEVAPI SKF_ImportRSAPrivateKey(DEVHANDLE hDev, HCONTAINER hContainer, RSA *rsa, ULONG symmAlgId);
ULONG DEVAPI SKF_ImportPrivateKey(DEVHANDLE hDev, HCONTAINER hContainer, EVP_PKEY *pkey, ULONG symmAlgId);
ULONG DEVAPI SKF_ExportECCPublicKey(HCONTAINER hContainer, BOOL bSign, EC_KEY **pp);
ULONG DEVAPI SKF_ExportRSAPublicKey(HCONTAINER hContainer, BOOL bSign, RSA **pp);
ULONG DEVAPI SKF_ExportEVPPublicKey(HCONTAINER hContainer, BOOL bSign, EVP_PKEY **pp);
ULONG DEVAPI SKF_ImportX509CertificateByKeyUsage(HCONTAINER hContainer, X509 *x509);
ULONG DEVAPI SKF_ImportX509Certificate(HCONTAINER hContainer, BOOL bSign, X509 *x509);
ULONG DEVAPI SKF_ExportX509Certificate(HCONTAINER hContainer, BOOL bSign, X509 **px509);


/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

int ERR_load_SKF_strings(void);

/* Error codes for the SKF functions. */

/* Function codes. */
# define SKF_F_SKF_CANCELWAITFORDEVEVENT                  100
# define SKF_F_SKF_CHANGEDEVAUTHKEY                       101
# define SKF_F_SKF_CHANGEPIN                              102
# define SKF_F_SKF_CLEARSECURESTATE                       103
# define SKF_F_SKF_CLOSEAPPLICATION                       104
# define SKF_F_SKF_CLOSECONTAINER                         105
# define SKF_F_SKF_CLOSEDEVICE                            106
# define SKF_F_SKF_CLOSEHANDLE                            107
# define SKF_F_SKF_CONNECTDEV                             108
# define SKF_F_SKF_CREATEAPPLICATION                      109
# define SKF_F_SKF_CREATECONTAINER                        110
# define SKF_F_SKF_CREATEFILE                             111
# define SKF_F_SKF_DECRYPT                                112
# define SKF_F_SKF_DECRYPTFINAL                           113
# define SKF_F_SKF_DECRYPTINIT                            114
# define SKF_F_SKF_DECRYPTUPDATE                          115
# define SKF_F_SKF_DELETEAPPLICATION                      116
# define SKF_F_SKF_DELETECONTAINER                        117
# define SKF_F_SKF_DELETEFILE                             118
# define SKF_F_SKF_DEVAUTH                                119
# define SKF_F_SKF_DIGEST                                 120
# define SKF_F_SKF_DIGESTFINAL                            121
# define SKF_F_SKF_DIGESTINIT                             122
# define SKF_F_SKF_DIGESTUPDATE                           123
# define SKF_F_SKF_DISCONNECTDEV                          124
# define SKF_F_SKF_ECCDECRYPT                             125
# define SKF_F_SKF_ECCEXPORTSESSIONKEY                    126
# define SKF_F_SKF_ECCSIGNDATA                            127
# define SKF_F_SKF_ECCVERIFY                              128
# define SKF_F_SKF_ENCRYPT                                129
# define SKF_F_SKF_ENCRYPTFINAL                           130
# define SKF_F_SKF_ENCRYPTINIT                            131
# define SKF_F_SKF_ENCRYPTUPDATE                          132
# define SKF_F_SKF_ENUMAPPLICATION                        133
# define SKF_F_SKF_ENUMCONTAINER                          134
# define SKF_F_SKF_ENUMDEV                                135
# define SKF_F_SKF_ENUMFILES                              136
# define SKF_F_SKF_EXPORTCERTIFICATE                      137
# define SKF_F_SKF_EXPORTECCPUBLICKEY                     138
# define SKF_F_SKF_EXPORTEVPPUBLICKEY                     139
# define SKF_F_SKF_EXPORTPUBLICKEY                        140
# define SKF_F_SKF_EXPORTRSAPUBLICKEY                     141
# define SKF_F_SKF_EXPORTX509CERTIFICATE                  142
# define SKF_F_SKF_EXTECCDECRYPT                          143
# define SKF_F_SKF_EXTECCENCRYPT                          144
# define SKF_F_SKF_EXTECCSIGN                             145
# define SKF_F_SKF_EXTECCVERIFY                           146
# define SKF_F_SKF_EXTRSAPRIKEYOPERATION                  147
# define SKF_F_SKF_EXTRSAPUBKEYOPERATION                  148
# define SKF_F_SKF_GENECCKEYPAIR                          149
# define SKF_F_SKF_GENERATEAGREEMENTDATAANDKEYWITHECC     150
# define SKF_F_SKF_GENERATEAGREEMENTDATAWITHECC           151
# define SKF_F_SKF_GENERATEKEYWITHECC                     152
# define SKF_F_SKF_GENEXTRSAKEY                           153
# define SKF_F_SKF_GENRANDOM                              154
# define SKF_F_SKF_GENRSAKEYPAIR                          155
# define SKF_F_SKF_GETCONTAINERTYPE                       156
# define SKF_F_SKF_GETDEVINFO                             157
# define SKF_F_SKF_GETDEVSTATE                            158
# define SKF_F_SKF_GETFILEINFO                            159
# define SKF_F_SKF_GETPININFO                             160
# define SKF_F_SKF_IMPORTCERTIFICATE                      161
# define SKF_F_SKF_IMPORTECCKEYPAIR                       162
# define SKF_F_SKF_IMPORTECCPRIVATEKEY                    163
# define SKF_F_SKF_IMPORTPRIVATEKEY                       164
# define SKF_F_SKF_IMPORTRSAKEYPAIR                       165
# define SKF_F_SKF_IMPORTRSAPRIVATEKEY                    166
# define SKF_F_SKF_IMPORTSESSIONKEY                       167
# define SKF_F_SKF_IMPORTX509CERTIFICATEBYKEYUSAGE        168
# define SKF_F_SKF_LOADLIBRARY                            169
# define SKF_F_SKF_LOCKDEV                                170
# define SKF_F_SKF_MAC                                    171
# define SKF_F_SKF_MACFINAL                               172
# define SKF_F_SKF_MACINIT                                173
# define SKF_F_SKF_MACUPDATE                              174
# define SKF_F_SKF_METHOD_LOAD_LIBRARY                    175
# define SKF_F_SKF_NEWECCCIPHER                           176
# define SKF_F_SKF_NEWENVELOPEDKEY                        177
# define SKF_F_SKF_OPENAPPLICATION                        178
# define SKF_F_SKF_OPENCONTAINER                          179
# define SKF_F_SKF_OPENDEVICE                             180
# define SKF_F_SKF_READFILE                               181
# define SKF_F_SKF_RSAEXPORTSESSIONKEY                    182
# define SKF_F_SKF_RSASIGNDATA                            183
# define SKF_F_SKF_RSAVERIFY                              184
# define SKF_F_SKF_SETLABEL                               185
# define SKF_F_SKF_SETSYMMKEY                             186
# define SKF_F_SKF_TRANSMIT                               187
# define SKF_F_SKF_UNBLOCKPIN                             188
# define SKF_F_SKF_UNLOCKDEV                              189
# define SKF_F_SKF_VERIFYPIN                              190
# define SKF_F_SKF_WAITFORDEVEVENT                        191
# define SKF_F_SKF_WRITEFILE                              192

/* Reason codes. */
# define SKF_R_APPLICATION_ALREADY_EXIST                  100
# define SKF_R_APPLICATION_NOT_EXIST                      101
# define SKF_R_BUFFER_TOO_SMALL                           102
# define SKF_R_CERTIFICATE_NOT_FOUND                      103
# define SKF_R_CONTAINER_TYPE_NOT_MATCH                   104
# define SKF_R_CSP_IMPORT_PUBLIC_KEY_ERROR                105
# define SKF_R_DECRYPT_INVALID_PADDING                    106
# define SKF_R_DEVICE_REMOVED                             107
# define SKF_R_DIGEST_ERROR                               108
# define SKF_R_DSO_LOAD_FAILURE                           109
# define SKF_R_EXPORT_FAILED                              110
# define SKF_R_FAILURE                                    111
# define SKF_R_FILE_ALREADY_EXIST                         112
# define SKF_R_FILE_ERROR                                 113
# define SKF_R_FILE_NOT_EXIST                             114
# define SKF_R_FUNCTION_NOT_SUPPORTED                     115
# define SKF_R_HASH_NOT_EQUAL                             116
# define SKF_R_INVALID_APPLICATION_NAME                   117
# define SKF_R_INVALID_CONTAINER_TYPE                     118
# define SKF_R_INVALID_DIGEST_HANDLE                      119
# define SKF_R_INVALID_ECC_PUBLIC_KEY                     120
# define SKF_R_INVALID_HANDLE                             121
# define SKF_R_INVALID_INPUT_LENGTH                       122
# define SKF_R_INVALID_INPUT_VALUE                        123
# define SKF_R_INVALID_KEY_INFO_TYPE                      124
# define SKF_R_INVALID_KEY_USAGE                          125
# define SKF_R_INVALID_MAC_LENGTH                         126
# define SKF_R_INVALID_MODULUS_LENGTH                     127
# define SKF_R_INVALID_NAME_LENGTH                        128
# define SKF_R_INVALID_OBJECT                             129
# define SKF_R_INVALID_PARAMETER                          130
# define SKF_R_INVALID_PIN                                131
# define SKF_R_INVALID_PIN_LENGTH                         132
# define SKF_R_INVALID_RSA_MODULUS_LENGTH                 133
# define SKF_R_INVALID_RSA_PUBLIC_KEY                     134
# define SKF_R_INVALID_USER_TYPE                          135
# define SKF_R_KEY_NOT_FOUND                              136
# define SKF_R_LOAD_LIBRARY_FAILURE                       137
# define SKF_R_MEMORY_ERROR                               138
# define SKF_R_NOT_INITIALIZED                            139
# define SKF_R_NOT_SUPPORTED_CIPHER_ALGOR                 140
# define SKF_R_NOT_SUPPORTED_DIGEST_ALGOR                 141
# define SKF_R_NOT_SUPPORTED_PKEY_ALGOR                   142
# define SKF_R_NO_EVENT                                   143
# define SKF_R_NO_SPACE                                   144
# define SKF_R_OPERATION_NOT_SUPPORTED                    145
# define SKF_R_PARSE_CERTIFICATE_FAILURE                  146
# define SKF_R_PIN_INCORRECT                              147
# define SKF_R_PIN_LOCKED                                 148
# define SKF_R_RANDOM_GENERATION_FAILED                   149
# define SKF_R_READ_FILE_FAILURE                          150
# define SKF_R_RSA_DECRYPTION_FAILURE                     151
# define SKF_R_RSA_ENCRYPTION_FAILURE                     152
# define SKF_R_RSA_KEY_GENERATION_FAILURE                 153
# define SKF_R_SKF_METHOD_NOT_INITIALIZED                 154
# define SKF_R_SUCCESS                                    155
# define SKF_R_TIMEOUT                                    156
# define SKF_R_UNKNOWN_CERTIFICATE_KEYUSAGE               157
# define SKF_R_UNKNOWN_ERROR                              158
# define SKF_R_UNKNOWN_VENDOR                             159
# define SKF_R_UNSUPPORTED_PRIVATE_KEY_TYPE               160
# define SKF_R_USER_ALREADY_LOGGED_IN                     161
# define SKF_R_USER_NOT_LOGGED_IN                         162
# define SKF_R_USER_PIN_NOT_INITIALIZED                   163
# define SKF_R_WISEC_AUTH_BLOCKED                         164
# define SKF_R_WISEC_CERTNOUSAGEERR                       165
# define SKF_R_WISEC_CERTUSAGEERR                         166
# define SKF_R_WISEC_CONTAINER_EXISTS                     167
# define SKF_R_WISEC_CONTAINER_NOT_EXISTS                 168
# define SKF_R_WISEC_DEVNOAUTH                            169
# define SKF_R_WISEC_FILEATTRIBUTEERR                     170
# define SKF_R_WISEC_INVALIDCONTAINERERR                  171
# define SKF_R_WISEC_KEYNOUSAGEERR                        172
# define SKF_R_WRITE_FILE_FAILURE                         173

#  ifdef  __cplusplus
}
#  endif
# endif
#endif
