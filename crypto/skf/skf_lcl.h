/* crypto/skf/skf.h */
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
 *
 */

#ifndef HEADER_SKF_H
#define HEADER_SKF_H

#ifdef __cplusplus
extern "C" {
#endif


int EC_KEY_set_ECCPUBLICKEYBLOB(EC_KEY *ec_key, const ECCPUBLICKEYBLOB *blob);
int EC_KEY_get_ECCPUBLICKEYBLOB(EC_KEY *ec_key, ECCPUBLICKEYBLOB *blob);
int EC_KEY_set_ECCPRIVATEKEYBLOB(EC_KEY *ec_key, const ECCPRIVATEKEYBLOB *blob)
int EC_KEY_get_ECCPRIVATEKEYBLOB(EC_KEY *ec_key, ECCPRIVATEKEYBLOB *blob);

int SM2_CIPHERTEXT_VALUE_set_ECCCIPHERBLOB(SM2_CIPHERTEXT_VALUE *cv,
	const ECCCIPHERBLOB *blob);
int SM2_CIPHERTEXT_VALUE_get_ECCCIPHERBLOB(const SM2_CIPHERTEXT_VALUE *a,
	void *out, size_t *outlen);
int ECDSA_SIG_to_SKF_ECCSIGNATUREBLOB(const ECDSA_SIG *sig,
	const EC_GROUP *group, void *out, size_t *outlen);

int RSA_set_RSAPUBLICKEYBLOB(RSA *rsa, const RSAPUBLICKEYBLOB *blob);
int RSA_get_RSAPUBLICKEYBLOB(RSA *rsa, RSAPUBLICKEYBLOB *blob);
int RSA_set_RSAPRIVATEKEYBLOB(RSA *rsa, const RSAPRIVATEKEYBLOB *blob);
int RSA_to_RSAPRIVATEKEYBLOB(RSA *rsa, RSAPRIVATEKEYBLOB *blob);



#define SAR_OK				0x00000000
#define SAR_FAIL			0x0A000001
#define SAR_UNKNOWNERR			0x0A000002
#define SAR_NOTSUPPORTYETERR		0x0A000003
#define SAR_FILEERR			0x0A000004
#define SAR_INVALIDHANDLEERR		0x0A000005
#define SAR_INVALIDPARAMERR		0x0A000006
#define SAR_READFILEERR			0x0A000007
#define SAR_WRITEFILEERR		0x0A000008
#define SAR_NAMELENERR			0x0A000009
#define SAR_KEYUSAGEERR			0x0A00000A
#define SAR_MODULUSLENERR		0x0A00000B
#define SAR_NOTINITIALIZEERR		0x0A00000C
#define SAR_OBJERR			0x0A00000D
#define SAR_MEMORYERR			0x0A00000E
#define SAR_TIMEOUTERR			0x0A00000F
#define SAR_INDATALENERR		0x0A000010
#define SAR_INDATAERR			0x0A000011
#define SAR_GENRANDERR			0x0A000012
#define SAR_HASHOBJERR			0x0A000013
#define SAR_HASHERR			0x0A000014
#define SAR_GENRSAKEYERR		0x0A000015
#define SAR_RSAMODULUSLENERR		0x0A000016
#define SAR_CSPIMPRTPUBKEYERR		0x0A000017
#define SAR_RSAENCERR			0x0A000018
#define SAR_RSADECERR			0x0A000019
#define SAR_HASHNOTEQUALERR		0x0A00001A
#define SAR_KEYNOTFOUNTERR		0x0A00001B
#define SAR_KEYNOTFOUNDERR		0x0A00001B
#define SAR_CERTNOTFOUNTERR		0x0A00001C
#define SAR_NOTEXPORTERR		0x0A00001D
#define SAR_DECRYPTPADERR		0x0A00001E
#define SAR_MACLENERR			0x0A00001F
#define SAR_BUFFER_TOO_SMALL		0x0A000020
#define SAR_KEYINFOTYPEERR		0x0A000021
#define SAR_NOT_EVENTERR		0x0A000022
#define SAR_DEVICE_REMOVED		0x0A000023
#define SAR_PIN_INCORRECT		0x0A000024
#define SAR_PIN_LOCKED			0x0A000025
#define SAR_PIN_INVALID			0x0A000026
#define SAR_PIN_LEN_RANGE		0x0A000027
#define SAR_USER_ALREADY_LOGGED_IN	0x0A000028
#define SAR_USER_PIN_NOT_INITIALIZED	0x0A000029
#define SAR_USER_TYPE_INVALID		0x0A00002A
#define SAR_APPLICATION_NAME_INVALID	0x0A00002B
#define SAR_APPLICATION_EXISTS		0x0A00002C
#define SAR_USER_NOT_LOGGED_IN		0x0A00002D
#define SAR_APPLICATION_NOT_EXISTS	0x0A00002E
#define SAR_FILE_ALREADY_EXIST		0x0A00002F
#define SAR_NO_ROOM			0x0A000030


#ifdef __cplusplus
}
#endif
#endif

