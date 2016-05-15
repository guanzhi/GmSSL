/* ssl/gmssl.h */
/* ====================================================================
 * Copyright (c) 2015 The GmSSL Project.  All rights reserved.
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


#ifndef HEADER_GMSSL_H
#define HEADER_GMSSL_H


#ifdef __cplusplus
extern "C" {
#endif

#if 0
#define GM1_VERSION		0x0101
#define GM1_VERSION_MAJOR	0x01
#define GM1_VERSION_MINOR	0x01
#else
#define GM1_VERSION		0x0401
#define GM1_VERSION_MAJOR	0x04
#define GM1_VERSION_MINOR	0x01
#endif

#define GM1_get_version(s) \
	((s->version >> 8) == GM1_VERSION_MAJOR ? s->version : 0)

#define GM1_get_client_version(s) \
	((s->client_version >> 8) == GM1_VERSION_MAJOR ? s->client_version : 0)


/* from GM/T 0024-2014 Table 2 */
#define GM1_CK_ECDHE_SM1_SM3		0x0300E001
#define GM1_CK_ECC_SM1_SM3		0x0300E003
#define GM1_CK_IBSDH_SM1_SM3		0x0300E005
#define GM1_CK_IBC_SM1_SM3		0x0300E007
#define GM1_CK_RSA_SM1_SM3		0x0300E009
#define GM1_CK_RSA_SM1_SHA1		0x0300E00A
#define GM1_CK_ECDHE_SM4_SM3		0x0300E011
#define GM1_CK_ECC_SM4_SM3		0x0300E013
#define GM1_CK_IBSDH_SM4_SM3		0x0300E015
#define GM1_CK_IBC_SM4_SM3		0x0300E017
#define GM1_CK_RSA_SM4_SM3		0x0300E019
#define GM1_CK_RSA_SM4_SHA1		0x0300E01A
/* GmSSL specific */
#define GM1_CK_ECDHE_SM2_SM4_SM3 	0x0300E031
#define GM1_CK_SM2_SM4_SM3		0x0300E033


#define GM1_TXT_ECDHE_SM1_SM3		"ECDHE-SM1-SM3"
#define GM1_TXT_ECC_SM1_SM3		"ECC-SM1-SM3"
#define GM1_TXT_IBSDH_SM1_SM3		"IBSDH-SM1-SM3"
#define GM1_TXT_IBC_SM1_SM3		"IBC-SM1-SM3"
#define GM1_TXT_RSA_SM1_SM3		"RSA-SM1-SM3"
#define GM1_TXT_RSA_SM1_SHA1		"RSA-SM1-SHA1"
#define GM1_TXT_ECDHE_SM4_SM3		"ECDHE-SM4-SM3"
#define GM1_TXT_ECC_SM4_SM3		"ECC-SM4-SM3"
#define GM1_TXT_IBSDH_SM4_SM3		"IBSDH-SM4-SM3"
#define GM1_TXT_IBC_SM4_SM3		"IBC-SM4-SM3"
#define GM1_TXT_RSA_SM4_SM3		"RSA-SM4-SM3"
#define GM1_TXT_RSA_SM4_SHA1		"RSA-SM4-SHA1"
/* GmSSL specific */
#define GM1_TXT_ECDHE_SM2_SM4_SM3	"ECDHE-SM2-SM4-SM3"
#define GM1_TXT_SM2_SM4_SM3		"SM2-SM4-SM3"


/* from GM/T 0024-2014 Table 1 */
#define GM1_AD_UNSUPPORTED_SITE2SITE	200 /* fatal */
#define GM1_AD_NO_AREA			201
#define GM1_AD_UNSUPPORTED_AREATYPE	202
#define GM1_AD_BAD_IBCPARAM		203 /* fatal */
#define GM1_AD_UNSUPPORTED_IBCPARAM	204 /* fatal */
#define GM1_AD_IDENTITY_NEED		205 /* fatal */

#if 0
/* Bits for algorithm_enc (symmetric encryption */
#define SSL_SM1			0x00004000L
#define SSL_SM4			0x00008000L

/* bits for algorithm_mac */
#define SSL_SM3			0x00000040L
#endif

#define SSL_HANDSHAKE_MAC_SM3	0x200

/* SSL_MAX_DIGEST in ssl_locl.h should be update */

#define GM1_PRF_SM3 (SSL_HANDSHAKE_MAC_SM3 << TLS1_PRF_DGST_SHIFT)





#ifdef __cplusplus
}
#endif
#endif

