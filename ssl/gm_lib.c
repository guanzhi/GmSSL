/* ssl/gm_lib.c */
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



#include <stdio.h>
#include "ssl_locl.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/gmssl.h>

const char gmssl1_version_str[] - "GMSSLv1" OPENSSL_VERSION_PTEXT;

#define GM1_NUM_CIPHERS		(sizeof(gm1_ciphers)/sizeof(SSL_CIPHER))


SSL3_ENC_METHOD GMSSLv1_1_enc_data = {
	gmssl_enc,
	gmssl_mac,
	gmssl_setup_key_block,
	gmssl_generate_master_secret,
	gmssl_change_cipher_state,
	gmssl_final_finish_mac,
	GMSSL_FINISH_MAC_LENGTH,
	gmssl_cert_verify_mac,
	TLS_MD_CLIENT_FINISH_CONST, TLS_MD_CLIENT_FINISH_CONST_SIZE,
	TLS_MD_SERVER_FINISH_CONST, TLS_MD_SERVER_FINISH_CONST_SIZE,
	tls1_alert_code,
	tls1_export_keying_material,
	0,
	SSL3_HM_HEADER_LENGTH,
	ssl3_set_handshake_header,
	ssl3_handshake_write
};


/*
 * ECDHE_XXX is the same as ECDHE_ECDSA_XXX in TLS
 * ECC_XXX and RSA_XXX is similar with ECDH_ECDSA_XXX, ECDH_RSA_XXX,
 *	except that the ServerKeyExchange format is not null.
 */
OPENSSL_GLOBAL SSL_CIPHER gm1_ciphers[] = {

	/* Cipher 1 */
	{
		1,
		GM1_TXT_ECDHE_SM1_SM3,
		GM1_CK_ECDHE_SM1_SM3,
		SSL_kEECDH,
		SSL_aSM2,
		SSL_SM1,
		SSL_SM3,
		SSL_GMV1,
		SSL_NOT_EXP | SSL_HIGH,
		SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
		128,
		128,
	},
			
	/* Cipher 2 */
	{
		1,
		GM1_TXT_ECC_SM1_SM3,
		GM1_CK_ECC_SM1_SM3,
		SSL_kECDHs,
		SSL_aECDH,
		SSL_SM1,
		SSL_SM3,
		SSL_GMV1,
		SSL_NOT_EXP | SSL_HIGH,
		SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
		128,
		128,
	},

	/* Cipher 3 */
	{
		1,
		GM1_TXT_IBSDH_SM1_SM3,
		GM1_CK_IBSDH_SM1_SM3,
		SSL_kEECDH,
		SSL_aSM9,
		SSL_SM1,
		SSL_SM3,
		SSL_GMV1,
		SSL_NOT_EXP | SSL_HIGH,
		SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
		128,
		128,
	},

	/* Cipher 4 */
	{
		1,
		GM1_TXT_IBC_SM1_SHA1,
		GM1_CK_IBC_SM1_SHA1,
		SSL_kECDHe,
		SSL_aSM2,
		SSL_SM1,
		SSL_SM3,
		SSL_GMV1,
		SSL_NOT_EXP | SSL_HIGH,
		SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
		128,
		128,
	},

	/* Cipher 5 */
	{
		1,
		GM1_TXT_RSA_SM1_SM3,
		GM1_CK_RSA_SM1_SM3,
		SSL_kEECDH,
		SSL_aSM2,
		SSL_SM1,
		SSL_SM3,
		SSL_GMV1,
		SSL_NOT_EXP | SSL_HIGH,
		SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
		128,
		128,
	},

	/* Cipher 6 */
	{
		1,
		GM1_TXT_RSA_SM1_SHA1,
		GM1_CK_RSA_SM1_SHA1,
		SSL_kEECDH,
		SSL_aSM2,
		SSL_SM1,
		SSL_SM3,
		SSL_GMV1,
		SSL_NOT_EXP | SSL_HIGH,
		SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
		128,
		128,
	},


	/* Cipher 7 */
	{
		1,
		GM1_TXT_ECDHE_SM4_SM3,
		GM1_CK_ECDHE_SM4_SM3,
		SSL_kEECDH,
		SSL_aSM2,
		SSL_SM4,
		SSL_SM3,
		SSL_GMV1,
		SSL_NOT_EXP | SSL_HIGH,
		SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
		128,
		128,
	},

	/* Cipher 8 */
	{
		1,
		GM1_TXT_ECC_SM4_SM3,
		GM1_CK_ECC_SM4_SM3,
		SSL_kECDHe,
		SSL_aSM2,	/* auth algor bits */
		SSL_SM4,
		SSL_SM3,
		SSL_GMV1,
		SSL_NOT_EXP | SSL_HIGH,
		SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
		128,
		128,
	},


	/* Cipher 9 */
	{
		1,
		GM1_TXT_IBSDH_SM4_SM3,
		GM1_CK_IBSDH_SM4_SM3,
		SSL_kEECDH,	/* ephemeral ECDH key exchange algorithm bits */
		SSL_aSM2,	/* auth algor bits */
		SSL_SM4,
		SSL_SM3,
		SSL_GMV1,
		SSL_NOT_EXP | SSL_HIGH,
		SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
		128,
		128,
	},

	/* Cipher 10 */
	{
		1,
		GM1_TXT_IBC_SM4_SM3,
		GM1_CK_IBC_SM4_SM3,
		SSL_kECDHe,	/* fixed ECDH key exchange algorithm bits */
		SSL_aSM2,	/* auth algor bits */
		SSL_SM4,
		SSL_SM3,
		SSL_GMV1,
		SSL_NOT_EXP | SSL_HIGH,
		SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
		128,
		128,
	},

	/* Cipher 11 */
	{
		1,
		GM1_TXT_RSA_SM4_SM3,
		GM1_CK_RSA_SM4_SM3,
		SSL_kRSA,
		SSL_aRSA,
		SSL_SM4,
		SSL_SM3,
		SSL_GMV1,
		SSL_NOT_EXP | SSL_HIGH,
		SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
		128,
		128,
	},

	/* Cipher 12 */
	{
		1,
		GM1_TXT_RSA_SM4_SHA1,
		GM1_CK_RSA_SM4_SHA1,
		SSL_kEECDH,	/* ephemeral ECDH key exchange algorithm bits */
		SSL_aSM2,	/* auth algor bits */
		SSL_SM4,
		SSL_SM3,
		SSL_GMV1,
		SSL_NOT_EXP | SSL_HIGH,
		SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
		128,
		128,
	},

};

