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
#include <openssl/gmssl1.h>

const char gm1_version_str[] = "GMSSLv1" OPENSSL_VERSION_PTEXT;

#define GM1_NUM_CIPHERS		(sizeof(gm1_ciphers)/sizeof(SSL_CIPHER))


SSL3_ENC_METHOD GMSSLv1_enc_data = {
	tls1_enc,
	tls1_mac,
	tls1_setup_key_block,
	tls1_generate_master_secret,
	tls1_change_cipher_state,
	tls1_final_finish_mac,
	TLS1_FINISH_MAC_LENGTH,
	tls1_cert_verify_mac,
	TLS_MD_CLIENT_FINISH_CONST, TLS_MD_CLIENT_FINISH_CONST_SIZE,
	TLS_MD_SERVER_FINISH_CONST, TLS_MD_SERVER_FINISH_CONST_SIZE,
	tls1_alert_code, //FIXME: GMSSL has some extra code
	tls1_export_keying_material,
	SSL_ENC_FLAG_EXPLICIT_IV | SSL_ENC_FLAG_SIGALGS /* | SSL_ENC_FLAG_SM3_PRF */
		/* | SSL_ENC_FLAGS_GM1_CIPHERS */,
	SSL3_HM_HEADER_LENGTH,
	ssl3_set_handshake_header,
	ssl3_handshake_write
};

/*
struct {
	ECParameters curve_params;
	ECPoint pubkey;
} ServerECDHEParams;

IBCEncryptionKey: derived from server ID

struct {
	switch (KeyExchangeAlgorithm):
	case ECDHE:
		ServerECDHEParams params;
		signed struct {
			uint8 client_random[32];
			uint8 server_random[32];
			ServerECDHEParams params;
		} signed_params;
	case ECC:
		signed struct {
			uint8 client_random[32];
			uint8 server_random[32];
			uint8 server_enc_cert[];
		} signed_params;
	case IBSDH:
		ServerIBSDHParams params;
		signed struct {
			uint8 client_random[32];
			uint8 server_random[32];
			ServerIBSDHParams params;
		} signed_params;
	case IBC:
		ServerIBCParams params;
		signed struct {
			uint8 client_random[32];
			uint8 server_random[32];
			ServerIBCParams params;
			uint8 IBCEncryptionKey[1024];
		} signed_params;
	case RSA:
		signed struct {
			uint8 client_random[32];
			uint8 server_random[32];
			uint8 server_enc_cert[];
		} signed_params;
	}
} ServerKeyExchange;

struct {
	switch (KeyExchangeAlgorithm):
	case ECDHE:
		uint8 ClientECDHEParams[];
	case IBSDH:
		uint8 ClientIBSDHParams[];
	case ECC:
		uint8 ECCEncryptedPreMasterSecret[];
	case IBE:
		uint8 IBCEncryptedPreMasterSecret[];
	case RSA:
		uint8 RSAEncryptedPreMasterSecret[];
	} exchangeKeys;
} ClientKeyExchange;
*/


	






/*
 * ECDHE_XXX is the same as ECDHE_ECDSA_XXX in TLS
 * ECC_XXX and RSA_XXX is similar with ECDH_ECDSA_XXX, ECDH_RSA_XXX,
 *	except that the ServerKeyExchange format is not null.
 */
OPENSSL_GLOBAL SSL_CIPHER gm1_ciphers[] = {
#if 1
	/* Cipher 1 */
	{
		1,
		GM1_TXT_ECDHE_SM1_SM3,
		GM1_CK_ECDHE_SM1_SM3,
		SSL_kECDHE2,
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
		SSL_kSM2,
		SSL_aSM2,
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
		SSL_aSM2,
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
		GM1_TXT_IBC_SM1_SM3,
		GM1_CK_IBC_SM1_SM3,
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
#endif

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

#if 1
	/* Cipher 9 */
	{
		1,
		GM1_TXT_IBSDH_SM4_SM3,
		GM1_CK_IBSDH_SM4_SM3,
		SSL_kIBSDH,
		SSL_aSM2,
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
		SSL_kIBC,
		SSL_aSM2,
		SSL_SM4,
		SSL_SM3,
		SSL_GMV1,
		SSL_NOT_EXP | SSL_HIGH,
		SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
		128,
		128,
	},
#endif
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

};

int gm1_num_ciphers(void)
{
	return GM1_NUM_CIPHERS;
}

const SSL_CIPHER *gm1_get_cipher(unsigned int u)
{
	if (u < GM1_NUM_CIPHERS)
		return (&(gm1_ciphers[GM1_NUM_CIPHERS - 1 - u]));
	else
		return NULL;
}



