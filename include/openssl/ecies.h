/* ====================================================================
 * Copyright (c) 2007 - 2017 The GmSSL Project.  All rights reserved.
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

#ifndef HEADER_ECIES_H
#define HEADER_ECIES_H

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_ECIES

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/kdf2.h>
#include <openssl/objects.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
ECIESAlgorithmSet ALGORITHM ::= {
	{OID ecies-recommendedParameters} |
	{OID ecies-specifiedParameters PARMS ECIESParameters},
	... -- Future combinations may be added
	{OID ecies-with-x9-63-sha1-aes128-cbc-hmac}
	{OID ecies-with-x9-63-sha256-aes128-cbc-hmac}
	{OID ecies-with-x9-63-sha256-aes192-cbc-hmac}
	{OID ecies-with-x9-63-sha512-aes256-cbc-hmac}
	{OID ecies-with-x9-63-sha256-xor-hmac}
}
*/

typedef struct ecies_params_st {
	/*
	KDFSet ALGORITHM ::= {
		{ OID x9-63-kdf PARMS HashAlgorithm } |
		{ OID nist-concatenation-kdf PARMS HashAlgorithm } |
		{ OID tls-kdf PARMS HashAlgorithm } |
		{ OID ikev2-kdf PARMS HashAlgorithm }
		... -- Future combinations may be added
	}
	*/
	int kdf_nid;
	const EVP_MD *kdf_md;

	/*
	SYMENCSet ALGORITHM ::= {
		{ OID xor-in-ecies } |
		{ OID tdes-cbc-in-ecies } |
		{ OID aes128-cbc-in-ecies } |
		{ OID aes192-cbc-in-ecies } |
		{ OID aes256-cbc-in-ecies } |
		{ OID aes128-ctr-in-ecies } |
		{ OID aes192-ctr-in-ecies } |
		{ OID aes256-ctr-in-ecies } ,
		... -- Future combinations may be added
	}
	*/
	int enc_nid;

	/*
	MACSet ALGORITHM ::= {
		{ OID hmac-full-ecies PARMS HashAlgorithm} |
		{ OID hmac-half-ecies PARMS HashAlgorithm} |
		{ OID cmac-aes128-ecies } |
		{ OID cmac-aes192-ecies } |
		{ OID cmac-aes256-ecies } ,
		... -- Future combinations may be added
	}
	*/
	int mac_nid;
	const EVP_MD *hmac_md;

} ECIES_PARAMS;

int ECIES_PARAMS_init_with_recommended(ECIES_PARAMS *param);
int ECIES_PARAMS_init_with_type(ECIES_PARAMS *param, int type);
KDF_FUNC ECIES_PARAMS_get_kdf(const ECIES_PARAMS *param);
int ECIES_PARAMS_get_enc(const ECIES_PARAMS *param, size_t inlen,
	const EVP_CIPHER **enc_cipher, size_t *enckeylen, size_t *ciphertextlen);
int ECIES_PARAMS_get_mac(const ECIES_PARAMS *param,
	const EVP_MD **hmac_md, const EVP_CIPHER **cmac_cipher,
	unsigned int *mackeylen, unsigned int *maclen);

int i2d_ECIESParameters(const ECIES_PARAMS *param, unsigned char **out);
ECIES_PARAMS *d2i_ECIESParameters(ECIES_PARAMS **param,
	const unsigned char **in, long len);

typedef struct ecies_ciphertext_value_st ECIES_CIPHERTEXT_VALUE;
DECLARE_ASN1_FUNCTIONS(ECIES_CIPHERTEXT_VALUE)

int ECIES_CIPHERTEXT_VALUE_ciphertext_length(const ECIES_CIPHERTEXT_VALUE *a);

ECIES_CIPHERTEXT_VALUE *ECIES_do_encrypt(const ECIES_PARAMS *param,
	const unsigned char *in, size_t inlen, EC_KEY *ec_key);
int ECIES_do_decrypt(const ECIES_PARAMS *param, const ECIES_CIPHERTEXT_VALUE *in,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key);
int ECIES_encrypt(int param, const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key);
int ECIES_decrypt(int param, const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key);
#define ECIES_encrypt_with_recommended(in,inlen,out,outlen,ec_key) \
	ECIES_encrypt(NID_ecies_with_x9_63_sha256_xor_hmac,in,inlen,out,outlen,ec_key)
#define ECIES_decrypt_with_recommended(in,inlen,out,outlen,ec_key) \
	ECIES_decrypt(NID_ecies_with_x9_63_sha256_xor_hmac,in,inlen,out,outlen,ec_key)


#ifdef __cplusplus
}
#endif
#endif
#endif
