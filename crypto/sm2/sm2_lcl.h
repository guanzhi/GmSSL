/*
 * Copyright (c) 2015 - 2017 The GmSSL Project.  All rights reserved.
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
 */

#define EC_KEY_METHOD_SM2	0x02

#define SM2_DEFAULT_POINT_CONVERSION_FORM	POINT_CONVERSION_UNCOMPRESSED

#define SM2_MAX_PKEY_DATA_LENGTH		((EC_MAX_NBYTES + 1) * 6)

#define SM2_MAX_PLAINTEXT_LENGTH		65535
#define SM2_MAX_CIPHERTEXT_LENGTH		(SM2_MAX_PLAINTEXT_LENGTH + 2048)


int SM2_get_public_key_data(EC_KEY *ec_key, unsigned char *out, size_t *outlen);

struct SM2CiphertextValue_st {
	BIGNUM *xCoordinate;
	BIGNUM *yCoordinate;
	ASN1_OCTET_STRING *hash;
	ASN1_OCTET_STRING *ciphertext;
};

struct sm2_kap_ctx_st {

	const EVP_MD *id_dgst_md;
	const EVP_MD *kdf_md;
	const EVP_MD *checksum_md;
	point_conversion_form_t point_form;
	KDF_FUNC kdf;

	int is_initiator;
	int do_checksum;

	EC_KEY *ec_key;
	unsigned char id_dgst[EVP_MAX_MD_SIZE];
	unsigned int id_dgstlen;

	EC_KEY *remote_pubkey;
	unsigned char remote_id_dgst[EVP_MAX_MD_SIZE];
	unsigned int remote_id_dgstlen;

	const EC_GROUP *group;
	BN_CTX *bn_ctx;
	BIGNUM *order;
	BIGNUM *two_pow_w;

	BIGNUM *t;
	EC_POINT *point;
	unsigned char pt_buf[1 + (OPENSSL_ECC_MAX_FIELD_BITS+7)/4];
	unsigned char checksum[EVP_MAX_MD_SIZE];

};

