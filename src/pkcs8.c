/*
 * Copyright (c) 2021 - 2021 The GmSSL Project.  All rights reserved.
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm2.h>
#include <gmssl/pem.h>
#include <gmssl/oid.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/pbkdf2.h>
#include <gmssl/digest.h>
#include <gmssl/sm4.h>
#include <gmssl/rand.h>

/*
PBKDF2-params ::= SEQUENCE {
	salt OCTET STRING,
	iterationCount INTEGER (1..MAX),
	keyLength INTEGER (1..MAX) OPTIONAL,
	prf AlgorithmIdentifier DEFAULT algid-hmacWithSHA1
}

这里prf的OID一般来说其他地方是用不到的，并且除了sm3-hmac之外，我们都不支持

*/

int pbkdf2_params_to_der(
	const uint8_t *salt, size_t saltlen,
	int iter,
	int keylen,
	int prf,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	size_t prflen = 0;

	switch (prf) {
	case OID_hmac_sm3:
		break;
	/*
	case OID_hmacWithSHA1:
	case OID_hmacWithSHA224:
	case OID_hmacWithSHA256:
	case OID_hmacWithSHA384:
	case OID_hmacWithSHA512:
	case OID_hmacWithSHA512_224:
	case OID_hmacWithSHA512_256:
		error_print();
		return -1;
	*/
	default:
		error_print();
		return -1;
	}

	if (asn1_octet_string_to_der(salt, saltlen, NULL, &len) != 1
		|| asn1_int_to_der(iter, NULL, &len) != 1
		|| asn1_int_to_der(keylen, NULL, &len) < 0
		|| asn1_object_identifier_to_der(prf, NULL, 0, NULL, &prflen) != 1
		|| asn1_null_to_der(NULL, &prflen) != 1
		|| asn1_sequence_to_der(NULL, prflen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_octet_string_to_der(salt, saltlen, out, outlen) != 1
		|| asn1_int_to_der(iter, out, outlen) != 1
		|| asn1_int_to_der(keylen, out, outlen) < 0
		|| asn1_sequence_header_to_der(prflen, out, outlen) != 1
		|| asn1_object_identifier_to_der(prf, NULL, 0, out, outlen) != 1
		|| asn1_null_to_der(out, outlen)  != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int pbkdf2_params_from_der(
	const uint8_t **salt, size_t *saltlen,
	int *iter,
	int *keylen,
	int *prf,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	const uint8_t *algo;
	size_t datalen;
	size_t algolen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_octet_string_from_der(salt, saltlen, &data, &datalen) != 1
		|| asn1_int_from_der(iter, &data, &datalen) != 1
		|| asn1_int_from_der(keylen, &data, &datalen) < 0
		|| asn1_sequence_from_der(&algo, &algolen, &data, &datalen) < 0
		|| datalen > 0) {
		error_print();
		return -1;
	}
	if (*saltlen < 1) {
		error_print();
		return -1;
	}
	if (*iter < 1) {
		error_print();
		return -1;
	}
	if (algo) {
		uint32_t nodes[32];
		size_t nodes_count;
		if (asn1_object_identifier_from_der(prf, nodes, &nodes_count, &algo, &algolen) != 1
			|| asn1_null_from_der(&algo, &algolen) != 1
			|| algolen > 0) {
			error_print();
			return -1;
		}
		if (*prf != OID_hmac_sm3) {
			error_print();
			return -1;
		}
	} else {
		//*prf = OID_hmacWithSHA1;
		error_print();
		return -1;
	}

	return 1;
}

int pbkdf2_algor_to_der(
	const uint8_t *salt, size_t saltlen,
	int iter,
	int keylen,
	int prf,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	uint32_t pbkdf2[] = { 1, 2, 840, 113549, 1, 5, 12 };
	size_t pbkdf2_count = sizeof(pbkdf2)/sizeof(pbkdf2[0]);

	if (asn1_object_identifier_to_der(OID_undef, pbkdf2, pbkdf2_count, NULL, &len) != 1
		|| pbkdf2_params_to_der(salt, saltlen, iter, keylen, prf, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(OID_undef, pbkdf2, pbkdf2_count, out, outlen) != 1
		|| pbkdf2_params_to_der(salt, saltlen, iter, keylen, prf, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int pbkdf2_algor_from_der(
	const uint8_t **salt, size_t *saltlen,
	int *iter,
	int *keylen,
	int *prf,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	uint32_t pbkdf2[] = { 1, 2, 840, 113549, 1, 5, 12 };
	size_t pbkdf2_count = sizeof(pbkdf2)/sizeof(pbkdf2[0]);
	int oid;
	uint32_t nodes[32];
	size_t nodes_count;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_object_identifier_from_der(&oid, nodes, &nodes_count, &data, &datalen) != 1
		|| pbkdf2_params_from_der(salt, saltlen, iter, keylen, prf, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	if (oid != OID_undef || nodes_count != pbkdf2_count
		|| memcmp(nodes, pbkdf2, sizeof(pbkdf2)) != 0) {
		error_print();
		return -1;
	}

	// FIXME: 检查keylen				
	return 1;
}

static uint32_t sm4_cbc_nodes[] = { 1, 2, 156, 10197, 1, 104, 2 };
static size_t sm4_cbc_nodes_count = sizeof(sm4_cbc_nodes)/sizeof(sm4_cbc_nodes[0]);


// 这个应该提取到外面，和digest_algor, encryption_algor, sign_algor 之类的放到一起
int pbes2_enc_algor_to_der(int cipher, const uint8_t *iv, size_t ivlen, uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (cipher != OID_sm4_cbc || ivlen != 16) {
		error_print();
		return -1;
	}
	if (asn1_object_identifier_to_der(OID_undef, sm4_cbc_nodes, sm4_cbc_nodes_count, NULL, &len) != 1
		|| asn1_octet_string_to_der(iv, ivlen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(OID_undef, sm4_cbc_nodes, sm4_cbc_nodes_count, out, outlen) != 1
		|| asn1_octet_string_to_der(iv, ivlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int pbes2_enc_algor_from_der(int *cipher, const uint8_t **iv, size_t *ivlen, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	uint32_t nodes[32];
	size_t nodes_count;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_object_identifier_from_der(cipher, nodes, &nodes_count, &data, &datalen) != 1
		|| asn1_octet_string_from_der(iv, ivlen, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	if (*cipher == OID_undef) {
		if (nodes_count == sm4_cbc_nodes_count
			&& memcmp(nodes, sm4_cbc_nodes, sizeof(sm4_cbc_nodes)) == 0) {
			*cipher = OID_sm4_cbc;
		} else {
			size_t i;
			error_print();
			for (i = 0; i < nodes_count; i++) {
				fprintf(stderr, " %d", nodes[i]);
			}
			fprintf(stderr, "\n");
			return -1;
		}
	}

	// FIXME: 检查ivlen					
	return 1;
}

int pbes2_params_to_der(
	const uint8_t *salt, size_t saltlen,
	int iter,
	int prf,
	int cipher,
	const uint8_t *iv, size_t ivlen,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	int keylen = -1;

	if (pbkdf2_algor_to_der(salt, saltlen, iter, keylen, prf, NULL, &len) != 1
		|| pbes2_enc_algor_to_der(cipher, iv, ivlen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| pbkdf2_algor_to_der(salt, saltlen, iter, keylen, prf, out, outlen) != 1
		|| pbes2_enc_algor_to_der(cipher, iv, ivlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int pbes2_params_from_der(
	const uint8_t **salt, size_t *saltlen,
	int *iter,
	int *prf,
	int *cipher,
	const uint8_t **iv, size_t *ivlen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	int keylen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (pbkdf2_algor_from_der(salt, saltlen, iter, &keylen, prf, &data, &datalen) != 1
		|| pbes2_enc_algor_from_der(cipher, iv, ivlen, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	if (keylen >= 0 && keylen != 16) {
		error_print();
		return -1;
	}
	return 1;
}

int pbes2_algor_to_der(
	const uint8_t *salt, size_t saltlen,
	int iter,
	int prf,
	int cipher,
	const uint8_t *iv, size_t ivlen,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	uint32_t pbes2[] = { 1, 2, 840, 113549, 1, 5, 13 };
	size_t pbes2_count = sizeof(pbes2)/sizeof(pbes2[0]);

	if (asn1_object_identifier_to_der(OID_undef, pbes2, pbes2_count, NULL, &len) != 1
		|| pbes2_params_to_der(salt, saltlen, iter, prf, cipher, iv, ivlen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(OID_undef, pbes2, pbes2_count, out, outlen) != 1
		|| pbes2_params_to_der(salt, saltlen, iter, prf, cipher, iv, ivlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int pbes2_algor_from_der(
	const uint8_t **salt, size_t *saltlen,
	int *iter,
	int *prf,
	int *cipher,
	const uint8_t **iv, size_t *ivlen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	uint32_t pbes2[] = { 1, 2, 840, 113549, 1, 5, 13 };
	size_t pbes2_count = sizeof(pbes2)/sizeof(pbes2[0]);
	int oid;
	uint32_t nodes[32];
	size_t nodes_count;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_object_identifier_from_der(&oid, nodes, &nodes_count, &data, &datalen) != 1
		|| pbes2_params_from_der(salt, saltlen, iter, prf, cipher, iv, ivlen, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	if (oid != OID_undef) {
		error_print();
		return -1;
	}
	if (nodes_count != pbes2_count && memcmp(nodes, pbes2, sizeof(pbes2)) != 0) {
		error_print();
		return -1;
	}
	return 1;
}

int pkcs8_enced_private_key_info_to_der(
	const uint8_t *salt, size_t saltlen,
	int iter,
	int prf,
	int cipher,
	const uint8_t *iv, size_t ivlen,
	const uint8_t *enced, size_t encedlen,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	pbes2_algor_to_der(salt, saltlen, iter, prf, cipher, iv, ivlen, NULL, &len);
	asn1_octet_string_to_der(enced, encedlen, NULL, &len);
	asn1_sequence_header_to_der(len, out, outlen);
	pbes2_algor_to_der(salt, saltlen, iter, prf, cipher, iv, ivlen, out, outlen);
	asn1_octet_string_to_der(enced, encedlen, out, outlen);
	return 1;
}

int pkcs8_enced_private_key_info_from_der(
	const uint8_t **salt, size_t *saltlen,
	int *iter,
	int *prf,
	int *cipher,
	const uint8_t **iv, size_t *ivlen,
	const uint8_t **enced, size_t *encedlen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (pbes2_algor_from_der(salt, saltlen, iter, prf, cipher, iv, ivlen, &data, &datalen) != 1
		|| asn1_octet_string_from_der(enced, encedlen, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	return 1;
}

// output PKCS #8 EncryptedPrivateKeyInfo

int sm2_enced_private_key_info_to_der(const SM2_KEY *sm2, const char *pass, uint8_t **out, size_t *outlen)
{
	SM4_KEY sm4_key;
	uint8_t salt[16];
	int iter = 65536;
	int prf = OID_hmac_sm3;
	uint8_t key[16];
	int cipher = OID_sm4_cbc;
	uint8_t iv[16];
	uint8_t info[256];
	uint8_t *pinfo = info;
	size_t infolen = 0;
	uint8_t enced[512];
	size_t encedlen;

	if (rand_bytes(salt, sizeof(salt)) != 1
		|| rand_bytes(iv, sizeof(iv)) != 1) {
		error_print();
		return -1;
	}

	// SM2_KEY to PKCS8 PrivateKeyInfo
	if (sm2_private_key_info_to_der(sm2, &pinfo, &infolen) != 1) {
		error_print();
		return -1;
	}

	// password to encryption key
	if (pbkdf2_genkey(DIGEST_sm3(), pass, strlen(pass), salt, sizeof(salt), iter, sizeof(key), key) != 1) {
		error_print();
		return -1;
	}

	// encrypt PrivateKeyInfo
	sm4_set_encrypt_key(&sm4_key, key);
	if (sm4_cbc_padding_encrypt(&sm4_key, iv, info, infolen, enced, &encedlen) != 1) {
		error_print();
		return -1;
	}

	// encode EncryptedPrivateKeyInfo
	if (pkcs8_enced_private_key_info_to_der(salt, sizeof(salt), iter, prf,
		cipher, iv, sizeof(iv), enced, encedlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_enced_private_key_info_from_der(SM2_KEY *sm2, const uint8_t **attrs, size_t *attrslen, const char *pass, const uint8_t **in, size_t *inlen)
{
	SM4_KEY sm4_key;
	const uint8_t *salt;
	size_t saltlen;
	int iter;
	int prf;
	int cipher;
	const uint8_t *iv;
	size_t ivlen;
	const uint8_t *enced;
	size_t encedlen;
	uint8_t key[16];
	uint8_t info[256];
	const uint8_t *pinfo = info;
	size_t infolen;

	if (pkcs8_enced_private_key_info_from_der(&salt, &saltlen, &iter, &prf,
		&cipher, &iv, &ivlen, &enced, &encedlen, in, inlen) != 1) {
		error_print();
		return -1;
	}

	if (pbkdf2_genkey(DIGEST_sm3(), pass, strlen(pass), salt, saltlen, iter, sizeof(key), key) != 1) {
		error_print();
		return -1;
	}

	sm4_set_decrypt_key(&sm4_key, key);
	if (sm4_cbc_padding_decrypt(&sm4_key, iv, enced, encedlen, info, &infolen) != 1) {
		error_print();
		return -1;
	}
	if (sm2_private_key_info_from_der(sm2, attrs, attrslen, &pinfo, &infolen) != 1
		|| infolen > 0) {
		error_print();
		return -1;
	}

	return 1;
}

int sm2_enced_private_key_info_to_pem(const SM2_KEY *key, const char *pass, FILE *fp)
{
	uint8_t buf[1024];
	uint8_t *p = buf;
	size_t len = 0;

	if (sm2_enced_private_key_info_to_der(key, pass, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (pem_write(fp, "ENCRYPTED PRIVATE KEY", buf, len) <= 0) {
		error_print();
		return -1;
	}
	return 1;
}

// TODO: return attributes
int sm2_enced_private_key_info_from_pem(SM2_KEY *key, const char *pass, FILE *fp)
{
	uint8_t buf[512];
	const uint8_t *cp = buf;
	size_t len;
	const uint8_t *attrs;
	size_t attrslen;

	if (pem_read(fp, "ENCRYPTED PRIVATE KEY", buf, &len) != 1) {
		error_print();
		return -1;
	}

	if (sm2_enced_private_key_info_from_der(key, &attrs, &attrslen, pass, &cp, &len) != 1
		|| len > 0) {
		error_print();
		return -1;
	}
	return 1;
}

