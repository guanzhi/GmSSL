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
#include <gmssl/oid.h>
#include <gmssl/sm2.h>
#include <gmssl/asn1.h>
#include <gmssl/pkcs8.h>
#include <gmssl/error.h>


static int test_pbkdf2_params(void)
{
	uint8_t salt[8] = {0};
	size_t saltlen;
	int iter = 65536;
	int keylen = 16;
	int prf = OID_hmac_sm3;

	uint8_t buf[128];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	const uint8_t *d;
	size_t dlen;
	const uint8_t *psalt;

	if (pbkdf2_params_to_der(salt, sizeof(salt), iter, keylen, prf, &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	pbkdf2_params_print(stderr, 0, 0, "PBKDF2-params", d, dlen);

	p = buf;
	cp = buf;
	len = 0;
	keylen = -1;
	prf = -1;
	if (pbkdf2_params_to_der(salt, sizeof(salt), iter, keylen, prf, &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	pbkdf2_params_print(stderr, 0, 0, "PBKDF2-params", d, dlen);

	p = buf;
	cp = buf;
	len = 0;
	keylen = -1;
	prf = -1;
	if (pbkdf2_params_to_der(salt, sizeof(salt), iter, keylen, prf, &p, &len) != 1
		|| pbkdf2_params_from_der(&psalt, &saltlen, &iter, &keylen, &prf, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 0, "PBKDF2-params\n");
	format_bytes(stderr, 0, 4, "salt", psalt, saltlen);
	format_print(stderr, 0, 4, "iterationCount: %d\n", iter);
	format_print(stderr, 0, 4, "keyLength: %d\n", keylen);
	format_print(stderr, 0, 4, "prf: %d\n", prf);

	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_pbkdf2_algor(void)
{
	uint8_t salt[8] = {0};
	size_t saltlen;
	int iter = 65536;
	int keylen = 16;
	int prf = OID_hmac_sm3;

	uint8_t buf[128];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	const uint8_t *d;
	size_t dlen;
	const uint8_t *psalt;

	if (pbkdf2_algor_to_der(salt, sizeof(salt), iter, keylen, prf, &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	pbkdf2_algor_print(stderr, 0, 0, "PBKDF2", d, dlen);

	p = buf;
	cp = buf;
	len = 0;
	if (pbkdf2_algor_to_der(salt, sizeof(salt), iter, keylen, prf, &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 0, "PBKDF2\n");
	format_bytes(stderr, 0, 4, "salt", psalt, saltlen);
	format_print(stderr, 0, 4, "iterationCount: %d\n", iter);
	format_print(stderr, 0, 4, "keyLength: %d\n", keylen);
	format_print(stderr, 0, 4, "prf: %d\n", prf);

	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_pbes2_enc_algor(void)
{
	int cipher = OID_sm4_cbc;
	uint8_t iv[16] = {1};

	uint8_t buf[128];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	const uint8_t *d;
	size_t dlen;
	const uint8_t *piv;
	size_t ivlen;

	if (pbes2_enc_algor_to_der(cipher, iv, sizeof(iv), &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	pbes2_enc_algor_print(stderr, 0, 0, "PBES2-Enc", d, dlen);

	p = buf;
	cp = buf;
	len = 0;

	if (pbes2_enc_algor_to_der(cipher, iv, sizeof(iv), &p, &len) != 1
		|| pbes2_enc_algor_from_der(&cipher, &piv, &ivlen, &cp, &len) != 1
		|| asn1_check(cipher == OID_sm4_cbc) != 1
		|| asn1_check(ivlen == sizeof(iv)) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_pbes2_params(void)
{
	uint8_t salt[8] = {0};
	size_t saltlen;
	int iter = 65536;
	int keylen = -1;
	int prf = OID_hmac_sm3;
	int cipher = OID_sm4_cbc;
	uint8_t iv[16];

	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	const uint8_t *d;
	size_t dlen;
	const uint8_t *psalt;
	const uint8_t *piv;
	size_t ivlen;

	if (pbes2_params_to_der(salt, sizeof(salt), iter, keylen, prf, cipher, iv, sizeof(iv), &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	pbes2_params_print(stderr, 0, 0, "PBES2-params", d, dlen);

	p = buf;
	cp = buf;
	len = 0;

	if (pbes2_params_to_der(salt, sizeof(salt), iter, keylen, prf, cipher, iv, sizeof(iv), &p, &len) != 1
		|| pbes2_params_from_der(&psalt, &saltlen, &iter, &keylen, &prf, &cipher, &piv, &ivlen, &cp, &len) != 1
		|| asn1_check(saltlen == sizeof(salt)) != 1
		|| asn1_check(iter == 65536) != 1
		|| asn1_check(keylen == -1) != 1
		|| asn1_check(prf == OID_hmac_sm3) != 1
		|| asn1_check(cipher == OID_sm4_cbc) != 1
		|| asn1_check(ivlen == sizeof(iv)) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_pbes2_algor(void)
{
	uint8_t salt[8] = {0};
	size_t saltlen;
	int iter = 65536;
	int keylen = -1;
	int prf = OID_hmac_sm3;
	int cipher = OID_sm4_cbc;
	uint8_t iv[16];

	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	const uint8_t *d;
	size_t dlen;
	const uint8_t *psalt;
	const uint8_t *piv;
	size_t ivlen;

	if (pbes2_algor_to_der(salt, sizeof(salt), iter, keylen, prf, cipher, iv, sizeof(iv), &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	pbes2_algor_print(stderr, 0, 0, "PBES2", d, dlen);

	p = buf;
	cp = buf;
	len = 0;

	if (pbes2_algor_to_der(salt, sizeof(salt), iter, keylen, prf, cipher, iv, sizeof(iv), &p, &len) != 1
		|| pbes2_algor_from_der(&psalt, &saltlen, &iter, &keylen, &prf, &cipher, &piv, &ivlen, &cp, &len) != 1
		|| asn1_check(saltlen == sizeof(salt)) != 1
		|| asn1_check(iter == 65536) != 1
		|| asn1_check(keylen == -1) != 1
		|| asn1_check(prf == OID_hmac_sm3) != 1
		|| asn1_check(cipher == OID_sm4_cbc) != 1
		|| asn1_check(ivlen == sizeof(iv)) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_pkcs8_enced_private_key_info(void)
{
	uint8_t salt[8] = { 1,0 };
	int iter = 65536;
	int keylen = -1;
	int prf = OID_hmac_sm3;
	int cipher = OID_sm4_cbc;
	uint8_t iv[16] = { 2,0 };
	uint8_t enced[128] = { 3,0 };

	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	const uint8_t *d;
	size_t dlen;
	const uint8_t *psalt;
	size_t saltlen;
	const uint8_t *piv;
	size_t ivlen;
	const uint8_t *penced;
	size_t encedlen;

	if (pkcs8_enced_private_key_info_to_der(
			salt, sizeof(salt), iter, keylen, prf,
			cipher, iv, sizeof(iv),
			enced, sizeof(enced), &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	pkcs8_enced_private_key_info_print(stderr, 0, 0, "EncryptedPrivateKeyInfo", d, dlen);

	p = buf;
	cp = buf;
	len = 0;

	if (pkcs8_enced_private_key_info_to_der(
			salt, sizeof(salt), iter, keylen, prf,
			cipher, iv, sizeof(iv),
			enced, sizeof(enced), &p, &len) != 1
		|| pkcs8_enced_private_key_info_from_der(
			&psalt, &saltlen, &iter, &keylen, &prf,
			&cipher, &piv, &ivlen,
			&penced, &encedlen, &cp, &len) != 1
		|| asn1_check(saltlen == sizeof(salt)) != 1
		|| asn1_check(keylen == -1) != 1
		|| asn1_check(prf == OID_hmac_sm3) != 1
		|| asn1_check(cipher == OID_sm4_cbc) != 1
		|| asn1_check(ivlen == sizeof(iv)) != 1
		|| asn1_check(encedlen == sizeof(enced)) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_pkcs8(void)
{
	int err = 0;
	SM2_KEY sm2_key;
	SM2_KEY sm2_buf;
	const uint8_t *attrs;
	size_t attrslen;
	uint8_t buf[1024];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	sm2_key_generate(&sm2_key);
	memcpy(&sm2_buf, &sm2_key, sizeof(sm2_key));
	sm2_key_print(stderr, 0, 0, "SM2_KEY", &sm2_key);

	if (sm2_private_key_info_encrypt_to_der(&sm2_key, "password", &p, &len) != 1) {
		error_print();
		return -1;
	}
	{
		const uint8_t *a = buf;
		size_t alen = len;
		const uint8_t *d;
		size_t dlen;
		if (asn1_sequence_from_der(&d, &dlen, &a, &alen) != 1
			|| asn1_length_is_zero(alen) != 1) {
			error_print();
			return -1;
		}
		pkcs8_enced_private_key_info_print(stderr, 0, 0, "test_pkcs8: 392", d, dlen);
		fprintf(stderr, "\n");
	}

	memset(&sm2_key, 0, sizeof(sm2_key));
	if (sm2_private_key_info_decrypt_from_der(&sm2_key, &attrs, &attrslen, "password", &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
		fprintf(stderr, "\n");
	sm2_key_print(stderr, 0, 0, "SM2_KEY", &sm2_key);

	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_pkcs8_pem(void)
{
	int err = 0;
	char *file = "test_pkcs8_pem.pem";
	char *pass = "password";
	SM2_KEY sm2_key;
	SM2_KEY sm2_buf;
	const uint8_t *attrs;
	size_t attrs_len;
	FILE *fp;

	sm2_key_generate(&sm2_key);
	memcpy(&sm2_buf, &sm2_key, sizeof(sm2_key));
	sm2_key_print(stderr, 0, 0, "SM2_KEY", &sm2_key);

	if (!(fp = fopen(file, "w"))
		|| sm2_private_key_info_encrypt_to_pem(&sm2_key, pass, fp) != 1) {
		error_print();
		return -1;
	}
	fclose(fp);

	memset(&sm2_key, 0, sizeof(sm2_key));
	if (!(fp = fopen(file, "r"))
		|| sm2_private_key_info_decrypt_from_pem(&sm2_key, pass, fp) != 1) {
		error_print();
		return -1;
	}
	sm2_key_print(stderr, 0, 0, "SM2_KEY", &sm2_key);

	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

int main(void)
{
	int err = 0;
	/*
	err += test_pbkdf2_params();
	err += test_pbkdf2_algor();
	err += test_pbes2_enc_algor();
	err += test_pbes2_params();
	err += test_pbes2_algor();
	err += test_pkcs8_enced_private_key_info();
	*/
	err += test_pkcs8();
//	err += test_pkcs8_pem();
	return err;
}
