/*
 * Copyright (c) 2014 - 2021 The GmSSL Project.  All rights reserved.
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
#include <gmssl/x509.h>
#include <gmssl/error.h>


static int test_x509_digest_algor(void)
{
	char *names[] = {"sm3", "md5", "sha1", "sha224", "sha256", "sha384", "sha512" };
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int algor;
	uint32_t nodes[32];
	size_t nodes_count;
	int i, j;

	printf("\n%s\n", __FUNCTION__);

	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		algor = x509_digest_algor_from_name(names[i]);
		if (x509_digest_algor_to_der(algor, &p, &len) != 1) {
			error_print();
			return -1;
		}
	}
	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		if (x509_digest_algor_from_der(&algor, nodes, &nodes_count, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		printf(" %s : ", x509_digest_algor_name(algor));
		for (j = 0; j < nodes_count; j++) {
			printf("%d ", nodes[j]);
		}
		printf("\n");
	}
	return 0;
}

static int test_x509_encryption_algor(void)
{
	char *names[] = { "sm4-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc" };
	uint8_t iv[16] = {0};
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int algor;
	uint32_t nodes[32];
	size_t nodes_count;
	const uint8_t *params;
	size_t paramslen;
	int i, j;

	printf("\n%s\n", __FUNCTION__);

	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		algor = x509_encryption_algor_from_name(names[i]);
		if (x509_encryption_algor_to_der(algor, iv, sizeof(iv), &p, &len) != 1) {
			error_print();
			return -1;
		}
	}
	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		if (x509_encryption_algor_from_der(&algor, nodes, &nodes_count, &params, &paramslen, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		printf(" %s : ", x509_encryption_algor_name(algor));
		for (j = 0; j < nodes_count; j++) {
			printf("%d ", nodes[j]);
		}
		printf("\n");
	}
	return 0;
}

static int test_x509_signature_algor(void)
{
	char *names[] = {
		"sm2sign-with-sm3",
		"rsasign-with-sm3",
		"ecdsa-with-sha1",
		"ecdsa-with-sha224",
		"ecdsa-with-sha256",
		"ecdsa-with-sha384",
		"ecdsa-with-sha512",
		"sha1WithRSAEncryption",
		"sha224WithRSAEncryption",
		"sha256WithRSAEncryption",
		"sha384WithRSAEncryption",
		"sha512WithRSAEncryption",
	};
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int algor;
	uint32_t nodes[32];
	size_t nodes_count;
	int i, j;

	printf("\n%s\n", __FUNCTION__);

	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		algor = x509_signature_algor_from_name(names[i]);
		if (x509_signature_algor_to_der(algor, &p, &len) != 1) {
			error_print();
			return -1;
		}
	}
	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		if (x509_signature_algor_from_der(&algor, nodes, &nodes_count, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		printf(" %s : ", x509_signature_algor_name(algor));
		for (j = 0; j < nodes_count; j++) {
			printf("%d ", nodes[j]);
		}
		printf("\n");
	}
	return 0;
}

static int test_x509_public_key_encryption_algor(void)
{
	char *names[] = {"sm2encrypt", "rsaesOAEP", "rsaEncryption" };
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int algor;
	uint32_t nodes[32];
	size_t nodes_count;
	const uint8_t *params;
	size_t paramslen;
	int i, j;

	printf("\n%s\n", __FUNCTION__);

	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		algor = x509_public_key_encryption_algor_from_name(names[i]);
		if (x509_public_key_encryption_algor_to_der(algor, &p, &len) != 1) {
			error_print();
			return -1;
		}
	}
	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		if (x509_public_key_encryption_algor_from_der(&algor, nodes, &nodes_count, &params, &paramslen, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		printf(" %s : ", x509_public_key_encryption_algor_name(algor));
		for (j = 0; j < nodes_count; j++) {
			printf("%d ", nodes[j]);
		}
		printf("\n");
	}
	return 0;
}



















int main(void)
{
	int err = 0;
	err += test_x509_digest_algor();
	err += test_x509_encryption_algor();
	err += test_x509_signature_algor();
	err += test_x509_public_key_encryption_algor();
	return err;
}
