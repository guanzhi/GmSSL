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
#include <gmssl/x509.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/cms.h>

static int test_cms_data(void)
{
	uint8_t data[20];
	uint8_t content_info[512];
	size_t content_info_len = sizeof(content_info);
	size_t len = 0;
	int i;

	memset(data, 'A', sizeof(data));

	cms_content_info_set_data(content_info, &content_info_len, data, sizeof(data));
	cms_content_info_print(stdout, content_info, content_info_len, 0, 0);
	return 1;
}

static int test_cms_sign(void)
{
	SM2_KEY sign_key;
	X509_CERTIFICATE sign_cert;
	uint8_t data[20];
	uint8_t content_info[1024];
	size_t content_info_len = 0;

	FILE *key_fp = fopen("sign_key.pem", "r");
	FILE *cert_fp = fopen("sign_cert.pem", "r");

	if (sm2_private_key_from_pem(&sign_key, key_fp) != 1) {
		error_print();
		return -1;
	}
	if (x509_certificate_from_pem(&sign_cert, cert_fp) != 1) {
		error_print();
		return -1;
	}
	if (cms_sign(&sign_key, &sign_cert, 1, CMS_data, data, 20, NULL, NULL, 0, content_info, &content_info_len) != 1) {
		error_print();
		return -1;
	}
	cms_content_info_print(stdout, content_info, content_info_len, 0, 0);

	return 1;
}


int main(void)
{
	test_cms_data();
	test_cms_sign();
	return 0;
}
