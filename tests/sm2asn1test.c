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
#include <gmssl/error.h>


static int test_sm2_point_octets(void)
{
	int err = 0;
	SM2_KEY sm2_key;
	SM2_POINT point;
	uint8_t buf[65];
	int i;

	// compress
	for (i = 0; i < 8; i++) {
		uint8_t buf[33];
		sm2_keygen(&sm2_key);
		sm2_point_to_compressed_octets(&sm2_key.public_key, buf);
		if (sm2_point_from_octets(&point, buf, sizeof(buf)) != 1) {
			error_print();
			err++;
			break;
		}
		if (memcmp(&sm2_key.public_key, &point, sizeof(SM2_POINT)) != 0) {
			error_print();
			err++;
			break;
		}
	}

	// uncompress
	for (i = 0; i < 8; i++) {
		uint8_t buf[65];
		sm2_keygen(&sm2_key);
		sm2_point_to_uncompressed_octets(&sm2_key.public_key, buf);
		if (sm2_point_from_octets(&point, buf, sizeof(buf)) != 1) {
			error_print();
			err++;
			break;
		}
		if (memcmp(&sm2_key.public_key, &point, sizeof(SM2_POINT)) != 0) {
			error_print();
			err++;
			break;
		}
	}

	printf("%s : %s\n", __func__, err ? "failed" : "ok");
	return err;
}

static int test_sm2_private_key(void)
{
	int err = 0;
	SM2_KEY sm2_key;
	SM2_KEY sm2_tmp;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;


	sm2_keygen(&sm2_key);

	if (sm2_private_key_to_der(&sm2_key, &p, &len) != 1) {
		error_print();
		err++;
		goto end;
	}
	if (sm2_private_key_from_der(&sm2_tmp, &cp, &len) != 1
		|| len > 0) {
		error_print();
		err++;
		goto end;
	}
	if (memcmp(&sm2_tmp, &sm2_key, sizeof(SM2_KEY)) != 0) {
		error_print();
		err++;
		goto end;
	}

	printf("%s : ok\n", __func__);
end:
	return err;
}

static int test_sm2_public_key_info(void)
{
	int err = 0;
	SM2_KEY sm2_key;
	SM2_KEY sm2_tmp;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	sm2_keygen(&sm2_key);

	if (sm2_public_key_info_to_der(&sm2_key, &p, &len) != 1) {
		error_print();
		err++;
		goto end;
	}
	if (sm2_public_key_info_from_der(&sm2_tmp, &cp, &len) != 1
		|| len > 0) {
		error_print();
		err++;
		goto end;
	}
	if (memcmp(&sm2_key.public_key, &sm2_tmp.public_key, sizeof(SM2_POINT)) != 0) {
		error_print();
		err++;
		goto end;
	}
	printf("%s : ok\n", __func__);
end:
	return err;
}



int main(void)
{
	test_sm2_point_octets();
	test_sm2_private_key();
	test_sm2_public_key_info();
	return 0;
}

