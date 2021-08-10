/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
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

