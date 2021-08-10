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
#include <gmssl/pkcs8.h>
#include <gmssl/error.h>


static int test_pbkdf2_params(void)
{
	int err = 0;
	uint8_t salt[8] = {0};
	const uint8_t *psalt;
	size_t saltlen;
	int iter = 65536;
	int keylen;
	int prf = OID_hmac_sm3;
	uint8_t buf[128];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	keylen = -1;
	if (pbkdf2_params_to_der(salt, sizeof(salt), iter, keylen, prf, &p, &len) != 1) {
		error_print();
		err++;
		goto end;
	}
	if (pbkdf2_params_from_der(&psalt, &saltlen, &iter, &keylen, &prf, &cp, &len) != 1
		|| len > 0) {
		error_print();
		err++;
		goto end;
	}

	keylen = 16;
	if (pbkdf2_params_to_der(salt, sizeof(salt), iter, keylen, prf, &p, &len) != 1) {
		error_print();
		err++;
		goto end;
	}
	if (pbkdf2_params_from_der(&psalt, &saltlen, &iter, &keylen, &prf, &cp, &len) != 1
		|| len > 0) {
		error_print();
		err++;
		goto end;
	}
	printf("%s : ok\n", __func__);
end:
	return err;
}

static int test_pbkdf2_algor(void)
{
	int err = 0;
	uint8_t salt[8] = {0};
	const uint8_t *psalt;
	size_t saltlen;
	int iter = 65536;
	int keylen;
	int prf = OID_hmac_sm3;
	uint8_t buf[128];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	keylen = -1;
	if (pbkdf2_algor_to_der(salt, sizeof(salt), iter, keylen, prf, &p, &len) != 1) {
		error_print();
		err++;
		goto end;
	}
	if (pbkdf2_algor_from_der(&psalt, &saltlen, &iter, &keylen, &prf, &cp, &len) != 1
		|| len > 0) {
		error_print();
		err++;
		goto end;
	}
	printf("%s : ok\n", __func__);
end:
	return err;
}


static int test_pbes2_enc_algor(void)
{
	int err = 0;
	int cipher = OID_sm4_cbc;
	uint8_t iv[16] = {1};
	const uint8_t *piv;
	size_t ivlen;
	uint8_t buf[128];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	if (pbes2_enc_algor_to_der(OID_sm4_cbc, iv, sizeof(iv), &p, &len) != 1) {
		error_print();
		err++;
		goto end;
	}
	if (pbes2_enc_algor_from_der(&cipher, &piv, &ivlen, &cp, &len) != 1
		|| len > 0) {
		error_print();
		err++;
		goto end;
	}
	printf("%s : ok\n", __func__);
end:
	return err;
}

static int test_pbes2_params(void)
{
	int err = 0;
	uint8_t salt[8] = {0};
	const uint8_t *psalt;
	size_t saltlen;
	int iter = 65536;
	int prf = OID_hmac_sm3;
	int cipher = OID_sm4_cbc;
	uint8_t iv[16];
	const uint8_t *piv;
	size_t ivlen;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	if (pbes2_params_to_der(salt, sizeof(salt), iter, prf, cipher, iv, sizeof(iv), &p, &len) != 1) {
		error_print();
		err++;
		goto end;
	}
	if (pbes2_params_from_der(&psalt, &saltlen, &iter, &prf, &cipher, &piv, &ivlen, &cp, &len) != 1
		|| len > 0) {
		error_print();
		err++;
		goto end;
	}
	printf("%s : ok\n", __func__);
end:
	return err;
}

static int test_pbes2_algor(void)
{
	int err = 0;
	uint8_t salt[8] = {0};
	const uint8_t *psalt;
	size_t saltlen;
	int iter = 65536;
	int prf = OID_hmac_sm3;
	int cipher = OID_sm4_cbc;
	uint8_t iv[16];
	const uint8_t *piv;
	size_t ivlen;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	if (pbes2_algor_to_der(salt, sizeof(salt), iter, prf, cipher, iv, sizeof(iv), &p, &len) != 1) {
		error_print();
		err++;
		goto end;
	}
	if (pbes2_algor_from_der(&psalt, &saltlen, &iter, &prf, &cipher, &piv, &ivlen, &cp, &len) != 1
		|| len > 0) {
		error_print();
		err++;
		goto end;
	}
	printf("%s : ok\n", __func__);
end:
	return err;
}

static int test_pkcs8_enced_private_key_info(void)
{
	int err = 0;
	uint8_t salt[8] = {0};
	const uint8_t *psalt;
	size_t saltlen;
	int iter = 65536;
	int prf = OID_hmac_sm3;
	int cipher = OID_sm4_cbc;
	uint8_t iv[16];
	const uint8_t *piv;
	size_t ivlen;
	uint8_t enced[128];
	const uint8_t *penced;
	size_t encedlen;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	if (pkcs8_enced_private_key_info_to_der(salt, sizeof(salt), iter, prf, cipher, iv, sizeof(iv),
		enced, sizeof(enced), &p, &len) != 1) {
		error_print();
		err++;
		goto end;
	}
	if (pkcs8_enced_private_key_info_from_der(&psalt, &saltlen, &iter, &prf, &cipher, &piv, &ivlen,
		&penced, &encedlen, &cp, &len) != 1
		|| len > 0) {
		error_print();
		err++;
		goto end;
	}
	printf("%s : ok\n", __func__);
end:
	return err;
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

	sm2_keygen(&sm2_key);
	memcpy(&sm2_buf, &sm2_key, sizeof(sm2_key));
	//sm2_key_print(stdout, &sm2_key, 0, 0);

	if (sm2_enced_private_key_info_to_der(&sm2_key, "passowrd", &p, &len) != 1) {
		error_print();
		err++;
		goto end;
	}

	memset(&sm2_key, 0, sizeof(sm2_key));
	if (sm2_enced_private_key_info_from_der(&sm2_key, &attrs, &attrslen, "password", &cp, &len) != 1
		|| len > 0) {
		error_print();
		err++;
		goto end;
	}
	//sm2_key_print(stdout, &sm2_key, 0, 0);

	if (memcmp(&sm2_key, &sm2_buf, sizeof(sm2_key)) != 0) {
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
	int err = 0;
	err += test_pbkdf2_params();
	err += test_pbkdf2_algor();
	err += test_pbes2_enc_algor();
	err += test_pbes2_params();
	err += test_pbes2_algor();
	err += test_pkcs8_enced_private_key_info();
	err += test_pkcs8();
	return err;
}
