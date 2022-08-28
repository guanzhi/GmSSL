/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/oid.h>
#include <gmssl/x509.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/tls.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>


static int test_tls13_gcm(void)
{

	BLOCK_CIPHER_KEY block_key;
	uint8_t key[16];
	uint8_t iv[12];
	uint8_t seq_num[8] = {0,0,0,0,0,0,0,1};
	int record_type = TLS_record_handshake;
	uint8_t in[40];
	size_t padding_len = 8;
	uint8_t out[256];
	size_t outlen;
	uint8_t buf[256];
	size_t buflen;

	rand_bytes(key, sizeof(key));
	rand_bytes(iv, sizeof(iv));
	rand_bytes(in, sizeof(in));

	memset(out, 1, sizeof(out));
	outlen = 0;
	memset(buf, 1, sizeof(buf));
	buflen = 0;

	if (block_cipher_set_encrypt_key(&block_key, BLOCK_CIPHER_sm4(), key) != 1) {
		error_print();
		return -1;
	}

	if (tls13_gcm_encrypt(&block_key, iv, seq_num, record_type, in, sizeof(in), padding_len, out, &outlen) != 1) {
		error_print();
		return -1;
	}
	if (tls13_gcm_decrypt(&block_key, iv, seq_num, out, outlen, &record_type, buf, &buflen) != 1) {
		error_print();
		return -1;
	}

	if (buflen != sizeof(in)) {
		error_print();
		return -1;
	}
	if (memcmp(in, buf, buflen) != 0) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_tls13_gcm() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return -1;
}
