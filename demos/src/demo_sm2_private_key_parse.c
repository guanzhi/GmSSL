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
#include <gmssl/mem.h>
#include <gmssl/sm2.h>
#include <gmssl/error.h>

int main(void)
{
	SM2_KEY sm2_key;
	char *password = "123456";
	unsigned char buf[512];
	unsigned char *p;
	size_t len;

	printf("Read SM2 private key file (PEM) from stdin ...\n");
	if (sm2_private_key_info_decrypt_from_pem(&sm2_key, password, stdin) != 1) {
		fprintf(stderr, "error\n");
		return 1;
	}

	p = buf;
	len = 0;
	if (sm2_private_key_to_der(&sm2_key, &p, &len) != 1) {
		fprintf(stderr, "error\n");
		return 1;
	}
	format_bytes(stdout, 0, 0, "buf", buf, len);
	sm2_key_print(stdout, 0, 0, "SM2PrivateKey", &sm2_key);

	gmssl_secure_clear(&sm2_key, sizeof(sm2_key));
	return 0;
}
