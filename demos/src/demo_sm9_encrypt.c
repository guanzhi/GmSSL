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
#include <gmssl/sm9.h>
#include <gmssl/error.h>


int main(void)
{
	SM9_ENC_MASTER_KEY master;
	SM9_ENC_MASTER_KEY master_public;
	SM9_ENC_KEY key;
	const char *id = "Alice";
	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len;
	char mbuf[256];
	size_t mlen;
	int ret;

	sm9_enc_master_key_generate(&master);
	sm9_enc_master_key_extract_key(&master, id, strlen(id), &key);

	sm9_enc_master_public_key_to_der(&master, &p, &len);
	sm9_enc_master_public_key_from_der(&master_public, &cp, &len);

	sm9_encrypt(&master_public, id, strlen(id), (uint8_t *)"hello", strlen("hello"), buf, &len);
	ret = sm9_decrypt(&key, id, strlen(id), buf, len, (uint8_t *)mbuf, &mlen);
	if (ret != 1) {
		fprintf(stderr, "decrypt failed\n");
		return 1;
	}
	mbuf[mlen] = 0;
	printf("decrypt result: %s\n", mbuf);

	return 0;
}
