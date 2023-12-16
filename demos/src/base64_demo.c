/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/base64.h>
#include <gmssl/error.h>
#include <gmssl/rand.h>

int main(void)
{
	BASE64_CTX ctx;

	uint8_t buf[200];
	char base64[400] = {0};
	uint8_t *in = buf;
	uint8_t *out = (uint8_t *)base64;
	int len;
	int i;
	int inlen = 47;

	rand_bytes(buf, sizeof(buf));

	base64_encode_init(&ctx);

	base64_encode_update(&ctx, in, inlen, out, &len);
	out += len;
	in += inlen;
	printf("1 %s\n", base64);

	base64_encode_update(&ctx, in, inlen, out, &len);
	out += len;
	in += inlen;
	printf("2 %s\n", base64);

	base64_encode_update(&ctx, in, 30, out, &len);
	out += len;
	in += 48;
	printf("3 %s\n", base64);

	base64_encode_update(&ctx, in, 30, out, &len);
	out += len;
	in += 48;
	printf("4 %s\n", base64);

	return 0;

}
