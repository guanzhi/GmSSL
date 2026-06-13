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
#include <gmssl/base64.h>
#include <gmssl/error.h>


static int test_base64(void)
{
	uint8_t bin1[50];
	uint8_t bin2[100];
	uint8_t bin3[200];
	uint8_t buf1[8000] = {0};
	uint8_t buf2[8000] = {0};

	BASE64_CTX ctx;
	uint8_t *p;
	int len;

	memset(bin1, 0x01, sizeof(bin1));
	memset(bin2, 0xA5, sizeof(bin2));
	memset(bin3, 0xff, sizeof(bin3));


	p = buf1;
	base64_encode_init(&ctx);
	base64_encode_update(&ctx, bin1, sizeof(bin1), p, &len); p += len;
	base64_encode_update(&ctx, bin2, sizeof(bin2), p, &len); p += len;
	base64_encode_update(&ctx, bin3, sizeof(bin3), p, &len); p += len;
	base64_encode_finish(&ctx, p, &len); p += len;
	len = (int)(p - buf1);

	p = buf2;
	base64_decode_init(&ctx);
	base64_decode_update(&ctx, buf1, len, p, &len); p += len;
	base64_decode_finish(&ctx, p, &len); p += len;
	len = (int)(p - buf2);

	printf("base64 test ");
	if (len != sizeof(bin1) + sizeof(bin2) + sizeof(bin3)
		|| memcmp(buf2, bin1, sizeof(bin1)) != 0
		|| memcmp(buf2 + sizeof(bin1), bin2, sizeof(bin2)) != 0
		|| memcmp(buf2 + sizeof(bin1) + sizeof(bin2), bin3, sizeof(bin3)) != 0) {
		printf("failed\n");
		return -1;
	} else {
		printf("ok\n");
	}

	return 1;
}

struct base64_one_byte_buffer {
	uint8_t data[1];
	uint8_t canary[8];
};

static int test_base64_decode_update_ex_padding(void)
{
	const uint8_t in[] = "AA==";
	struct base64_one_byte_buffer buf;
	uint8_t original_canary[sizeof(buf.canary)];
	BASE64_CTX ctx;
	int len = 0;
	int ret;

	memset(&buf, 0xff, sizeof(buf));
	memset(buf.canary, 0xcc, sizeof(buf.canary));
	memcpy(original_canary, buf.canary, sizeof(original_canary));

	base64_decode_init(&ctx);
	ret = base64_decode_update_ex(&ctx, in, sizeof(in) - 1,
		buf.data, &len, sizeof(buf.data));
	if (ret != 0 || len != 1 || buf.data[0] != 0) {
		error_print();
		return -1;
	}
	if (memcmp(buf.canary, original_canary, sizeof(original_canary)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

struct base64_two_byte_buffer {
	uint8_t data[2];
	uint8_t canary[8];
};

static int test_base64_decode_update_ex_maxout(void)
{
	const uint8_t in[] = "AAAA";
	struct base64_two_byte_buffer buf;
	uint8_t original_canary[sizeof(buf.canary)];
	BASE64_CTX ctx;
	int len = 0;
	int ret;

	memset(&buf, 0xcc, sizeof(buf));
	memcpy(original_canary, buf.canary, sizeof(original_canary));

	base64_decode_init(&ctx);
	ret = base64_decode_update_ex(&ctx, in, sizeof(in) - 1,
		buf.data, &len, sizeof(buf.data));
	if (ret != -1 || len != 0) {
		error_print();
		return -1;
	}
	if (memcmp(buf.canary, original_canary, sizeof(original_canary)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_base64() != 1) goto err;
	if (test_base64_decode_update_ex_padding() != 1) goto err;
	if (test_base64_decode_update_ex_maxout() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return -1;
}
