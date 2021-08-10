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
#include <gmssl/base64.h>
#include <gmssl/error.h>

int test_base64(void)
{
	uint8_t bin1[50];
	uint8_t bin2[100];
	uint8_t bin3[200];
	uint8_t buf1[8000] = {0};
	uint8_t buf2[8000] = {0};

	int err = 0;
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
	printf("%s\n", buf1);


	p = buf2;
	base64_decode_init(&ctx);
	base64_decode_update(&ctx, buf1, len, p, &len); p += len;
	base64_decode_finish(&ctx, p, &len); p += len;
	len = (int)(p - buf2);

	printf("len = %d\n", len);
	print_der(buf2, len);
	printf("\n");

	return err;
}

int main(void)
{
	test_base64();
	return 0;
}









