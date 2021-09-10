/*
 * Copyright (c) 2014 - 2021 The GmSSL Project.  All rights reserved.
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









