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
#include <gmssl/sm2.h>
#include <gmssl/error.h>

void gen_ciphertext(void)
{
	SM2_KEY sm2_key;
	SM2_CIPHERTEXT ciphertext;

	sm2_key_generate(&sm2_key);
	sm2_do_encrypt(&sm2_key, (uint8_t *)"P@ssw0rd", 8, &ciphertext);

	// 这里我们需要把密文的各个部分输出乘C的数组
}


// 这个例子要把一个来自于其他软件的密文转换为GmSSL的密文
int main(void)
{
	SM2_CIPHERTEXT C;
	uint8_t ciphertext_der[SM2_MAX_CIPHERTEXT_SIZE];

	if (sm2_ciphertext_to_der(&C, &p, &len) != 1) {
		fprintf(stderr, "sm2_ciphertext_to_der() error\n");
		goto err;
	}

	format_bytes(stdout, 0, 0, "Ciphertext", der, derlen);

	return 0;
}
