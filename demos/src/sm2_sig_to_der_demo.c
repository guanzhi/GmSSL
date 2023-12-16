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


int main(void)
{
	SM2_KEY sm2_key;
	uint8_t dgst[32] = {0};

	SM2_SIGNATURE sig;
	uint8_t der[SM2_MAX_SIGNATURE_SIZE];
	uint8_t *p = der;
	size_t derlen = 0;

	sm2_key_generate(&sm2_key);
	sm2_do_sign(&sm2_key, dgst, &sig);

	if (sm2_signature_to_der(&sig, &p, &derlen) != 1) {
		fprintf(stderr, "sm2_signature_to_der() error\n");
		return -1;
	}

	format_bytes(stdout, 0, 0, "signature", der, derlen);
	printf("signature length = %zu bytes\n", derlen);

	return 0;
}
