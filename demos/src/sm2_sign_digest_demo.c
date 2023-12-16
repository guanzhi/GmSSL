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


int main(void)
{
	SM2_KEY sm2_key;
	uint8_t dgst[32];
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE] = {0};
	size_t siglen;

	sm2_key_generate(&sm2_key);
	sm3_digest((uint8_t *)"abc", 3, dgst);

	if (sm2_sign(&key, 


	return 0;
}
