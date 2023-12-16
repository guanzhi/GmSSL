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
	SM2_SIGNATURE sig;

	// the signatue binary data might be invalid, and will not pass verification
	uint8_t r[32] = { 1, 2, 3, };
	uint8_t s[32] = { 4, 5, 6, };

	memcpy(sig.r, r, 32);
	memcpy(sig.s, s, 32);

	return 0;
}
