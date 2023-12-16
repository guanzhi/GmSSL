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
#include <gmssl/sm4.h>

int main(void)
{
	printf("%lld\n", SM4_GCM_IV_MAX_SIZE);
	printf("%lld\n", SM4_GCM_MAX_AAD_SIZE);
	printf("%lld\n", SM4_GCM_MAX_PLAINTEXT_SIZE);
	return 0;
}
