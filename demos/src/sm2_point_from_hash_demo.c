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
#include <gmssl/rand.h>
#include <gmssl/error.h>


int main(void)
{
	SM2_POINT P;

	if (sm2_point_from_hash(&P, (uint8_t *)"Alice", strlen("Alice")) != 1) {
		fprintf(stderr, "sm2_point_from_hash() error\n");
		goto err;
	}

	sm2_point_print(stdout, 0, 0, "SM2_POINT = Hash(\"Alice\")", &P);

err:
	return 0;
}
