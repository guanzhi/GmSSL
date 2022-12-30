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
#include <assert.h>
#include <gmssl/sm2.h>
#include <gmssl/sm2_recover.h>
#include <gmssl/error.h>


static int test_sm2_signature_to_public_key_points(void)
{
	SM2_KEY key;
	uint8_t dgst[32] = {1,2,3,4};
	SM2_SIGNATURE sig;
	SM2_POINT points[4];
	size_t points_cnt, i;

	sm2_key_generate(&key);
	sm2_do_sign(&key, dgst, &sig);
	sm2_signature_to_public_key_points(&sig, dgst, points, &points_cnt);

	for (i = 0; i < points_cnt; i++) {
		int vr;
		sm2_point_print(stderr, 0, 0, "point", &points[i]);
		vr = sm2_do_verify((SM2_KEY *)&points[1], dgst, &sig);
		printf("verify = %d\n", vr);
	}
	return 1;
}

int main(void)
{
	if (test_sm2_signature_to_public_key_points() != 1) { error_print(); return -1; }
	return 0;
}
