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
	SM2_POINT A;
	SM2_POINT B;
	SM2_POINT C;
	uint8_t a[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3};
	uint8_t b[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5};
	uint8_t c[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4};
	uint8_t zero[32] = {0};

	sm2_point_mul_generator(&A, a);
	sm2_point_mul_generator(&B, b);
	sm2_point_mul_generator(&C, c);

	printf("G is the generator point on SM2 curve\n");
	sm2_point_print(stdout, 0, 0, "3G", &A);
	sm2_point_print(stdout, 0, 0, "5G", &B);
	sm2_point_print(stdout, 0, 0, "4G", &C);

	sm2_point_add(&A, &A, &B);
	sm2_point_dbl(&C, &C);

	sm2_point_print(stdout, 0, 0, "3G + 5G", &A);
	sm2_point_print(stdout, 0, 0, "2 * 4G", &C);

	sm2_point_mul_generator(&C, c);
	sm2_point_add(&C, &C, &C);

	sm2_point_print(stdout, 0, 0, "4G + 4G", &C);

	sm2_point_mul_generator(&C, zero);
	sm2_point_print(stdout, 0, 0, "0 * G", &C);

	if (sm2_point_is_on_curve(&C) == 1) {
		printf("0 * G is on SM2 curve\n");
	}

	return 0;
}
