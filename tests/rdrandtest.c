/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/rdrand.h>
#include <gmssl/error.h>


int test_rdrand(void)
{
	const uint8_t zeros[32] = {0};
	uint8_t buf[32] = {0};

	if (rdrand_bytes(buf, sizeof(buf)) != 1) {
		error_print();
		return -1;
	}
	if (memcmp(buf, zeros, sizeof(zeros)) == 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int test_rdseed(void)
{
	const uint8_t zeros[32] = {0};
	uint8_t buf[32] = {0};

	if (rdseed_bytes(buf, sizeof(buf)) != 1) {
		error_print();
		return -1;
	}
	if (memcmp(buf, zeros, sizeof(zeros)) == 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_rdrand() != 1) goto err;
	if (test_rdseed() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
