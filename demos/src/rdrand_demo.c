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
#include <gmssl/rdrand.h>
#include <gmssl/error.h>


int main(void)
{
	uint8_t buf[32];

	if (rdrand_bytes(buf, sizeof(buf)) != 1) {
		error_print();
		return -1;
	}

	format_bytes(stdout, 0, 0, "rdrand output", buf, sizeof(buf));

	return 0;
}
