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
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <zephyr/random/random.h>

#define RAND_MAX_BUF_SIZE 4096

int rand_bytes(uint8_t *buf, size_t len)
{
	if (!buf) {
		error_print();
		return -1;
	}
	if (len > RAND_MAX_BUF_SIZE) {
		error_print();
		return -1;
	}
	if (!len) {
		return 0;
	}

	sys_rand_get(buf, len);

	return 1;
}
