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
#include <stdint.h>
#include <unistd.h> // in Linux
#ifdef APPLE
#include <sys/random.h> // in Apple
#endif
#include <gmssl/rand.h>
#include <gmssl/error.h>


#define RAND_MAX_BUF_SIZE 256 // requirement of getentropy()

int rand_bytes(uint8_t *buf, size_t len)
{
	if (!buf) {
		error_print();
		return -1;
	}
	if (!len || len > RAND_MAX_BUF_SIZE) {
		error_print();
		return -1;
	}
	if (getentropy(buf, len) != 0) {
		error_print();
		return -1;
	}
	return 1;
}
