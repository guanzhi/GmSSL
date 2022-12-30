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
#include <gmssl/sm2.h>
#include <gmssl/sm2_commit.h>
#include <gmssl/error.h>


static int test_sm2_commit(void)
{
	uint8_t x[32];
	uint8_t xvec[8][32];
	uint8_t r[32];
	uint8_t commit[65];
	size_t commitlen;
	int ret;

	rand_bytes(x, sizeof(x));
	format_bytes(stderr, 0, 0, "secret", x, sizeof(x));

	sm2_commit_generate(x, r, commit, &commitlen);
	format_bytes(stderr, 0, 0, "random", r, sizeof(r));
	format_bytes(stderr, 0, 0, "commitment", commit, commitlen);

	ret = sm2_commit_open(x, r, commit, commitlen);
	printf("open commitment: %s\n", ret == 1 ? "success" : "failure");


	sm2_commit_vector_generate(&x, 1, r, commit, &commitlen);
	format_bytes(stderr, 0, 0, "random", r, sizeof(r));
	format_bytes(stderr, 0, 0, "commitment", commit, commitlen);

	ret = sm2_commit_vector_open(&x, 1, r, commit, commitlen);
	printf("open commitment: %s\n", ret == 1 ? "success" : "failure");


	rand_bytes(xvec[0], sizeof(xvec));
	sm2_commit_vector_generate(xvec, 8, r, commit, &commitlen);
	ret = sm2_commit_vector_open(xvec, 8, r, commit, commitlen);
	printf("open commitment: %s\n", ret == 1 ? "success" : "failure");

	return 1;
}

int main(void)
{
	if (test_sm2_commit() != 1) { error_print(); return -1; }
	return 0;
}
