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
#include <gmssl/version.h>


int main(int argc, char **argv)
{
	if (gmssl_version_num() < 30100) {
		fprintf(stderr, "GmSSL version is lower than 3.0.0\n");
		return 1;
	}
	printf("GmSSL version: %s\n", gmssl_version_str());

	return 0;
}
