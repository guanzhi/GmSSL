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
#include <gmssl/error.h>


int main(void)
{
	SM2_KEY sm2_key;
	SM2_POINT P;
	uint8_t compressed[33] = {0};
	uint8_t uncompressed[65] = {0};

	sm2_key_generate(&sm2_key);
	P = sm2_key.public_key;

	sm2_point_to_uncompressed_octets(&P, uncompressed);
	format_bytes(stdout, 0, 0, "SM2 Point (uncompressed) ", uncompressed, 65);

	sm2_point_to_compressed_octets(&P, compressed);
	format_bytes(stdout, 0, 0, "SM2 Point (compressed)   ", compressed, 33);

	return 0;
}
