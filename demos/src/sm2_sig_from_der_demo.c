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
#include <gmssl/hex.h>
#include <gmssl/error.h>


int main(void)
{
	SM2_SIGNATURE sig;
	uint8_t der[SM2_MAX_SIGNATURE_SIZE];
	size_t derlen;

	if (sm2_signature_from_der(&sig, &cp, &derlen) != 1) {
		fprintf(stderr, "sm2_signature_from_der() error\n");
		goto err;
	}

	if (dlen > 0) {
		fprintf(stderr, "signature followed by other data\n");
		goto err;
	}

err:
	return 0;
}
