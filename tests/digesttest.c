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
#include <gmssl/digest.h>

const char *digests[] = {
#ifdef ENABLE_BROKEN_CRYPTO
	"md5",
	"sha1",
#endif
	"sm3",
	"sha224",
	"sha256",
	"sha384",
	"sha512",
	"sha512-224",
	"sha512-256",
};

int main(void)
{
	uint8_t dgst[64];
	size_t dgstlen;
	size_t i, j;

	for (i = 0; i < sizeof(digests)/sizeof(digests[0]); i++) {
		const DIGEST *algor = digest_from_name(digests[i]);
		digest(algor, (uint8_t *)"abc", 3, dgst, &dgstlen);

		printf("%s (%zu) ", digests[i], dgstlen);
		for (j = 0; j < dgstlen; j++) {
			printf("%02x", dgst[j]);
		}
		printf("\n");
	}

	return 0;
}
