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
#include <gmssl/digest.h>

const char *digests[] = {
	"sm3",
#ifdef ENABLE_SHA1
	"sha1",
#endif
#ifdef ENABLE_SHA2
	"sha224",
	"sha256",
	"sha384",
	"sha512",
	"sha512-224",
	"sha512-256",
#endif
};

int main(void)
{
	int err = 0;
	uint8_t dgst[64];
	size_t dgstlen;
	size_t i, j;

	for (i = 0; i < sizeof(digests)/sizeof(digests[0]); i++) {
		const DIGEST *algor = digest_from_name(digests[i]);
		DIGEST_CTX ctx;

		if (digest(algor, (uint8_t *)"abc", 3, dgst, &dgstlen) != 1) {
			printf("%s digest failed\n", digests[i]);
			err++;
			continue;
		}

		printf("%s (%zu) ", digests[i], dgstlen);
		for (j = 0; j < dgstlen; j++) {
			printf("%02x", dgst[j]);
		}
		printf("\n");

		if (digest_init(&ctx, algor) != 1
			|| digest_update(&ctx, NULL, 0) != 1
			|| digest_finish(&ctx, dgst, &dgstlen) != 1) {
			printf("%s empty update failed\n", digests[i]);
			err++;
		}

		if (digest(algor, NULL, 0, dgst, &dgstlen) != 1) {
			printf("%s empty digest failed\n", digests[i]);
			err++;
		}
	}

	return err;
}
