/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/digest.h>

const char *digests[] = {
	"md5",
	"sha1",
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
