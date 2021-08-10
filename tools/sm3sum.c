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
#include <gmssl/sm3.h>


int main(int argc, char **argv)
{
	char *prog = argv[0];
	SM3_CTX ctx;
	uint8_t dgst[32];
	uint8_t buf[4096];
	ssize_t len;
	int i;

	if (argc > 1) {
		fprintf(stderr, "usage: echo -n \"abc\" | %s\n", prog);
		fprintf(stderr, "       %s < path/to/file\n", prog);
		return 0;
	}

	sm3_init(&ctx);
	while ((len = fread(buf, 1, sizeof(buf), stdin)) > 0) {
		sm3_update(&ctx, buf, len);
	}
	sm3_finish(&ctx, dgst);

	for (i = 0; i < sizeof(dgst); i++) {
		printf("%02x", dgst[i]);
	}
	printf("\n");
	return 0;
}
