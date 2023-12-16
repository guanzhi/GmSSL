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
#include <gmssl/mem.h>
#include <gmssl/sm2.h>
#include <gmssl/error.h>

int main(int argc, char **argv)
{
	char *prog = argv[0];
	char *keyfile;
	char *pass;
	FILE *keyfp = NULL;
	SM2_KEY sm2_key;
	uint8_t z[32];

	if (argc < 2) {
		fprintf(stderr, "usage: %s <key.pem> <pass>\n", prog);
		return -1;
	}
	keyfile = argv[1];

	if (!(keyfp = fopen(keyfile, "rb"))) {
		fprintf(stderr, "%s: open file '%s' failure\n", prog, keyfile);
		return -1;
	}
	if (sm2_public_key_info_from_pem(&sm2_key, keyfp) != 1) {
		fprintf(stderr, "%s: load key failure\n", prog);
		fclose(keyfp);
		return -1;
	}

	sm2_compute_z(z, &sm2_key.public_key, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID));
	format_bytes(stdout, 0, 0, "z", z, sizeof(z));

	fclose(keyfp);
	return 0;
}












