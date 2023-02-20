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
#include <gmssl/mem.h>
#include <gmssl/sm2.h>


int main(int argc, char **argv)
{
	int ret = -1;
	char *prog = argv[0];
	char *keyfile;
	char *pass;
	FILE *keyfp = NULL;
	SM2_KEY sm2_key;

	if (argc < 3) {
		fprintf(stderr, "usage: %s <key.pem> <pass>\n", prog);
		return -1;
	}
	keyfile = argv[1];
	pass = argv[2];

	if (!(keyfp = fopen(keyfile, "rb"))) {
		fprintf(stderr, "%s: open file '%s' failure\n", prog, keyfile);
		return -1;
	}
	if (sm2_private_key_info_decrypt_from_pem(&sm2_key, pass, keyfp) != 1) {
		fprintf(stderr, "%s: load key failure\n", prog);
		goto end;
	}
	if (sm2_private_key_info_to_pem(&sm2_key, stdout) != 1) {
		fprintf(stderr, "%s: export failure\n", prog);
		goto end;
	}
	ret = 0;

end:
	gmssl_secure_clear(&sm2_key, sizeof(sm2_key));
	if (keyfp) fclose(keyfp);
	return ret;
}












