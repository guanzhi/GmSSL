/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <gmssl/sdf.h>


static const char *usage = "-lib so_path {-sign|-encrypt} -key num [-out file]";

static const char *options =
"\n"
"Options\n"
"\n"
"    -lib so_path         Vendor's SDF dynamic library\n"
"    -sign                Export signing public key\n"
"    -encrypt             Export encryption public key\n"
"    -key num             Private key index number\n"
"    -out file | stdout   Output public key in PEM format\n"
"\n"
"Examples\n"
"\n"
"    $ gmssl sdfexport -sign -key 1 -out sm2signpub.pem\n"
"    $ gmssl sdfexport -encrypt -key 1 -out sm2signpub.pem\n"
"\n";


int sdfexport_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *lib = NULL;
	int sign_public_key = 0;
	int enc_public_key = 0;
	int index = -1;
	char *outfile = NULL;
	FILE *outfp = stdout;
	SDF_DEVICE dev;
	SM2_KEY sm2_key;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: gmssl %s %s\n", prog, usage);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: gmssl %s %s\n", prog, usage);
			printf("%s\n", options);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-lib")) {
			if (--argc < 1) goto bad;
			lib = *(++argv);
		} else if (!strcmp(*argv, "-sign")) {
			if (enc_public_key) {
				fprintf(stderr, "gmssl %s: '-sign' and '-encrypt' should not used together\n", prog);
				goto end;
			}
			sign_public_key = 1;
		} else if (!strcmp(*argv, "-encrypt")) {
			if (sign_public_key) {
				fprintf(stderr, "gmssl %s: '-sign' and '-encrypt' should not used together\n", prog);
				goto end;
			}
			enc_public_key = 1;
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			index = atoi(*(++argv));
			if (index < 0) {
				fprintf(stderr, "gmssl %s: illegal key index %d\n", prog, index);
				goto end;
			}
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "wb"))) {
				fprintf(stderr, "gmssl %s: open '%s' failure : %s\n", prog, outfile, strerror(errno));
				goto end;
			}
		} else {
			fprintf(stderr, "gmssl %s: illegal option '%s'\n", prog, *argv);
			goto end;
bad:
			fprintf(stderr, "gmssl %s: '%s' option value missing\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}

	if (!lib) {
		fprintf(stderr, "gmssl %s: option '-lib' required\n", prog);
		goto end;
	}
	if (!sign_public_key && !enc_public_key) {
		fprintf(stderr, "gmssl %s: '-sign' or '-encrypt' option required\n", prog);
		goto end;
	}
	if (index < 0) {
		fprintf(stderr, "gmssl %s: '-index' option required\n", prog);
		goto end;
	}

	if (sdf_load_library(lib, NULL) != 1) {
		fprintf(stderr, "gmssl %s: load library failure\n", prog);
		goto end;
	}
	if (sdf_open_device(&dev) != 1) {
		fprintf(stderr, "gmssl %s: open device failure\n", prog);
		goto end;
	}

	if (sign_public_key) {
		if (sdf_export_sign_public_key(&dev, index, &sm2_key) != 1) {
			fprintf(stderr, "%s: load sign key failed\n", prog);
			goto end;
		}
	} else {
		if (sdf_export_encrypt_public_key(&dev, index, &sm2_key) != 1) {
			fprintf(stderr, "%s: load sign key failed\n", prog);
			goto end;
		}
	}
	if (sm2_public_key_info_to_pem(&sm2_key, outfp) != 1) {
		fprintf(stderr, "gmssl %s: output public key to PEM failed\n", prog);
		goto end;
	}

	sdf_close_device(&dev);

	ret = 0;
end:
	if (lib) sdf_unload_library();
	return ret;
}
