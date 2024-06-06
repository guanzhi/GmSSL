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


static const char *usage = "-lib so_path";

static const char *options =
"\n"
"Options\n"
"\n"
"    -lib so_path        Vendor's SDF dynamic library\n"
"\n"
"Examples\n"
"\n"
"    $ gmssl sdfinfo\n"
"\n";


int sdfinfo_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *lib = NULL;
	SDF_DEVICE dev;

	memset(&dev, 0, sizeof(dev));

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

	if (sdf_load_library(lib, NULL) != 1) {
		fprintf(stderr, "gmssl %s: load library failure\n", prog);
		goto end;
	}

	if (sdf_open_device(&dev) != 1) {
		fprintf(stderr, "gmssl %s: open device failure\n", prog);
		goto end;
	}

	sdf_print_device_info(stdout, 0, 0, "SDF", &dev);

	sdf_close_device(&dev);

	ret = 0;
end:
	if (lib) sdf_unload_library();
	return ret;
}
