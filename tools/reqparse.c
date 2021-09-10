<<<<<<< HEAD:tools/reqparse.c
﻿/*
 * Copyright (c) 2020 - 2021 The GmSSL Project.  All rights reserved.
=======
/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
>>>>>>> 5fc13a8aefa3fb395f32927e35dda4210a3c1a23:tools/pkcs8view.c
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
#include <gmssl/pem.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>


int main(int argc, char **argv)
{
	char *prog = argv[0];
	char *infile = NULL;
	X509_CERT_REQUEST req;
	FILE *infp = stdin;

	argc--;
	argv++;

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
help:
			fprintf(stderr, "usage: %s [-in file]\n", prog);
			return -1;

		} else if(!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);

		} else {
			fprintf(stderr, "%s: illegal option '%s'\n", prog, *argv);
			goto help;
		}

		argc--;
		argv++;
	}

	if (infile) {
		if (!(infp = fopen(infile, "r"))) {
			error_print();
			return -1;
		}
	}

	int ret = x509_cert_request_from_pem(&req, infp);
	if (ret < 0) {
		error_print();
		return -1;
	}
	if (ret == 0) {
		error_print();
		return -1;
	}
	x509_cert_request_print(stdout, &req, 0, 0);
	return 0;

bad:
	fprintf(stderr, "%s: '%s' option value required\n", prog, *argv);
	return -1;
}
