/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/mem.h>
#include <gmssl/hex.h>
#include <gmssl/sm3.h>


static const char *usage = "-pass str -salt hex -iter num -outlen num [-bin|-hex] [-out file]";

static const char *options =
"\n"
"Options\n"
"\n"
"    -pass str           Password to be converted into key\n"
"    -salt hex           Salt value, 8 to 64 bytes\n"
"    -iter num           Iteration count, larger iter make it more secure but slower\n"
"    -outlen num         Generate key bytes\n"
"    -bin                Output binary key\n"
"    -hex                Output key in hex digits\n"
"    -out file | stdout  Output data\n"
"\n"
"Examples\n"
"\n"
"  $ SALT=`gmssl rand -outlen 8 -hex`\n"
"  $ gmssl sm3_pbkdf2 -pass P@ssw0rd -salt $SALT -iter 10000 -outlen 16 -hex\n"
"\n";


int sm3_pbkdf2_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *pass = NULL;
	char *salthex = NULL;
	uint8_t salt[SM3_PBKDF2_MAX_SALT_SIZE];
	size_t saltlen;
	int iter = 0;
	int outlen = 0;
	int bin = 0;
	char *outfile = NULL;
	uint8_t outbuf[64];
	FILE *outfp = stdout;
	int i;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: gmssl %s %s\n", prog, usage);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: gmssl %s %s\n", prog, options);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
		} else if (!strcmp(*argv, "-salt")) {
			if (--argc < 1) goto bad;
			salthex = *(++argv);
			if (strlen(salthex) > sizeof(salt) * 2) {
				fprintf(stderr, "gmssl %s: invalid salt length\n", prog);
				goto end;
			}
			if (hex_to_bytes(salthex, strlen(salthex), salt, &saltlen) != 1) {
				fprintf(stderr, "gmssl %s: invalid HEX digits\n", prog);
				goto end;
			}
			if (saltlen < 1 || saltlen > SM3_PBKDF2_MAX_SALT_SIZE) {
				fprintf(stderr, "gmssl %s: invalid salt length\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-iter")) {
			if (--argc < 1) goto bad;
			iter = atoi(*(++argv));
			if (iter < SM3_PBKDF2_MIN_ITER || iter > SM3_PBKDF2_MAX_ITER) {
				fprintf(stderr, "gmssl %s: invalid '-iter' value\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-outlen")) {
			if (--argc < 1) goto bad;
			outlen = atoi(*(++argv));
			if (outlen < 1 || outlen > sizeof(outbuf)) {
				fprintf(stderr, "gmssl %s: invalid outlen\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-hex")) {
			bin = 0;
		} else if (!strcmp(*argv, "-bin")) {
			bin = 1;
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

	if (!pass) {
		fprintf(stderr, "gmssl %s: option '-pass' required\n", prog);
		goto end;
	}
	if (!salthex) {
		fprintf(stderr, "gmssl %s: option '-salt' required\n", prog);
		goto end;
	}
	if (!iter) {
		fprintf(stderr, "gmssl %s: option '-iter' required\n", prog);
		goto end;
	}
	if (!outlen) {
		fprintf(stderr, "gmssl %s: option '-outlen' required\n", prog);
		goto end;
	}

	if (sm3_pbkdf2(pass, strlen(pass), salt, saltlen, iter, outlen, outbuf) != 1) {
		fprintf(stderr, "gmssl %s: inner error\n", prog);
		goto end;
	}

	if (bin) {
		if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
			fprintf(stderr, "gmssl %s: output failure : %s\n", prog, strerror(errno));
			goto end;
		}
	} else {
		for (i = 0; i < outlen; i++) {
			fprintf(outfp, "%02x", outbuf[i]);
		}
		fprintf(outfp, "\n");
	}
	ret = 0;

end:
	gmssl_secure_clear(outbuf, sizeof(outbuf));
	gmssl_secure_clear(salt, sizeof(salt));
	if (outfile && outfp) fclose(outfp);
	return ret;
}
