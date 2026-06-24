/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/mem.h>
#include <gmssl/zuc.h>
#include <gmssl/hex.h>
#include <gmssl/endian.h>


static const char *usage =
	"-key hex -count num -bearer num -direction num [-in file|-in_hex hex] [-hex|-bin] [-out file]";

static const char *help =
"Options\n"
"\n"
"    -key hex             128-EIA3 integrity key, 16 bytes\n"
"    -count num           COUNT parameter, 32-bit integer, decimal or 0x-prefixed hex\n"
"    -bearer num          BEARER parameter, 5-bit integer in [0, 31]\n"
"    -direction num       DIRECTION parameter, 0 or 1\n"
"    -in_hex hex          Input message bytes in HEX format\n"
"    -in file | stdin     Input file path\n"
"                         `-in_hex` and `-in` should not be used together\n"
"                         If neither `-in_hex` nor `-in` specified, read from stdin\n"
"    -hex                 Output MAC as hex string (by default)\n"
"    -bin                 Output MAC as binary\n"
"                         `-hex` and `-bin` should not be used together\n"
"    -out file | stdout   Output file path. If not specified, output to stdout\n"
"\n"
"Examples\n"
"\n"
"    gmssl zuc_128_eia3 -key 00000000000000000000000000000000 \\\n"
"        -count 0 -bearer 0 -direction 0 -in_hex 00\n"
"\n";

static int parse_uint64(const char *s, uint64_t max, uint64_t *out)
{
	char *end = NULL;
	unsigned long long v;

	if (!s || !*s) {
		return -1;
	}
	errno = 0;
	v = strtoull(s, &end, 0);
	if (errno || *end || v > max) {
		return -1;
	}
	*out = (uint64_t)v;
	return 1;
}

static uint8_t *read_content(FILE *infp, size_t *outlen, const char *prog)
{
	const size_t initial_size = 4096;
	const size_t max_size = 512 * 1024 * 1024;
	uint8_t *buf = NULL;
	size_t bufsiz = initial_size;
	size_t len = 0;

	if (!(buf = (uint8_t *)malloc(bufsiz))) {
		fprintf(stderr, "gmssl %s: malloc failure\n", prog);
		return NULL;
	}
	for (;;) {
		size_t n;

		if (len == bufsiz) {
			uint8_t *tmp;

			if (bufsiz >= max_size) {
				fprintf(stderr, "gmssl %s: input too long, should be less than %zu\n", prog, max_size);
				free(buf);
				return NULL;
			}
			bufsiz *= 2;
			if (bufsiz > max_size) {
				bufsiz = max_size;
			}
			if (!(tmp = (uint8_t *)realloc(buf, bufsiz))) {
				fprintf(stderr, "gmssl %s: realloc failure\n", prog);
				free(buf);
				return NULL;
			}
			buf = tmp;
		}

		n = fread(buf + len, 1, bufsiz - len, infp);
		len += n;

		if (feof(infp)) {
			break;
		}
		if (ferror(infp)) {
			fprintf(stderr, "gmssl %s: read failure : %s\n", prog, strerror(errno));
			free(buf);
			return NULL;
		}
	}

	*outlen = len;
	return buf;
}

int zuc_128_eia3_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *keyhex = NULL;
	char *inhex = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	int outformat = 0;
	uint8_t key[ZUC_KEY_SIZE];
	size_t keylen;
	uint8_t *in = NULL;
	size_t inlen = 0;
	size_t nbits;
	size_t nbytes = 0;
	uint64_t v;
	ZUC_UINT32 count = 0;
	ZUC_UINT5 bearer = 0;
	ZUC_BIT direction = 0;
	ZUC_UINT32 macword;
	uint8_t mac[ZUC_MAC_SIZE];
	int count_set = 0;
	int bearer_set = 0;
	int direction_set = 0;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	size_t i;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: gmssl %s %s\n", prog, usage);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: gmssl %s %s\n", prog, usage);
			printf("%s\n", help);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyhex = *(++argv);
			if (strlen(keyhex) != sizeof(key) * 2) {
				fprintf(stderr, "gmssl %s: key should be 16 bytes\n", prog);
				goto end;
			}
			if (hex_to_bytes(keyhex, strlen(keyhex), key, &keylen) != 1) {
				fprintf(stderr, "gmssl %s: invalid key hex digits\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-count")) {
			if (--argc < 1) goto bad;
			if (parse_uint64(*(++argv), UINT32_MAX, &v) != 1) {
				fprintf(stderr, "gmssl %s: invalid COUNT value\n", prog);
				goto end;
			}
			count = (ZUC_UINT32)v;
			count_set = 1;
		} else if (!strcmp(*argv, "-bearer")) {
			if (--argc < 1) goto bad;
			if (parse_uint64(*(++argv), 31, &v) != 1) {
				fprintf(stderr, "gmssl %s: invalid BEARER value\n", prog);
				goto end;
			}
			bearer = (ZUC_UINT5)v;
			bearer_set = 1;
		} else if (!strcmp(*argv, "-direction")) {
			if (--argc < 1) goto bad;
			if (parse_uint64(*(++argv), 1, &v) != 1) {
				fprintf(stderr, "gmssl %s: invalid DIRECTION value\n", prog);
				goto end;
			}
			direction = (ZUC_BIT)v;
			direction_set = 1;
		} else if (!strcmp(*argv, "-in_hex")) {
			if (infile) {
				fprintf(stderr, "gmssl %s: `-in` and `-in_hex` should not be used together\n", prog);
				goto end;
			}
			if (--argc < 1) goto bad;
			inhex = *(++argv);
		} else if (!strcmp(*argv, "-in")) {
			if (inhex) {
				fprintf(stderr, "gmssl %s: `-in` and `-in_hex` should not be used together\n", prog);
				goto end;
			}
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "rb"))) {
				fprintf(stderr, "gmssl %s: open '%s' failure : %s\n", prog, infile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-hex")) {
			if (outformat == 2) {
				fprintf(stderr, "gmssl %s: `-hex` and `-bin` should not be used together\n", prog);
				goto end;
			}
			outformat = 1;
		} else if (!strcmp(*argv, "-bin")) {
			if (outformat == 1) {
				fprintf(stderr, "gmssl %s: `-hex` and `-bin` should not be used together\n", prog);
				goto end;
			}
			outformat = 2;
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

	if (!keyhex) {
		fprintf(stderr, "gmssl %s: option '-key' required\n", prog);
		goto end;
	}
	if (!count_set || !bearer_set || !direction_set) {
		fprintf(stderr, "gmssl %s: options '-count', '-bearer' and '-direction' are required\n", prog);
		goto end;
	}

	if (inhex) {
		if (strlen(inhex) % 2) {
			fprintf(stderr, "gmssl %s: invalid input hex length\n", prog);
			goto end;
		}
		nbytes = strlen(inhex) / 2;
		if (!(in = (uint8_t *)malloc(nbytes ? nbytes : 1))) {
			fprintf(stderr, "gmssl %s: malloc failure\n", prog);
			goto end;
		}
		if (hex_to_bytes(inhex, strlen(inhex), in, &inlen) != 1) {
			fprintf(stderr, "gmssl %s: invalid input hex digits\n", prog);
			goto end;
		}
	} else if (!(in = read_content(infp, &inlen, prog))) {
		goto end;
	}
	nbytes = inlen;
	nbits = inlen * 8;

	macword = zuc_eia_generate_mac((ZUC_UINT32 *)in, nbits, key, count, bearer, direction);
	PUTU32(mac, macword);

	if (outformat == 2) {
		if (fwrite(mac, 1, sizeof(mac), outfp) != sizeof(mac)) {
			fprintf(stderr, "gmssl %s: output failure : %s\n", prog, strerror(errno));
			goto end;
		}
	} else {
		for (i = 0; i < sizeof(mac); i++) {
			fprintf(outfp, "%02x", mac[i]);
		}
		fprintf(outfp, "\n");
	}

	ret = 0;

end:
	gmssl_secure_clear(key, sizeof(key));
	gmssl_secure_clear(mac, sizeof(mac));
	if (in) {
		gmssl_secure_clear(in, inlen);
		free(in);
	}
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
