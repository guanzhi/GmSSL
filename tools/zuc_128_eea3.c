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
	"-key hex -count num -bearer num -direction num [-in file] [-out file]";

static const char *help =
"Options\n"
"\n"
"    -key hex             128-EEA3 confidentiality key, 16 bytes\n"
"    -count num           COUNT parameter, 32-bit integer, decimal or 0x-prefixed hex\n"
"    -bearer num          BEARER parameter, 5-bit integer in [0, 31]\n"
"    -direction num       DIRECTION parameter, 0 or 1\n"
"    -in file | stdin     Input file path. If not specified, read from stdin\n"
"    -out file | stdout   Output ciphertext bytes. If not specified, output to stdout\n"
"\n"
"Examples\n"
"\n"
"    gmssl zuc_128_eea3 -key 173d14ba5003731d7a60049470f00a29 \\\n"
"        -count 0x66035492 -bearer 15 -direction 0 \\\n"
"        -in plaintext.bin -out ciphertext.bin\n"
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

int zuc_128_eea3_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *keyhex = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	uint8_t key[ZUC_KEY_SIZE];
	size_t keylen;
	uint8_t *in = NULL;
	size_t inlen = 0;
	uint8_t *padded = NULL;
	ZUC_UINT32 *inwords = NULL;
	ZUC_UINT32 *outwords = NULL;
	uint8_t *out = NULL;
	size_t nbits;
	size_t nbytes = 0;
	size_t nwords = 0;
	size_t i;
	uint64_t v;
	ZUC_UINT32 count = 0;
	ZUC_UINT5 bearer = 0;
	ZUC_BIT direction = 0;
	int count_set = 0;
	int bearer_set = 0;
	int direction_set = 0;
	FILE *infp = stdin;
	FILE *outfp = stdout;

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
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "rb"))) {
				fprintf(stderr, "gmssl %s: open '%s' failure : %s\n", prog, infile, strerror(errno));
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

	if (!keyhex) {
		fprintf(stderr, "gmssl %s: option '-key' required\n", prog);
		goto end;
	}
	if (!count_set || !bearer_set || !direction_set) {
		fprintf(stderr, "gmssl %s: options '-count', '-bearer' and '-direction' are required\n", prog);
		goto end;
	}

	if (!(in = read_content(infp, &inlen, prog))) {
		goto end;
	}
	nbytes = inlen;
	nbits = inlen * 8;
	nwords = (nbits + 31) / 32;

	if (!(padded = (uint8_t *)calloc(nwords ? nwords : 1, sizeof(uint32_t)))
		|| !(inwords = (ZUC_UINT32 *)calloc(nwords ? nwords : 1, sizeof(uint32_t)))
		|| !(outwords = (ZUC_UINT32 *)calloc(nwords ? nwords : 1, sizeof(uint32_t)))
		|| !(out = (uint8_t *)calloc(nwords ? nwords : 1, sizeof(uint32_t)))) {
		fprintf(stderr, "gmssl %s: malloc failure\n", prog);
		goto end;
	}
	memcpy(padded, in, inlen);
	for (i = 0; i < nwords; i++) {
		inwords[i] = GETU32(padded + i * 4);
	}

	zuc_eea_encrypt(inwords, outwords, nbits, key, count, bearer, direction);
	for (i = 0; i < nwords; i++) {
		PUTU32(out + i * 4, outwords[i]);
	}

	if (nbytes && fwrite(out, 1, nbytes, outfp) != nbytes) {
		fprintf(stderr, "gmssl %s: output failure : %s\n", prog, strerror(errno));
		goto end;
	}

	ret = 0;

end:
	gmssl_secure_clear(key, sizeof(key));
	if (in) {
		gmssl_secure_clear(in, inlen);
		free(in);
	}
	if (padded) {
		gmssl_secure_clear(padded, (nwords ? nwords : 1) * sizeof(uint32_t));
		free(padded);
	}
	if (inwords) {
		gmssl_secure_clear(inwords, (nwords ? nwords : 1) * sizeof(uint32_t));
		free(inwords);
	}
	if (outwords) {
		gmssl_secure_clear(outwords, (nwords ? nwords : 1) * sizeof(uint32_t));
		free(outwords);
	}
	if (out) {
		gmssl_secure_clear(out, (nwords ? nwords : 1) * sizeof(uint32_t));
		free(out);
	}
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
