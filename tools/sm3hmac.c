/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
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


static const char *usage = "-key hex [-in file | -in_str str] [-bin|-hex] [-out file]";

static const char *help =
"Options\n"
"\n"
"    -key hex               Hex string of the MAC key\n"
"    -in_str str            Input as text string\n"
"    -in file | stdin       Input file path\n"
"                           `-in_str` and `-in` should not be used together\n"
"                           If neither `-in` nor `-in_str` specified, read from stdin\n"
"    -hex                   Output MAC-tag as hex string (by default)\n"
"    -bin                   Output MAC-tag as binary\n"
"                           `-hex` and `-bin` should not be used together\n"
"    -out file | stdout     Output file path. If not specified, output to stdout\n"
"\n"
"Examples\n"
"\n"
"    KEY_HEX=`gmssl rand -outlen 16 -hex`\n"
"    gmssl sm3hmac -key $KEY_HEX -in_str abc\n"
"\n"
"    gmssl sm3hmac -key $KEY_HEX -in_str abc -bin\n"
"\n"
"    gmssl sm3hmac -key $KEY_HEX -in /path/to/file\n"
"\n"
"  When reading from stdin, make sure the trailing newline character is removed\n"
"\n"
"  Linux/Mac:\n"
"    echo -n abc | gmssl sm3hmac -key $KEY_HEX\n"
"\n"
"  Windows:\n"
"    C:\\> echo |set/p=\"abc\" | gmssl sm3hmac -key 11223344556677881122334455667788\n"
"\n";

int sm3hmac_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *keyhex = NULL;
	int outformat = 0;
	char *in_str = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	uint8_t key[SM3_DIGEST_SIZE];
	size_t keylen;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	SM3_DIGEST_CTX ctx;
	uint8_t mac[SM3_HMAC_SIZE];
	size_t i;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, usage);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, usage);
			printf("%s\n", help);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyhex = *(++argv);
			if (strlen(keyhex) > sizeof(key) * 2) {
				fprintf(stderr, "%s: key should be less than 64 digits (32 bytes)\n", prog);
				goto end;
			}
			if (hex_to_bytes(keyhex, strlen(keyhex), key, &keylen) != 1) {
				fprintf(stderr, "%s: invalid HEX digits\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-hex")) {
			if (outformat == 2) {
				fprintf(stderr, "%s: `-hex` and `-bin` should not be used together\n", prog);
				goto end;
			}
			outformat = 1;
		} else if (!strcmp(*argv, "-bin")) {
			if (outformat == 1) {
				fprintf(stderr, "%s: `-hex` and `-bin` should not be used together\n", prog);
				goto end;
			}
			outformat = 2;
		} else if (!strcmp(*argv, "-in_str")) {
			if (infile) {
				fprintf(stderr, "%s: `-in` and `-in_str` should not be used together\n", prog);
				goto end;
			}
			if (--argc < 1) goto bad;
			in_str = *(++argv);
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, infile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "wb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, outfile, strerror(errno));
				goto end;
			}
		} else {
			fprintf(stderr, "%s: illegal option '%s'\n", prog, *argv);
			goto end;
bad:
			fprintf(stderr, "%s: '%s' option value missing\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}

	if (!keyhex) {
		fprintf(stderr, "%s: option '-key' required\n", prog);
		goto end;
	}

	if (sm3_digest_init(&ctx, key, keylen) != 1) {
		fprintf(stderr, "%s: inner error\n", prog);
		goto end;
	}

	if (in_str) {
		if (sm3_digest_update(&ctx, (uint8_t *)in_str, strlen(in_str)) != 1) {
			fprintf(stderr, "%s: inner error\n", prog);
			goto end;
		}
	} else {
		uint8_t buf[4096];
		size_t len;
		while ((len = fread(buf, 1, sizeof(buf), infp)) > 0) {
			if (sm3_digest_update(&ctx, buf, len) != 1) {
				fprintf(stderr, "%s: inner error\n", prog);
				goto end;
			}
		}
		memset(buf, 0, sizeof(buf));
	}
	if (sm3_digest_finish(&ctx, mac) != 1) {
		fprintf(stderr, "%s: inner error\n", prog);
		goto end;
	}

	if (outformat > 1) {
		if (fwrite(mac, 1, sizeof(mac), outfp) != sizeof(mac)) {
			fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
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
	gmssl_secure_clear(&ctx, sizeof(ctx));
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
