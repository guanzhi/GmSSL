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
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm2.h>
#include <gmssl/hex.h>
#include <gmssl/error.h>


static const char *usage = "[-hex|-bin] [-pubkey pem [-id str]] [-in file|-in_str str] [-out file]";

static const char *help =
"Options\n"
"\n"
"    -hex                   Output hash value as hex string (by default)\n"
"    -bin                   Output hash value as binary\n"
"    -pubkey pem            Signer's SM2 public key\n"
"                           When `-pubkey` is specified, hash with SM2 Z value\n"
"    -id str                SM2 Signer's ID string\n"
"    -id_hex hex            SM2 Signer's ID in hex format\n"
"                           `-id` and `-id_hex` should be used with `-pubkey`\n"
"                           `-id` and `-id_hex` should not be used together\n"
"                           If `-pubkey` is specified without `-id` or `id_hex`,\n"
"                           the default ID string '1234567812345678' is used\n"
"    -in_str str            To be hashed string\n"
"    -in file | stdin       To be hashed file path\n"
"                           `-in_str` and `-in` should not be used together\n"
"                           If neither `-in` nor `-in_str` specified, read from stdin\n"
"    -out file | stdout     Output file path. If not specified, output to stdout\n"
"\n"
"Examples\n"
"\n"
"    gmssl sm3 -in_str abc\n"
"\n"
"    gmssl sm3 -in_str abc -bin\n"
"\n"
"    gmssl sm3 -in /path/to/file\n"
"\n"
"    gmssl sm3 -pubkey sm2pubkey.pem -id alice -in /path/to/file -bin\n"
"\n"
"  When reading from stdin, make sure the trailing newline character is removed\n"
"\n"
"  Linux/Mac:\n"
"    echo -n abc | gmssl sm3\n"
"\n"
"  Windows:\n"
"    C:\\> echo |set/p=\"abc\" | gmssl sm3\n"
"\n";


int sm3_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	int outformat = 0;
	char *pubkeyfile = NULL;
	char *in_str = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	char *id = NULL;
	char *id_hex = NULL;
	FILE *pubkeyfp = NULL;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	uint8_t id_bin[64];
	size_t id_bin_len;
	SM3_DIGEST_CTX sm3_ctx;
	uint8_t dgst[32];
	int i;

	argc--;
	argv++;

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, usage);
			printf("%s\n", help);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-hex")) {
			if (outformat > 0) {
				fprintf(stderr, "%s: `-hex` and `-bin` should not be used together\n", prog);
				goto end;
			}
			outformat = 1;
		} else if (!strcmp(*argv, "-bin")) {
			if (outformat > 0) {
				fprintf(stderr, "%s: `-hex` and `-bin` should not be used together\n", prog);
				goto end;
			}
			outformat = 2;
		} else if (!strcmp(*argv, "-pubkey")) {
			if (--argc < 1) goto bad;
			pubkeyfile = *(++argv);
			if (!(pubkeyfp = fopen(pubkeyfile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, pubkeyfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-id")) {
			if (id_hex) {
				fprintf(stderr, "%s: `-id` and `-id_hex` should not be used together\n", prog);
				goto end;
			}
			if (--argc < 1) goto bad;
			id = *(++argv);
		} else if (!strcmp(*argv, "-id_hex")) {
			if (id) {
				fprintf(stderr, "%s: `-id` and `-id_hex` should not be used together\n", prog);
				goto end;
			}
			if (--argc < 1) goto bad;
			id_hex = *(++argv);
			if (strlen(id_hex) > sizeof(id_bin) * 2) {
				fprintf(stderr, "%s: `-id_hex` should be less then %zu bytes\n", prog, sizeof(id_bin));
				goto end;
			}
			if (hex_to_bytes(id_hex, strlen(id_hex), id_bin, &id_bin_len) != 1) {
				fprintf(stderr, "%s: invalid `-id_hex` value\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-in_str")) {
			if (infile) {
				fprintf(stderr, "%s: `-in` and `-in_str` should not be used together\n", prog);
				goto end;
			}
			if (--argc < 1) goto bad;
			in_str = *(++argv);
		} else if (!strcmp(*argv, "-in")) {
			if (in_str) {
				fprintf(stderr, "%s: `-in` and `-in_str` should not be used together\n", prog);
				goto end;
			}
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

	if ((id || id_hex) && !pubkeyfile) {
		fprintf(stderr, "%s: option `-id` or `-id_hex` must be with '-pubkey'\n", prog);
		goto end;
	}

	if (sm3_digest_init(&sm3_ctx, NULL, 0) != 1) {
		fprintf(stderr, "%s: inner error\n", prog);
		goto end;
	}

	if (pubkeyfile) {
		SM2_KEY sm2_key;
		uint8_t z[32];

		if (sm2_public_key_info_from_pem(&sm2_key, pubkeyfp) != 1) {
			fprintf(stderr, "%s: parse public key failed\n", prog);
			goto end;
		}

		if (id_hex) {
			sm2_compute_z(z, &sm2_key.public_key, (char *)id_bin, id_bin_len);
		} else {
			if (!id) {
				id = SM2_DEFAULT_ID;
			}
			sm2_compute_z(z, &sm2_key.public_key, id, strlen(id));
		}

		if (sm3_digest_update(&sm3_ctx, z, sizeof(z)) != 1) {
			fprintf(stderr, "%s: inner error\n", prog);
			goto end;
		}
	}

	if (in_str) {
		if (sm3_digest_update(&sm3_ctx, (uint8_t *)in_str, strlen(in_str)) != 1) {
			fprintf(stderr, "%s: inner error\n", prog);
			goto end;
		}

	} else {
		uint8_t buf[4096];
		size_t len;
		while ((len = fread(buf, 1, sizeof(buf), infp)) > 0) {
			if (sm3_digest_update(&sm3_ctx, buf, len) != 1) {
				fprintf(stderr, "%s: inner error\n", prog);
				goto end;
			}
		}
		memset(buf, 0, sizeof(buf));
	}
	if (sm3_digest_finish(&sm3_ctx, dgst) != 1) {
		fprintf(stderr, "%s: inner error\n", prog);
		goto end;
	}
	memset(&sm3_ctx, 0, sizeof(sm3_ctx));

	if (outformat > 1) {
		if (fwrite(dgst, 1, sizeof(dgst), outfp) != sizeof(dgst)) {
			fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
			goto end;
		}
	} else {
		for (i = 0; i < sizeof(dgst); i++) {
			fprintf(outfp, "%02x", dgst[i]);
		}
		fprintf(outfp, "\n");
	}
	ret = 0;
end:
	if (pubkeyfp) fclose(pubkeyfp);
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
