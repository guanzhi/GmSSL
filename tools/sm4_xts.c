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
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm4.h>
#include <gmssl/mem.h>
#include <gmssl/hex.h>
#include <gmssl/error.h>


static const char *usage = "{-encrypt|-decrypt} -key hex -iv hex -data_unit_size num [-in file] [-out file]";

static const char *options =
"Options\n"
"\n"
"    -encrypt              Encrypt\n"
"    -decrypt              Decrypt\n"
"    -key hex              Symmetric key in HEX format, 32 bytes\n"
"    -iv hex               IV (tweak in XTS), 16 bytes\n"
"    -data_unit_size num   Encrypted disk sector size, typically 512 or 4096 bytes\n"
"    -in file | stdin      Input data\n"
"    -out file | stdout    Output data\n"
"\n"
"Examples\n"
"\n"
"  $ DATA=`gmssl rand -outlen 2048`\n"
"  $ KEY=`gmssl rand -outlen 32 -hex`\n"
"  $ IV=`gmssl rand -outlen 16 -hex`\n"
"  $ echo -n $DATA | gmssl sm4_xts -encrypt -key $KEY -iv $IV -data_unit_size 512 -out sm4_xts_ciphertext.bin\n"
"  $ gmssl sm4_xts -decrypt -key $KEY -iv $IV -data_unit_size 512 -in sm4_xts_ciphertext.bin\n"
"\n";

int sm4_xts_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	int enc = -1;
	char *keyhex = NULL;
	char *ivhex = NULL;
	int data_unit_size = 512;
	char *infile = NULL;
	char *outfile = NULL;
	uint8_t key[32];
	size_t keylen;
	uint8_t iv[16];
	size_t ivlen;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	SM4_XTS_CTX ctx;
	uint8_t *buf = NULL;
	size_t buflen;
	size_t inlen;
	size_t outlen;

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
		} else if (!strcmp(*argv, "-encrypt")) {
			if (enc == 0) {
				fprintf(stderr, "gmssl %s: `-encrypt` `-decrypt` should not be used together\n", prog);
				goto end;
			}
			enc = 1;
		} else if (!strcmp(*argv, "-decrypt")) {
			if (enc == 1) {
				fprintf(stderr, "gmssl %s: `-encrypt` `-decrypt` should not be used together\n", prog);
				goto end;
			}
			enc = 0;
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyhex = *(++argv);
			if (strlen(keyhex) != sizeof(key) * 2) {
				fprintf(stderr, "gmssl %s: invalid key length\n", prog);
				goto end;
			}
			if (hex_to_bytes(keyhex, strlen(keyhex), key, &keylen) != 1) {
				fprintf(stderr, "gmssl %s: invalid key hex digits\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-iv")) {
			if (--argc < 1) goto bad;
			ivhex = *(++argv);
			if (strlen(ivhex) != sizeof(iv) * 2) {
				fprintf(stderr, "gmssl %s: invalid IV length\n", prog);
				goto end;
			}
			if (hex_to_bytes(ivhex, strlen(ivhex), iv, &ivlen) != 1) {
				fprintf(stderr, "gmssl %s: invalid IV hex digits\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-data_unit_size")) {
			if (--argc < 1) goto bad;
			data_unit_size = atoi(*(++argv));
			if (data_unit_size < 16) {
				fprintf(stderr, "gmssl %s: `-data_unit_size` should be larger than SM4 block size\n", prog);
				goto end;
			}
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
			fprintf(stderr, "gmssl %s: illegal option `%s`\n", prog, *argv);
			goto end;
bad:
			fprintf(stderr, "gmssl %s: `%s` option value missing\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}

	if (enc < 0) {
		fprintf(stderr, "gmssl %s: option -encrypt or -decrypt should be set\n", prog);
		goto end;
	}
	if (!keyhex) {
		fprintf(stderr, "gmssl %s: option `-key` missing\n", prog);
		goto end;
	}
	if (!ivhex) {
		fprintf(stderr, "gmssl %s: option `-iv` missing\n", prog);
		goto end;
	}

	if (enc) {
		if (sm4_xts_encrypt_init(&ctx, key, iv, data_unit_size) != 1) {
			error_print();
			goto end;
		}
	} else {
		if (sm4_xts_decrypt_init(&ctx, key, iv, data_unit_size) != 1) {
			error_print();
			goto end;
		}
	}

	buflen = data_unit_size * 16;
	if (!(buf = (uint8_t *)malloc(buflen))) {
		fprintf(stderr, "gmssl %s: malloc failure\n", prog);
		goto end;
	}

	while ((inlen = fread(buf, 1, buflen, infp)) > 0) {
		if (enc) {
			if (sm4_xts_encrypt_update(&ctx, buf, inlen, buf, &outlen) != 1) {
				error_print();
				goto end;
			}
		} else {
			if (sm4_xts_decrypt_update(&ctx, buf, inlen, buf, &outlen) != 1) {
				error_print();
				goto end;
			}
		}
		if (fwrite(buf, 1, outlen, outfp) != outlen) {
			fprintf(stderr, "gmssl %s: output failure : %s\n", prog, strerror(errno));
			goto end;
		}
	}

	if (enc) {
		if (sm4_xts_encrypt_finish(&ctx, buf, &outlen) != 1) {
			error_print();
			goto end;
		}
	} else {
		if (sm4_xts_decrypt_finish(&ctx, buf, &outlen) != 1) {
			error_print();
			goto end;
		}
	}
	if (fwrite(buf, 1, outlen, outfp) != outlen) {
		fprintf(stderr, "gmssl %s: output failure : %s\n", prog, strerror(errno));
		goto end;
	}


	ret = 0;

end:
	gmssl_secure_clear(key, sizeof(key));
	gmssl_secure_clear(iv, sizeof(iv));
	gmssl_secure_clear(&ctx, sizeof(ctx));
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	if (buf) free(buf);
	return ret;
}
