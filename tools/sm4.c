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
#include <string.h>
#include <stdlib.h>
#include <gmssl/mem.h>
#include <gmssl/sm4.h>
#include <gmssl/hex.h>


#define SM4_MODE_CBC 1
#define SM4_MODE_CTR 2

static const char *options = "{-cbc|-ctr} {-encrypt|-decrypt} -key hex -iv hex [-in file] [-out file]";

int sm4_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *keyhex = NULL;
	char *ivhex = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	uint8_t key[16];
	uint8_t iv[16];
	size_t keylen = sizeof(key);
	size_t ivlen = sizeof(iv);
	FILE *infp = stdin;
	FILE *outfp = stdout;
	int mode = 0;
	int enc = -1;
	SM4_CBC_CTX cbc_ctx;
	SM4_CTR_CTX ctr_ctx;
	uint8_t inbuf[4096];
	size_t inlen;
	uint8_t outbuf[4196];
	size_t outlen;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyhex = *(++argv);
			if (strlen(keyhex) != sizeof(key) * 2) {
				fprintf(stderr, "%s: invalid key length\n", prog);
				goto end;
			}
			if (hex_to_bytes(keyhex, strlen(keyhex), key, &keylen) != 1) {
				fprintf(stderr, "%s: invalid HEX digits\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-iv")) {
			if (--argc < 1) goto bad;
			ivhex = *(++argv);
			if (strlen(ivhex) != sizeof(iv) * 2) {
				fprintf(stderr, "%s: invalid IV length\n", prog);
				goto end;
			}
			if (hex_to_bytes(ivhex, strlen(ivhex), iv, &ivlen) != 1) {
				fprintf(stderr, "%s: invalid HEX digits\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-encrypt")) {
			enc = 1;
		} else if (!strcmp(*argv, "-decrypt")) {
			enc = 0;
		} else if (!strcmp(*argv, "-cbc")) {
			if (mode) goto bad;
			mode = SM4_MODE_CBC;
		} else if (!strcmp(*argv, "-ctr")) {
			if (mode) goto bad;
			mode = SM4_MODE_CTR;
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "r"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, infile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "w"))) {
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

	if (!mode) {
		fprintf(stderr, "%s: mode not assigned, -cbc or -ctr option required\n", prog);
		goto end;
	}
	if (!keyhex) {
		fprintf(stderr, "%s: option '-key' missing\n", prog);
		goto end;
	}
	if (!ivhex) {
		fprintf(stderr, "%s: option '-iv' missing\n", prog);
		goto end;
	}


	if (mode == SM4_MODE_CTR) {
		if (sm4_ctr_encrypt_init(&ctr_ctx, key, iv) != 1) {
			fprintf(stderr, "%s: inner error\n", prog);
			goto end;
		}
		while ((inlen = fread(inbuf, 1, sizeof(inbuf), infp)) > 0) {
			if (sm4_ctr_encrypt_update(&ctr_ctx, inbuf, inlen, outbuf, &outlen) != 1) {
				fprintf(stderr, "%s: inner error\n", prog);
				goto end;
			}
			if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
				fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
				goto end;
			}
		}
		if (sm4_ctr_encrypt_finish(&ctr_ctx, outbuf, &outlen) != 1) {
			fprintf(stderr, "%s: inner error\n", prog);
			goto end;
		}
		if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
			fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
			goto end;
		}

		ret = 0;
		goto end;
	}

	if (enc < 0) {
		fprintf(stderr, "%s: option -encrypt or -decrypt should be set\n", prog);
		goto end;
	}

	if (enc) {
		if (sm4_cbc_encrypt_init(&cbc_ctx, key, iv) != 1) {
			fprintf(stderr, "%s: inner error\n", prog);
			goto end;
		}
		while ((inlen = fread(inbuf, 1, sizeof(inbuf), infp)) > 0) {
			if (sm4_cbc_encrypt_update(&cbc_ctx, inbuf, inlen, outbuf, &outlen) != 1) {
				fprintf(stderr, "%s: inner error\n", prog);
				goto end;
			}
			if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
				fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
				goto end;
			}
		}
		if (sm4_cbc_encrypt_finish(&cbc_ctx, outbuf, &outlen) != 1) {
			fprintf(stderr, "%s: inner error\n", prog);
			goto end;
		}
		if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
			fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
			goto end;
		}

	} else {
		if (sm4_cbc_decrypt_init(&cbc_ctx, key, iv) != 1) {
			fprintf(stderr, "%s: inner error\n", prog);
			goto end;
		}
		while ((inlen = fread(inbuf, 1, sizeof(inbuf), infp)) > 0) {
			if (sm4_cbc_decrypt_update(&cbc_ctx, inbuf, inlen, outbuf, &outlen) != 1) {
				fprintf(stderr, "%s: inner error\n", prog);
				goto end;
			}
			if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
				fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
				goto end;
			}
		}
		if (sm4_cbc_decrypt_finish(&cbc_ctx, outbuf, &outlen) != 1) {
			fprintf(stderr, "%s: inner error\n", prog);
			goto end;
		}
		if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
			fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
			goto end;
		}
	}
	ret = 0;

end:
	gmssl_secure_clear(&cbc_ctx, sizeof(cbc_ctx));
	gmssl_secure_clear(&ctr_ctx, sizeof(ctr_ctx));
	gmssl_secure_clear(key, sizeof(key));
	gmssl_secure_clear(iv, sizeof(iv));
	gmssl_secure_clear(inbuf, sizeof(inbuf));
	gmssl_secure_clear(outbuf, sizeof(outbuf));
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
