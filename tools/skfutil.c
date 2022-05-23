/*
 * Copyright (c) 2014 - 2021 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <gmssl/mem.h>
#include <gmssl/hex.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/skf.h>


#define OP_NONE			0
#define OP_DEVINFO		1
#define OP_EXPORTPUBKEY		2
#define OP_SIGN			3
#define OP_RAND			4



static void print_usage(FILE *fp, const char *prog)
{
	fprintf(fp, "usage:\n");
	fprintf(fp, "  %s -lib so_path -dev str -devinfo\n", prog);
	fprintf(fp, "  %s -lib so_path -dev str -app str [-pass str] -container str -exportpubkey [-out file]\n", prog);
	fprintf(fp, "  %s -lib so_path -dev str -app str [-pass str] -container str -sign [-in file] [-out file]\n", prog);
	fprintf(fp, "  %s -lib so_path -dev str -rand num [-out file]\n", prog);
}

int skfutil_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *lib = NULL;
	int op = 0;
	char *devname = NULL;
	char *authkeystr = NULL;
	char *appname = NULL;
	char *container_name = NULL;
	char *pass = NULL;
	char *id = SM2_DEFAULT_ID;
	int num = 0;
	char *infile = NULL;
	char *outfile = NULL;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	unsigned char buf[4096];
	unsigned int ulen;
	int len;

	uint8_t authkey[16];
	size_t authkeylen;
	SKF_DEVICE dev;
	SKF_KEY key;
	int dev_opened = 0;
	int key_opened = 0;

	memset(&dev, 0, sizeof(dev));
	memset(&key, 0, sizeof(key));

	argc--;
	argv++;

	if (argc < 1) {
		print_usage(stderr, prog);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			print_usage(stdout, prog);
			goto end;
		} else if (!strcmp(*argv, "-lib")) {
			if (--argc < 1) goto bad;
			lib = *(++argv);
		} else if (!strcmp(*argv, "-lib")) {
			if (--argc < 1) goto bad;
			devname = *(++argv);
		} else if (!strcmp(*argv, "-devinfo")) {
			op = OP_DEVINFO;
		} else if (!strcmp(*argv, "-dev")) {
			if (--argc < 1) goto bad;
			devname = *(++argv);
		} else if (!strcmp(*argv, "-authkey")) {
			if (--argc < 1) goto bad;
			authkeystr = *(++argv);
			if (strlen(authkeystr) != 32) {
				fprintf(stderr, "%s: invalid authkey length\n", prog);
				goto end;
			}
			hex_to_bytes(authkeystr, strlen(authkeystr), authkey, &authkeylen);
		} else if (!strcmp(*argv, "-exportpubkey")) {
			op = OP_EXPORTPUBKEY;
		} else if (!strcmp(*argv, "-sign")) {
			op = OP_SIGN;
		} else if (!strcmp(*argv, "-app")) {
			if (--argc < 1) goto bad;
			appname = *(++argv);
		} else if (!strcmp(*argv, "-container")) {
			if (--argc < 1) goto bad;
			container_name = *(++argv);
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
		} else if (!strcmp(*argv, "-id")) {
			if (--argc < 1) goto bad;
			id = *(++argv);
		} else if (!strcmp(*argv, "-rand")) {
			if (--argc < 1) goto bad;
			len = atoi(*(++argv));
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

	if (!lib) {
		fprintf(stderr, "%s: option '-lib' required\n", prog);
		goto end;
	}
	if (skf_load_library(lib, NULL) != 1) {
		fprintf(stderr, "%s: load library failure\n", prog);
		goto end;
	}

	if (!op) {
		fprintf(stderr, "%s: option of (-devinfo|-exportpubkey|-sign|-rand) required\n", prog);
		goto end;
	}

	if (!devname) {
		fprintf(stderr, "%s: option '-dev' required\n", prog);
		goto end;
	}
	if (op == OP_DEVINFO) {
		skf_print_device_info(stdout, 0, 0, devname);
		ret = 0;
		goto end;
	}

	if (skf_open_device(&dev, devname, authkey) != 1) {
		fprintf(stderr, "%s: open device failure\n", prog);
		goto end;
	}
	dev_opened = 1;

	if (op == OP_RAND) {
		if (skf_rand_bytes(&dev, buf, len) != 1) {
			fprintf(stderr, "%s: inner error\n", prog);
			goto end;
		}
		if (fwrite(buf, 1, len, outfp) != len) {
			fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
			goto end;
		}
		ret = 0;
		goto end;
	}

	if (!appname) {
		fprintf(stderr, "%s: option '-app' required\n", prog);
		goto end;
	}
	if (!container_name) {
		fprintf(stderr, "%s: option '-container' required\n", prog);
		goto end;
	}
	if (!pass) {
		fprintf(stderr, "%s: option '-pass' required\n", prog);
		goto end;
	}

	if (op == OP_EXPORTPUBKEY) {
		if (skf_load_sign_key(&dev, appname, pass, container_name, &key) != 1) {
			fprintf(stderr, "%s: load sign key failed\n", prog);
			goto end;
		}
		if (sm2_public_key_info_to_pem(&(key.public_key), outfp) != 1) {
			fprintf(stderr, "%s: output public key PEM failure\n", prog);
			goto end;
		}
		ret = 0;
		goto end;
	}

	if (op == OP_SIGN) {
		SM3_CTX sm3_ctx;
		uint8_t dgst[32];
		uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
		size_t siglen;

		if (skf_load_sign_key(&dev, appname, pass, container_name, &key) != 1) {
			fprintf(stderr, "%s: load sign key failed\n", prog);
			goto end;
		}
		key_opened = 1;

		sm3_init(&sm3_ctx);
		sm2_compute_z(dgst, &(key.public_key.public_key), id, strlen(id));
		sm3_update(&sm3_ctx, dgst, sizeof(dgst));

		while ((len = fread(buf, 1, sizeof(buf), infp)) > 0) {
			sm3_update(&sm3_ctx, buf, len);
		}
		sm3_finish(&sm3_ctx, dgst);

		if ((ret = skf_sign(&key, dgst, sig, &siglen)) != 1) {
			fprintf(stderr, "%s: inner error\n", prog);
			goto end;
		}
		ret = 0;
		goto end;

	} else {
		fprintf(stderr, "%s: this should not happen\n", prog);
		goto end;
	}

end:
	gmssl_secure_clear(buf, sizeof(buf));
	if (key_opened) skf_release_key(&key);
	if (dev_opened) skf_close_device(&dev);
	if (lib) skf_unload_library();
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
