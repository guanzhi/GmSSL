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
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm4.h>
#include <gmssl/hex.h>
#include <gmssl/error.h>


#define SM4_MODE_CBC 1
#define SM4_MODE_CTR 2

static const char *options = "{-cbc|-ctr} {-encrypt|-decrypt} -key hex -iv hex [-in file] [-out file]";


int sm4_main(int argc, char **argv)
{
	char *prog = argv[0];
	char *keystr = NULL;
	char *ivstr = NULL;
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

	if (argc < 2) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}

	argc--;
	argv++;

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			fprintf(stderr, "usage: %s %s\n", prog, options);
			return 0;
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keystr = *(++argv);
		} else if (!strcmp(*argv, "-iv")) {
			if (--argc < 1) goto bad;
			ivstr = *(++argv);
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
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
		} else {
			fprintf(stderr, "%s: illegal option '%s'\n", prog, *argv);
			return 1;
bad:
			fprintf(stderr, "%s: no option value\n", prog);
			return 1;
		}

		argc--;
		argv++;
	}

	if (!mode) {
		fprintf(stderr, "%s: mode not assigned, -cbc or -ctr option required\n", prog);
		return 1;
	}

	if (!keystr) {
		error_print();
		return -1;
	}
	if (strlen(keystr) != 32) {
		printf("keystr len = %d\n", strlen(keystr));
		error_print();
		return -1;
	}
	if (hex_to_bytes(keystr, strlen(keystr), key, &keylen) != 1) {
		error_print();
		return -1;
	}

	if (!ivstr) {
		error_print();
		return -1;
	}
	if (strlen(ivstr) != 32) {
		error_print();
		return -1;
	}
	if (hex_to_bytes(ivstr, strlen(ivstr), iv, &ivlen) != 1) {
		error_print();
		return -1;
	}

	if (infile) {
		if (!(infp = fopen(infile, "r"))) {
			error_print();
			return -1;
		}
	}
	if (outfile) {
		if (!(outfp = fopen(outfile, "w"))) {
			error_print();
			return -1;
		}
	}


	if (mode == SM4_MODE_CTR) {
		if (sm4_ctr_encrypt_init(&ctr_ctx, key, iv) != 1) {
			error_print();
			return -1;
		}
		while ((inlen = fread(inbuf, 1, sizeof(inbuf), infp)) > 0) {
			if (sm4_ctr_encrypt_update(&ctr_ctx, inbuf, inlen, outbuf, &outlen) != 1) {
				error_print();
				return -1;
			}
			if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
				error_print();
				return -1;
			}
		}
		if (sm4_ctr_encrypt_finish(&ctr_ctx, outbuf, &outlen) != 1) {
			error_print();
			return -1;
		}
		if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
			error_print();
			return -1;
		}


		return 0;
	}


	if (enc < 0) {
		error_print();
		return -1;
	}

	if (enc) {
		if (sm4_cbc_encrypt_init(&cbc_ctx, key, iv) != 1) {
			error_print();
			return -1;
		}
		while ((inlen = fread(inbuf, 1, sizeof(inbuf), infp)) > 0) {
			if (sm4_cbc_encrypt_update(&cbc_ctx, inbuf, inlen, outbuf, &outlen) != 1) {
				error_print();
				return -1;
			}
			if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
				error_print();
				return -1;
			}
		}
		if (sm4_cbc_encrypt_finish(&cbc_ctx, outbuf, &outlen) != 1) {
			error_print();
			return -1;
		}
		if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
			error_print();
			return -1;
		}

	} else {
		if (sm4_cbc_decrypt_init(&cbc_ctx, key, iv) != 1) {
			error_print();
			return -1;
		}
		while ((inlen = fread(inbuf, 1, sizeof(inbuf), infp)) > 0) {
			if (sm4_cbc_decrypt_update(&cbc_ctx, inbuf, inlen, outbuf, &outlen) != 1) {
				error_print();
				return -1;
			}
			if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
				error_print();
				return -1;
			}
		}
		if (sm4_cbc_decrypt_finish(&cbc_ctx, outbuf, &outlen) != 1) {
			error_print();
			return -1;
		}
		if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
			error_print();
			return -1;
		}
	}

	return 0;
}
