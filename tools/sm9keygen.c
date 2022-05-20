/*
 * Copyright (c) 2021 - 2021 The GmSSL Project.  All rights reserved.
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
#include <gmssl/mem.h>
#include <gmssl/oid.h>
#include <gmssl/sm9.h>
#include <gmssl/error.h>

static const char *options = "-alg (sm9sign|sm9encrypt) -in master_key.pem -inpass str -id str [-out pem] -outpass str";

int sm9keygen_main(int argc, char **argv)
{
	int ret = -1;
	char *prog = argv[0];
	char *alg = NULL;
	char *infile = NULL;
	char *inpass = NULL;
	char *id = NULL;
	char *outfile = NULL;
	char *outpass = NULL;
	int oid = 0;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	SM9_SIGN_MASTER_KEY sign_msk;
	SM9_ENC_MASTER_KEY enc_msk;
	SM9_SIGN_KEY sign_key;
	SM9_ENC_KEY enc_key;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			fprintf(stdout, "usage: %s %s\n", prog, options);
			return 0;
		} else if (!strcmp(*argv, "-alg")) {
			if (--argc < 1) goto bad;
			alg = *(++argv);
			if ((oid = sm9_oid_from_name(alg)) < 1) {
				fprintf(stdout, "%s: invalid alg '%s', should be sm9sign or sm9encrypt\n", prog, alg);
				goto end;
			}
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "r"))) {
				error_print();
				goto end;
			}
		} else if (!strcmp(*argv, "-inpass")) {
			if (--argc < 1) goto bad;
			inpass = *(++argv);
		} else if (!strcmp(*argv, "-id")) {
			if (--argc < 1) goto bad;
			id = *(++argv);
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "w"))) {
				error_print();
				goto end;
			}
		} else if (!strcmp(*argv, "-outpass")) {
			if (--argc < 1) goto bad;
			outpass = *(++argv);
		} else {
bad:
			fprintf(stderr, "%s: illegal option '%s'\n", prog, *argv);
			return 1;
		}


		argc--;
		argv++;
	}

	if (!id) {
		fprintf(stderr, "%s: option '-id' is required\n", prog);
		goto end;
	}
	if (!inpass || !outpass) {
		error_print();
		goto end;
	}

	switch (oid) {
	case OID_sm9sign:
		if (sm9_sign_master_key_info_decrypt_from_pem(&sign_msk, inpass, infp) != 1
		|| sm9_sign_master_key_extract_key(&sign_msk, id, strlen(id), &sign_key) != 1
			|| sm9_sign_key_info_encrypt_to_pem(&sign_key, outpass, outfp) != 1) {
			error_print();
			goto end;
		}
		break;
	case OID_sm9encrypt:
		if (sm9_enc_master_key_info_decrypt_from_pem(&enc_msk, inpass, infp) != 1
			|| sm9_enc_master_key_extract_key(&enc_msk, id, strlen(id), &enc_key) != 1
			|| sm9_enc_key_info_encrypt_to_pem(&enc_key, outpass, outfp) != 1) {
			error_print();
			goto end;
		}
		break;
	default:
		error_print();
		goto end;
	}
	ret = 0;
end:
	gmssl_secure_clear(&sign_msk, sizeof(sign_msk));
	gmssl_secure_clear(&enc_msk, sizeof(enc_msk));
	gmssl_secure_clear(&sign_key, sizeof(sign_key));
	gmssl_secure_clear(&enc_key, sizeof(enc_key));
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return 1;
}
