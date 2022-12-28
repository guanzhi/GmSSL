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
#include <gmssl/file.h>
#include <gmssl/x509.h>
#include <gmssl/cms.h>
#include <gmssl/error.h>


/*
302 typedef struct {
303         uint8_t *certs;
304         size_t certs_len;
305         SM2_KEY *sign_key;
306 } CMS_CERTS_AND_KEY;



输出长度主要由输入长度和

*/

static const char *options = "-key file -pass str -cert file -in file [-out file]";

int cmssign_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *keyfile = NULL;
	char *pass = NULL;
	char *certfile = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	FILE *keyfp = NULL;
	FILE *certfp = NULL;
	FILE *infp = NULL;
	FILE *outfp = stdout;
	SM2_KEY key;
	uint8_t cert[1024];
	size_t certlen;
	uint8_t *in = NULL;
	size_t inlen;
	uint8_t *cms = NULL;
	size_t cmslen, cms_maxlen;
	CMS_CERTS_AND_KEY cert_and_key;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}

	while (argc > 1) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);
			if (!(keyfp = fopen(keyfile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, keyfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
		} else if (!strcmp(*argv, "-cert")) {
			if (--argc < 1) goto bad;
			certfile = *(++argv);
			if (!(certfp = fopen(certfile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, certfile, strerror(errno));
				goto end;
			}
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

	if (!keyfile) {
		fprintf(stderr, "%s: '-key' option required\n", prog);
		goto end;
	}
	if (!pass) {
		fprintf(stderr, "%s: '-pass' option required\n", prog);
		goto end;
	}
	if (!certfile) {
		fprintf(stderr, "%s: '-cert' option required\n", prog);
		goto end;
	}
	if (!infile) {
		fprintf(stderr, "%s: '-in' option required\n", prog);
		goto end;
	}

	if (sm2_private_key_info_decrypt_from_pem(&key, pass, keyfp) != 1) {
		fprintf(stderr, "%s: private key decryption failure\n", prog);
		goto end;
	}
	if (x509_cert_from_pem(cert, &certlen, sizeof(cert), certfp) != 1) {
		fprintf(stderr, "%s: load certificate failure\n", prog);
		goto end;
	}
	{
		SM2_KEY public_key;
		if (x509_cert_get_subject_public_key(cert, certlen, &public_key) != 1) {
			fprintf(stderr, "%s: parse certficate failure\n", prog);
			goto end;
		}
		if (sm2_public_key_equ(&key, &public_key) != 1) {
			fprintf(stderr, "%s: key and cert are not match!\n", prog);
			goto end;
		}
	}

	cert_and_key.certs = cert;
	cert_and_key.certs_len = certlen;
	cert_and_key.sign_key = &key;

	if (file_size(infp, &inlen) != 1) {
		fprintf(stderr, "%s: get input length failed\n", prog);
		goto end;
	}
	if (!(in = malloc(inlen))) {
		fprintf(stderr, "%s: malloc failure\n", prog);
		goto end;
	}
	if (fread(in, 1, inlen, infp) != inlen) {
		fprintf(stderr, "%s: read file error : %s\n",  prog, strerror(errno));
		goto end;
	}

	cms_maxlen = (inlen * 4)/3 + 4096; // 主要由SignerInfos，其中的DN长度决定
	if (!(cms = malloc(cms_maxlen))) {
		fprintf(stderr, "%s: malloc failure\n", prog);
		goto end;
	}

	if (cms_sign(cms, &cmslen, &cert_and_key, 1, OID_cms_data, in, inlen, NULL, 0) != 1) {
		fprintf(stderr, "%s: sign failure\n", prog);
		goto end;
	}

	if (cms_to_pem(cms, cmslen, outfp) != 1) {
		fprintf(stderr, "%s: output failure\n", prog);
		goto end;
	}

	ret = 0;

end:
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	if (keyfile && keyfp) fclose(keyfp);
	if (cms) free(cms);
	if (in) free(in);
	return ret;
}
