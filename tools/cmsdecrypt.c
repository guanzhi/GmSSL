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



static const char *options = "-key file -pass str -cert file -in file [-out file]";

int cmsdecrypt_main(int argc, char **argv)
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
	uint8_t cert[1024];
	size_t certlen;
	size_t inlen;
	uint8_t *cms = NULL;
	size_t cmslen, cms_maxlen;
	SM2_KEY key;
	int content_type;
	uint8_t *content = NULL;
	size_t content_len;
	const uint8_t *rcpt_infos;
	size_t rcpt_infos_len;
	const uint8_t *shared_info1;
	const uint8_t *shared_info2;
	size_t shared_info1_len, shared_info2_len;

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

	if (file_size(infp, &inlen) != 1) {
		fprintf(stderr, "%s: get input length failed\n", prog);
		goto end;
	}
	cms_maxlen = (inlen * 3)/4 + 1;
	if (!(cms = malloc(cms_maxlen))) {
		fprintf(stderr, "%s: malloc failure\n", prog);
		goto end;
	}
	if (cms_from_pem(cms, &cmslen, cms_maxlen, infp) != 1) {
		fprintf(stderr, "%s: read CMS failure\n", prog);
		goto end;
	}

	if (!(content = malloc(cmslen))) {
		fprintf(stderr, "%s: malloc failure\n", prog);
		goto end;
	}

	if (cms_deenvelop(cms, cmslen,
		&key, cert, certlen,
		&content_type, content, &content_len,
		&rcpt_infos, &rcpt_infos_len,
		&shared_info1, &shared_info1_len,
		&shared_info2, &shared_info2_len) != 1) {
		fprintf(stderr, "%s: decryption failure\n", prog);
		goto end;
	}
	if (content_type != OID_cms_data) {
		fprintf(stderr, "%s: invalid CMS content type: %s\n", prog, cms_content_type_name(content_type));
		goto end;
	}

	if (fwrite(content, 1, content_len, outfp) != content_len) {
		fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
		goto end;
	}

	ret = 0;

end:
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	if (keyfile && keyfp) fclose(keyfp);
	if (cms) free(cms);
	if (content) free(content);
	return ret;
}
