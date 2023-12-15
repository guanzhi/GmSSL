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
#include <gmssl/cms.h>
#include <gmssl/x509.h>
#include <gmssl/rand.h>


/*

签名的时候要提供签名者的证书，并且提供签名私钥
但是验证的时候假定CMS中已经包含签名者的证书了，但是我们要提供CA证书库

加密的时候要指定接收者的证书，并且可以有多个接收者
解密的时候只提供一个解密私钥，但是最好配合解密者的证书，从这个证书中找到解密者的名字

如果即加密又签名，那么输出的是SignedAndEnveloped

CMS有PEM吗？

cms -encrypt -rcpt a.pem -rcpt b.pem -rcpt c.pem -in file -sign -signcert a.pem -signcert b.pem
	-rcptcert -rcpt_cert -sign_cert b.pem -signkey

首先接收者可以有多个证书

这里面有个问题，因为我们要输出一个加密的对象，因此我们必须把输入的内容读取进来。


EnvelopedData 是一个封装的SEQUENCE中，因此必须读取所有的内容。
如果是一个文件，就需要读取所有的文件内容，如果是一个stream ,也需要读取完整的内容到一个足够大的buffer中，如何设置这个buffer的大小呢



对于输入文件，如果输入有文件名的话，可以直接通过stat获取文件长度
但是如果对于stream的话，实际上我们是没有办法获得输入长度的，那么就直接准备一个buffer好了。
不要给自己找麻烦了，直接只支持文件输入吧
encrypt

*/

static const char *options = "-encrypt (-rcptcert pem)* -in file -out file";


static int get_files_size(int argc, char **argv, const char *option, size_t *len)
{
	char *prog = argv[0];
	char *file = NULL;
	FILE *fp = NULL;

	argc--;
	argv++;

	*len = 0;
	while (argc > 1) {
		if (!strcmp(*argv, option)) {
			size_t fsize;

			if (--argc < 1) {
				fprintf(stderr, "%s: '%s' option value missing\n", prog, *argv);
				return -1;
			}
			file = *(++argv);

			if (!(fp = fopen(file, "rb"))) {
				fprintf(stderr, "%s: open '%s' failed : %s\n", prog, file, strerror(errno));
				return -1;
			}
			if (file_size(fp, &fsize) != 1) {
				fprintf(stderr, "%s: access '%s' failed : %s\n", prog, file, strerror(errno));
				fclose(fp);
				return -1;
			}
			*len += fsize;
			fclose(fp);
		}
		argc--;
		argv++;
	}

	return 1;
}

int cmsencrypt_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	int op = 0;
	char *infile = NULL;
	char *outfile = NULL;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	uint8_t *rcpt_certs = NULL;
	size_t rcpt_certs_len;
	uint8_t key[16];
	uint8_t iv[16];
	uint8_t *inbuf = NULL;
	size_t inlen;
	uint8_t *cms = NULL;
	size_t cmslen;
	uint8_t *cert;

	if (argc < 2) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}

	// 预先统计证书缓冲大小和输入大小
	if (get_files_size(argc, argv, "-rcptcert", &rcpt_certs_len) != 1) {
		goto end;
	}
	if (rcpt_certs_len <= 0) {
		fprintf(stderr, "%s: invalid cert length\n", prog);
		goto end;
	}
	rcpt_certs_len = (rcpt_certs_len * 3)/4;
	if (!(rcpt_certs = malloc(rcpt_certs_len))) {
		fprintf(stderr, "%s: malloc failure\n", prog);
		goto end;
	}
	cert = rcpt_certs;

	if (get_files_size(argc, argv, "-in", &inlen) != 1) {
		goto end;
	}
	if (inlen <= 0) {
		fprintf(stderr, "%s: invalid input length\n", prog);
		goto end;
	}
	if (!(inbuf = malloc(inlen))) {
		fprintf(stderr, "%s: %s\n", prog, strerror(errno));
		goto end;
	}

	argc--;
	argv++;

	while (argc > 1) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-rcptcert")) {
			char *certfile;
			FILE *certfp;
			size_t certlen;
			if (--argc < 1) goto bad;
			certfile = *(++argv);
			if (!(certfp = fopen(certfile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, certfile, strerror(errno));
				goto end;
			}
			if (x509_cert_from_pem(cert, &certlen, rcpt_certs_len, certfp) != 1) {
				fprintf(stderr, "%s: error\n", prog);
				fclose(certfp);
				goto end;
			}
			cert += certlen;
			fclose(certfp);
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, infile, strerror(errno));
				goto end;
			}
			if ((inlen = fread(inbuf, 1, inlen, infp)) <= 0) {
				fprintf(stderr, "%s: read data error: %s\n", prog, strerror(errno));
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

	rcpt_certs_len = cert - rcpt_certs;

	if (rand_bytes(key, sizeof(key)) != 1
		|| rand_bytes(iv, sizeof(iv)) != 1
		|| cms_envelop(NULL, &cmslen, rcpt_certs, rcpt_certs_len,
			OID_sm4_cbc, key, sizeof(key), iv, sizeof(iv),
			OID_cms_data, inbuf, inlen, NULL, 0, NULL, 0) != 1) {
		fprintf(stderr, "%s: inner error\n", prog);
		goto end;
	}
	if (!(cms = malloc(cmslen))) {
		fprintf(stderr, "%s: malloc failure\n", prog);
		goto end;
	}
	if (cms_envelop(cms, &cmslen, rcpt_certs, rcpt_certs_len,
		OID_sm4_cbc, key, sizeof(key), iv, sizeof(iv),
		OID_cms_data, inbuf, inlen, NULL, 0, NULL, 0) != 1) {
		fprintf(stderr, "%s: inner error\n", prog);
		goto end;
	}
	if (cms_to_pem(cms, cmslen, outfp) != 1) {
		fprintf(stderr, "%s: output CMS failure\n", prog);
		goto end;
	}

	ret = 0;

end:
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	if (rcpt_certs) free(rcpt_certs);
	if (inbuf) free(inbuf);
	if (cms) free(cms);
	return ret;
}
