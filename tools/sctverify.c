/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/hex.h>
#include <gmssl/x509.h>
#include <gmssl/sct.h>
#include <gmssl/error.h>


#define SCTVERIFY_MAX_SCT_LIST_SIZE	65536
#define SCTVERIFY_MAX_ENTRY_SIZE	65536
#define SCTVERIFY_MAX_CT_LOGS		16


static const char *options =
	"-in file [-cert pem | -precert der] [-issuer_key_hash hex]"
	" -log_key pem [-log_key pem ...] [-at_least num] [-digest name]"
	" [-verbose]";

static const char *help =
"Options\n"
"\n"
"    -in file            Input SignedCertificateTimestampList in binary format\n"
"    -cert pem           Input certificate and verify SCTs over an x509_entry\n"
"    -precert der        Input TBSCertificate DER and verify SCTs over a precert_entry\n"
"    -issuer_key_hash hex\n"
"                        32-byte issuer key hash, required with -precert\n"
"    -log_key pem        CT Log public key in SubjectPublicKeyInfo PEM format\n"
"                        This option can be repeated\n"
"    -at_least num       Required number of successful SCT verifications, default 1\n"
"    -digest name        Digest for CT Log ID, default sha256\n"
"    -verbose            Print verification result to stderr\n"
"\n"
"Examples\n"
"\n"
"    gmssl sctverify -in sctlist.bin -cert cert.pem -log_key ctlog.pem -at_least 1\n"
"    gmssl sctverify -in sctlist.bin -precert tbs.der -issuer_key_hash HEX -log_key ctlog.pem\n"
"\n";

static int read_file(const char *file, uint8_t *buf, size_t *buflen, size_t maxlen)
{
	FILE *fp;
	size_t len;

	if (!(fp = fopen(file, "rb"))) {
		return -1;
	}
	len = fread(buf, 1, maxlen, fp);
	if (ferror(fp) || (len == maxlen && fgetc(fp) != EOF)) {
		fclose(fp);
		return -1;
	}
	fclose(fp);
	*buflen = len;
	return 1;
}

int sctverify_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *infile = NULL;
	char *certfile = NULL;
	char *precertfile = NULL;
	char *digest_name = "sha256";
	char *str;
	FILE *certfp = NULL;
	FILE *logkeyfp = NULL;
	int entry_type = -1;
	int verbose = 0;
	size_t at_least = 1;
	size_t i;

	uint8_t sct_list[SCTVERIFY_MAX_SCT_LIST_SIZE];
	size_t sct_list_len = 0;
	uint8_t entry[SCTVERIFY_MAX_ENTRY_SIZE];
	size_t entry_len = 0;
	uint8_t issuer_key_hash[SCT_ISSUER_KEY_HASH_SIZE];
	size_t issuer_key_hash_len = 0;
	CT_LOG_INFO ct_logs[SCTVERIFY_MAX_CT_LOGS];
	size_t ct_logs_cnt = 0;
	const DIGEST *digest;

	argc--;
	argv++;

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n\n", prog, options);
			printf("%s\n", help);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
		} else if (!strcmp(*argv, "-cert")) {
			if (--argc < 1) goto bad;
			certfile = *(++argv);
			entry_type = SCT_log_entry_type_x509_entry;
		} else if (!strcmp(*argv, "-precert")) {
			if (--argc < 1) goto bad;
			precertfile = *(++argv);
			entry_type = SCT_log_entry_type_precert_entry;
		} else if (!strcmp(*argv, "-issuer_key_hash")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (hex_to_bytes(str, strlen(str), issuer_key_hash,
				&issuer_key_hash_len) != 1
				|| issuer_key_hash_len != sizeof(issuer_key_hash)) {
				fprintf(stderr, "%s: invalid `-issuer_key_hash` value\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-log_key")) {
			if (--argc < 1) goto bad;
			if (ct_logs_cnt >= SCTVERIFY_MAX_CT_LOGS) {
				fprintf(stderr, "%s: too many `-log_key` options\n", prog);
				goto end;
			}
			str = *(++argv);
			if (!(logkeyfp = fopen(str, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n",
					prog, str, strerror(errno));
				goto end;
			}
			memset(&ct_logs[ct_logs_cnt], 0, sizeof(CT_LOG_INFO));
			if (x509_public_key_info_from_pem(&ct_logs[ct_logs_cnt].log_key,
				logkeyfp) != 1) {
				fprintf(stderr, "%s: parse CT log public key failure\n", prog);
				goto end;
			}
			fclose(logkeyfp);
			logkeyfp = NULL;
			ct_logs[ct_logs_cnt].log_name = str;
			ct_logs_cnt++;
		} else if (!strcmp(*argv, "-at_least")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			at_least = (size_t)atoi(str);
			if (!at_least) {
				fprintf(stderr, "%s: invalid `-at_least` value\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-digest")) {
			if (--argc < 1) goto bad;
			digest_name = *(++argv);
		} else if (!strcmp(*argv, "-verbose")) {
			verbose = 1;
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

	if (!infile) {
		fprintf(stderr, "%s: '-in' option required\n", prog);
		goto end;
	}
	if ((certfile && precertfile) || (!certfile && !precertfile)) {
		fprintf(stderr, "%s: exactly one of '-cert' or '-precert' required\n", prog);
		goto end;
	}
	if (!ct_logs_cnt) {
		fprintf(stderr, "%s: '-log_key' option required\n", prog);
		goto end;
	}
	if (at_least > ct_logs_cnt) {
		fprintf(stderr, "%s: `-at_least` must be <= number of CT log keys\n", prog);
		goto end;
	}
	if (!(digest = digest_from_name(digest_name))) {
		fprintf(stderr, "%s: invalid `-digest` value\n", prog);
		goto end;
	}
	if (read_file(infile, sct_list, &sct_list_len, sizeof(sct_list)) != 1) {
		fprintf(stderr, "%s: read SCT list failure\n", prog);
		goto end;
	}

	switch (entry_type) {
	case SCT_log_entry_type_x509_entry:
		if (!(certfp = fopen(certfile, "rb"))) {
			fprintf(stderr, "%s: open '%s' failure : %s\n",
				prog, certfile, strerror(errno));
			goto end;
		}
		if (x509_cert_from_pem(entry, &entry_len, sizeof(entry), certfp) != 1) {
			fprintf(stderr, "%s: read certificate failure\n", prog);
			goto end;
		}
		break;
	case SCT_log_entry_type_precert_entry:
		if (issuer_key_hash_len != SCT_ISSUER_KEY_HASH_SIZE) {
			fprintf(stderr, "%s: '-issuer_key_hash' option required with '-precert'\n", prog);
			goto end;
		}
		if (read_file(precertfile, entry, &entry_len, sizeof(entry)) != 1) {
			fprintf(stderr, "%s: read TBSCertificate failure\n", prog);
			goto end;
		}
		break;
	}

	for (i = 0; i < ct_logs_cnt; i++) {
		size_t dgstlen;

		if (x509_public_key_digest_ex(&ct_logs[i].log_key, digest,
			ct_logs[i].log_id, &dgstlen) != 1
			|| dgstlen != SCT_LOG_ID_SIZE) {
			fprintf(stderr, "%s: compute CT log id failure\n", prog);
			goto end;
		}
	}

	if (sct_list_verify(sct_list, sct_list_len, entry_type,
		issuer_key_hash_len ? issuer_key_hash : NULL,
		entry, entry_len, ct_logs, ct_logs_cnt, at_least) != 1) {
		fprintf(stderr, "%s: SCT list verification failure\n", prog);
		goto end;
	}

	if (verbose) {
		fprintf(stderr, "%s: SCT list verification success\n", prog);
		fprintf(stderr, "%s: verified at least %zu SCT(s) with %zu CT log key(s)\n",
			prog, at_least, ct_logs_cnt);
	}
	ret = 0;

end:
	if (certfp) fclose(certfp);
	if (logkeyfp) fclose(logkeyfp);
	return ret;
}
