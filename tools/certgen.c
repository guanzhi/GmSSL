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
#include <gmssl/mem.h>
#include <gmssl/rand.h>
#include <gmssl/pkcs8.h>
#include <gmssl/error.h>
#include <gmssl/hex.h>
#include <gmssl/x509.h>
#include <gmssl/x509_ext.h>


static const char *options =
	"[-C str] [-ST str] [-L str] [-O str] [-OU str] -CN str"
	" -serial_len num"
	" -days num"
	" -key pem -pass pass"
	" [-sm2_id str | -sm2_id_hex hex]"
	" [-gen_authority_key_id]"
	" [-gen_subject_key_id]"
	" [-key_usage str]*"
	" [-subject_dns_name str]*"
	" [-issuer_dns_name str]*"
	" [-ca -path_len_constraint num]"
	" [-ext_key_usage str]*"
	" [-crl_http_uri uri] [-crl_ldap_uri uri]"
	" [-inhibit_any_policy num]"
	" [-ca_issuers_uri uri] [-ocsp_uri uri uri]"
	" [-out pem]";

static char *usage =
"Options\n"
"\n"
"    -serial_len num              Serial number length in bytes\n"
"    -days num                    Validity peroid in days\n"
"    -key file                    Private key file in PEM format\n"
"    -pass pass                   Password for decrypting private key file\n"
"    -sm2_id str                  Signer's ID in SM2 signature algorithm\n"
"    -sm2_id_hex hex              Signer's ID in hex format\n"
"                                 When `-sm2_id` or `-sm2_id_hex` is specified,\n"
"                                   must use the same ID in other commands explicitly.\n"
"                                 If neither `-sm2_id` nor `-sm2_id_hex` is specified,\n"
"                                   the default string '1234567812345678' is used\n"
"    -out file                    Output certificate file in PEM format\n"
"\n"
"  Subject and Issuer options\n"
"\n"
"    -C  str                      Country\n"
"    -ST str                      State or province name\n"
"    -L  str                      Locality\n"
"    -O  str                      Organization\n"
"    -OU str                      Organizational unit\n"
"    -CN str                      Common name\n"
"\n"
"  Extension options\n"
"\n"
"    -gen_authority_key_id        Generate AuthorityKeyIdentifier extension use SM3\n"
"    -gen_subject_key_id          Generate SubjectKeyIdentifier extension use SM3\n"
"    -key_usage str               Add KeyUsage extension\n"
"                                 this option can be called multi-times\n"
"                                 avaiable values:\n"
"                                     * digitalSignature\n"
"                                     * nonRepudiation\n"
"                                     * keyEncipherment\n"
"                                     * dataEncipherment\n"
"                                     * keyAgreement\n"
"                                     * keyCertSign\n"
"                                     * cRLSign\n"
"                                     * encipherOnly\n"
"                                     * decipherOnly\n"
"    -subject_dns_name str        Add DNS name to SubjectAltName extension\n"
"                                 this option can be called multi-times\n"
"    -issuer_dns_name str         Add DNS name to IssuerAltName extension\n"
"                                 this option can be called multi-times\n"
"    -ca                          Set cA of BasicConstaints extension\n"
"    -path_len_constraint num     Set pathLenConstraint of BasicConstaints extension\n"
"    -ext_key_usage str           Set ExtKeyUsage extension\n"
"                                 this option can be called multi-times\n"
"                                 avaiable values:\n"
"                                     * anyExtendedKeyUsage\n"
"                                     * serverAuth\n"
"                                     * clientAuth\n"
"                                     * codeSigning\n"
"                                     * emailProtection\n"
"                                     * timeStamping\n"
"                                     * OCSPSigning\n"
"    -crl_http_uri uri            Set HTTP URI of CRL of CRLDistributionPoints extension\n"
"    -crl_ldap_uri uri            Set LDAP URI of CRL of CRLDistributionPoints extension\n"
"    -inhibit_any_policy num      Set skipCerts number of InhibitAnyPolicy extension\n"
"    -ca_issuers_uri uri          Set URI of the CA certificate in DER-encoding o FreshestCRL extension\n"
"    -ocsp_uri uri                Set OCSP URI of FreshestCRL extension\n"
"\n"
"Examples\n"
"\n"
"    gmssl sm2keygen -pass P@ssw0rd -out rootcakey.pem\n"
"\n"
"    gmssl certgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN ROOTCA -days 3650 \\\n"
"          -key rootcakey.pem -pass P@ssw0rd \\\n"
"          -ca -path_len_constraint 6 \\\n"
"          -key_usage keyCertSign -key_usage cRLSign \\\n"
"          -crl_http_uri http://pku.edu.cn/ca.crl \\\n"
"          -ca_issuers_uri http://pku.edu.cn/ca.crt -ocsp_uri http://ocsp.pku.edu.cn \\\n"
"          -out rootcacert.pem\n"
"\n";


static int ext_key_usage_set(int *usages, const char *usage_name)
{
	int flag;
	if (x509_key_usage_from_name(&flag, usage_name) != 1) {
		error_print();
		return -1;
	}
	*usages |= flag;
	return 1;
}

int certgen_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *str;

	// SerialNumber
	uint8_t serial[20];
	int serial_len = 12;

	// Issuer, Subject
	uint8_t name[256];
	size_t namelen;
	char *country = NULL;
	char *state = NULL;
	char *locality = NULL;
	char *org = NULL;
	char *org_unit = NULL;
	char *common_name = NULL;

	// Validity
	int days = 0;
	time_t not_before;
	time_t not_after;

	// Private Key
	FILE *keyfp = NULL;
	char *pass = NULL;
	SM2_KEY sm2_key;
	char signer_id[SM2_MAX_ID_LENGTH + 1] = {0};
	size_t signer_id_len = 0;

	uint8_t *cert = NULL;
	size_t certlen = 0;
	FILE *outfp = stdout;
	char *outfile = NULL;
	uint8_t *p;

	// Extensions
	uint8_t exts[4096];
	size_t extslen = 0;

	// AuthorityKeyIdentifier
	int gen_authority_key_id = 0;

	// SubjectKeyIdentifier
	int gen_subject_key_id = 0;

	// KeyUsage
	int key_usage = 0;

	// SubjectAltName
	uint8_t subject_alt_name[2048];
	size_t subject_alt_name_len = 0;

	// IssuerAltName
	uint8_t issuer_alt_name[512];
	size_t issuer_alt_name_len = 0;

	// BasicConstraints
	int ca = -1;
	int path_len_constraint = -1;

	// ExtKeyUsageSyntax
	int ext_key_usages[12];
	size_t ext_key_usages_cnt = 0;

	// CRLDistributionPoints
	char *crl_http_uri = NULL;
	char *crl_ldap_uri = NULL;

	// InhibitAnyPolicy
	int inhibit_any_policy = -1;

	// FreshestCRL
	char *ca_issuers_uri = NULL;
	char *ocsp_uri = NULL;


	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: gmssl %s %s\n", prog, options);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: gmssl %s %s\n\n", prog, options);
			printf("%s\n", usage);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-serial_len")) {
			if (--argc < 1) goto bad;
			serial_len = atoi(*(++argv));
			if (serial_len <= 0 || serial_len > sizeof(serial)) {
				fprintf(stderr, "%s: invalid `-serial_len` value, need a number less than %zu\n", prog, sizeof(serial));
				goto end;
			}
		} else if (!strcmp(*argv, "-CN")) {
			if (--argc < 1) goto bad;
			common_name = *(++argv);
		} else if (!strcmp(*argv, "-O")) {
			if (--argc < 1) goto bad;
			org = *(++argv);
		} else if (!strcmp(*argv, "-OU")) {
			if (--argc < 1) goto bad;
			org_unit = *(++argv);
		} else if (!strcmp(*argv, "-C")) {
			if (--argc < 1) goto bad;
			country = *(++argv);
			if (strlen(country) != 2) {
				fprintf(stderr, "%s: invalid '-C' value, need 2-char country name such as 'CN', 'US'\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-ST")) {
			if (--argc < 1) goto bad;
			state = *(++argv);
		} else if (!strcmp(*argv, "-L")) {
			if (--argc < 1) goto bad;
			locality = *(++argv);
		} else if (!strcmp(*argv, "-days")) {
			if (--argc < 1) goto bad;
			days = atoi(*(++argv));
			if (days <= 0) {
				fprintf(stderr, "%s: invalid `-days` value, need a positive number\n", prog);
				goto end;
			}

		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (!(keyfp = fopen(str, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, str, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
		} else if (!strcmp(*argv, "-sm2_id")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (strlen(str) > sizeof(signer_id) - 1) {
				fprintf(stderr, "%s: invalid `-sm2_id` length\n", prog);
				goto end;
			}
			strncpy(signer_id, str, sizeof(signer_id));
			signer_id_len = strlen(str);
		} else if (!strcmp(*argv, "-sm2_id_hex")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (strlen(str) > (sizeof(signer_id) - 1) * 2) {
				fprintf(stderr, "%s: invalid `-sm2_id_hex` length\n", prog);
				goto end;
			}
			if (hex_to_bytes(str, strlen(str), (uint8_t *)signer_id, &signer_id_len) != 1) {
				fprintf(stderr, "%s: invalid `-sm2_id_hex` value\n", prog);
				goto end;
			}

		} else if (!strcmp(*argv, "-gen_authority_key_id")) {
			gen_authority_key_id = 1;
		} else if (!strcmp(*argv, "-gen_subject_key_id")) {
			gen_subject_key_id = 1;
		} else if (!strcmp(*argv, "-key_usage")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (ext_key_usage_set(&key_usage, str) != 1) {
				fprintf(stderr, "%s: invalid `-key_usage` value '%s'\n", prog, str);
				goto end;
			}
		} else if (!strcmp(*argv, "-subject_dns_name")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (x509_general_names_add_dns_name(
				subject_alt_name, &subject_alt_name_len, sizeof(subject_alt_name), str) != 1) {
				fprintf(stderr, "%s: inner error on processing `-subject_dns_name`\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-issuer_dns_name")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (x509_general_names_add_dns_name(
				issuer_alt_name, &issuer_alt_name_len, sizeof(issuer_alt_name), str) != 1) {
				fprintf(stderr, "%s: inner error on processing `-issuer_dns_name`\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-ca")) {
			ca = 1;
		} else if (!strcmp(*argv, "-path_len_constraint")) {
			if (--argc < 1) goto bad;
			path_len_constraint = atoi(*(++argv));
			if (path_len_constraint < 0) {
				fprintf(stderr, "%s: invalid `-path_len_constraint` value\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-ext_key_usage")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (x509_key_purpose_from_name(str) <= 0) {
				fprintf(stderr, "%s: invalid `-ext_key_usage` value '%s'\n", prog, str);
				goto end;
			}
			if (ext_key_usages_cnt >= sizeof(ext_key_usages)/sizeof(ext_key_usages[0])) {
				fprintf(stderr, "%s: too much `-ext_key_usage` options\n", prog);
				goto end;
			}
			ext_key_usages[ext_key_usages_cnt++] = x509_key_purpose_from_name(str);
		} else if (!strcmp(*argv, "-crl_http_uri")) {
			if (--argc < 1) goto bad;
			crl_http_uri = *(++argv);
		} else if (!strcmp(*argv, "-crl_ldap_uri")) {
			if (--argc < 1) goto bad;
			crl_ldap_uri = *(++argv);
		} else if (!strcmp(*argv, "-inhibit_any_policy")) {
			if (--argc < 1) goto bad;
			inhibit_any_policy = atoi(*(++argv));
			if (inhibit_any_policy < 0) {
				fprintf(stderr, "%s: invalid `-inhibit_any_policy` value\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-ca_issuers_uri")) {
			if (--argc < 1) goto bad;
			ca_issuers_uri = *(++argv);
		} else if (!strcmp(*argv, "-ocsp_uri")) {
			if (--argc < 1) goto bad;
			ocsp_uri = *(++argv);

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
			fprintf(stderr, "%s: `%s` value missing\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}

	if (!common_name) {
		fprintf(stderr, "%s: option `-CN` required\n", prog);
		printf("usage: gmssl %s %s\n\n", prog, options);
		goto end;
	}
	if (!days) {
		fprintf(stderr, "%s: option `-days` required\n", prog);
		printf("usage: gmssl %s %s\n\n", prog, options);
		goto end;
	}
	if (!keyfp) {
		fprintf(stderr, "%s: option `-key` required\n", prog);
		printf("usage: gmssl %s %s\n\n", prog, options);
		goto end;
	}
	if (!pass) {
		fprintf(stderr, "%s: option `-pass` required\n", prog);
		printf("usage: gmssl %s %s\n\n", prog, options);
		goto end;
	}

	if (sm2_private_key_info_decrypt_from_pem(&sm2_key, pass, keyfp) != 1) {
		fprintf(stderr, "%s: load private key failed\n", prog);
		goto end;
	}
	if (!signer_id_len) {
		strcpy(signer_id, SM2_DEFAULT_ID);
		signer_id_len = strlen(SM2_DEFAULT_ID);
	}

	// Serial
	if (rand_bytes(serial, sizeof(serial)) != 1) {
		fprintf(stderr, "%s: RNG error\n", prog);
		goto end;
	}

	// Issuer, Subject
	if (x509_name_set(name, &namelen, sizeof(name), country, state, locality, org, org_unit, common_name) != 1) {
		fprintf(stderr, "%s: set Issuer/Subject Name error\n", prog);
		goto end;
	}

	// Validity
	time(&not_before);
	if (x509_validity_add_days(&not_after, not_before, days) != 1) {
		fprintf(stderr, "%s: set Validity failure\n", prog);
		goto end;
	}

	// Extensions
	if (gen_authority_key_id) {
		if (x509_exts_add_default_authority_key_identifier(exts, &extslen, sizeof(exts), &sm2_key) != 1) {
			fprintf(stderr, "%s: set AuthorityKeyIdentifier extension failure\n", prog);
			goto end;
		}
	}
	if (gen_subject_key_id) {
		if (x509_exts_add_subject_key_identifier_ex(exts, &extslen, sizeof(exts), -1, &sm2_key) != 1) {
			fprintf(stderr, "%s: set SubjectKeyIdentifier extension failure\n", prog);
			goto end;
		}
	}
	if (key_usage) {
		if (x509_exts_add_key_usage(exts, &extslen, sizeof(exts), X509_critical, key_usage) != 1) {
			fprintf(stderr, "%s: set KeyUsage extension failure\n", prog);
			goto end;
		}
	}
	// no CertificatePolicies
	// no PolicyMappings
	if (subject_alt_name_len) {
		if (x509_exts_add_subject_alt_name(exts, &extslen, sizeof(exts),
			-1, subject_alt_name, subject_alt_name_len) != 1) {
			fprintf(stderr, "%s: set SubjectAltName extension failure\n", prog);
			goto end;
		}
	}
	if (issuer_alt_name_len) {
		if (x509_exts_add_issuer_alt_name(exts, &extslen, sizeof(exts),
			-1, issuer_alt_name, issuer_alt_name_len) != 1) {
			fprintf(stderr, "%s: set IssuerAltName extension failure\n", prog);
			goto end;
		}
	}
	// no SubjectDirectoryAttributes
	if (ca >= 0 || path_len_constraint >= 0) {
		if (x509_exts_add_basic_constraints(exts, &extslen, sizeof(exts),
			X509_critical, ca, path_len_constraint) != 1) {
			fprintf(stderr, "%s: set BasicConstraints extension failure\n", prog);
			goto end;
		}
	}
	// no NameConstraints
	// no PolicyConstraints
	if (ext_key_usages_cnt) {
		if (x509_exts_add_ext_key_usage(exts, &extslen, sizeof(exts),
			-1, ext_key_usages, ext_key_usages_cnt) != 1) {
			fprintf(stderr, "%s: set ExtKeyUsage extension failure\n", prog);
			goto end;
		}
	}
	if (crl_http_uri || crl_ldap_uri) {
		if (x509_exts_add_crl_distribution_points(exts, &extslen, sizeof(exts),
			-1,
			crl_http_uri, crl_http_uri ? strlen(crl_http_uri) : 0,
			crl_ldap_uri, crl_ldap_uri ? strlen(crl_ldap_uri) : 0) != 1) {
			fprintf(stderr, "%s: set CRLDistributionPoints extension failure\n", prog);
			return -1;
		}
	}
	if (inhibit_any_policy >= 0) {
		if (x509_exts_add_inhibit_any_policy(exts, &extslen, sizeof(exts),
			X509_critical, inhibit_any_policy) != 1) {
			fprintf(stderr, "%s: set InhibitAnyPolicy extension failure\n", prog);
			goto end;
		}
	}
	if (ca_issuers_uri || ocsp_uri) {
		if (x509_exts_add_authority_info_access(exts, &extslen, sizeof(exts), 0,
			ca_issuers_uri, ca_issuers_uri ? strlen(ca_issuers_uri) : 0,
			ocsp_uri, ocsp_uri ? strlen(ocsp_uri) : 0) != 1) {
			fprintf(stderr, "%s: set AuthorityInfoAccess extension failure\n",  prog);
			goto end;
		}
	}

	if (x509_cert_sign_to_der(
		X509_version_v3,
		serial, serial_len,
		OID_sm2sign_with_sm3,
		name, namelen,
		not_before, not_after,
		name, namelen,
		&sm2_key,
		NULL, 0,
		NULL, 0,
		exts, extslen,
		&sm2_key, signer_id, signer_id_len,
		NULL, &certlen) != 1) {
		fprintf(stderr, "%s: certificate generation failure\n", prog);
		goto end;
	}
	if (!(cert = malloc(certlen))) {
		fprintf(stderr, "%s: malloc failure\n", prog);
		goto end;
	}
	p = cert;
	certlen = 0;
	if (x509_cert_sign_to_der(
		X509_version_v3,
		serial, serial_len,
		OID_sm2sign_with_sm3,
		name, namelen,
		not_before, not_after,
		name, namelen,
		&sm2_key,
		NULL, 0,
		NULL, 0,
		exts, extslen,
		&sm2_key, signer_id, signer_id_len,
		&p, &certlen) != 1) {
		fprintf(stderr, "%s: certificate generation failure\n", prog);
		goto end;
	}
	if (x509_cert_to_pem(cert, certlen, outfp) != 1) {
		fprintf(stderr, "%s: output certificate failed\n", prog);
		goto end;
	}
	ret = 0;

end:
	gmssl_secure_clear(&sm2_key, sizeof(SM2_KEY));
	if (cert) free(cert);
	if (keyfp) fclose(keyfp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
