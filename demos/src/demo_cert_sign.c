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
#include <gmssl/hex.h>
#include <gmssl/mem.h>
#include <gmssl/rand.h>
#include <gmssl/x509.h>
#include <gmssl/x509_ext.h>
#include <gmssl/x509_req.h>



static int ext_key_usage_set(int *usages, const char *usage_name)
{
	int flag = 0;
	if (x509_key_usage_from_name(&flag, usage_name) != 1) {
		return -1;
	}
	*usages |= flag;
	return 1;
}

int main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *str;

	// Input Req/CSR
	char *infile = "careq.pem";
	FILE *infp = NULL;
	uint8_t req[512];
	size_t reqlen;
	char req_id[SM2_MAX_ID_LENGTH + 1] = {0};
	size_t req_id_len = 0;

	// SerialNumber
	uint8_t serial[20];
	int serial_len = 12;

	// Validity
	int days = 365;
	time_t not_before;
	time_t not_after;

	// Subject from Req
	const uint8_t *subject;
	size_t subject_len;
	SM2_KEY subject_public_key;

	// CA certficate and Private Key
	uint8_t *cacert = NULL;
	char *rootcacert="rootcacert.pem";
	size_t cacertlen;
	FILE *keyfp = NULL;
	char *rootcakey="rootcakey.pem";
	char *pass = "1234";
	SM2_KEY sm2_key;
	char signer_id[SM2_MAX_ID_LENGTH + 1] = {0};
	size_t signer_id_len = 0;

	// Issuer from CA certificate
	const uint8_t *issuer;
	size_t issuer_len;
	SM2_KEY issuer_public_key;

	// Output
	char *outfile = "cacert.pem";
	FILE *outfp = stdout;
	uint8_t *cert = NULL;
	size_t certlen = 0;
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
	char *keyusage="keyCertSign";

	// SubjectAltName
	uint8_t subject_alt_name[2048];
	size_t subject_alt_name_len = 0;

	// IssuerAltName
	uint8_t issuer_alt_name[512];
	size_t issuer_alt_name_len = 0;

	// BasicConstraints
	int ca = -1;
	int path_len_constraint = 0;

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





			if (!(infp = fopen(infile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, infile, strerror(errno));
				goto end;
			}
			

			if (!(outfp = fopen(outfile, "wb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, outfile, strerror(errno));
				goto end;
			}


			if (x509_cert_new_from_file(&cacert, &cacertlen, rootcacert) != 1) {
				fprintf(stderr, "%s: load ca certificate '%s' failure\n", prog, rootcacert);
				goto end;
			}
			
			
			if (!(keyfp = fopen(rootcakey, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, rootcakey, strerror(errno));
				goto end;
			}
			

			if (ext_key_usage_set(&key_usage, keyusage) != 1) {
				fprintf(stderr, "%s: invalid `-key_usage` value '%s'\n", prog, keyusage);
				goto end;
			}

	if (!days) {
		fprintf(stderr, "%s: '-days' option required\n", prog);
		goto end;
	}
	if (!cacert) {
		fprintf(stderr, "%s: '-cacert' option required\n", prog);
		goto end;
	}
	if (!keyfp) {
		fprintf(stderr, "%s: '-key' option required\n", prog);
		goto end;
	}
	if (!pass) {
		fprintf(stderr, "%s: '-pass' option required\n", prog);
		goto end;
	}

	if (x509_req_from_pem(req, &reqlen, sizeof(req), infp) != 1) {
		fprintf(stderr, "%s: parse CSR failure\n", prog);
		goto end;
	}
	if (!req_id_len) {
		strcpy(req_id, SM2_DEFAULT_ID);
		req_id_len = strlen(SM2_DEFAULT_ID);
	}
	if (x509_req_verify(req, reqlen, req_id, req_id_len) != 1) {
		fprintf(stderr, "%s: signature verification failure\n", prog);
		goto end;
	}
	if (x509_req_get_details(req, reqlen,
		NULL, &subject, &subject_len, &subject_public_key,
		NULL, NULL, NULL, NULL, NULL) != 1) {
		fprintf(stderr, "%s: parse CSR failure\n", prog);
		goto end;
	}

	if (x509_cert_get_subject(cacert, cacertlen, &issuer, &issuer_len) != 1
		|| x509_cert_get_subject_public_key(cacert, cacertlen, &issuer_public_key) != 1) {
		fprintf(stderr, "%s: parse CA certificate failure\n", prog);
		goto end;
	}
	if (sm2_private_key_info_decrypt_from_pem(&sm2_key, pass, keyfp) != 1) {
		fprintf(stderr, "%s: load private key failure\n", prog);
		goto end;
	}
	if (sm2_public_key_equ(&sm2_key, &issuer_public_key) != 1) {
		fprintf(stderr, "%s: private key and CA certificate not match\n", prog);
		goto end;
	}
	if (!signer_id_len) {
		strcpy(signer_id, SM2_DEFAULT_ID);
		signer_id_len = strlen(SM2_DEFAULT_ID);
	}

	if (rand_bytes(serial, serial_len) != 1) {
		fprintf(stderr, "%s: random number generator error\n", prog);
		goto end;
	}

	time(&not_before);
	if (x509_validity_add_days(&not_after, not_before, days) != 1) {
		fprintf(stderr, "%s: set Validity failure\n", prog);
		goto end;
	}

	// following code copy from certgen.c
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
		issuer, issuer_len,
		not_before, not_after,
		subject, subject_len,
		&subject_public_key,
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
		issuer, issuer_len,
		not_before, not_after,
		subject, subject_len,
		&subject_public_key,
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
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
