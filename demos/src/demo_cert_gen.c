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

int main(int argc, char *argv[])
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
	char *country = "CN";
	char *state = "Beijing";
	char *locality = "Haidian";
	char *org = "PKU";
	char *org_unit = "CS";
	char *common_name = "ROOTCA";

	// Validity
	int days = 3650;
	time_t not_before;
	time_t not_after;

	// Private Key
	char *keyfile="rootcakey.pem";  //可由/demos/scripts/cert_gen.sh生成
	FILE *keyfp = NULL;
	char *pass = "1234";
	SM2_KEY sm2_key;
	char signer_id[SM2_MAX_ID_LENGTH + 1] = {0};
	size_t signer_id_len = 0;

	uint8_t *cert = NULL;
	size_t certlen = 0;
	FILE *outfp = stdout;
	char *outfile = "rootcacert.pem";
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
	char *keyusage1="keyCertSign";
	char *keyusage2="cRLSign";

	// SubjectAltName
	uint8_t subject_alt_name[2048];
	size_t subject_alt_name_len = 0;

	// IssuerAltName
	uint8_t issuer_alt_name[512];
	size_t issuer_alt_name_len = 0;

	// BasicConstraints
	int ca = 1;
	int path_len_constraint = 6;

	// ExtKeyUsageSyntax
	int ext_key_usages[12];
	size_t ext_key_usages_cnt = 0;

	// CRLDistributionPoints
	char *crl_http_uri = "http://pku.edu.cn/ca.crl";
	char *crl_ldap_uri = NULL;

	// InhibitAnyPolicy
	int inhibit_any_policy = -1;

	// FreshestCRL
	char *ca_issuers_uri = "http://pku.edu.cn/ca.crt";
	char *ocsp_uri = "http://ocsp.pku.edu.cn";


	if (!(keyfp = fopen(keyfile, "rb"))) {
		fprintf(stderr, "%s: open '%s' failure : %s\n", prog, keyfile, strerror(errno));
		goto end;
	}


	if (ext_key_usage_set(&key_usage, keyusage1) != 1) {
		fprintf(stderr, "%s: invalid `-key_usage` value '%s'\n", prog, keyusage1);
		goto end;
	}
	
	if (ext_key_usage_set(&key_usage, keyusage2) != 1) {
		fprintf(stderr, "%s: invalid `-key_usage` value '%s'\n", prog, keyusage2);
		goto end;
	}
	
	
	if (!(outfp = fopen(outfile, "wb"))) {
		fprintf(stderr, "%s: open '%s' failure : %s\n", prog, outfile, strerror(errno));
		goto end;
	}
	
	if (!signer_id_len) {
		strcpy(signer_id, SM2_DEFAULT_ID);
		signer_id_len = strlen(SM2_DEFAULT_ID);
	}



	if (sm2_private_key_info_decrypt_from_pem(&sm2_key, pass, keyfp) != 1) {
		fprintf(stderr, "%s: load private key failed\n", prog);
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


	if (key_usage) {
		if (x509_exts_add_key_usage(exts, &extslen, sizeof(exts), X509_critical, key_usage) != 1) {
			fprintf(stderr, "%s: set KeyUsage extension failure\n", prog);
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

	if (crl_http_uri || crl_ldap_uri) {
		if (x509_exts_add_crl_distribution_points(exts, &extslen, sizeof(exts),
			-1,
			crl_http_uri, crl_http_uri ? strlen(crl_http_uri) : 0,
			crl_ldap_uri, crl_ldap_uri ? strlen(crl_ldap_uri) : 0) != 1) {
			fprintf(stderr, "%s: set CRLDistributionPoints extension failure\n", prog);
			return -1;
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
