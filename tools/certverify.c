/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/file.h>
#include <gmssl/x509.h>
#include <gmssl/x509_ext.h>
#include <gmssl/error.h>


enum {
	TLS_cert_chain_tlcp_server = 1,
	TLS_cert_chain_server,
	TLS_cert_chain_client,
};

static const char *usage =
	"-in pem [-tlcp_server|-server|-client] -cacert pem"
	" [-crl der] [-ocsp der] [-hostname str]";

static const char *help =
"Options\n"
"\n"
"    -in pem             Certificate chain in PEM format\n"
"    -tlcp_server        Verify TLCP server certificate chain, default\n"
"    -server             Verify TLS server certificate chain\n"
"    -client             Verify TLS client certificate chain\n"
"    -cacert pem         Trusted CA certificate(s) in PEM format\n"
"    -crl der            CRL in DER format\n"
"    -ocsp der           OCSPResponse in DER format\n"
"    -hostname str       Server hostname for certificate verification\n"
"\n"
"Examples\n"
"\n"
"    gmssl certverify -tlcp_server -in certs.pem -cacert cacerts.pem -hostname localhost\n"
"\n";

static int cert_match_server_name_normalized(const uint8_t *cert, size_t certlen,
	const char *hostname)
{
	int ret;
	const uint8_t *dns_name;
	size_t dns_name_len;

	if (!cert || !certlen || !hostname || !strlen(hostname)) {
		error_print();
		return -1;
	}
	if ((ret = x509_cert_get_subject_alt_name_dns_name(cert, certlen,
		&dns_name, &dns_name_len)) < 0) {
		error_print();
		return -1;
	} else if (ret == 0) {
		return 0;
	}
	return x509_general_name_normalized_equ(X509_gn_dns_name, dns_name, dns_name_len,
		X509_gn_dns_name, (const uint8_t *)hostname, strlen(hostname));
}

static const char *verify_result_name(int verify_result)
{
	switch (verify_result) {
	case X509_verify_ok:
		return "ok";
	case X509_verify_err_certificate:
		return "certificate";
	case X509_verify_err_cert_chain:
		return "cert_chain";
	case X509_verify_err_trust_anchor:
		return "trust_anchor";
	case X509_verify_err_depth:
		return "depth";
	case X509_verify_err_crl:
		return "crl";
	case X509_verify_err_ocsp:
		return "ocsp";
	case X509_verify_err_constraints:
		return "constraints";
	case X509_verify_err_tls_extensions:
		return "tls_extensions";
	case X509_verify_err_hostname:
		return "hostname";
	}
	return "unknown";
}

int certverify_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *infile = NULL;
	char *cacertfile = NULL;
	char *crlfile = NULL;
	char *ocspfile = NULL;
	char *hostname = NULL;
	int chain_type = TLS_cert_chain_tlcp_server;
	uint8_t *certs = NULL;
	size_t certslen = 0;
	uint8_t *cacerts = NULL;
	size_t cacertslen = 0;
	uint8_t *crl = NULL;
	size_t crl_len = 0;
	uint8_t *ocsp = NULL;
	size_t ocsp_len = 0;
	int certs_type = X509_cert_chain_server;
	int verify_result = X509_verify_ok;
	const uint8_t *cert;
	size_t certlen;
	int rv;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: gmssl %s %s\n", prog, usage);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: gmssl %s %s\n\n", prog, usage);
			printf("%s\n", help);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
		} else if (!strcmp(*argv, "-tlcp_server")) {
			if (chain_type) {
				fprintf(stderr, "%s: chain type option conflicts\n", prog);
				goto end;
			}
			chain_type = TLS_cert_chain_tlcp_server;
		} else if (!strcmp(*argv, "-server")) {
			if (chain_type) {
				fprintf(stderr, "%s: chain type option conflicts\n", prog);
				goto end;
			}
			chain_type = TLS_cert_chain_server;
		} else if (!strcmp(*argv, "-client")) {
			if (chain_type) {
				fprintf(stderr, "%s: chain type option conflicts\n", prog);
				goto end;
			}
			chain_type = TLS_cert_chain_client;
		} else if (!strcmp(*argv, "-cacert")) {
			if (--argc < 1) goto bad;
			cacertfile = *(++argv);
		} else if (!strcmp(*argv, "-crl")) {
			if (--argc < 1) goto bad;
			crlfile = *(++argv);
		} else if (!strcmp(*argv, "-ocsp")) {
			if (--argc < 1) goto bad;
			ocspfile = *(++argv);
		} else if (!strcmp(*argv, "-hostname")) {
			if (--argc < 1) goto bad;
			hostname = *(++argv);
			if (!strlen(hostname) || strchr(hostname, '\r') || strchr(hostname, '\n')) {
				fprintf(stderr, "%s: invalid '-hostname' value\n", prog);
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

	if (!infile) {
		fprintf(stderr, "%s: '-in' option required\n", prog);
		goto end;
	}
	if (!cacertfile) {
		fprintf(stderr, "%s: '-cacert' option required\n", prog);
		goto end;
	}
	if (hostname && chain_type == TLS_cert_chain_client) {
		fprintf(stderr, "%s: '-hostname' only allowed with '-tlcp_server' or '-server'\n", prog);
		goto end;
	}
	if (x509_certs_new_from_file(&certs, &certslen, infile) != 1) {
		fprintf(stderr, "%s: load '%s' failed\n", prog, infile);
		goto end;
	}
	if (x509_certs_new_from_file(&cacerts, &cacertslen, cacertfile) != 1) {
		fprintf(stderr, "%s: load '%s' failed\n", prog, cacertfile);
		goto end;
	}
	if (crlfile) {
		if (file_read_all(crlfile, &crl, &crl_len) != 1) {
			fprintf(stderr, "%s: load '%s' failed\n", prog, crlfile);
			goto end;
		}
	}
	if (ocspfile) {
		if (file_read_all(ocspfile, &ocsp, &ocsp_len) != 1) {
			fprintf(stderr, "%s: load '%s' failed\n", prog, ocspfile);
			goto end;
		}
	}

	switch (chain_type) {
	case TLS_cert_chain_tlcp_server:
		if (x509_certs_verify_tlcp(certs, certslen, X509_cert_chain_server,
			cacerts, cacertslen, crl, crl_len, ocsp, ocsp_len,
			X509_MAX_VERIFY_DEPTH, &verify_result) != 1) {
			fprintf(stderr, "%s: Vcerification failure: %s\n", prog, verify_result_name(verify_result));
			goto end;
		}
		break;
	case TLS_cert_chain_server:
		if (x509_certs_verify(certs, certslen, X509_cert_chain_server,
			cacerts, cacertslen, crl, crl_len, ocsp, ocsp_len,
			X509_MAX_VERIFY_DEPTH, &verify_result) != 1) {
			fprintf(stderr, "%s: Verification failure: %s\n", prog, verify_result_name(verify_result));
			goto end;
		}
		break;
	case TLS_cert_chain_client:
		if (x509_certs_verify(certs, certslen, X509_cert_chain_client,
			cacerts, cacertslen, crl, crl_len, ocsp, ocsp_len,
			X509_MAX_VERIFY_DEPTH, &verify_result) != 1) {
			fprintf(stderr, "%s: Verification failure: %s\n", prog, verify_result_name(verify_result));
			goto end;
		}
		break;
	default:
		error_print();
		goto end;
	}


	if (hostname) {
		if (x509_certs_get_cert_by_index(certs, certslen, 0, &cert, &certlen) != 1) {
			fprintf(stderr, "%s: read entity certificate failure\n", prog);
			goto end;
		}
		if ((rv = cert_match_server_name_normalized(cert, certlen, hostname)) < 0) {
			fprintf(stderr, "%s: hostname verification error\n", prog);
			goto end;
		}
		if (rv == 0) {
			fprintf(stderr, "%s: Verification failure: %s\n", prog, verify_result_name(X509_verify_err_hostname));
			goto end;
		}
	}

	printf("Verification success\n");
	ret = 0;
end:
	if (certs) free(certs);
	if (cacerts) free(cacerts);
	if (crl) free(crl);
	if (ocsp) free(ocsp);
	return ret;
}
