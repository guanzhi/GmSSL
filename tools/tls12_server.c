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
#include <gmssl/mem.h>
#include <gmssl/sm2.h>
#include <gmssl/tls.h>
#include <gmssl/error.h>


static const char *options = "[-port num] -cert pem -key pem -pass str [-cacert pem]";

static const char *help =
"Options\n"
"\n"
"    -port num              Listening port number, default 443\n"
"    -cipher_suite str      Supported cipher suites, may appear multiple times, higher priority first\n"
"    -supported_group str   Supported elliptic curves, may appear multiple times, higher priority first\n"
"    -sig_alg str           Supported signature algorithms\n"
"    -cert pem              Server's certificate chain in PEM format\n"
"    -key pem               Server's encrypted private key in PEM format\n"
"    -pass str              Password to decrypt private key\n"
"    -cert_request          Client certificate request\n"
"    -cacert pem            CA certificate for client certificate verification\n"
"    -verify_depth num      Certificate verification depth\n"
"    -client_cert_optional  Allow client send empty Certificate\n"
"    -renegotiation_info    Send renegotiation_info response when client supports RFC 5746\n"
"\n"
#include "tls12_help.h"
"\n";


int tls12_server_main(int argc , char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	int port = 443;
	int cipher_suites[4];
	size_t cipher_suites_cnt = 0;
	int supported_groups[4];
	size_t supported_groups_cnt = 0;
	int sig_algs[4];
	size_t sig_algs_cnt = 0;
	char *certfiles[4];
	size_t certfiles_cnt = 0;
	char *keyfiles[sizeof(certfiles)/sizeof(certfiles[0])];
	size_t keyfiles_cnt = 0;
	char *passes[sizeof(certfiles)/sizeof(certfiles[0])];
	size_t passes_cnt = 0;
	int cert_request = 0;
	char *cacertfile = NULL;
	int verify_depth = TLS_DEFAULT_VERIFY_DEPTH;
	int client_cert_optional = 0;
	int renegotiation_info = 0;
	TLS_CTX ctx;
	TLS_CONNECT conn;
	char buf[1600] = {0};
	size_t len = sizeof(buf);
	tls_socket_t sock;
	tls_socket_t conn_sock;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;

	size_t i;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			printf("%s\n", help);
			return 0;
		} else if (!strcmp(*argv, "-port")) {
			if (--argc < 1) goto bad;
			port = atoi(*(++argv));
		} else if (!strcmp(*argv, "-cipher_suite")) {
			char *cipher_suite_name;
			int cipher_suite;
			if (cipher_suites_cnt >= sizeof(cipher_suites)/sizeof(cipher_suites[0])) {
				fprintf(stderr, "%s: too many -cipher_suite options\n", prog);
				return -1;
			}
			if (--argc < 1) goto bad;
			cipher_suite_name = *(++argv);
			if ((cipher_suite = tls_cipher_suite_from_name(cipher_suite_name)) == 0) {
				fprintf(stderr, "%s: invalid -cipher_suite '%s' value\n", prog, cipher_suite_name);
				return -1;
			}
			cipher_suites[cipher_suites_cnt] = cipher_suite;
			cipher_suites_cnt++;
		} else if (!strcmp(*argv, "-supported_group")) {
			char *supported_group_name;
			int supported_group;
			if (supported_groups_cnt >= sizeof(supported_groups)/sizeof(supported_groups[0])) {
				fprintf(stderr, "%s: too many -supported_group options\n", prog);
				return -1;
			}
			if (--argc < 1) goto bad;
			supported_group_name = *(++argv);
			if ((supported_group = tls_named_curve_from_name(supported_group_name)) == 0) {
				fprintf(stderr, "%s: -supported_group '%s' not supported\n", prog, supported_group_name);
				return -1;
			}
			supported_groups[supported_groups_cnt++] = supported_group;
		} else if (!strcmp(*argv, "-sig_alg")) {
			char *sig_alg_name;
			int sig_alg;
			if (sig_algs_cnt >= sizeof(sig_algs)/sizeof(sig_algs[0])) {
				fprintf(stderr, "%s: too many -sig_alg options\n", prog);
				return -1;
			}
			if (--argc < 1) goto bad;
			sig_alg_name = *(++argv);
			if ((sig_alg = tls_signature_scheme_from_name(sig_alg_name)) == 0) {
				fprintf(stderr, "%s: -sig_alg '%s' not supported\n", prog, sig_alg_name);
				return -1;
			}
			sig_algs[sig_algs_cnt++] = sig_alg;
		} else if (!strcmp(*argv, "-cert")) {
			if (certfiles_cnt >= sizeof(certfiles)/sizeof(certfiles[0])) {
				fprintf(stderr, "%s: too many -cert options\n", prog);
				return -1;
			}
			if (--argc < 1) goto bad;
			certfiles[certfiles_cnt++] = *(++argv);
		} else if (!strcmp(*argv, "-key")) {
			if (keyfiles_cnt >= sizeof(keyfiles)/sizeof(keyfiles[0])) {
				fprintf(stderr, "%s: too many -key options\n", prog);
				return -1;
			}
			if (--argc < 1) goto bad;
			keyfiles[keyfiles_cnt++] = *(++argv);
		} else if (!strcmp(*argv, "-pass")) {
			if (passes_cnt >= sizeof(passes)/sizeof(passes[0])) {
				fprintf(stderr, "%s: too many -pass options\n", prog);
				return -1;
			}
			if (--argc < 1) goto bad;
			passes[passes_cnt++] = *(++argv);
		} else if (!strcmp(*argv, "-cert_request")) {
			cert_request = 1;
		} else if (!strcmp(*argv, "-cacert")) {
			if (--argc < 1) goto bad;
			cacertfile = *(++argv);
		} else if (!strcmp(*argv, "-verify_depth")) {
			if (--argc < 1) goto bad;
			verify_depth = atoi(*(++argv));
			if (verify_depth < 1) {
				fprintf(stderr, "%s: invalid -verify_depth value '%d'\n", prog, verify_depth);
				return -1;
			}
		} else if (!strcmp(*argv, "-client_cert_optional")) {
			client_cert_optional = 1;
		} else if (!strcmp(*argv, "-renegotiation_info")) {
			renegotiation_info = 1;
		} else {
			fprintf(stderr, "%s: invalid option '%s'\n", prog, *argv);
			return 1;
bad:
			fprintf(stderr, "%s: option '%s' argument required\n", prog, *argv);
			return 1;
		}
		argc--;
		argv++;
	}

	if (!certfiles_cnt) {
		fprintf(stderr, "%s: '-cert' option required\n", prog);
		return 1;
	}
	if (!keyfiles_cnt) {
		fprintf(stderr, "%s: '-key' option required\n", prog);
		return 1;
	}
	if (!passes_cnt) {
		fprintf(stderr, "%s: '-pass' option required\n", prog);
		return 1;
	}
	if (certfiles_cnt != keyfiles_cnt || keyfiles_cnt != passes_cnt) {
		error_print();
		return -1;
	}

	if (tls_socket_lib_init() != 1) {
		error_print();
		return -1;
	}

	if (tls_ctx_init(&ctx, TLS_protocol_tls12, TLS_server_mode) != 1) {
		error_print();
		return -1;
	}

	if (tls_ctx_set_cipher_suites(&ctx, cipher_suites, cipher_suites_cnt) != 1) {
		fprintf(stderr, "%s: context init error\n", prog);
		goto end;
	}

	// supported_groups
	if (supported_groups_cnt > 0) {
		if (tls_ctx_set_supported_groups(&ctx, supported_groups, supported_groups_cnt) != 1) {
			error_print();
			goto end;
		}
	}

	// signature_algorithms
	if (sig_algs_cnt > 0) {
		if (tls_ctx_set_signature_algorithms(&ctx, sig_algs, sig_algs_cnt) != 1) {
			error_print();
			goto end;
		}
	}

	if (renegotiation_info) {
		if (tls12_ctx_set_renegotiation_info(&ctx, 1) != 1) {
			error_print();
			goto end;
		}
	}

	// Certificate
	for (i = 0; i < certfiles_cnt; i++) {
		if (tls_ctx_add_certificate_chain_and_key(&ctx, certfiles[i], keyfiles[i], passes[i]) != 1) {
			error_print();
			goto end;;
		}
	}

	// CertificateRequest
	if (cert_request) {
		if (!cacertfile) {
			fprintf(stderr, "%s: -cacert required by -cert_request\n", prog);
			goto end;
		}
		if (tls_ctx_set_ca_certificates(&ctx, cacertfile, verify_depth) != 1) {
			error_print();
			goto end;
		}
		if (tls_ctx_enable_certificate_request(&ctx, 1) != 1) {
			error_print();
			goto end;
		}
		if (client_cert_optional) {
			if (tls13_ctx_enable_client_certificate_optional(&ctx, 1) != 1) {
				error_print();
				goto end;
			}
		}
	}

	if (tls_socket_create(&sock, AF_INET, SOCK_STREAM, 0) != 1) {
		fprintf(stderr, "%s: create socket error\n", prog);
		goto end;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(port);

	if (tls_socket_bind(sock, &server_addr) != 1) {
		fprintf(stderr, "%s: socket bind error\n", prog);
		goto end;
	}

	puts("start listen ...\n");
	tls_socket_listen(sock, 1);

restart:

	//client_addrlen = sizeof(client_addr);

	if (tls_socket_accept(sock, &client_addr, &conn_sock) != 1) {
		fprintf(stderr, "%s: socket accept error\n", prog);
		goto end;
	}
	puts("socket connected\n");

	if (tls_init(&conn, &ctx) != 1) {
		error_print();
		goto end;
	}

	if (tls_set_socket(&conn, conn_sock) != 1) {
		error_print();
		goto end;
	}

	if (tls_do_handshake(&conn) != 1) {
		error_print();
		goto end;
	}

	for (;;) {

		int rv;
		size_t sentlen;

		do {
			len = sizeof(buf);
			if ((rv = tls_recv(&conn, (uint8_t *)buf, sizeof(buf), &len)) != 1) {
				if (rv < 0) fprintf(stderr, "%s: recv failure\n", prog);
				else fprintf(stderr, "%s: Disconnected by remote\n", prog);

				//tls_socket_close(conn.sock); // FIXME:		
				tls_cleanup(&conn);
				goto restart;
			}
		} while (!len);

		if (tls_send(&conn, (uint8_t *)buf, len, &sentlen) != 1) {
			fprintf(stderr, "%s: send failure, close connection\n", prog);
			tls_socket_close(conn.sock);
			goto end;
		}
	}


end:
	return ret;
}
