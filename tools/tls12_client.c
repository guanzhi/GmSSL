/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/tls.h>
#include <gmssl/error.h>


static int client_ciphers[] = { TLS_cipher_ecdhe_sm4_cbc_sm3 };

static const char *http_get =
	"GET / HTTP/1.1\r\n"
	"Hostname: aaa\r\n"
	"\r\n\r\n";

static const char *options = "-host str [-port num] [-cacert pem] [-cert pem -key pem -pass str] [-trusted_ca_keys]";

static const char *help =
"Options\n"
"\n"
"    -host str              Server's hostname\n"
"    -port num              Server's port number, default 443\n"
"    -cipher_suite str      Supported cipher suites, may appear multiple times, higher priority first\n"
"    -supported_group str   Supported elliptic curves, may appear multiple times, higher priority first\n"
"    -sig_alg str           Supported signature algorithms\n"
"    -cacert pem            Root CA certificate in PEM format\n"
"    -verify_depth num      Certificate verification depth\n"
"    -cert pem              Client's certificate chain in PEM format\n"
"    -key pem               Client's encrypted private key in PEM format\n"
"    -pass str              Password to decrypt private key\n"
"    -client_cert_optional  Allow client send empty Certificate\n"
"    -server_name str       Send server_name (SNI) request\n"
"    -trusted_ca_keys       Send trusted_ca_keys request\n"
"    -renegotiation_info    Send renegotiation_info extension\n"
"    -renegotiation_info_scsv\n"
"                          Send TLS_EMPTY_RENEGOTIATION_INFO_SCSV\n"
"    -status_request        Send status_request (OCSP Stapling) request\n"
"\n"
#include "tls12_help.h"
"\n";

static int set_socket_nonblocking(tls_socket_t sock)
{
#ifdef WIN32
	u_long mode = 1;
	if (ioctlsocket(sock, FIONBIO, &mode) != 0) {
		error_print();
		return -1;
	}
#else
	int flags;
	if ((flags = fcntl(sock, F_GETFL)) < 0
		|| fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
		error_print();
		return -1;
	}
#endif
	return 1;
}

static int do_handshake_select(TLS_CONNECT *conn)
{
	int ret;
	fd_set rfds;
	fd_set wfds;

	for (;;) {
		ret = tls_do_handshake(conn);
		if (ret == 1) {
			return 1;
		}
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		if (ret == TLS_ERROR_RECV_AGAIN) {
			FD_SET(conn->sock, &rfds);
		} else if (ret == TLS_ERROR_SEND_AGAIN) {
			FD_SET(conn->sock, &wfds);
		} else {
			error_print();
			return -1;
		}
		if (select((int)(conn->sock + 1), &rfds, &wfds, NULL, NULL) < 0) {
			error_print();
			return -1;
		}
	}
}

static int do_shutdown_select(TLS_CONNECT *conn)
{
	int ret;
	fd_set rfds;
	fd_set wfds;

	for (;;) {
		ret = tls_shutdown(conn);
		if (ret == 1) {
			return 1;
		}
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		if (ret == TLS_ERROR_RECV_AGAIN) {
			FD_SET(conn->sock, &rfds);
		} else if (ret == TLS_ERROR_SEND_AGAIN) {
			FD_SET(conn->sock, &wfds);
		} else {
			error_print();
			return -1;
		}
		if (select((int)(conn->sock + 1), &rfds, &wfds, NULL, NULL) < 0) {
			error_print();
			return -1;
		}
	}
}

static int do_send_select(TLS_CONNECT *conn, const uint8_t *buf, size_t len)
{
	int ret;
	size_t offset = 0;
	fd_set rfds;
	fd_set wfds;

	while (offset < len) {
		size_t sentlen = 0;

		ret = tls_send(conn, buf + offset, len - offset, &sentlen);
		if (ret == 1) {
			offset += sentlen;
			continue;
		}
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		if (ret == TLS_ERROR_RECV_AGAIN) {
			FD_SET(conn->sock, &rfds);
		} else if (ret == TLS_ERROR_SEND_AGAIN) {
			FD_SET(conn->sock, &wfds);
		} else {
			error_print();
			return -1;
		}
		if (select((int)(conn->sock + 1), &rfds, &wfds, NULL, NULL) < 0) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int tls12_client_main(int argc, char *argv[])
{
	int ret = -1;
	char *prog = argv[0];
	char *host = NULL;
	int port = 443;
	int cipher_suites[4];
	size_t cipher_suites_cnt = 0;
	int supported_groups[4];
	size_t supported_groups_cnt = 0;
	int sig_algs[4];
	size_t sig_algs_cnt = 0;
	char *cacertfile = NULL;
	int verify_depth = TLS_DEFAULT_VERIFY_DEPTH;
	char *certfile = NULL;
	char *keyfile = NULL;
	char *pass = NULL;
	int client_cert_optional = 0;
	char *server_name = NULL;
	int trusted_ca_keys = 0;
	int renegotiation_info = 0;
	int empty_renegotiation_info_scsv = 0;
	TLS_CTX ctx;
	TLS_CONNECT conn;
	struct hostent *hp;
	struct sockaddr_in server;
	tls_socket_t sock = -1;
	char buf[1024] = {0};
	size_t len = sizeof(buf);
	char send_buf[1024] = {0};

	argc--;
	argv++;
	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}
	while (argc >= 1) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			printf("%s\n", help);
			return 0;
		} else if (!strcmp(*argv, "-host")) {
			if (--argc < 1) goto bad;
			host = *(++argv);
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
			if (--argc < 1) goto bad;
			certfile = *(++argv);
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
		} else if (!strcmp(*argv, "-server_name")) {
			if (--argc < 1) goto bad;
			server_name = *(++argv);
		} else if (!strcmp(*argv, "-trusted_ca_keys")) {
			trusted_ca_keys = 1;
		} else if (!strcmp(*argv, "-renegotiation_info")) {
			renegotiation_info = 1;
		} else if (!strcmp(*argv, "-renegotiation_info_scsv")) {
			empty_renegotiation_info_scsv = 1;
		} else if (!strcmp(*argv, "-client_cert_optional")) {
			client_cert_optional = 1;
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

	if (!host) {
		fprintf(stderr, "%s: '-in' option required\n", prog);
		return -1;
	}

	if (!cipher_suites_cnt) {
		fprintf(stderr, "%s: option '-cipher_suite' missing\n", prog);
		return -1;
	}

	if (tls_socket_lib_init() != 1) {
		error_print();
		return -1;
	}

	if (tls_ctx_init(&ctx, TLS_protocol_tls12, TLS_client_mode) != 1) {
		error_print();
		return -1;
	}

	if (tls_ctx_set_cipher_suites(&ctx, cipher_suites, cipher_suites_cnt) != 1) {
		error_print();
		goto end;
	}

	if (trusted_ca_keys) {
		if (tls_ctx_enable_trusted_ca_keys(&ctx, 1) != 1) {
			error_print();
			goto end;
		}
	}

	if (cacertfile) {
		if (tls_ctx_set_ca_certificates(&ctx, cacertfile, verify_depth) != 1) {
			fprintf(stderr, "%s: failed to load CA certificate\n", prog);
			goto end;
		}
	}

	if (supported_groups_cnt > 0) {
		if (tls_ctx_set_supported_groups(&ctx, supported_groups, supported_groups_cnt) != 1) {
			error_print();
			goto end;
		}
	}

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
	if (empty_renegotiation_info_scsv) {
		if (tls12_ctx_set_empty_renegotiation_info_scsv(&ctx, 1) != 1) {
			error_print();
			goto end;
		}
	}

	if (certfile) {
		if (!keyfile) {
			fprintf(stderr, "%s: option '-key' missing\n", prog);
			goto end;
		}
		if (!pass) {
			fprintf(stderr, "%s: option '-pass' missing\n", prog);
			goto end;
		}
		if (tls_ctx_set_certificate_and_key(&ctx, certfile, keyfile, pass) != 1) {
			fprintf(stderr, "%s: failed to load client certificate\n", prog);
			goto end;
		}
	}

	if (tls_init(&conn, &ctx) != 1) {
		error_print();
		goto end;
	}

	if (server_name) {
		if (tls_set_server_name(&conn, (uint8_t *)server_name, strlen(server_name)) != 1) {
			error_print();
			goto end;
		}
	}

	if (tls_socket_create(&sock, AF_INET, SOCK_STREAM, 0) != 1) {
		fprintf(stderr, "%s: faild to open socket\n", prog);
		goto end;
	}

	if (!(hp = gethostbyname(host))) {
		fprintf(stderr, "%s: failed to parse host name '%s'\n", prog, host);
		goto end;
	}

	server.sin_addr = *((struct in_addr *)hp->h_addr_list[0]);
	server.sin_family = AF_INET;
	server.sin_port = htons(port);

	if (tls_socket_connect(sock, &server) != 1) {
		fprintf(stderr, "%s: socket connect error\n", prog);
		goto end;
	}

	if (tls_set_socket(&conn, sock) != 1) {
		error_print();
		goto end;
	}

	if (set_socket_nonblocking(sock) != 1) {
		error_print();
		goto end;
	}

	if (do_handshake_select(&conn) != 1) {
		fprintf(stderr, "%s: error\n", prog);
		goto end;
	}

	for (;;) {
		fd_set fds;
		if (!fgets(send_buf, sizeof(send_buf), stdin)) {
			if (feof(stdin)) {
				do_shutdown_select(&conn);
				goto end;
			} else {
				continue;
			}
		}
		if (do_send_select(&conn, (uint8_t *)send_buf, strlen(send_buf)) != 1) {
			fprintf(stderr, "%s: send error\n", prog);
			goto end;
		}

		FD_ZERO(&fds);
		FD_SET(conn.sock, &fds);
#ifdef WIN32
#else
		FD_SET(fileno(stdin), &fds);
#endif

		if (select((int)(conn.sock + 1), &fds, NULL, NULL, NULL) < 0) {
			fprintf(stderr, "%s: select failed\n", prog);
			goto end;
		}

		if (FD_ISSET(conn.sock, &fds)) {
			for (;;) {
				int rv;

				memset(buf, 0, sizeof(buf));
				len = sizeof(buf);
				if ((rv = tls_recv(&conn, (uint8_t *)buf, sizeof(buf), &len)) != 1) {
					if (rv == -EAGAIN
						|| rv == TLS_ERROR_RECV_AGAIN
						|| rv == TLS_ERROR_SEND_AGAIN) {
						break;
					}
					if (rv == 0) {
						do_shutdown_select(&conn);
					}
					goto end;
				}
				fwrite(buf, 1, len, stdout);
				fflush(stdout);

				// FIXME: change `tls_recv` API or functions			
				if (conn.datalen == 0) {
					break;
				}
			}

		}
#ifdef WIN32
#else
		if (FD_ISSET(fileno(stdin), &fds)) {
			memset(send_buf, 0, sizeof(send_buf));

			if (!fgets(send_buf, sizeof(send_buf), stdin)) {
				if (feof(stdin)) {
					do_shutdown_select(&conn);
					goto end;
				} else {
					continue;
				}
			}
			if (do_send_select(&conn, (uint8_t *)send_buf, strlen(send_buf)) != 1) {
				fprintf(stderr, "%s: send error\n", prog);
				goto end;
			}
		}
#endif
	}


end:
	if (sock != -1) tls_socket_close(sock);
	tls_ctx_cleanup(&ctx);
	tls_cleanup(&conn);
	return 0;
}
