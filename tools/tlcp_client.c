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
#include <gmssl/tls.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>


#define TIMEOUT_SECONDS 1

static const char *usage =
	"-host str [-port num] [-cacert pem]"
	" [-cert pem -key pem -pass str]"
	" [-certout pem]"
	" [-get path|-in file]"
	" [-alpn str]"
	" [-trusted_ca_keys]"
	" [-verbose]";

static const char *help =
"Options\n"
"\n"
"    -host str              Domain name or IP address of remote host\n"
"    -port num              Port number of remote host, default 443\n"
"    -cipher_suite str      Supported cipher suites, may appear multiple times, higher priority first\n"
"    -supported_group str   Supported elliptic curves, may appear multiple times, higher priority first\n"
"    -sig_alg str           Supported signature algorithms\n"
"    -cacert pem            Trusted CA certificate(s) in PEM format\n"
"    -verify_depth num      Certificate verification depth\n"
"    -cert pem              Client certificate(s) in PEM format\n"
"    -key pem               Private key of client certificate in PEM format\n"
"    -pass password         Password of encrypted private key\n"
"    -client_cert_optional  Allow client send empty Certificate\n"
"    -get path              Send a GET request with given path of URI\n"
"    -in file | stdin       Send input data and read response until close or timeout\n"
"    -certout pem           Save server certificates to a PEM file\n"
"    -server_name str       Send server_name (SNI) request\n"
"    -trusted_ca_keys       Send trusted_ca_keys request\n"
"    -alpn str              Application protocol name, may appear multiple times, higher priority first\n"
"    -status_request        Send status_request (OCSP Stapling) request\n"
"    -verbose               Print TLS handshake messages\n"
"\n"
#include "tlcp_help.h"
"\n";


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

static int do_recv_until_timeout(TLS_CONNECT *conn, char *prog)
{
	char buf[1024];
	size_t len;
	fd_set fds;
	struct timeval timeout;

	for (;;) {
		FD_ZERO(&fds);
		FD_SET(conn->sock, &fds);
		timeout.tv_sec = TIMEOUT_SECONDS;
		timeout.tv_usec = 0;

		switch (select((int)(conn->sock + 1), &fds, NULL, NULL, &timeout)) {
		case -1:
			fprintf(stderr, "%s: select error\n", prog);
			return -1;
		case 0:
			do_shutdown_select(conn);
			return 1;
		}

		len = sizeof(buf);
		switch (tls_recv(conn, (uint8_t *)buf, sizeof(buf), &len)) {
		case 1:
			fwrite(buf, 1, len, stdout);
			fflush(stdout);
			break;
		case 0:
			do_shutdown_select(conn);
			return 1;
		case TLS_ERROR_RECV_AGAIN:
		case TLS_ERROR_SEND_AGAIN:
			break;
		default:
			fprintf(stderr, "%s: tls_recv error\n", prog);
			return -1;
		}
	}
}

static int do_send_file_select(TLS_CONNECT *conn, FILE *fp)
{
	uint8_t buf[4096];
	size_t len;

	while ((len = fread(buf, 1, sizeof(buf), fp)) > 0) {
		if (do_send_select(conn, buf, len) != 1) {
			return -1;
		}
	}
	if (ferror(fp)) {
		error_print();
		return -1;
	}
	return 1;
}

int tlcp_client_main(int argc, char *argv[])
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
	char *server_name = NULL;
	int trusted_ca_keys = 0;
	char *alpn_protocols[4];
	size_t alpn_protocols_cnt = 0;
	int client_cert_optional = 0;
	char *get = NULL;
	char *infile = NULL;
	char *certoutfile = NULL;
	int verbose = 0;
	struct hostent *hp;
	struct sockaddr_in server;
	tls_socket_t sock = tls_socket_invalid();
	TLS_CTX ctx;
	TLS_CONNECT conn;
	char buf[1024] = {0};
	size_t len = sizeof(buf);
	char send_buf[1024] = {0};
	int read_stdin = 1;

	argc--;
	argv++;
	if (argc < 1) {
		fprintf(stderr, "usage: gmssl %s %s\n", prog, usage);
		return 1;
	}
	while (argc >= 1) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: gmssl %s %s\n\n", prog, usage);
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
		} else if (!strcmp(*argv, "-alpn")) {
			if (alpn_protocols_cnt >= sizeof(alpn_protocols)/sizeof(alpn_protocols[0])) {
				fprintf(stderr, "%s: too many -alpn options\n", prog);
				return -1;
			}
			if (--argc < 1) goto bad;
			alpn_protocols[alpn_protocols_cnt++] = *(++argv);
		} else if (!strcmp(*argv, "-client_cert_optional")) {
			client_cert_optional = 1;
		} else if (!strcmp(*argv, "-get")) {
			if (--argc < 1) goto bad;
			get = *(++argv);
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
		} else if (!strcmp(*argv, "-certout")) {
			if (--argc < 1) goto bad;
			certoutfile = *(++argv);
		} else if (!strcmp(*argv, "-verbose")) {
			verbose = 1;
		} else {
			fprintf(stderr, "%s: invalid option '%s'\n", prog, *argv);
			return 1;
bad:
			fprintf(stderr, "%s: option '%s' argument required\n", prog, *argv);
			return 0;
		}
		argc--;
		argv++;
	}



	if (!host) {
		fprintf(stderr, "%s: option '-host' missing\n", prog);
		return -1;
	}

	if (!cipher_suites_cnt) {
		fprintf(stderr, "%s: option '-cipher_suite' missing\n", prog);
		return -1;
	}
	if (get && infile) {
		fprintf(stderr, "%s: '-get' and '-in' should not be used together\n", prog);
		return -1;
	}

	if (tls_socket_lib_init() != 1) {
		error_print();
		return -1;
	}

	if (tls_ctx_init(&ctx, TLS_protocol_tlcp, TLS_client_mode) != 1) {
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

	if (alpn_protocols_cnt) {
		if (tls_ctx_set_application_layer_protocol_negotiation(&ctx,
			alpn_protocols, alpn_protocols_cnt) != 1) {
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

	if (verbose && tls_ctx_set_verbose(&ctx, verbose) != 1) {
		error_print();
		goto end;
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
		fprintf(stderr, "%s: failed to connect socket\n", prog);
		goto end;
	}

	if (tls_set_socket(&conn, sock) != 1) {
		error_print();
		goto end;
	}

	if (tls_socket_set_nonblocking(sock, 1) != 1) {
		error_print();
		goto end;
	}

	if (do_handshake_select(&conn) != 1) {
		fprintf(stderr, "%s: error\n", prog);
		goto end;
	}
	tls_connect_print(stderr, 0, 0, NULL, &conn);

	if (certoutfile) {
		FILE *certoutfp;
		if (!(certoutfp = fopen(certoutfile, "wb"))) {
			fprintf(stderr, "%s: open '%s' failure\n", prog, certoutfile);
			perror("fopen");
			goto end;
		}
		if (x509_certs_to_pem(conn.peer_cert_chain, conn.peer_cert_chain_len, certoutfp) != 1) {
			fprintf(stderr, "%s: x509_certs_to_pem error\n", prog);
			fclose(certoutfp);
			goto end;
		}
		fclose(certoutfp);
	}

	if (get) {
		snprintf(buf, sizeof(buf), "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", get, host);

		if (do_send_select(&conn, (uint8_t *)buf, strlen(buf)) != 1) {
			fprintf(stderr, "%s: send error\n", prog);
			goto end;
		}

		if (do_recv_until_timeout(&conn, prog) != 1) {
			goto end;
		}
		ret = 0;
		goto end;
	}

	if (infile) {
		FILE *infp = stdin;
		if (strcmp(infile, "-") && strcmp(infile, "stdin")) {
			if (!(infp = fopen(infile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure\n", prog, infile);
				goto end;
			}
		}
		if (do_send_file_select(&conn, infp) != 1) {
			if (infp != stdin) fclose(infp);
			fprintf(stderr, "%s: send error\n", prog);
			goto end;
		}
		if (infp != stdin) fclose(infp);
		if (do_recv_until_timeout(&conn, prog) != 1) {
			goto end;
		}
		ret = 0;
		goto end;
	}

	for (;;) {
		fd_set fds;

		FD_ZERO(&fds);
		FD_SET(conn.sock, &fds);

		if (read_stdin) {
#ifdef WIN32
			if (fgets(buf, sizeof(buf), stdin)) {
				if (do_send_select(&conn, (uint8_t *)buf, strlen(buf)) != 1) {
					fprintf(stderr, "%s: send error\n", prog);
					goto end;
				}
			} else {
				if (!feof(stdin)) {
					fprintf(stderr, "%s: length of input line exceeds buffer size\n", prog);
					goto end;
				}	
				do_shutdown_select(&conn);
				ret = 0;
				goto end;
			}	
#else
			FD_SET(STDIN_FILENO, &fds); // in POSIX, first arg type is int
#endif
		}
		if (select(conn.sock + 1, &fds, NULL, NULL, NULL) < 0) {
			fprintf(stderr, "%s: select error\n", prog);
			goto end;
		}

#ifdef WIN32
#else
		if (read_stdin && FD_ISSET(STDIN_FILENO, &fds)) {

			if (fgets(buf, sizeof(buf), stdin)) {
				if (do_send_select(&conn, (uint8_t *)buf, strlen(buf)) != 1) {
					fprintf(stderr, "%s: send error\n", prog);
					goto end;
				}
			} else {
				if (!feof(stdin)) {
					fprintf(stderr, "%s: length of input line exceeds buffer size\n", prog);
					goto end;
				}
				do_shutdown_select(&conn);
				ret = 0;
				goto end;
			}
		}
#endif

		if (FD_ISSET(conn.sock, &fds)) {
			int rv;

			len = sizeof(buf);
			rv = tls_recv(&conn, (uint8_t *)buf, sizeof(buf), &len);

			if (rv == 1) {
				fwrite(buf, 1, len, stdout);
				fflush(stdout);
			} else if (rv == 0) {
				fprintf(stderr, "Connection closed by remote host\n");
				do_shutdown_select(&conn);
				ret = 0;
				goto end;
			} else if (rv == TLS_ERROR_RECV_AGAIN
				|| rv == TLS_ERROR_SEND_AGAIN) {
				continue;
			} else {
				error_print();
				fprintf(stderr, "%s: tls_recv error\n", prog);
				goto end;
			}
		}
	}

end:
	// FIXME: clean ctx and connection ASAP, as Ctrl-C is not handled
	if (tls_socket_is_valid(sock)) tls_socket_close(sock);
	tls_ctx_cleanup(&ctx);
	tls_cleanup(&conn);
	return ret;
}
