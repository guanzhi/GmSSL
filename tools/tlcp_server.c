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
#include <gmssl/mem.h>
#include <gmssl/sm2.h>
#include <gmssl/tls.h>
#include <gmssl/error.h>


static const char *options = "[-port num] -cert pem -key pem -pass str [-alpn str] [-cacert pem] [-verbose]";


static const char *help =
"Options\n"
"\n"
"    -port num              Listening port number, default 443\n"
"    -cert pem              Server's certificate chain in PEM format, may appear multiple times\n"
"    -key pem               Server's signing and encryption private keys in PEM format: signing key first, encryption key second, may appear multiple times\n"
"    -pass str              Password to decrypt both private keys in the same -key PEM, may appear multiple times\n"
"    -alpn str              Application protocol name, may appear multiple times, higher priority first\n"
"    -cacert pem            CA certificate for client certificate verification\n"
"    -verbose               Print TLS handshake messages\n"
"\n"
#include "tlcp_help.h"
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

int tlcp_server_main(int argc , char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	int port = 443;
	char *certfiles[4];
	size_t certfiles_cnt = 0;
	char *signkeyfiles[sizeof(certfiles)/sizeof(certfiles[0])];
	size_t signkeyfiles_cnt = 0;
	char *signpasses[sizeof(certfiles)/sizeof(certfiles[0])];
	size_t signpasses_cnt = 0;
	char *alpn_protocols[4];
	size_t alpn_protocols_cnt = 0;
	char *cacertfile = NULL;
	int verbose = 0;

	int server_ciphers[] = {
		TLS_cipher_ecc_sm4_gcm_sm3,
		TLS_cipher_ecc_sm4_cbc_sm3,
	};

	TLS_CTX ctx;
	TLS_CONNECT conn;
	char buf[1600] = {0};
	size_t len = sizeof(buf);
	tls_socket_t sock;
	tls_socket_t conn_sock;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	tls_socklen_t client_addrlen;
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
		} else if (!strcmp(*argv, "-cert")) {
			if (certfiles_cnt >= sizeof(certfiles)/sizeof(certfiles[0])) {
				fprintf(stderr, "%s: too many -cert options\n", prog);
				return -1;
			}
			if (--argc < 1) goto bad;
			certfiles[certfiles_cnt++] = *(++argv);
		} else if (!strcmp(*argv, "-key")) {
			if (signkeyfiles_cnt >= sizeof(signkeyfiles)/sizeof(signkeyfiles[0])) {
				fprintf(stderr, "%s: too many -key options\n", prog);
				return -1;
			}
			if (--argc < 1) goto bad;
			signkeyfiles[signkeyfiles_cnt++] = *(++argv);
		} else if (!strcmp(*argv, "-pass")) {
			if (signpasses_cnt >= sizeof(signpasses)/sizeof(signpasses[0])) {
				fprintf(stderr, "%s: too many -pass options\n", prog);
				return -1;
			}
			if (--argc < 1) goto bad;
			signpasses[signpasses_cnt++] = *(++argv);
		} else if (!strcmp(*argv, "-alpn")) {
			if (alpn_protocols_cnt >= sizeof(alpn_protocols)/sizeof(alpn_protocols[0])) {
				fprintf(stderr, "%s: too many -alpn options\n", prog);
				return -1;
			}
			if (--argc < 1) goto bad;
			alpn_protocols[alpn_protocols_cnt++] = *(++argv);
		} else if (!strcmp(*argv, "-cacert")) {
			if (--argc < 1) goto bad;
			cacertfile = *(++argv);
		} else if (!strcmp(*argv, "-verbose")) {
			verbose = 1;
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
	if (!signkeyfiles_cnt) {
		fprintf(stderr, "%s: '-key' option required\n", prog);
		return 1;
	}
	if (!signpasses_cnt) {
		fprintf(stderr, "%s: '-pass' option required\n", prog);
		return 1;
	}
	if (certfiles_cnt != signkeyfiles_cnt || signkeyfiles_cnt != signpasses_cnt) {
		fprintf(stderr, "%s: -cert/-key/-pass counts mismatch\n", prog);
		return 1;
	}

	memset(&ctx, 0, sizeof(ctx));
	memset(&conn, 0, sizeof(conn));

	if (tls_ctx_init(&ctx, TLS_protocol_tlcp, TLS_server_mode) != 1
		|| tls_ctx_set_cipher_suites(&ctx, server_ciphers, sizeof(server_ciphers)/sizeof(int)) != 1) {
		error_print();
		return -1;
	}
	if (verbose && tls_ctx_set_verbose(&ctx, verbose) != 1) {
		error_print();
		return -1;
	}
	if (alpn_protocols_cnt) {
		if (tls_ctx_set_application_layer_protocol_negotiation(&ctx,
			alpn_protocols, alpn_protocols_cnt) != 1) {
			error_print();
			return -1;
		}
	}
	for (i = 0; i < certfiles_cnt; i++) {
		if (tlcp_ctx_add_server_certificate_and_keys(&ctx,
			certfiles[i], signkeyfiles[i], signpasses[i]) != 1) {
			error_print();
			return -1;
		}
	}
	if (cacertfile) {
		if (tls_ctx_set_ca_certificates(&ctx, cacertfile, TLS_DEFAULT_VERIFY_DEPTH) != 1) {
			error_print();
			return -1;
		}
	}


	if (tls_socket_lib_init() != 1) {
		error_print();
		return -1;
	}

	if (tls_socket_create(&sock, AF_INET, SOCK_STREAM, 0) != 1) {
		error_print();
		return 1;
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

	client_addrlen = sizeof(client_addr);

	if (tls_socket_accept(sock, &client_addr, &conn_sock) != 1) {
		fprintf(stderr, "%s: socket accept error\n", prog);
		goto end;
	}
	puts("socket connected\n");

	if (tls_init(&conn, &ctx) != 1
		|| tls_set_socket(&conn, conn_sock) != 1) {
		error_print();
		return -1;
	}

	if (set_socket_nonblocking(conn_sock) != 1) {
		error_print();
		return -1;
	}

	if (do_handshake_select(&conn) != 1) {
		error_print();
		return -1;
	}

	for (;;) {

		int rv;
		fd_set fds;

		do {
			FD_ZERO(&fds);
			FD_SET(conn.sock, &fds);

			if (select((int)(conn.sock + 1), &fds, NULL, NULL, NULL) < 0) {
				fprintf(stderr, "%s: select failed\n", prog);
				goto end;
			}

			len = sizeof(buf);
			if ((rv = tls_recv(&conn, (uint8_t *)buf, sizeof(buf), &len)) != 1) {
				if (rv == -EAGAIN
					|| rv == TLS_ERROR_RECV_AGAIN
					|| rv == TLS_ERROR_SEND_AGAIN) {
					continue;
				}
				if (rv < 0) {
					fprintf(stderr, "%s: recv failure\n", prog);
				} else {
					if (do_shutdown_select(&conn) != 1) {
						fprintf(stderr, "%s: shutdown failure\n", prog);
					}
					fprintf(stderr, "%s: Disconnected by remote\n", prog);
				}

				//tls_socket_close(conn.sock); // FIXME: 		
				tls_cleanup(&conn);
				goto restart;
			}
		} while (!len);

		if (do_send_select(&conn, (uint8_t *)buf, len) != 1) {
			fprintf(stderr, "%s: send failure, close connection\n", prog);
			tls_socket_close(conn.sock);
			goto end;
		}
	}


end:
	return ret;
}
