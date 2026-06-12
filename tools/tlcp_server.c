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


static const char *options = "[-port num] -cert file -key file -pass str -ex_key file -ex_pass str [-cacert file]";


static const char *help =
"Options\n"
"\n"
"    -port num              Listening port number, default 443\n"
"    -cert file             Server's certificate chain in PEM format, may appear multiple times\n"
"    -key file              Server's signing private key in PEM format, may appear multiple times\n"
"    -pass str              Password to decrypt signing private key, may appear multiple times\n"
"    -ex_key file           Server's encryption private key in PEM format, may appear multiple times\n"
"    -ex_pass str           Password to decrypt encryption private key, may appear multiple times\n"
"    -cacert file           CA certificate for client certificate verification\n"
"\n"
#include "tlcp_help.h"
"\n";

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
	char *enckeyfiles[sizeof(certfiles)/sizeof(certfiles[0])];
	size_t enckeyfiles_cnt = 0;
	char *encpasses[sizeof(certfiles)/sizeof(certfiles[0])];
	size_t encpasses_cnt = 0;
	char *cacertfile = NULL;

	int server_ciphers[] = { TLS_cipher_ecc_sm4_cbc_sm3, };

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
		} else if (!strcmp(*argv, "-ex_key")) {
			if (enckeyfiles_cnt >= sizeof(enckeyfiles)/sizeof(enckeyfiles[0])) {
				fprintf(stderr, "%s: too many -ex_key options\n", prog);
				return -1;
			}
			if (--argc < 1) goto bad;
			enckeyfiles[enckeyfiles_cnt++] = *(++argv);
		} else if (!strcmp(*argv, "-ex_pass")) {
			if (encpasses_cnt >= sizeof(encpasses)/sizeof(encpasses[0])) {
				fprintf(stderr, "%s: too many -ex_pass options\n", prog);
				return -1;
			}
			if (--argc < 1) goto bad;
			encpasses[encpasses_cnt++] = *(++argv);
		} else if (!strcmp(*argv, "-cacert")) {
			if (--argc < 1) goto bad;
			cacertfile = *(++argv);
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
	if (!enckeyfiles_cnt) {
		fprintf(stderr, "%s: '-ex_key' option required\n", prog);
		return 1;
	}
	if (!encpasses_cnt) {
		fprintf(stderr, "%s: '-ex_pass' option required\n", prog);
		return 1;
	}
	if (certfiles_cnt != signkeyfiles_cnt || signkeyfiles_cnt != signpasses_cnt
		|| signpasses_cnt != enckeyfiles_cnt || enckeyfiles_cnt != encpasses_cnt) {
		fprintf(stderr, "%s: -cert/-key/-pass/-ex_key/-ex_pass counts mismatch\n", prog);
		return 1;
	}

	memset(&ctx, 0, sizeof(ctx));
	memset(&conn, 0, sizeof(conn));

	if (tls_ctx_init(&ctx, TLS_protocol_tlcp, TLS_server_mode) != 1
		|| tls_ctx_set_cipher_suites(&ctx, server_ciphers, sizeof(server_ciphers)/sizeof(int)) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; i < certfiles_cnt; i++) {
		if (tlcp_ctx_add_server_certificate_and_keys(&ctx,
			certfiles[i], signkeyfiles[i], signpasses[i],
			enckeyfiles[i], encpasses[i]) != 1) {
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

	if (tls_do_handshake(&conn) != 1) {
		error_print();
		return -1;
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
