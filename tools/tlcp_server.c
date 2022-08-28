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
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <gmssl/mem.h>
#include <gmssl/sm2.h>
#include <gmssl/tls.h>
#include <gmssl/error.h>


static const char *options = "[-port num] -cert file -key file [-pass str] -ex_key file [-ex_pass str] [-cacert file]";

int tlcp_server_main(int argc , char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	int port = 443;
	char *certfile = NULL;
	char *signkeyfile = NULL;
	char *signpass = NULL;
	char *enckeyfile = NULL;
	char *encpass = NULL;
	char *cacertfile = NULL;

	int server_ciphers[] = { TLS_cipher_ecc_sm4_cbc_sm3, };
	uint8_t verify_buf[4096];

	TLS_CTX ctx;
	TLS_CONNECT conn;
	char buf[1600] = {0};
	size_t len = sizeof(buf);

	int sock;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	socklen_t client_addrlen;
	int conn_sock;


	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			return 0;
		} else if (!strcmp(*argv, "-port")) {
			if (--argc < 1) goto bad;
			port = atoi(*(++argv));
		} else if (!strcmp(*argv, "-cert")) {
			if (--argc < 1) goto bad;
			certfile = *(++argv);
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			signkeyfile = *(++argv);
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			signpass = *(++argv);
		} else if (!strcmp(*argv, "-ex_key")) {
			if (--argc < 1) goto bad;
			enckeyfile = *(++argv);
		} else if (!strcmp(*argv, "-ex_pass")) {
			if (--argc < 1) goto bad;
			encpass = *(++argv);
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
	if (!certfile) {
		fprintf(stderr, "%s: '-cert' option required\n", prog);
		return 1;
	}
	if (!signkeyfile) {
		fprintf(stderr, "%s: '-key' option required\n", prog);
		return 1;
	}
	if (!signpass) {
		fprintf(stderr, "%s: '-pass' option required\n", prog);
		return 1;
	}
	if (!enckeyfile) {
		fprintf(stderr, "%s: '-ex_key' option required\n", prog);
		return 1;
	}
	if (!encpass) {
		fprintf(stderr, "%s: '-ex_pass' option required\n", prog);
		return 1;
	}

	memset(&ctx, 0, sizeof(ctx));
	memset(&conn, 0, sizeof(conn));

	if (tls_ctx_init(&ctx, TLS_protocol_tlcp, TLS_server_mode) != 1
		|| tls_ctx_set_cipher_suites(&ctx, server_ciphers, sizeof(server_ciphers)/sizeof(int)) != 1
		|| tls_ctx_set_tlcp_server_certificate_and_keys(&ctx, certfile, signkeyfile, signpass, enckeyfile, encpass) != 1) {
		error_print();
		return -1;
	}
	if (cacertfile) {
		if (tls_ctx_set_ca_certificates(&ctx, cacertfile, TLS_DEFAULT_VERIFY_DEPTH) != 1) {
			error_print();
			return -1;
		}
	}

	// Socket
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		error_print();
		return 1;
	}
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(port);
	if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		error_print();
		perror("tlcp_accept: bind: ");
		goto end;
	}
	puts("start listen ...\n");
	listen(sock, 1);



restart:

	client_addrlen = sizeof(client_addr);
	if ((conn_sock = accept(sock, (struct sockaddr *)&client_addr, &client_addrlen)) < 0) {
		error_print();
		goto end;
	}
	puts("socket connected\n");

	if (tls_init(&conn, &ctx) != 1
		|| tls_set_socket(&conn, conn_sock) != 1) {
		error_print();
		return -1;
	}

	if (tls_do_handshake(&conn) != 1) {
		error_print(); // 为什么这个会触发呢？
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

				//close(conn.sock);
				tls_cleanup(&conn);
				goto restart;
			}
		} while (!len);

		if (tls_send(&conn, (uint8_t *)buf, len, &sentlen) != 1) {
			fprintf(stderr, "%s: send failure, close connection\n", prog);
			close(conn.sock);
			goto end;
		}
	}


end:
	return ret;
}
