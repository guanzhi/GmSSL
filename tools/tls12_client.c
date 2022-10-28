﻿/*
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
#ifdef WIN32
#include <winsock2.h>
#else

#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif


#include <gmssl/tls.h>
#include <gmssl/error.h>


// TLSv1.2客户单和TLCP客户端可能没有什么区别

static int client_ciphers[] = { TLS_cipher_ecdhe_sm4_cbc_sm3 };

static const char *http_get =
	"GET / HTTP/1.1\r\n"
	"Hostname: aaa\r\n"
	"\r\n\r\n";

static const char *options = "-host str [-port num] [-cacert file] [-cert file -key file -pass str]";

int tls12_client_main(int argc, char *argv[])
{
	int ret = -1;
	char *prog = argv[0];
	char *host = NULL;
	int port = 443;
	char *cacertfile = NULL;
	char *certfile = NULL;
	char *keyfile = NULL;
	char *pass = NULL;
	struct hostent *hp;
	struct sockaddr_in server;
#ifdef WIN32
	SOCKET sock;
#else	
	int sock;
#endif
	TLS_CTX ctx;
	TLS_CONNECT conn;
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
			return 0;
		} else if (!strcmp(*argv, "-host")) {
			if (--argc < 1) goto bad;
			host = *(++argv);
		} else if (!strcmp(*argv, "-port")) {
			if (--argc < 1) goto bad;
			port = atoi(*(++argv));
		} else if (!strcmp(*argv, "-cacert")) {
			if (--argc < 1) goto bad;
			cacertfile = *(++argv);
		} else if (!strcmp(*argv, "-cert")) {
			if (--argc < 1) goto bad;
			certfile = *(++argv);
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
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
		fprintf(stderr, "%s: '-in' option required\n", prog);
		return -1;
	}
	if (!(hp = gethostbyname(host))) {
		//herror("tls12_client: '-host' invalid"); // herror() not in winsock2, use WSAGetLastError() instead
		goto end;
	}

	memset(&ctx, 0, sizeof(ctx));
	memset(&conn, 0, sizeof(conn));

	server.sin_addr = *((struct in_addr *)hp->h_addr_list[0]);
	server.sin_family = AF_INET;
	server.sin_port = htons(port);


	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		//fprintf(stderr, "%s: open socket error : %s\n", prog, strerror(errno)); //FIXME: WIN32 use WSAGetLastError()			
		goto end;
	}
	if (connect(sock, (struct sockaddr *)&server , sizeof(server)) < 0) {
		//fprintf(stderr, "%s: connect error : %s\n", prog, strerror(errno)); //			
		goto end;
	}

	if (tls_ctx_init(&ctx, TLS_protocol_tls12, TLS_client_mode) != 1
		|| tls_ctx_set_cipher_suites(&ctx, client_ciphers, sizeof(client_ciphers)/sizeof(client_ciphers[0])) != 1) {
		fprintf(stderr, "%s: context init error\n", prog);
		goto end;
	}
	if (cacertfile) {
		if (tls_ctx_set_ca_certificates(&ctx, cacertfile, TLS_DEFAULT_VERIFY_DEPTH) != 1) {
			fprintf(stderr, "%s: context init error\n", prog);
			goto end;
		}
	}
	if (certfile) {
		if (tls_ctx_set_certificate_and_key(&ctx, certfile, keyfile, pass) != 1) {
			fprintf(stderr, "%s: context init error\n", prog);
			goto end;
		}
	}

	if (tls_init(&conn, &ctx) != 1
		|| tls_set_socket(&conn, sock) != 1
		|| tls_do_handshake(&conn) != 1) {
		fprintf(stderr, "%s: error\n", prog);
		goto end;
	}

	for (;;) {
		fd_set fds;
		size_t sentlen;

		FD_ZERO(&fds);
		FD_SET(conn.sock, &fds);
		FD_SET(fileno(stdin), &fds);

		if (select((int)(conn.sock + 1), &fds, NULL, NULL, NULL) < 0) {
			fprintf(stderr, "%s: select failed\n", prog);
			goto end;
		}

		if (FD_ISSET(conn.sock, &fds)) {
			for (;;) {
				memset(buf, 0, sizeof(buf));
				if (tls_recv(&conn, (uint8_t *)buf, sizeof(buf), &len) != 1) {
					goto end;
				}
				fwrite(buf, 1, len, stdout);
				fflush(stdout);

				// 应该调整tls_recv 逻辑、API或者其他方式			
				if (conn.datalen == 0) {
					break;
				}
			}

		}
		if (FD_ISSET(fileno(stdin), &fds)) {
			memset(send_buf, 0, sizeof(send_buf));

			if (!fgets(send_buf, sizeof(send_buf), stdin)) {
				if (feof(stdin)) {
					tls_shutdown(&conn);
					goto end;
				} else {
					continue;
				}
			}
			if (tls_send(&conn, (uint8_t *)send_buf, strlen(send_buf), &sentlen) != 1) {
				fprintf(stderr, "%s: send error\n", prog);
				goto end;
			}
		}
	}


end:
#ifdef WIN32
	closesocket(sock);
#else
	close(sock);
#endif
	tls_ctx_cleanup(&ctx);
	tls_cleanup(&conn);
	return 0;
}
