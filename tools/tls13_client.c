/*
 * Copyright (c) 2021 - 2021 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <gmssl/tls.h>
#include <gmssl/error.h>


// TLSv1.2客户单和TLCP客户端可能没有什么区别

static int client_ciphers[] = { TLS_cipher_sm4_gcm_sm3 };

static const char *http_get =
	"GET / HTTP/1.1\r\n"
	"Hostname: aaa\r\n"
	"\r\n\r\n";

static const char *options = "-host str [-port num] [-cacert file] [-cert file -key file -pass str]";

int tls13_client_main(int argc, char *argv[])
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
	int sock;
	TLS_CTX ctx;
	TLS_CONNECT conn;
	char buf[1024] = {0};
	size_t len = sizeof(buf);
	char send_buf[1024] = {0};
	size_t send_len;

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
		herror("tls13_client: '-host' invalid");
		goto end;
	}

	memset(&ctx, 0, sizeof(ctx));
	memset(&conn, 0, sizeof(conn));

	server.sin_addr = *((struct in_addr *)hp->h_addr_list[0]);
	server.sin_family = AF_INET;
	server.sin_port = htons(port);


	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "%s: open socket error : %s\n", prog, strerror(errno));
		goto end;
	}
	if (connect(sock, (struct sockaddr *)&server , sizeof(server)) < 0) {
		fprintf(stderr, "%s: connect error : %s\n", prog, strerror(errno));
		goto end;
	}

	if (tls_ctx_init(&ctx, TLS_protocol_tls13, TLS_client_mode) != 1
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
		FD_SET(STDIN_FILENO, &fds);

		if (select(conn.sock + 1, &fds, NULL, NULL, NULL) < 0) {
			fprintf(stderr, "%s: select failed\n", prog);
			goto end;
		}

		if (FD_ISSET(conn.sock, &fds)) {
			for (;;) {
				memset(buf, 0, sizeof(buf));
				if (tls13_recv(&conn, (uint8_t *)buf, sizeof(buf), &len) != 1) {
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
		if (FD_ISSET(STDIN_FILENO, &fds)) {
			memset(send_buf, 0, sizeof(send_buf));

			if (!fgets(send_buf, sizeof(send_buf), stdin)) {
				if (feof(stdin)) {
					tls_shutdown(&conn);
					goto end;
				} else {
					continue;
				}
			}
			if (tls13_send(&conn, (uint8_t *)send_buf, strlen(send_buf), &sentlen) != 1) {
				fprintf(stderr, "%s: send error\n", prog);
				goto end;
			}
		}
	}

end:
	close(sock);
	tls_ctx_cleanup(&ctx);
	tls_cleanup(&conn);
	return 0;
}
