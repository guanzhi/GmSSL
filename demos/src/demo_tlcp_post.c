/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

﻿#include <stdio.h>
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
#include "url_parser.h"


int main(int argc, char *argv[])
{
	int ret = -1;
	char *prog = argv[0];
	const int cipher = TLS_cipher_ecc_sm4_cbc_sm3;
	URL_COMPONENTS *url;
	struct hostent *hp;
	int port = 443;
	struct sockaddr_in server;
	int sock;
	TLS_CTX ctx;
	TLS_CONNECT conn;
	char request[1024];
	uint8_t buf[16800];
	char *p;
	size_t len;

	if (argc != 2) {
		fprintf(stderr, "example: echo \"key=word\" | tlcp_post https://sm2only.ovssl.cn\n");
		return 1;
	}

	if (!(url = parse_url(argv[1]))) {
		fprintf(stderr, "parse url '%s' failure\n", argv[1]);
		return 1;
	}
	if (!(hp = gethostbyname(url->host))) {
		herror("tlcp_client: '-host' invalid");
		goto end;
	}
	if (url->port != -1) {
		port = url->port;
	}

	server.sin_addr = *((struct in_addr *)hp->h_addr_list[0]);
	server.sin_family = AF_INET;
	server.sin_port = htons(port);

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		goto end;
	}
	if (connect(sock, (struct sockaddr *)&server , sizeof(server)) < 0) {
		perror("connect");
		goto end;
	}

	memset(&ctx, 0, sizeof(ctx));
	memset(&conn, 0, sizeof(conn));

	tls_ctx_init(&ctx, TLS_protocol_tlcp, TLS_client_mode);
	tls_ctx_set_cipher_suites(&ctx, &cipher, 1);
	tls_init(&conn, &ctx);
	tls_set_socket(&conn, sock);

	if (tls_do_handshake(&conn) != 1) {
		fprintf(stderr, "%s: error\n", prog);
		goto end;
	}

	snprintf(request, sizeof(request)-1, "POST %s HTTP/1.1\r\nHost: %s\r\n\r\n",
		url->path ? url->path : "/",
		url->host);

	tls_send(&conn, (uint8_t *)request, strlen(request), &len);

	len = fread(buf, 1, sizeof(buf), stdin);
	if (len) {
		tls_send(&conn, buf, len, &len);
	}

	if (tls_recv(&conn, buf, sizeof(buf), &len) != 1) {
		fprintf(stderr, "recv failure\n");
		goto end;
	}
	buf[len] = 0;

	p = strstr((char *)buf, "\r\n\r\n");
	if (p) {
		printf("%s", p + 4);
		fflush(stdout);
	}

end:
	free_url_components(url);
	close(sock);
	tls_ctx_cleanup(&ctx);
	tls_cleanup(&conn);
	return 0;
}
