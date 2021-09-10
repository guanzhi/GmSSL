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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <gmssl/sm2.h>
#include <gmssl/tls.h>
#include <gmssl/error.h>


void print_usage(const char *prog)
{
	printf("Usage: %s [options]\n", prog);
	printf("  -port <num>\n");
	printf("  -cert <file>\n");
	printf("  -signkey <file>\n");
}

int main(int argc , char *argv[])
{
	int ret = -1;
	char *prog = argv[0];
	int port = 443;
	char *certfile = NULL;
	char *signkeyfile = NULL;
	FILE *certfp = NULL;
	FILE *signkeyfp = NULL;
	SM2_KEY signkey;

	uint8_t verify_buf[4096];


	TLS_CONNECT conn;
	char buf[1600] = {0};
	size_t len = sizeof(buf);

	if (argc < 2) {
		print_usage(prog);
		return 0;
	}

	argc--;
	argv++;
	while (argc >= 1) {
		if (!strcmp(*argv, "-help")) {
			print_usage(prog);
			return 0;

		} else if (!strcmp(*argv, "-port")) {
			if (--argc < 1) goto bad;
			port = atoi(*(++argv));

		} else if (!strcmp(*argv, "-cert")) {
			if (--argc < 1) goto bad;
			certfile = *(++argv);

		} else if (!strcmp(*argv, "-signkey")) {
			if (--argc < 1) goto bad;
			signkeyfile = *(++argv);

		} else {
			print_usage(prog);
			return 0;
		}
		argc--;
		argv++;
	}

	if (!certfile || !signkeyfile) {
		print_usage(prog);
		return -1;
	}

	if (!(certfp = fopen(certfile, "r"))) {
		error_print();
		return -1;
	}


	if (!(signkeyfp = fopen(signkeyfile, "r"))) {
		error_print();
		return -1;
	}
	if (sm2_private_key_from_pem(&signkey, signkeyfp) != 1) {
		error_print();
		return -1;
	}

	memset(&conn, 0, sizeof(conn));
	if (tls12_accept(&conn, port, certfp, &signkey,
		NULL /* certfp */, verify_buf, 4096) != 1) {
		error_print();
		return -1;
	}

	// 我要做一个反射的服务器，接收到用户的输入之后，再反射回去
	for (;;) {

		// 接收一个消息
		// 按道理说第二次执行的时候是不可能成功的了，因此客户端没有数据发过来
		do {
			len = sizeof(buf);
			if (tls_recv(&conn, (uint8_t *)buf, &len) != 1) {
				error_print();
				return -1;
			}
		} while (!len);


		// 把这个消息再发回去
		if (tls_send(&conn, (uint8_t *)buf, len) != 1) {
			error_print();
			return -1;
		}

		fprintf(stderr, "-----------------\n\n\n\n\n\n");

	}



	return 1;
bad:
	fprintf(stderr, "%s: command error\n", prog);

	return 0;
}
