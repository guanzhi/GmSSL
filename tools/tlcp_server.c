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



static const char *options = "[-port num] -cert file -key file [-pass str] -ex_key file [-ex_pass str] [-cacert file]";

int tlcp_server_main(int argc , char **argv)
{
	int ret = -1;
	char *prog = argv[0];
	int port = 443;
	char *file = NULL;

	FILE *certfp = NULL;
	FILE *signkeyfp = NULL;
	FILE *enckeyfp = NULL;
	SM2_KEY signkey;
	SM2_KEY enckey;

	char *pass = NULL;
	char *ex_pass = NULL;

	uint8_t verify_buf[4096];


	TLS_CONNECT conn;
	char buf[1600] = {0};
	size_t len = sizeof(buf);

	if (argc < 2) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}

	argc--;
	argv++;
	while (argc >= 1) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			return 0;
		} else if (!strcmp(*argv, "-port")) {
			if (--argc < 1) goto bad;
			port = atoi(*(++argv));
		} else if (!strcmp(*argv, "-cert")) {
			if (--argc < 1) goto bad;
			file = *(++argv);
			if (!(certfp = fopen(file, "r"))) {
				error_print();
				return -1;
			}
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			file = *(++argv);
			if (!(signkeyfp = fopen(file, "r"))) {
				error_print();
				return -1;
			}
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
		} else if (!strcmp(*argv, "-ex_key")) {
			if (--argc < 1) goto bad;
			file = *(++argv);
			if (!(enckeyfp = fopen(file, "r"))) {
				error_print();
				return -1;
			}
		} else if (!strcmp(*argv, "-ex_pass")) {
			if (--argc < 1) goto bad;
			ex_pass = *(++argv);
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

	if (!certfp) {
		error_print();
		return -1;
	}
	if (!signkeyfp) {
		error_print();
		return -1;
	}
	if (!enckeyfp) {
		error_print();
		return -1;
	}

	if (!pass) {
		pass = getpass("Sign Key Password : ");
	}
	if (sm2_private_key_info_decrypt_from_pem(&signkey, pass, signkeyfp) != 1) {
		error_print();
		return -1;
	}

	if (!ex_pass) {
		ex_pass = getpass("Encryption Key Password : ");
	}
	if (sm2_private_key_info_decrypt_from_pem(&enckey, ex_pass, enckeyfp) != 1) {
		error_print();
		return -1;
	}

	memset(&conn, 0, sizeof(conn));
	if (tlcp_accept(&conn, port, certfp, &signkey, &enckey,
		NULL, verify_buf, 4096) != 1) {
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


	return 0;
}
