/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
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
