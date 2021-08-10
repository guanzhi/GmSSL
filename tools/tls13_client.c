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
#include <gmssl/tls.h>
#include <gmssl/error.h>


const char *http_get =
	"GET / HTTP/1.1\r\n"
	"Hostname: aaa\r\n"
	"\r\n\r\n";

void print_usage(const char *prog)
{
	printf("Usage: %s [options]\n", prog);
	printf("  -host <str>\n");
	printf("  -port <num>\n");
	printf("  -cacerts <file>\n");
	printf("  -cert <file>\n");
	printf("  -key <file>\n");
}

int main(int argc , char *argv[])
{
	int ret = -1;
	char *prog = argv[0];
	char *host = NULL;
	int port = 443;
	TLS_CONNECT conn;
	char buf[100] = {0};
	size_t len = sizeof(buf);

	char *cacertsfile = NULL;
	char *certfile = NULL;
	char *keyfile = NULL;

	FILE *cacertsfp = NULL;
	FILE *certfp = NULL;
	FILE *keyfp = NULL;
	SM2_KEY sign_key;


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

		} else if (!strcmp(*argv, "-host")) {
			if (--argc < 1) goto bad;
			host = *(++argv);

		} else if (!strcmp(*argv, "-port")) {
			if (--argc < 1) goto bad;
			port = atoi(*(++argv));

		} else if (!strcmp(*argv, "-cacerts")) {
			if (--argc < 1) goto bad;
			cacertsfile = *(++argv);

		} else if (!strcmp(*argv, "-cert")) {
			if (--argc < 1) goto bad;
			certfile = *(++argv);

		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);

		} else {
			print_usage(prog);
			return 0;
		}
		argc--;
		argv++;
	}

	if (!host /*|| !certfile || !keyfile */) {
		print_usage(prog);
		return -1;
	}

	if (cacertsfile) {
		if (!(cacertsfp = fopen(cacertsfile, "r"))) {
			error_print();
			return -1;
		}
	}
	if (certfile) {
		if (!(certfp = fopen(certfile, "r"))) {
			error_print();
			return -1;
		}
	}
	if (keyfile) {
		if (!(keyfp = fopen(keyfile, "r"))) {
			error_print();
			return -1;
		}
		if (sm2_private_key_from_pem(&sign_key, keyfp) != 1) {
			error_print();
			return -1;
		}
	}

	memset(&conn, 0, sizeof(conn));

	if (tls13_connect(&conn, host, port, cacertsfp, certfp, &sign_key) != 1) {
		error_print();
		return -1;
	}

	// 这个client 发收了一个消息就结束了
	if (tls_send(&conn, (uint8_t *)"12345\n", 6) != 1) {
		error_print();
		return -1;
	}

	for (;;) {
		memset(buf, 0, sizeof(buf));
		len = sizeof(buf);
		if (tls_recv(&conn, (uint8_t *)buf, &len) != 1) {
			error_print();
			return -1;
		}
		if (len > 0) {
			printf("%s\n", buf);
			break;
		}
	}

	return 1;
bad:
	fprintf(stderr, "%s: command error\n", prog);

	return 0;
}


