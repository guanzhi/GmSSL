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
#include <gmssl/mem.h>
#include <gmssl/sm2.h>
#include <gmssl/tls.h>


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

	FILE *certfp = NULL;
	FILE *signkeyfp = NULL;
	FILE *enckeyfp = NULL;
	FILE *cacertfp = NULL;
	SM2_KEY signkey;
	SM2_KEY enckey;

	uint8_t verify_buf[4096];

	TLS_CONNECT conn;
	char buf[1600] = {0};
	size_t len = sizeof(buf);


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
			if (!(certfp = fopen(certfile, "r"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, certfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			signkeyfile = *(++argv);
			if (!(signkeyfp = fopen(signkeyfile, "r"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, signkeyfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			signpass = *(++argv);
		} else if (!strcmp(*argv, "-ex_key")) {
			if (--argc < 1) goto bad;
			enckeyfile = *(++argv);
			if (!(enckeyfp = fopen(enckeyfile, "r"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, enckeyfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-ex_pass")) {
			if (--argc < 1) goto bad;
			encpass = *(++argv);
		} else if (!strcmp(*argv, "-cacert")) {
			if (--argc < 1) goto bad;
			cacertfile = *(++argv);
			if (!(cacertfp = fopen(cacertfile, "r"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, cacertfile, strerror(errno));
				goto end;
			}
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
		goto end;
	}
	if (!signkeyfile) {
		fprintf(stderr, "%s: '-key' option required\n", prog);
		goto end;
	}
	if (!signpass) {
		fprintf(stderr, "%s: '-pass' option required\n", prog);
		goto end;
	}
	if (!enckeyfile) {
		fprintf(stderr, "%s: '-ex_key' option required\n", prog);
		goto end;
	}
	if (!encpass) {
		fprintf(stderr, "%s: '-ex_pass' option required\n", prog);
		goto end;
	}

	if (sm2_private_key_info_decrypt_from_pem(&signkey, signpass, signkeyfp) != 1) {
		fprintf(stderr, "%s: load private key failure\n", prog);
		goto end;
	}
	if (sm2_private_key_info_decrypt_from_pem(&enckey, encpass, enckeyfp) != 1) {
		fprintf(stderr, "%s: load private key failure\n", prog);
		goto end;
	}

	printf("start ...........\n");

	memset(&conn, 0, sizeof(conn));

	if (tlcp_accept(&conn, port, certfp, &signkey, &enckey, cacertfp, verify_buf, 4096) != 1) {
		fprintf(stderr, "%s: tlcp accept failure\n", prog);
		goto end;
	}

	for (;;) {

		do {
			len = sizeof(buf);
			if (tls_recv(&conn, (uint8_t *)buf, &len) != 1) {
				fprintf(stderr, "%s: recv failure\n", prog);
				goto end;
			}
		} while (!len);


		if (tls_send(&conn, (uint8_t *)buf, len) != 1) {
			fprintf(stderr, "%s: send failure\n", prog);
			goto end;
		}
	}


end:
	gmssl_secure_clear(&signkey, sizeof(signkey));
	gmssl_secure_clear(&enckey, sizeof(enckey));
	if (certfp) fclose(certfp);
	if (signkeyfp) fclose(signkeyfp);
	if (enckeyfp) fclose(enckeyfp);
	if (cacertfp) fclose(cacertfp);
	return ret;
}
