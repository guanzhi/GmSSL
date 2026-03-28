/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/hex.h>
#include <gmssl/tls.h>
#include <gmssl/error.h>


static int client_ciphers[] = { TLS_cipher_sm4_gcm_sm3 };

static const char *http_get =
	"GET / HTTP/1.1\r\n"
	"Hostname: aaa\r\n"
	"\r\n\r\n";

static const char *options = "-host str [-port num] [-cacert file] [-cert file -key file -pass str]";

static const char *help =
"Options\n"
"\n"
"    -host str              Server's hostname\n"
"    -port num              Server's port number, default 443\n"
"    -cacert file           Root CA certificate\n"
"    -cert file             Client's certificate chain in PEM format\n"
"    -key file              Client's encrypted private key in PEM format\n"
"    -pass str              Password to decrypt private key\n"
"    -sess_in               Load server's session ticket file\n"
"    -sess_out              Save server's session ticket file\n"
"    -psk_identity str      Identity of pre_shared_key\n"
"    -psk hex               Pre-shared key in HEX format\n"
"    -early_data file       Send early data\n"
"\n"
"Examples\n"
"\n"
"    gmssl sm2keygen -pass 1234 -out rootcakey.pem\n"
"    gmssl certgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN ROOTCA -days 3650 \\\n"
"            -key rootcakey.pem -pass 1234 -out rootcacert.pem \\\n"
"            -key_usage keyCertSign -key_usage cRLSign -ca\n"
"\n"
"    gmssl sm2keygen -pass 1234 -out cakey.pem\n"
"    gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN \"Sub CA\" \\\n"
"            -key cakey.pem -pass 1234 -out careq.pem\n"
"    gmssl reqsign -in careq.pem -days 365 -key_usage keyCertSign -cacert rootcacert.pem -key rootcakey.pem -pass 1234 \\\n"
"            -out cacert.pem -ca -path_len_constraint 0\n"
"\n"
"    gmssl sm2keygen -pass 1234 -out signkey.pem\n"
"    gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost -key signkey.pem -pass 1234 -out signreq.pem\n"
"    gmssl reqsign -in signreq.pem -days 365 -key_usage digitalSignature -cacert cacert.pem -key cakey.pem -pass 1234 -out signcert.pem\n"
"\n"
"    cat signcert.pem > certs.pem\n"
"    cat cacert.pem >> certs.pem\n"
"\n"
"    sudo gmssl tls13_server -port 4430 -cert certs.pem -key signkey.pem -pass 1234\n"
"    gmssl tls13_client -host 127.0.0.1 -port 4430 -cacert rootcacert.pem\n"
"            -sess_in session.bin -sess_out session.bin\n"
"\n";

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
	tls_socket_t sock = -1;
	TLS_CTX ctx;
	TLS_CONNECT conn;
	char buf[1024] = {0};
	size_t len = sizeof(buf);
	char send_buf[1024] = {0};

	char *sess_in = NULL;
	char *sess_out = NULL;
	char *psk_identity = NULL;
	char *psk = NULL;
	uint8_t psk_buf[32];
	size_t psk_len;

	char *early_data_file = NULL;
	FILE *early_data_fp = NULL;
	int max_early_data_size = 0;

	argc--;
	argv++;
	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}
	while (argc >= 1) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			printf("%s\n", help);
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
		} else if (!strcmp(*argv, "-sess_in")) {
			if (--argc < 1) goto bad;
			sess_in = *(++argv);
		} else if (!strcmp(*argv, "-sess_out")) {
			if (--argc < 1) goto bad;
			sess_out = *(++argv);
		} else if (!strcmp(*argv, "-psk_identity")) {
			if (--argc < 1) goto bad;
			psk_identity = *(++argv);
		} else if (!strcmp(*argv, "-psk")) {
			if (--argc < 1) goto bad;
			psk = *(++argv);
		} else if (!strcmp(*argv, "-early_data")) {
			if (--argc < 1) goto bad;
			early_data_file = *(++argv);
		} else if (!strcmp(*argv, "-max_early_data_size")) {
			if (--argc < 1) goto bad;
			max_early_data_size = atoi(*(++argv));
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

	if (tls_socket_lib_init() != 1) {
		error_print();
		return -1;
	}
	if (!(hp = gethostbyname(host))) {
		//herror("tls13_client: '-host' invalid");			
		goto end;
	}



	memset(&ctx, 0, sizeof(ctx));
	memset(&conn, 0, sizeof(conn));

	server.sin_addr = *((struct in_addr *)hp->h_addr_list[0]);
	server.sin_family = AF_INET;
	server.sin_port = htons(port);

	if (tls_socket_create(&sock, AF_INET, SOCK_STREAM, 0) != 1) {
		fprintf(stderr, "%s: socket create error\n", prog);
		goto end;
	}
	if (tls_socket_connect(sock, &server) != 1) {
		fprintf(stderr, "%s: socket connect error\n", prog);
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
	if (tls_init(&conn, &ctx) != 1) {
		fprintf(stderr, "%s: error\n", prog);
		goto end;
	}

	if (sess_in) {

		if (tls13_add_pre_shared_key_from_file(&conn, sess_in) != 1) {
			error_print();
			return -1;
		}
		tls13_enable_pre_shared_key(&conn, 1);
		tls13_set_psk_key_exchange_modes(&conn, 1, 1);
	}
	if (sess_out) {
		if (tls13_set_session_outfile(&conn, sess_out) != 1) {
			error_print();
			goto end;
		}
	}
	if (psk) {
		if (!psk_identity) {
			error_print();
			return -1;
		}
		if (strlen(psk) != sizeof(psk_buf) * 2) {
			error_print();
			return -1;
		}
		if (hex_to_bytes(psk, strlen(psk), psk_buf, &psk_len) != 1) {
			error_print();
			return -1;
		}
		if (tls13_add_pre_shared_key(&conn, DIGEST_sm3(), (uint8_t *)psk_identity, strlen(psk_identity), psk_buf, psk_len, 0) != 1) {
			error_print();
			return -1;
		}

		tls13_enable_pre_shared_key(&conn, 1);
		tls13_set_psk_key_exchange_modes(&conn, 1, 1);

	}


	if (early_data_file) {
		uint8_t early_data[8192];
		size_t early_data_len;

		if (!(early_data_fp = fopen(early_data_file, "rb"))) {
			error_print();
			return -1;
		}

		early_data_len = fread(early_data, 1, sizeof(early_data), early_data_fp);

		if (early_data_len) {

			if (tls13_set_early_data(&conn, early_data, early_data_len) != 1) {
				fclose(early_data_fp);
				error_print();
				return -1;
			}
		}
		fclose(early_data_fp);
	}



	if (tls_set_socket(&conn, sock) != 1
		|| tls_do_handshake(&conn) != 1) {
		fprintf(stderr, "%s: error\n", prog);
		goto end;
	}

	for (;;) {
		fd_set fds;
		size_t sentlen;

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


		FD_ZERO(&fds);
		FD_SET(conn.sock, &fds);
#ifdef WIN32
#else
		FD_SET(fileno(stdin), &fds);
#endif

		if (select((int)(conn.sock + 1), // In WinSock2, select() ignore the this arg
			&fds, NULL, NULL, NULL) < 0) {
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

				// FIXME: change tls13_recv API			
				if (conn.datalen == 0) {
					break;
				}
			}

		}
#ifdef WIN32
#else
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
			if (tls13_send(&conn, (uint8_t *)send_buf, strlen(send_buf), &sentlen) != 1) {
				fprintf(stderr, "%s: send error\n", prog);
				goto end;
			}
		}
#endif
	}

end:
	if (sock != -1) tls_socket_close(sock);
	tls_ctx_cleanup(&ctx);
	tls_cleanup(&conn);
	return 0;
}
