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
#include <gmssl/mem.h>
#include <gmssl/hex.h>
#include <gmssl/sm2.h>
#include <gmssl/tls.h>
#include <gmssl/error.h>


static const char *options = "[-port num] -cert file -key file -pass str [-cacert file]";

static const char *help =
"Options\n"
"\n"
"    -port num                 Listening port number, default 443\n"
"    -cert file                Server's certificate chain in PEM format\n"
"    -key file                 Server's encrypted private key in PEM format\n"
"    -pass str                 Password to decrypt private key\n"
"    -cacert file              CA certificate for client certificate verification\n"
"    -new_session_ticket num   Send NewSessionTicket <num> times\n"
"    -ticket_key hex           Session ticket encrypt/decrypt key in HEX format\n"
"    -psk_identity str         Identity of pre_shared_key\n"
"    -psk hex                  Pre-shared key in HEX format\n"
"    -early_data               Accept EarlyData, support 0-RTT\n"
"    -max_early_data_size num  Set extension max_early_data_size\n"
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
"\n";

int tls13_server_main(int argc , char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	int port = 443;
	char *certfile = NULL;
	char *keyfile = NULL;
	char *pass = NULL;
	char *cacertfile = NULL;
	int server_ciphers[] = { TLS_cipher_sm4_gcm_sm3, };
	TLS_CTX ctx;
	TLS_CONNECT conn;
	char buf[1600] = {0};
	size_t len = sizeof(buf);
	tls_socket_t sock;
	tls_socket_t conn_sock;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;

	int new_session_ticket = 0;
	char *ticket_key = NULL;
	uint8_t ticket_key_buf[16];

	// TODO: clean
	char *psk_identity = NULL;
	char *psk = NULL;
	uint8_t psk_buf[32];
	size_t psk_len;

	int early_data = 0;
	int max_early_data_size = 0;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			printf("%s\n", help);
			return 0;
		} else if (!strcmp(*argv, "-port")) {
			if (--argc < 1) goto bad;
			port = atoi(*(++argv));
		} else if (!strcmp(*argv, "-cert")) {
			if (--argc < 1) goto bad;
			certfile = *(++argv);
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
		} else if (!strcmp(*argv, "-cacert")) {
			if (--argc < 1) goto bad;
			cacertfile = *(++argv);
		} else if (!strcmp(*argv, "-new_session_ticket")) {
			if (--argc < 1) goto bad;
			new_session_ticket = atoi(*(++argv));
		} else if (!strcmp(*argv, "-ticket_key")) {
			if (--argc < 1) goto bad;
			ticket_key = *(++argv);
		} else if (!strcmp(*argv, "-psk_identity")) {
			if (--argc < 1) goto bad;
			psk_identity = *(++argv);
		} else if (!strcmp(*argv, "-psk")) {
			if (--argc < 1) goto bad;
			psk = *(++argv);
		} else if (!strcmp(*argv, "-early_data")) {
			early_data = 1;
		} else if (!strcmp(*argv, "-max_early_data_size")) {
			if (--argc < 1) goto bad;
			max_early_data_size = atoi(*(++argv));
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
	/*
	if (!certfile) {
		fprintf(stderr, "%s: '-cert' option required\n", prog);
		return 1;
	}
	if (!keyfile) {
		fprintf(stderr, "%s: '-key' option required\n", prog);
		return 1;
	}
	if (!pass) {
		fprintf(stderr, "%s: '-pass' option required\n", prog);
		return 1;
	}
	*/

	if (tls_socket_lib_init() != 1) {
		error_print();
		return -1;
	}

	memset(&ctx, 0, sizeof(ctx));
	memset(&conn, 0, sizeof(conn));

	if (tls_ctx_init(&ctx, TLS_protocol_tls13, TLS_server_mode) != 1
		|| tls_ctx_set_cipher_suites(&ctx, server_ciphers, sizeof(server_ciphers)/sizeof(int)) != 1
		|| tls_ctx_set_certificate_and_key(&ctx, certfile, keyfile, pass) != 1) {
		error_print();
		return -1;
	}
	if (cacertfile) {
		if (tls_ctx_set_ca_certificates(&ctx, cacertfile, TLS_DEFAULT_VERIFY_DEPTH) != 1) {
			error_print();
			return -1;
		}
	}

	// NewSessionTicket
	if (new_session_ticket < 0) {
		error_print();
		return -1;
	}
	if (new_session_ticket > 0) {
		if (!ticket_key) {
			error_print();
			return -1;
		}
		if (tls13_ctx_set_new_session_ticket(&ctx, new_session_ticket) != 1) {
			error_print();
			return -1;
		}
	}

	if (ticket_key) {
		size_t ticket_key_len;
		if (strlen(ticket_key) != sizeof(ticket_key_buf) * 2) {
			error_print();
			return -1;
		}
		if (hex_to_bytes(ticket_key, strlen(ticket_key), ticket_key_buf, &ticket_key_len) != 1) {
			error_print();
			return -1;
		}
		if (tls13_ctx_set_session_ticket_key(&ctx, ticket_key_buf, ticket_key_len) != 1) {
			error_print();
			return -1;
		}
		tls13_enable_pre_shared_key(&conn, 1);
		tls13_set_psk_key_exchange_modes(&conn, 1, 1);
	}

	if (tls_socket_create(&sock, AF_INET, SOCK_STREAM, 0) != 1) {
		fprintf(stderr, "%s: socket create error\n", prog);
		goto end;
	}
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(port);
	if (tls_socket_bind(sock, &server_addr) != 1) {
		fprintf(stderr, "%s: socket bind error\n", prog);
		goto end;
	}
	puts("start listen ...\n");
	tls_socket_listen(sock, 1);



restart:

	//client_addrlen = sizeof(client_addr);
	if (tls_socket_accept(sock, &client_addr, &conn_sock) != 1) {
		fprintf(stderr, "%s: socket accept error\n", prog);
		goto end;
	}
	puts("socket connected\n");

	if (tls_init(&conn, &ctx) != 1
		|| tls_set_socket(&conn, conn_sock) != 1) {
		error_print();
		return -1;
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

	if (max_early_data_size > 0) {
		if (tls13_set_max_early_data_size(&conn, max_early_data_size) != 1) {
			error_print();
			return -1;
		}
	}

	if (early_data) {
		if (tls13_enable_early_data(&conn, 1) != 1) {
			error_print();
			return -1;
		}
	}


	if (tls_do_handshake(&conn) != 1) {
		error_print();
		return -1;
	}

	for (;;) {

		int rv;
		size_t sentlen;

		do {
			len = sizeof(buf);
			if ((rv = tls13_recv(&conn, (uint8_t *)buf, sizeof(buf), &len)) != 1) {
				if (rv < 0) fprintf(stderr, "%s: recv failure\n", prog);
				else fprintf(stderr, "%s: Disconnected by remote\n", prog);

				//close(conn.sock);
				tls_cleanup(&conn);
				goto restart;
			}
		} while (!len);

		if (tls13_send(&conn, (uint8_t *)buf, len, &sentlen) != 1) {
			fprintf(stderr, "%s: send failure, close connection\n", prog);
			tls_socket_close(conn.sock);
			goto end;
		}
	}


end:
	return ret;
}
