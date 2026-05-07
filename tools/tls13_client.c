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


static const char *http_get =
	"GET / HTTP/1.1\r\n"
	"Hostname: aaa\r\n"
	"\r\n\r\n";

static const char *options = "-host str [-port num] [-cacert file] [-cert file -key file -pass str]";

static const char *help =
"Options\n"
"\n"
"    -host str                 Server's hostname\n"
"    -port num                 Server's port number, default 443\n"
"    -cipher_suite str         Supported cipher suites, may appear multiple times, higher priority first\n"
"    -supported_group str      Supported elliptic curves, may appear multiple times, higher priority first\n"
"    -sig_alg str              Supported signature algorithms\n"
"    -max_key_exchanges num    Number of key exchanges in key_share extension\n"
"    -cacert file              Root CA certificate\n"
"    -cert file                Client's certificate chain in PEM format\n"
"    -key file                 Client's encrypted private key in PEM format\n"
"    -pass str                 Password to decrypt private key\n"
"    -server_name              Send server_name (SNI) request\n"
"    -signature_algorithms_cert Send signature_algorithms_cert extension\n"
"    -status_request           Send status_request (OCSP Stapling) request\n"
"    -ct                       Send signed_certificate_timestamp (SCT) request\n"
"    -psk_ke                   Support PSK-only key exchange\n"
"    -psk_dhe_ke               Support PSK with (EC)DHE key exchange\n"
"    -psk_identity str         PSK Identity\n"
"    -psk_cipher_suite str     PSK cipher suite\n"
"    -psk_key hex              PSK key in HEX format, of PSK hash length\n"
"    -sess_in                  Load server's session ticket file\n"
"    -sess_out                 Save server's session ticket file\n"
"    -early_data file          Send early data, -psk_ke and/or -psk_dhe_ke should be set\n"
"    -post_handshake_auth      Support post_handshake_auth\n"
"\n"
"CipherSuites\n"
"    TLS_SM4_GCM_SM3        TLS 1.3\n"
"    TLS_AES_128_GCM_SHA256 TLS 1.3\n"
"    TLS_ECC_SM4_CBC_SM3    TLCP\n"
"    TLS_ECDHE_SM4_CBC_SM3  TLCP TLS 1.2\n"
"    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 TLS 1.2\n"
"\n"
" -supported_group\n"
"    sm2p256v1\n"
"    prime256v1\n"
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

	int psk_ke = 0;
	int psk_dhe_ke = 0;

	// psk external
	char *psk_identities[16];
	size_t psk_identities_cnt = 0;
	char *psk_cipher_suites[16];
	size_t psk_cipher_suites_cnt = 0;
	char *psk_keys[16];
	size_t psk_keys_cnt = 0;


	char *early_data_file = NULL;
	FILE *early_data_fp = NULL;
	int max_early_data_size = 0;

	char *cipher_suite;
	int cipher;
	int cipher_suites[4];
	size_t cipher_suites_cnt = 0;

	char *supported_group_name;
	int supported_group;
	int supported_groups[4];
	size_t supported_groups_cnt = 0;

	char  *max_key_exchanges = NULL;
	int max_key_exchanges_cnt;

	char *sig_alg_name;
	int sig_alg;
	int sig_algs[4];
	size_t sig_algs_cnt = 0;


	int server_name = 0;
	int signature_algorithms_cert = 0;
	int status_request = 0;
	int signed_certificate_timestamp = 0;
	int post_handshake_auth = 0;

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
		} else if (!strcmp(*argv, "-server_name")) {
			server_name = 1;
		} else if (!strcmp(*argv, "-signature_algorithms_cert")) {
			signature_algorithms_cert = 1;
		} else if (!strcmp(*argv, "-status_request")) {
			status_request = 1;
		} else if (!strcmp(*argv, "-ct")) {
			signed_certificate_timestamp = 1;
		} else if (!strcmp(*argv, "-post_handshake_auth")) {
			post_handshake_auth = 1;
		} else if (!strcmp(*argv, "-sess_in")) {
			if (--argc < 1) goto bad;
			sess_in = *(++argv);
		} else if (!strcmp(*argv, "-sess_out")) {
			if (--argc < 1) goto bad;
			sess_out = *(++argv);

		} else if (!strcmp(*argv, "-psk_ke")) {
			psk_ke = 1;
		} else if (!strcmp(*argv, "-psk_dhe_ke")) {
			psk_dhe_ke = 1;
		} else if (!strcmp(*argv, "-psk_identity")) {
			if (--argc < 1) goto bad;
			if (psk_identities_cnt > sizeof(psk_identities)/sizeof(psk_identities[0])) {
				error_print();
				return -1;
			}
			psk_identities[psk_identities_cnt++] = *(++argv);
		} else if (!strcmp(*argv, "-psk_cipher_suite")) {
			if (--argc < 1) goto bad;
			if (psk_cipher_suites_cnt > sizeof(psk_cipher_suites)/sizeof(psk_cipher_suites[0])) {
				error_print();
				return -1;
			}
			psk_cipher_suites[psk_cipher_suites_cnt++] = *(++argv);
		} else if (!strcmp(*argv, "-psk_key")) {
			if (--argc < 1) goto bad;
			if (psk_keys_cnt > sizeof(psk_keys)/sizeof(psk_keys[0])) {
				error_print();
				return -1;
			}
			psk_keys[psk_keys_cnt++] = *(++argv);
		} else if (!strcmp(*argv, "-early_data")) {
			if (--argc < 1) goto bad;
			early_data_file = *(++argv);
		} else if (!strcmp(*argv, "-max_early_data_size")) {
			if (--argc < 1) goto bad;
			max_early_data_size = atoi(*(++argv));
		} else if (!strcmp(*argv, "-cipher_suite")) {
			if (--argc < 1) goto bad;
			cipher_suite = *(++argv);
			if ((cipher = tls_cipher_suite_from_name(cipher_suite)) == 0) {
				error_print();
				fprintf(stderr, "%s: cipher suite '%s' not supported\n", prog, cipher_suite);
				return -1;
			}
			if (cipher_suites_cnt >= sizeof(cipher_suites)/sizeof(cipher_suites[0])) {
				error_print();
				fprintf(stderr, "%s: too much cipher suites\n", prog);
				return -1;
			}
			cipher_suites[cipher_suites_cnt] = cipher;
			cipher_suites_cnt++;
		} else if (!strcmp(*argv, "-supported_group")) {
			if (--argc < 1) goto bad;
			supported_group_name = *(++argv);
			if ((supported_group = tls_named_curve_from_name(supported_group_name)) == 0) {
				error_print();
				fprintf(stderr, "%s: supported_group '%s' not supported\n", prog, supported_group_name);
				return -1;
			}
			if (supported_groups_cnt >= sizeof(supported_groups)/sizeof(supported_groups[0])) {
				error_print();
				fprintf(stderr, "%s: too much supported_group\n", prog);
				return -1;
			}
			supported_groups[supported_groups_cnt++] = supported_group;
		} else if (!strcmp(*argv, "-sig_alg")) {
			if (--argc < 1) goto bad;
			sig_alg_name = *(++argv);
			if ((sig_alg = tls_signature_scheme_from_name(sig_alg_name)) == 0) {
				error_print();
				fprintf(stderr, "%s: sig_alg '%s' not supported\n", prog, sig_alg_name);
				return -1;
			}
			if (sig_algs_cnt >= sizeof(sig_algs)/sizeof(sig_algs[0])) {
				error_print();
				fprintf(stderr, "%s: too much sig_algs\n", prog);
				return -1;
			}
			sig_algs[sig_algs_cnt++] = sig_alg;
		} else if (!strcmp(*argv, "-max_key_exchanges")) {
			if (--argc < 1) goto bad;
			max_key_exchanges = *(++argv);
			max_key_exchanges_cnt = atoi(max_key_exchanges);
			if (max_key_exchanges_cnt < 0) {
				error_print();
				return -1;
			}
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





	if (tls_ctx_init(&ctx, TLS_protocol_tls13, TLS_client_mode) != 1) {
		fprintf(stderr, "%s: context init error\n", prog);
		goto end;
	}

	/*
	if (!cipher_suites_cnt) {
		error_print();
		fprintf(stderr, "%s: option '-cipher_suite' required\n", prog);
		goto end;
	}
	*/

	if (tls_ctx_set_cipher_suites(&ctx, cipher_suites, cipher_suites_cnt) != 1) {
		fprintf(stderr, "%s: context init error\n", prog);
		goto end;
	}

	if (supported_groups_cnt > 0) {
		if (tls_ctx_set_supported_groups(&ctx, supported_groups, supported_groups_cnt) != 1) {
			error_print();
			return -1;
		}
	}

	if (max_key_exchanges) {
		tls13_ctx_set_max_key_exchanges(&ctx, max_key_exchanges_cnt);
	}


	if (sig_algs_cnt > 0) {
		if (tls_ctx_set_signature_algorithms(&ctx, sig_algs, sig_algs_cnt) != 1) {
			error_print();
			return -1;
		}
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

	if (psk_ke || psk_dhe_ke) {
		if (!sess_in && !psk_keys_cnt) {
			fprintf(stderr, "%s: -sess_in or -psk is required\n", prog);
			error_print();
			return -1;
		}
		error_print();
		tls13_ctx_set_psk_key_exchange_modes(&ctx, psk_ke, psk_dhe_ke);
	}






							
	if (tls13_init(&conn, &ctx) != 1) {
		fprintf(stderr, "%s: error\n", prog);
		goto end;
	}


	if (server_name) {
		if (tls_set_server_name(&conn, (uint8_t *)host, strlen(host)) != 1) {
			error_print();
			goto end;
		}
	}

	if (signature_algorithms_cert) {
		if (tls_enable_signature_algorithms_cert(&conn) != 1) {
			error_print();
			return -1;
		}
	}

	if (status_request) {
		if (tls13_set_client_status_request(&conn, NULL, 0, NULL, 0) != 1) {
			error_print();
			goto end;
		}
	}
	if (signed_certificate_timestamp) {
		if (tls_enable_signed_certificate_timestamp(&conn) != 1) {
			error_print();
			goto end;
		}
	}

	if (sess_in) {
		FILE *sess_infp;
		int psk_ret = 1;

		if (!(sess_infp = fopen(sess_in, "rb"))) {
			error_print();
			goto end;
		}

		while (psk_ret) {
			if ((psk_ret = tls13_add_pre_shared_key_from_session_file(&conn, sess_infp)) < 0) {
				error_print();
				fclose(sess_infp);
				return -1;
			}
		}
		fclose(sess_infp);


		// 客户端是否发送pre_shared_key是由什么决定的？需要显式的支持吗
		// 我觉得应该是不需要的，因为如果设置了psk_key_exchange_mode，那么自然要发送pre_shared_key
		tls13_enable_pre_shared_key(&conn, 1);
	}

	if (sess_out) {
		if (tls13_set_session_outfile(&conn, sess_out) != 1) {
			error_print();
			goto end;
		}
	}

	if (psk_keys_cnt) {
		const uint32_t obfuscated_ticket_age = 0;
		size_t i;

		if (psk_identities_cnt != psk_keys_cnt || psk_cipher_suites_cnt != psk_keys_cnt) {
			error_print();
			return -1;
		}
		for (i = 0; i < psk_keys_cnt; i++) {
			int psk_cipher_suite;
			const BLOCK_CIPHER *psk_cipher;
			const DIGEST *psk_digest;
			uint8_t psk_key[64];
			size_t psk_key_len;

			if (!(psk_cipher_suite = tls_cipher_suite_from_name(psk_cipher_suites[i]))) {
				error_print();
				return -1;
			}
			if (tls13_cipher_suite_get(psk_cipher_suite, &psk_cipher, &psk_digest) != 1) {
				error_print();
				return -1;
			}
			if (strlen(psk_keys[i]) != psk_digest->digest_size * 2) {
				error_print();
				return -1;
			}
			if (hex_to_bytes(psk_keys[i], strlen(psk_keys[i]), psk_key, &psk_key_len) != 1) {
				error_print();
				return -1;
			}
			if (tls13_add_pre_shared_key(&conn, (uint8_t *)psk_identities[i], strlen(psk_identities[i]),
				psk_key, psk_key_len, psk_cipher_suite, obfuscated_ticket_age) != 1) {
				error_print();
				return -1;
			}
		}

		tls13_enable_pre_shared_key(&conn, 1);
	}

	if (early_data_file) {
		uint8_t early_data[8192];
		size_t early_data_len;

		if (!psk_ke && !psk_dhe_ke) {
			error_print();
			fprintf(stderr, "%s: -early_data need -psk_ke and/or -psk_dhe_ke set\n", prog);
			return -1;
		}

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

	if (post_handshake_auth) {
	}



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


	if (tls_set_socket(&conn, sock) != 1
		|| tls_do_handshake(&conn) != 1) {
		fprintf(stderr, "%s: error\n", prog);
		goto end;
	}


	fprintf(stderr, ">>>>>>>>>>>>\n");



	for (;;) {
		fd_set fds;
		size_t sentlen;


		FD_ZERO(&fds);


		// listen socket
		FD_SET(conn.sock, &fds);

		// listen stdin
		FD_SET(fileno(stdin), &fds);


		// 等待阻塞
		if (select((int)(conn.sock + 1), // In WinSock2, select() ignore the this arg
			&fds, NULL, NULL, NULL) < 0) {
			fprintf(stderr, "%s: select failed\n", prog);
			goto end;
		}

		/*
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
		*/


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
	}

end:
	if (sock != -1) tls_socket_close(sock);
	tls_ctx_cleanup(&ctx);
	tls_cleanup(&conn);
	return 0;
}
