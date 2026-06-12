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



static const char *options = "[-port num] -cert pem -key pem -pass str [-cacert pem] [-verbose]";

static const char *help =
"Options\n"
"\n"
"    -port num                 Listening port number, default 443\n"
"    -cipher_suite str         Client's cipher suites, may appear multiple times, higher priority first\n"
"    -supported_group str      Supported elliptic curves, may appear multiple times, higher priority first\n"
"    -sig_alg str              Supported signature algorithms\n"
"    -cert pem                 Server's certificate chain in PEM format\n"
"    -key pem                  Server's encrypted private key in PEM format\n"
"    -pass str                 Password to decrypt private key\n"
"    -cert_request             Client certificate request\n"
"    -client_cert_optional     Allow client send empty Certificate\n"
"    -cacert pem               CA certificate for client certificate verification\n"
"    -verify_depth num         Certificate verification depth\n"
"    -psk_ke                   Support PSK-only key exchange\n"
"    -psk_dhe_ke               Support PSK with (EC)DHE key exchange\n"
"    -psk_identity str         PSK Identity\n"
"    -psk_cipher_suite str     PSK cipher suite\n"
"    -psk_key hex              PSK key in HEX format, of PSK hash length\n"
"    -early_data               Accept EarlyData, support 0-RTT\n"
"    -max_early_data_size num  Set extension max_early_data_size\n"
"    -new_session_ticket num   Send NewSessionTicket <num> times\n"
"    -ticket_key hex           Session ticket encrypt/decrypt key in HEX format\n"
"    -key_update_seq_num num   Send KeyUpdate handshake after sending/receiving <num> records\n"
"    -tls13_change_cipher_spec Support ChangeCipherSpec in TLS 1.3 to be compatible with middlebox\n"
"    -verbose                  Print TLS handshake messages\n"
"\n"
#include "tls13_help.h"
"\n";


static int set_socket_nonblocking(tls_socket_t sock)
{
#ifdef WIN32
	u_long mode = 1;
	if (ioctlsocket(sock, FIONBIO, &mode) != 0) {
		error_print();
		return -1;
	}
#else
	int flags;
	if ((flags = fcntl(sock, F_GETFL)) < 0
		|| fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
		error_print();
		return -1;
	}
#endif
	return 1;
}

static int do_handshake_select(TLS_CONNECT *conn)
{
	int ret;
	fd_set rfds;
	fd_set wfds;

	for (;;) {
		ret = tls_do_handshake(conn);
		if (ret == 1) {
			return 1;
		}
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		if (ret == TLS_ERROR_RECV_AGAIN) {
			FD_SET(conn->sock, &rfds);
		} else if (ret == TLS_ERROR_SEND_AGAIN) {
			FD_SET(conn->sock, &wfds);
		} else {
			error_print();
			return -1;
		}
		if (select((int)(conn->sock + 1), &rfds, &wfds, NULL, NULL) < 0) {
			error_print();
			return -1;
		}
	}
}

static int do_shutdown_select(TLS_CONNECT *conn)
{
	int ret;
	fd_set rfds;
	fd_set wfds;

	for (;;) {
		ret = tls_shutdown(conn);
		if (ret == 1) {
			return 1;
		}
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		if (ret == TLS_ERROR_RECV_AGAIN) {
			FD_SET(conn->sock, &rfds);
		} else if (ret == TLS_ERROR_SEND_AGAIN) {
			FD_SET(conn->sock, &wfds);
		} else {
			error_print();
			return -1;
		}
		if (select((int)(conn->sock + 1), &rfds, &wfds, NULL, NULL) < 0) {
			error_print();
			return -1;
		}
	}
}


int tls13_server_main(int argc , char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	int port = 443;

	char *certfiles[4];
	size_t certfiles_cnt = 0;
	char *keyfiles[sizeof(certfiles)/sizeof(certfiles[0])];
	size_t keyfiles_cnt = 0;
	char *passes[sizeof(certfiles)/sizeof(certfiles[0])];
	size_t passes_cnt = 0;

	TLS_CTX ctx;
	TLS_CONNECT conn;
	tls_socket_t sock;
	tls_socket_t conn_sock;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;

	char buf[1600] = {0};
	size_t len = sizeof(buf);

	int cipher_suites[4];
	size_t cipher_suites_cnt = 0;


	// NewSessionTicket
	int new_session_ticket = 0;
	char *ticket_key = NULL;
	uint8_t ticket_key_buf[16];

	// psk_key_exchange_modes
	int psk_ke = 0;
	int psk_dhe_ke = 0;

	// pre_shared_key from external
	char *psk_identities[16];
	size_t psk_identities_cnt = 0;
	char *psk_cipher_suites[16];
	size_t psk_cipher_suites_cnt = 0;
	char *psk_keys[16];
	size_t psk_keys_cnt = 0;

	// early_data
	int early_data = 0;
	int max_early_data_size = 0;

	// supported_groups
	int supported_groups[4];
	size_t supported_groups_cnt = 0;

	// signature_algorithms
	int sig_algs[4];
	size_t sig_algs_cnt = 0;

	// KeyUpdate
	int key_update_seq_num = 0;

	// CertificateRequest
	int client_cert_optional = 0;

	// ChangeCipherSpec
	int tls13_change_cipher_spec = 0;
	int verbose = 0;


	size_t i;


	// CertificateRequest
	int cert_request = 0;
	char *cacertfile = NULL;
	int verify_depth = TLS_DEFAULT_VERIFY_DEPTH;

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
			if (certfiles_cnt >= sizeof(certfiles)/sizeof(certfiles[0])) {
				fprintf(stderr, "%s: too many -cert options\n", prog);
				return -1;
			}
			if (--argc < 1) goto bad;
			certfiles[certfiles_cnt++] = *(++argv);
		} else if (!strcmp(*argv, "-key")) {
			if (keyfiles_cnt >= sizeof(keyfiles)/sizeof(keyfiles[0])) {
				fprintf(stderr, "%s: too many -key options\n", prog);
				return -1;
			}
			if (--argc < 1) goto bad;
			keyfiles[keyfiles_cnt++] = *(++argv);
		} else if (!strcmp(*argv, "-pass")) {
			if (passes_cnt >= sizeof(passes)/sizeof(passes[0])) {
				fprintf(stderr, "%s: too many -pass options\n", prog);
				return -1;
			}
			if (--argc < 1) goto bad;
			passes[passes_cnt++] = *(++argv);
		} else if (!strcmp(*argv, "-cert_request")) {
			cert_request = 1;
		} else if (!strcmp(*argv, "-cacert")) {
			if (--argc < 1) goto bad;
			cacertfile = *(++argv);
		} else if (!strcmp(*argv, "-verify_depth")) {
			if (--argc < 1) goto bad;
			verify_depth = atoi(*(++argv));
			if (verify_depth < 1) {
				fprintf(stderr, "%s: invalid -verify_depth value '%d'\n", prog, verify_depth);
				return -1;
			}
		} else if (!strcmp(*argv, "-new_session_ticket")) {
			if (--argc < 1) goto bad;
			new_session_ticket = atoi(*(++argv));
			if (new_session_ticket < 0) {
				fprintf(stderr, "%s: invalid -new_session_ticket value\n", prog);
				return -1;
			}
		} else if (!strcmp(*argv, "-ticket_key")) {
			if (--argc < 1) goto bad;
			ticket_key = *(++argv);
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
			early_data = 1;
		} else if (!strcmp(*argv, "-max_early_data_size")) {
			if (--argc < 1) goto bad;
			max_early_data_size = atoi(*(++argv));
		} else if (!strcmp(*argv, "-cipher_suite")) {
			char *cipher_suite_name;
			int cipher_suite;
			if (cipher_suites_cnt >= sizeof(cipher_suites)/sizeof(cipher_suites[0])) {
				fprintf(stderr, "%s: too many -cipher_suite options\n", prog);
				return -1;
			}
			if (--argc < 1) goto bad;
			cipher_suite_name = *(++argv);
			if ((cipher_suite = tls_cipher_suite_from_name(cipher_suite_name)) == 0) {
				fprintf(stderr, "%s: -cipher suite value '%s' invalid\n", prog, cipher_suite_name);
				return -1;
			}
			cipher_suites[cipher_suites_cnt] = cipher_suite;
			cipher_suites_cnt++;
		} else if (!strcmp(*argv, "-supported_group")) {
			char *supported_group_name;
			int supported_group;
			if (supported_groups_cnt >= sizeof(supported_groups)/sizeof(supported_groups[0])) {
				fprintf(stderr, "%s: too many -supported_group options\n", prog);
				return -1;
			}
			if (--argc < 1) goto bad;
			supported_group_name = *(++argv);
			if ((supported_group = tls_named_curve_from_name(supported_group_name)) == 0) {
				fprintf(stderr, "%s: -supported_group value '%s' invalid\n", prog, supported_group_name);
				return -1;
			}
			supported_groups[supported_groups_cnt++] = supported_group;
		} else if (!strcmp(*argv, "-sig_alg")) {
			char *sig_alg_name;
			int sig_alg;
			if (sig_algs_cnt >= sizeof(sig_algs)/sizeof(sig_algs[0])) {
				fprintf(stderr, "%s: too many -sig_alg options\n", prog);
				return -1;
			}
			if (--argc < 1) goto bad;
			sig_alg_name = *(++argv);
			if ((sig_alg = tls_signature_scheme_from_name(sig_alg_name)) == 0) {
				fprintf(stderr, "%s: -sig_alg value '%s' invalid\n", prog, sig_alg_name);
				return -1;
			}
			sig_algs[sig_algs_cnt++] = sig_alg;
		} else if (!strcmp(*argv, "-key_update_seq_num")) {
			if (--argc < 1) goto bad;
			key_update_seq_num = atoi(*(++argv));
			if (key_update_seq_num < 0) {
				error_print();
				fprintf(stderr, "%s: invalid -key_update_seq_num value\n", prog);
				return -1;
			}
		} else if (!strcmp(*argv, "-client_cert_optional")) {
			client_cert_optional = 1;
		} else if (!strcmp(*argv, "-tls13_change_cipher_spec")) {
			tls13_change_cipher_spec = 1;
		} else if (!strcmp(*argv, "-verbose")) {
			verbose = 1;
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


	// 不应该放在这里啊
	if (certfiles_cnt != keyfiles_cnt || keyfiles_cnt != passes_cnt) {
		error_print();
		return -1;
	}

	if (!cipher_suites_cnt) {
		error_print();
		goto end;
	}


	if (tls_socket_lib_init() != 1) {
		error_print();
		return -1;
	}

	memset(&ctx, 0, sizeof(ctx));
	memset(&conn, 0, sizeof(conn));




	if (tls_ctx_init(&ctx, TLS_protocol_tls13, TLS_server_mode) != 1) {
		error_print();
		return -1;
	}
	if (verbose && tls_ctx_set_verbose(&ctx, verbose) != 1) {
		error_print();
		goto end;
	}

	if (tls_ctx_set_cipher_suites(&ctx, cipher_suites, cipher_suites_cnt) != 1) {
		fprintf(stderr, "%s: context init error\n", prog);
		goto end;
	}

	// supported_groups
	if (supported_groups_cnt > 0) {
		if (tls_ctx_set_supported_groups(&ctx, supported_groups, supported_groups_cnt) != 1) {
			error_print();
			goto end;
		}
	}

	// signature_algorithms
	if (sig_algs_cnt > 0) {
		if (tls_ctx_set_signature_algorithms(&ctx, sig_algs, sig_algs_cnt) != 1) {
			error_print();
			goto end;
		}
	}

	// Certificate
	for (i = 0; i < certfiles_cnt; i++) {
		if (tls_ctx_add_certificate_chain_and_key(&ctx, certfiles[i], keyfiles[i], passes[i]) != 1) {
			error_print();
			goto end;;
		}
	}

	// CertificateRequest
	if (cert_request) {
		if (!cacertfile) {
			fprintf(stderr, "%s: -cacert required by -cert_request\n", prog);
			goto end;
		}
		if (tls_ctx_set_ca_certificates(&ctx, cacertfile, verify_depth) != 1) {
			error_print();
			goto end;
		}
		if (tls_ctx_enable_certificate_request(&ctx, 1) != 1) {
			error_print();
			goto end;
		}
		if (client_cert_optional) {
			if (tls13_ctx_enable_client_certificate_optional(&ctx, 1) != 1) {
				error_print();
				goto end;
			}
		}
	}

	// psk_key_exchange_modes
	if (psk_ke || psk_dhe_ke) {
		if (tls13_ctx_set_psk_key_exchange_modes(&ctx, psk_ke, psk_dhe_ke) != 1) {
			error_print();
			goto end;
		}
	}

	// NewSessionTicket
	if (new_session_ticket > 0) {
		size_t ticket_key_len;

		if (!ticket_key) {
			fprintf(stderr, "%s: -ticket_key is required by -new_session_ticket\n", prog);
			goto end;
		}

		if (tls13_ctx_enable_new_session_ticket(&ctx, new_session_ticket) != 1) {
			error_print();
			goto end;
		}

		if (strlen(ticket_key) != sizeof(ticket_key_buf) * 2) {
			error_print();
			goto end;
		}
		if (hex_to_bytes(ticket_key, strlen(ticket_key), ticket_key_buf, &ticket_key_len) != 1) {
			error_print();
			goto end;
		}
		if (tls13_ctx_set_session_ticket_key(&ctx, ticket_key_buf, ticket_key_len) != 1) {
			error_print();
			goto end;
		}
		if (tls13_enable_pre_shared_key(&conn, 1) != 1) {
			error_print();
			goto end;
		}
	}

	// early_data
	if (early_data) {
		if (tls13_ctx_enable_early_data(&ctx, 1) != 1) {
			error_print();
			goto end;
		}
		if (max_early_data_size > 0) {
			if (tls13_ctx_set_max_early_data_size(&ctx, max_early_data_size) != 1) {
				error_print();
				goto end;
			}
		}
	}

	// KeyUpdate
	if (key_update_seq_num > 0) {
		if (tls13_ctx_enable_key_update(&ctx, 1) != 1) {
			error_print();
			goto end;
		}
		if (tls13_ctx_set_key_update_seq_num_limit(&ctx, key_update_seq_num) != 1) {
			error_print();
			goto end;
		}
	}

	// ChangeCipherSpec
	if (tls13_change_cipher_spec) {
		if (tls13_ctx_set_change_cipher_spec_compat(&ctx, 1) != 1) {
			error_print();
			goto end;
		}
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

	if (tls_init(&conn, &ctx) != 1) {
		error_print();
		goto end;
	}

	puts("start listen ...\n");
	tls_socket_listen(sock, 1);

	//client_addrlen = sizeof(client_addr);
	if (tls_socket_accept(sock, &client_addr, &conn_sock) != 1) {
		fprintf(stderr, "%s: socket accept error\n", prog);
		goto end;
	}
	puts("socket connected\n");

	if (tls_set_socket(&conn, conn_sock) != 1) {
		error_print();
		goto end;
	}

	if (set_socket_nonblocking(conn_sock) != 1) {
		error_print();
		goto end;
	}


	// pre_shared_key from external
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
				goto end;
			}
			if (tls13_cipher_suite_get(psk_cipher_suite, &psk_cipher, &psk_digest) != 1) {
				error_print();
				goto end;
			}
			if (strlen(psk_keys[i]) != psk_digest->digest_size * 2) {
				error_print();
				goto end;
			}
			if (hex_to_bytes(psk_keys[i], strlen(psk_keys[i]), psk_key, &psk_key_len) != 1) {
				error_print();
				goto end;
			}
			if (tls13_add_pre_shared_key(&conn, (uint8_t *)psk_identities[i], strlen(psk_identities[i]),
				psk_key, psk_key_len, psk_cipher_suite, obfuscated_ticket_age) != 1) {
				error_print();
				goto end;
			}
		}

		tls13_enable_pre_shared_key(&conn, 1);
	}

	if (do_handshake_select(&conn) != 1) {
		error_print();
		goto end;
	}

	if (conn.early_data && conn.early_data_len) {
		format_string(stderr, 0, 0, "EarlyData", conn.early_data_buf, conn.early_data_len);
	}

	size_t send_len = 0;
	size_t send_offset = 0;



	for (;;) {
		fd_set fds_recv;

		fd_set fds_send; // 只有在接收数据之后才需要设置

		size_t sentlen;

		FD_ZERO(&fds_recv);
		FD_ZERO(&fds_send);

		// listen socket
		FD_SET(conn.sock, &fds_recv);

		if (send_len > 0) {
			FD_SET(conn.sock, &fds_send);
		}

		if (select((int)(conn.sock + 1), // In WinSock2, select() ignore the this arg
			&fds_recv, &fds_send, NULL, NULL) < 0) {
			fprintf(stderr, "%s: select failed\n", prog);
			goto end;
		}

		if (send_len > 0 && FD_ISSET(conn.sock, &fds_send)) {
			fprintf(stderr, ">>>>>>>> send back\n");

			format_bytes(stderr, 0, 0, "tls13_send", (const uint8_t *)buf + send_offset, send_len);

			if ((ret = tls_send(&conn, (uint8_t *)buf + send_offset, send_len, &sentlen)) != 1) {
				if (ret == TLS_ERROR_SEND_AGAIN || ret == TLS_ERROR_RECV_AGAIN) {
					continue;
				}
				fprintf(stderr, "%s: send error\n", prog);
				goto end;
			}

			send_offset += sentlen;
			send_len -= sentlen;

			fprintf(stderr, "---------------\n");

			//memset(conn.record, 0, sizeof(conn.record));
			//memset(conn.plain_record, 0, sizeof(conn.plain_record));
		}


		if (FD_ISSET(conn.sock, &fds_recv)) {

			memset(buf, 0, sizeof(buf));

			if ((ret = tls_recv(&conn, (uint8_t *)buf, sizeof(buf), &len)) != 1) {
				if (ret == TLS_ERROR_SEND_AGAIN || ret == TLS_ERROR_RECV_AGAIN) {
					continue;
				} else if (ret == 0) {
					do_shutdown_select(&conn);
					goto end;
				}
				error_print();
				goto end;
			}
			fwrite(buf, 1, len, stdout);
			fflush(stdout);

			send_len = len;
			send_offset = 0;
			/*
			// FIXME: change tls13_recv API			
			if (conn.datalen == 0) {
				break;
			}
			*/
		}


		fprintf(stderr, "\n");
	}



end:
	return ret;
}
