/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/hex.h>
#include <gmssl/tls.h>
#include <gmssl/error.h>

#ifdef _WIN32
#define tls_stdio_fileno(fp) _fileno(fp)
#else
#define tls_stdio_fileno(fp) fileno(fp)
#endif


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

static int do_send_select(TLS_CONNECT *conn, const uint8_t *buf, size_t len)
{
	int ret;
	size_t offset = 0;
	fd_set rfds;
	fd_set wfds;

	while (offset < len) {
		size_t sentlen = 0;

		ret = tls_send(conn, buf + offset, len - offset, &sentlen);
		if (ret == 1) {
			offset += sentlen;
			continue;
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
	return 1;
}

static int do_recv_until_timeout(TLS_CONNECT *conn, char *prog)
{
	char buf[1024];
	size_t len;
	fd_set fds;
	struct timeval timeout;

	for (;;) {
		FD_ZERO(&fds);
		FD_SET(conn->sock, &fds);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		switch (select((int)(conn->sock + 1), &fds, NULL, NULL, &timeout)) {
		case -1:
			fprintf(stderr, "%s: select failed\n", prog);
			return -1;
		case 0:
			do_shutdown_select(conn);
			return 1;
		}

		len = sizeof(buf);
		switch (tls_recv(conn, (uint8_t *)buf, sizeof(buf), &len)) {
		case 1:
			fwrite(buf, 1, len, stdout);
			fflush(stdout);
			break;
		case 0:
			do_shutdown_select(conn);
			return 1;
		case TLS_ERROR_RECV_AGAIN:
		case TLS_ERROR_SEND_AGAIN:
			break;
		default:
			fprintf(stderr, "%s: tls_recv error\n", prog);
			return -1;
		}
	}
}

static int do_send_file_select(TLS_CONNECT *conn, FILE *fp)
{
	uint8_t buf[4096];
	size_t len;

	while ((len = fread(buf, 1, sizeof(buf), fp)) > 0) {
		if (do_send_select(conn, buf, len) != 1) {
			return -1;
		}
	}
	if (ferror(fp)) {
		error_print();
		return -1;
	}
	return 1;
}

static const char *options = "-host str [-port num] [-cacert pem] [-cert pem -key pem -pass str] [-get path|-in file] [-verbose]";

static const char *help =
"Options\n"
"\n"
"    -host str                 Server's hostname\n"
"    -port num                 Server's port number, default 443\n"
"    -cipher_suite str         Supported cipher suites, may appear multiple times, higher priority first\n"
"    -supported_group str      Supported elliptic curves, may appear multiple times, higher priority first\n"
"    -sig_alg str              Supported signature algorithms\n"
"    -max_key_exchanges num    Number of key exchanges in key_share extension\n"
"    -cacert pem               Root CA certificate in PEM format\n"
"    -verify_depth num         Certificate verification depth\n"
"    -cert pem                 Client's certificate chain in PEM format\n"
"    -key pem                  Client's encrypted private key in PEM format\n"
"    -pass str                 Password to decrypt private key\n"
"    -server_name str          Send server_name (SNI) request\n"
"    -signature_algorithms_cert Send signature_algorithms_cert extension\n"
"    -certificate_authorities  Send certificate_authorities extension\n"
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
"    -key_update_seq_num num   Send KeyUpdate handshake after sending/receiving <num> records\n"
"    -post_handshake_auth      Support post_handshake_auth\n"
"    -client_cert_optional     Allow client send empty Certificate\n"
"    -tls13_change_cipher_spec Support ChangeCipherSpec in TLS 1.3 to be compatible with middlebox\n"
"    -get path                 Send a HTTP GET request and read response until close or timeout\n"
"    -in file | stdin          Send input data and read response until close or timeout\n"
"    -verbose                  Print TLS handshake messages\n"
"\n"
#include "tls13_help.h"
"\n";

int tls13_client_main(int argc, char *argv[])
{
	int ret = -1;
	char *prog = argv[0];

	TLS_CTX ctx;
	TLS_CONNECT conn;

	struct hostent *hp;
	struct sockaddr_in server;
	tls_socket_t sock = tls_socket_invalid();
	char buf[1024] = {0};
	size_t len = sizeof(buf);
	char send_buf[1024] = {0};
	size_t sent_len = 0;
	size_t sent_offset = 0;

	char *host = NULL;
	int port = 443;

	// cipher_suites
	int cipher_suites[4];
	size_t cipher_suites_cnt = 0;

	// CA certificates
	char *cacertfile = NULL;
	int verify_depth = TLS_DEFAULT_VERIFY_DEPTH;

	// CertificateRequest
	char *certfile = NULL;
	char *keyfile = NULL;
	char *pass = NULL;
	int client_cert_optional = 0;

	// supported_groups
	int supported_groups[4];
	size_t supported_groups_cnt = 0;

	// key_share
	char  *max_key_exchanges = NULL;
	int max_key_exchanges_cnt;

	// signature_algorithms
	int sig_algs[4];
	size_t sig_algs_cnt = 0;

	// server_name
	char *server_name = NULL;

	// certificate_authorities
	int certificate_authorities = 0;

	// signature_algorithms_cert
	int signature_algorithms_cert = 0;

	// status_request
	int status_request = 0;

	// signed_certificate_timestamp
	int signed_certificate_timestamp = 0;

	// post_handshake_auth
	int post_handshake_auth = 0;

	// NewSessionTicket
	char *sess_out = NULL;

	// psk_key_exchange_modes
	int psk_ke = 0;
	int psk_dhe_ke = 0;

	// pre_shared_key from NewSessionTicket
	char *sess_in = NULL;

	// pre_shared_key from external
	char *psk_identities[16];
	size_t psk_identities_cnt = 0;
	int psk_cipher_suites[16];
	size_t psk_cipher_suites_cnt = 0;
	char *psk_keys[16];
	size_t psk_keys_cnt = 0;

	// EarlyData
	char *early_data_file = NULL;
	FILE *early_data_fp = NULL;
	int max_early_data_size = 0;

	// KeyUpdate
	int key_update_seq_num = 0;

	// ChangeCipherSpec
	int tls13_change_cipher_spec = 0;
	int verbose = 0;
	char *get = NULL;
	char *infile = NULL;

	int send_again = 0;


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
				fprintf(stderr, "%s: invalid -cipher_suite '%s' value\n", prog, cipher_suite_name);
				return -1;
			}
			cipher_suites[cipher_suites_cnt] = cipher_suite;
			cipher_suites_cnt++;
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
			if (--argc < 1) goto bad;
			server_name = *(++argv);
		} else if (!strcmp(*argv, "-signature_algorithms_cert")) {
			signature_algorithms_cert = 1;
		} else if (!strcmp(*argv, "-certificate_authorities")) {
			certificate_authorities = 1;
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
			if (psk_identities_cnt >= sizeof(psk_identities)/sizeof(psk_identities[0])) {
				fprintf(stderr, "%s: too many -psk_identity options\n", prog);
				return -1;
			}
			if (--argc < 1) goto bad;
			psk_identities[psk_identities_cnt++] = *(++argv);
		} else if (!strcmp(*argv, "-psk_cipher_suite")) {
			char *cipher_suite_name;
			int cipher_suite;
			if (psk_cipher_suites_cnt >= sizeof(psk_cipher_suites)/sizeof(psk_cipher_suites[0])) {
				fprintf(stderr, "%s: too many -psk_cipher_suite options\n", prog);
				return -1;
			}
			if (--argc < 1) goto bad;
			cipher_suite_name = *(++argv);
			if ((cipher_suite = tls_cipher_suite_from_name(cipher_suite_name)) == 0) {
				fprintf(stderr, "%s: -psk_cipher_suite '%s' not supported\n", prog, cipher_suite_name);
				return -1;
			}
			psk_cipher_suites[psk_cipher_suites_cnt++] = cipher_suite;
		} else if (!strcmp(*argv, "-psk_key")) {
			char *psk_key_hex;
			if (psk_keys_cnt >= sizeof(psk_keys)/sizeof(psk_keys[0])) {
				fprintf(stderr, "%s: too many -psk_key options\n", prog);
				return -1;
			}
			if (--argc < 1) goto bad;
			psk_key_hex = *(++argv);
			if (strlen(psk_key_hex) != 64) {
				fprintf(stderr, "%s: invalid -psk_key '%s' length\n", prog, psk_key_hex);
				return -1;
			}
			psk_keys[psk_keys_cnt++] = psk_key_hex;
		} else if (!strcmp(*argv, "-early_data")) {
			if (--argc < 1) goto bad;
			early_data_file = *(++argv);
		} else if (!strcmp(*argv, "-max_early_data_size")) {
			if (--argc < 1) goto bad;
			max_early_data_size = atoi(*(++argv));
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
				fprintf(stderr, "%s: -supported_group '%s' not supported\n", prog, supported_group_name);
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
				fprintf(stderr, "%s: -sig_alg '%s' not supported\n", prog, sig_alg_name);
				return -1;
			}
			sig_algs[sig_algs_cnt++] = sig_alg;
		} else if (!strcmp(*argv, "-max_key_exchanges")) {
			if (--argc < 1) goto bad;
			max_key_exchanges = *(++argv);
			max_key_exchanges_cnt = atoi(max_key_exchanges);
			if (max_key_exchanges_cnt < 0) {
				fprintf(stderr, "%s: -max_key_exchanges value '%s' invalid\n", prog, max_key_exchanges);
				return -1;
			}
		} else if (!strcmp(*argv, "-key_update_seq_num")) {
			if (--argc < 1) goto bad;
			key_update_seq_num = atoi(*(++argv));
			if (key_update_seq_num < 0) {
				fprintf(stderr, "%s: invalid -key_update_seq_num value\n", prog);
				return -1;
			}
		} else if (!strcmp(*argv, "-client_cert_optional")) {
			client_cert_optional = 1;
		} else if (!strcmp(*argv, "-tls13_change_cipher_spec")) {
			tls13_change_cipher_spec = 1;
		} else if (!strcmp(*argv, "-get")) {
			if (--argc < 1) goto bad;
			get = *(++argv);
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
		} else if (!strcmp(*argv, "-verbose")) {
			verbose = 5;
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

	if (!host) {
		fprintf(stderr, "%s: '-host' option required\n", prog);
		return -1;
	}

	if (!cipher_suites_cnt) {
		fprintf(stderr, "%s: option '-cipher_suite' required\n", prog);
		return -1;
	}
	if (get && infile) {
		fprintf(stderr, "%s: '-get' and '-in' should not be used together\n", prog);
		return -1;
	}

	// TLS_CTX

	if (tls_ctx_init(&ctx, TLS_protocol_tls13, TLS_client_mode) != 1) {
		error_print();
		return -1;
	}
	if (verbose && tls_ctx_set_verbose(&ctx, verbose) != 1) {
		error_print();
		goto end;
	}

	// cipher_suites
	if (tls_ctx_set_cipher_suites(&ctx, cipher_suites, cipher_suites_cnt) != 1) {
		error_print();
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

	// key_share
	if (max_key_exchanges) {
		if (tls13_ctx_set_max_key_exchanges(&ctx, max_key_exchanges_cnt) != 1) {
			error_print();
			goto end;
		}
	}

	// CA certificates
	if (cacertfile) {
		if (tls_ctx_set_ca_certificates(&ctx, cacertfile, verify_depth) != 1) {
			fprintf(stderr, "%s: failed to load certificate '%s'\n", prog, cacertfile);
			goto end;
		}
	}

	// CertificateRequest
	if (certfile) {
		if (!keyfile) {
			fprintf(stderr, "%s: option -key is required\n", prog);
			goto end;
		}
		if (!pass) {
			fprintf(stderr, "%s: option -pass is requried\n", prog);
			goto end;
		}
		if (tls_ctx_add_certificate_chain_and_key(&ctx, certfile, keyfile, pass) != 1) {
			fprintf(stderr, "%s: load certificate chain and key failed\n", prog);
			goto end;
		}
	}

	// psk_key_exchange_modes
	if (psk_ke || psk_dhe_ke) {
		// allow ClientHello with psk_key_exchange_modes, but no pre_shared_key
		if (tls13_ctx_set_psk_key_exchange_modes(&ctx, psk_ke, psk_dhe_ke) != 1) {
			error_print();
			goto end;
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

	// CertificateRequest
	if (client_cert_optional) {
		if (tls13_ctx_enable_client_certificate_optional(&ctx, 1) != 1) {
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


	// TLS_CONNECT

	if (tls_init(&conn, &ctx) != 1) {
		error_print();
		goto end;
	}

	if (signature_algorithms_cert) {
		if (tls_enable_signature_algorithms_cert(&conn, 1) != 1) {
			error_print();
			goto end;
		}
	}

	if (certificate_authorities) {
		if (tls13_enable_certificate_authorities(&conn, 1) != 1) {
			error_print();
			goto end;
		}
	}

	if (server_name) {
		if (tls_set_server_name(&conn, (uint8_t *)server_name, strlen(server_name)) != 1) {
			error_print();
			goto end;
		}
	}

	if (status_request) {
		if (tls13_set_client_status_request(&conn, NULL, 0, NULL, 0) != 1) {
			error_print();
			goto end;
		}
	}

	if (signed_certificate_timestamp) {
		if (tls_enable_signed_certificate_timestamp(&conn, 1) != 1) {
			error_print();
			goto end;
		}
	}

	if (post_handshake_auth) {
	}

	// NewSessionTicket
	if (sess_out) {
		if (tls13_set_session_outfile(&conn, sess_out) != 1) {
			error_print();
			goto end;
		}
	}

	// pre_shared_key from external
	if (psk_keys_cnt) {
		const uint32_t obfuscated_ticket_age = 0;
		size_t i;

		if (psk_identities_cnt != psk_keys_cnt || psk_cipher_suites_cnt != psk_keys_cnt) {
			error_print();
			goto end;
		}
		for (i = 0; i < psk_keys_cnt; i++) {
			const BLOCK_CIPHER *psk_cipher;
			const DIGEST *psk_digest;
			uint8_t psk_key[64];
			size_t psk_key_len;

			if (tls_cipher_suite_get(psk_cipher_suites[i], &psk_cipher, &psk_digest) != 1) {
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
				psk_key, psk_key_len, psk_cipher_suites[i], obfuscated_ticket_age) != 1) {
				error_print();
				goto end;
			}
		}

		tls13_enable_pre_shared_key(&conn, 1);

	// pre_shared_key from NewSessionTicket
	} else if (sess_in) {
		FILE *sess_infp;

		if (!psk_dhe_ke && !psk_ke) {
			fprintf(stderr, "%s: option '-psk_dhe_ke' or '-psk_ke' required\n", prog);
			goto end;
		}

		if (!(sess_infp = fopen(sess_in, "rb"))) {
			fprintf(stderr, "%s: open file '%s' failure\n", prog, sess_in);
			goto end;
		}

		do {
			if ((ret = tls13_add_pre_shared_key_from_session_file(&conn, sess_infp)) < 0) {
				fclose(sess_infp);
				fprintf(stderr, "%s: load session file '%s' failure\n", prog, sess_in);
				goto end;
			}
		} while (ret);

		fclose(sess_infp);

		if (tls13_enable_pre_shared_key(&conn, 1) != 1) {
			error_print();
			goto end;
		}
	}

	// EarlyData
	if (early_data_file) {
		uint8_t early_data[8192];
		size_t early_data_len;

		if (!psk_keys_cnt && !sess_in) {
			fprintf(stderr, "%s: -psk_key or -sess_in required by -early_data\n", prog);
			goto end;
		}

		if (!(early_data_fp = fopen(early_data_file, "rb"))) {
			fprintf(stderr, "%s: open file '%s' failure\n", prog, early_data_file);
			goto end;
		}

		if (!(early_data_len = fread(early_data, 1, sizeof(early_data), early_data_fp))) {
			if (feof(early_data_fp)) {
				fprintf(stderr, "%s: empty file '%s'\n", prog, early_data_file);
			} else {
				fprintf(stderr, "%s: read file '%s' failure\n", prog, early_data_file);
				fclose(early_data_fp);
				goto end;
			}
		}
		fclose(early_data_fp);

		if (early_data_len) {
			if (tls13_set_early_data(&conn, early_data, early_data_len) != 1) {
				error_print();
				goto end;
			}
		}
	}


	// socket

	if (tls_socket_lib_init() != 1) {
		error_print();
		goto end;
	}

	if (!(hp = gethostbyname(host))) {
#ifdef WIN32
		fprintf(stderr, "%s: parse -host value error: %d\n", prog, WSAGetLastError());
#else
		fprintf(stderr, "%s: parse -host value error: %s\n", prog, hstrerror(h_errno));
#endif
		goto end;
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

	if (tls_set_socket(&conn, sock) != 1) {
		error_print();
		goto end;
	}

	if (tls_socket_set_nonblocking(sock, 1) != 1) {
		error_print();
		goto end;
	}

	if (do_handshake_select(&conn) != 1) {
		fprintf(stderr, "%s: error\n", prog);
		goto end;
	}

	tls_connect_print(stderr, 0, 0, NULL, &conn);
	fprintf(stderr, "\n");

	if (get) {
		snprintf(buf, sizeof(buf), "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", get, host);
		if (do_send_select(&conn, (uint8_t *)buf, strlen(buf)) != 1) {
			fprintf(stderr, "%s: send error\n", prog);
			goto end;
		}
		if (do_recv_until_timeout(&conn, prog) != 1) {
			goto end;
		}
		ret = 0;
		goto end;
	}

	if (infile) {
		FILE *infp = stdin;
		if (strcmp(infile, "-") && strcmp(infile, "stdin")) {
			if (!(infp = fopen(infile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure\n", prog, infile);
				goto end;
			}
		}
		if (do_send_file_select(&conn, infp) != 1) {
			if (infp != stdin) fclose(infp);
			fprintf(stderr, "%s: send error\n", prog);
			goto end;
		}
		if (infp != stdin) fclose(infp);
		if (do_recv_until_timeout(&conn, prog) != 1) {
			goto end;
		}
		ret = 0;
		goto end;
	}

	for (;;) {

		fd_set fds_send;
		fd_set fds_recv;

		size_t sentlen;

		FD_ZERO(&fds_send);
		FD_ZERO(&fds_recv);


		// listen socket
		FD_SET(conn.sock, &fds_recv);

		// listen stdin
		FD_SET(tls_stdio_fileno(stdin), &fds_recv);


		if (sent_len > 0) {
			FD_SET(conn.sock, &fds_send);
		}

		// 等待阻塞
		if (select((int)(conn.sock + 1), // In WinSock2, select() ignore the this arg
			&fds_recv, &fds_send, NULL, NULL) < 0) {
			fprintf(stderr, "%s: select failed\n", prog);
			goto end;
		}

		// 读socket
		if (FD_ISSET(conn.sock, &fds_recv)) {

			memset(buf, 0, sizeof(buf));
			if ((ret = tls_recv(&conn, (uint8_t *)buf, sizeof(buf), &len)) != 1) {
				if (ret == TLS_ERROR_SEND_AGAIN || ret == TLS_ERROR_RECV_AGAIN) {
					continue;
				} else if (ret == 0) {
					do_shutdown_select(&conn);
					ret = 0;
					goto end;
				} else {
					error_print();
					goto end;
				}
			}
			fwrite(buf, 1, len, stdout);
			fflush(stdout);


		}

		if (FD_ISSET(tls_stdio_fileno(stdin), &fds_recv)) {

			memset(send_buf, 0, sizeof(send_buf));

			if (!fgets(send_buf, sizeof(send_buf), stdin)) {
				if (feof(stdin)) {
					fprintf(stderr, "client shutdown\n");
					do_shutdown_select(&conn);
					ret = 0;
					goto end;
				} else {
					continue;
				}
			}
			sent_len = strlen(send_buf);
			sent_offset = 0;

		}

		if (sent_len > 0 && FD_ISSET(conn.sock, &fds_send)) {

			// tls13_send 会返回一个 -1 , 但是没有打印错误信息！！！！			
			if ((ret = tls_send(&conn, (uint8_t *)send_buf + sent_offset, sent_len, &sentlen)) != 1) {
				if (ret == TLS_ERROR_SEND_AGAIN || ret == TLS_ERROR_RECV_AGAIN) {
					continue;
				} else {
					fprintf(stderr, "ret = %d\n", ret);
					fprintf(stderr, "%s: send error\n", prog);
					goto end;
				}
			}

			sent_offset += sentlen;
			sent_len -= sentlen;
		}

		fprintf(stderr, "\n");

	}

end:
	if (tls_socket_is_valid(sock)) tls_socket_close(sock);
	tls_ctx_cleanup(&ctx);
	tls_cleanup(&conn);
	return 0;
}
