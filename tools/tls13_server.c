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


/*
如果采用PSK模式并且是外部密钥，那么意味着每个预置密钥关联一个cipher_suite
那么ClientHello中的cipher_suites应该是这些套件的集合
但是ClientHello也可能支持PSK之外的套件，因此最终是常规cipher_suite + psk_cipher_suite的合集


我们需要多组证书，也就是   -cert -key -pass 构成一组，我们可以用一个数组把这些放到一起



*/


static const char *options = "[-port num] -cert file -key file -pass str [-cacert file]";

static const char *help =
"Options\n"
"\n"
"    -port num                 Listening port number, default 443\n"
"    -cipher_suite str         Client's cipher suites, may appear multiple times, higher priority first\n"
"    -supported_group str      Supported elliptic curves, may appear multiple times, higher priority first\n"
"    -sig_alg str              Supported signature algorithms\n"
"    -cert file                Server's certificate chain in PEM format\n"
"    -key file                 Server's encrypted private key in PEM format\n"
"    -pass str                 Password to decrypt private key\n"
"    -cacert file              CA certificate for client certificate verification\n"
"    -new_session_ticket num   Send NewSessionTicket <num> times\n"
"    -ticket_key hex           Session ticket encrypt/decrypt key in HEX format\n"
"    -psk_ke                   Support PSK-only key exchange\n"
"    -psk_dhe_ke               Support PSK with (EC)DHE key exchange\n"
"    -psk_identity str         PSK Identity\n"
"    -psk_cipher_suite str     PSK cipher suite\n"
"    -psk_key hex              PSK key in HEX format, of PSK hash length\n"
"    -early_data               Accept EarlyData, support 0-RTT\n"
"    -max_early_data_size num  Set extension max_early_data_size\n"
"\n"
"    -cipher_suite options\n"
"      TLS_SM4_GCM_SM3         TLS 1.3\n"
"      TLS_AES_128_GCM_SHA256  TLS 1.3\n"
"      TLS_ECC_SM4_CBC_SM3     TLCP\n"
"      TLS_ECDHE_SM4_CBC_SM3   TLCP TLS 1.2\n"
"      TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 TLS 1.2\n"
"\n"
"    -supported_group options\n"
"      sm2p256v1\n"
"      prime256v1\n"
"\n"
"    -sig_alg options\n"
"      sm2sig_sm3\n"
"      ecdsa_secp256r1_sha256\n"
"\n"
"Examples\n"
"\n"
"    gmssl sm2keygen -pass 1234 -out sm2rootcakey.pem\n"
"    gmssl certgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN ROOTCA -days 3650 \\\n"
"            -key sm2rootcakey.pem -pass 1234 -out sm2rootcacert.pem \\\n"
"            -key_usage keyCertSign -key_usage cRLSign -ca\n"
"\n"
"    gmssl sm2keygen -pass 1234 -out sm2cakey.pem\n"
"    gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN \"Sub CA\" \\\n"
"            -key sm2cakey.pem -pass 1234 -out sm2careq.pem\n"
"    gmssl reqsign -in sm2careq.pem -days 365 -key_usage keyCertSign -cacert rootcacert.pem -key rootcakey.pem -pass 1234 \\\n"
"            -out sm2cacert.pem -ca -path_len_constraint 0\n"
"\n"
"    gmssl sm2keygen -pass 1234 -out sm2signkey.pem\n"
"    gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost -key sm2signkey.pem -pass 1234 -out sm2signreq.pem\n"
"    gmssl reqsign -in sm2signreq.pem -days 365 -key_usage digitalSignature -cacert sm2cacert.pem -key sm2cakey.pem -pass 1234 -out sm2signcert.pem\n"
"\n"
"    cat sm2signcert.pem > sm2certs.pem\n"
"    cat sm2cacert.pem >> sm2certs.pem\n"
"\n"
"    sudo gmssl tls13_server -port 4430 -cert sm2certs.pem -key sm2signkey.pem -pass 1234 -cipher_suite TLS_SM4_GCM_SM3 -supported_group sm2p256v1 -sig_alg sm2sig_sm3\n"
"    gmssl tls13_client -host 127.0.0.1 -port 4430 -cacert sm2rootcacert.pem -cipher_suite TLS_SM4_GCM_SM3 -supported_group sm2p256v1 -sig_alg sm2sig_sm3\n"
"\n"
"\n"
"    sudo gmssl tls13_server -port 4430 -cert sm2certs.pem -key sm2signkey.pem -pass 1234 \\\n"
"       -cipher_suite TLS_SM4_GCM_SM3 -cipher_suite TLS_AES_128_GCM_SHA256 \\\n"
"       -supported_group sm2p256v1 -supported_group prime256v1 \\\n"
"       -sig_alg sm2sig_sm3 -sig_alg ecdsa_secp256r1_sha256\n"
"\n"
"    gmssl tls13_client -host 127.0.0.1 -port 4430 -cacert sm2rootcacert.pem \\\n"
"       -cipher_suite TLS_SM4_GCM_SM3 -cipher_suite TLS_AES_128_GCM_SHA256 \\\n"
"       -supported_group sm2p256v1 -supported_group prime256v1 \\\n"
"       -sig_alg sm2sig_sm3 -sig_alg ecdsa_secp256r1_sha256 \\\n"
"       -max_key_exchanges 2 \\\n"
"       -server_name \\\n"
"       -signature_algorithms_cert \\\n"
"       -status_request \\\n"
"       -post_handshake_auth \\\n"
"       -ct\n"
"\n"
"\n"
"    TICKET_KEY=11223344556677881122334455667788\n"
"    sudo gmssl tls13_server -port 4430 -cert sm2certs.pem -key sm2signkey.pem -pass 1234 \\\n"
"       -cipher_suite TLS_SM4_GCM_SM3 -supported_group sm2p256v1 -sig_alg sm2sig_sm3 \\\n"
"       -new_session_ticket 2 -ticket_key $TICKET_KEY\n"
"\n"
"    gmssl tls13_client -host 127.0.0.1 -port 4430 -cacert sm2rootcacert.pem \\\n"
"       -cipher_suite TLS_SM4_GCM_SM3 -supported_group sm2p256v1 -sig_alg sm2sig_sm3 \\\n"
"       -sess_out session.bin\n"
"\n"
"    sudo gmssl tls13_server -port 4430 -cert sm2certs.pem -key sm2signkey.pem -pass 1234 \\\n"
"       -cipher_suite TLS_SM4_GCM_SM3 -supported_group sm2p256v1 \\\n"
"       -psk_dhe_ke -ticket_key $TICKET_KEY\n"
"\n"
"    gmssl tls13_client -host 127.0.0.1 -port 4430 \\\n"
"       -cipher_suite TLS_SM4_GCM_SM3 -supported_group sm2p256v1 \\\n"
"       -psk_dhe_ke -sess_in session.bin\n"
"\n"
"\n"
"    PSK=1122334455667788112233445566778811223344556677881122334455667788\n"
"    sudo gmssl tls13_server -port 4430 -cipher_suite TLS_SM4_GCM_SM3 \\\n"
"       -psk_ke -psk_identity 001 -psk_cipher_suite TLS_SM4_GCM_SM3 -psk_key $PSK\n"
"    gmssl tls13_client -host 127.0.0.1 -port 4430 -cipher_suite TLS_SM4_GCM_SM3 \\\n"
"       -psk_ke -psk_identity 001 -psk_cipher_suite TLS_SM4_GCM_SM3 -psk_key $PSK\n"
"\n"
"\n";

int tls13_server_main(int argc , char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	int port = 443;
	char *certfile = NULL;
	char *keyfile = NULL;
	char *pass = NULL;


	char *certfiles[4];
	char *keyfiles[sizeof(certfiles)/sizeof(certfiles[0])];
	char *passes[sizeof(certfiles)/sizeof(certfiles[0])];
	size_t certfiles_cnt = 0;
	size_t keyfiles_cnt = 0;
	size_t passes_cnt = 0;



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

	int psk_ke = 0;
	int psk_dhe_ke = 0;


	// external psk
	char *psk_identities[16];
	size_t psk_identities_cnt = 0;
	char *psk_cipher_suites[16];
	size_t psk_cipher_suites_cnt = 0;
	char *psk_keys[16];
	size_t psk_keys_cnt = 0;


	int early_data = 0;
	int max_early_data_size = 0;

	char *cipher_suite_name;
	int cipher_suite;
	int cipher_suites[4];
	size_t cipher_suites_cnt = 0;

	char *supported_group_name;
	int supported_group;
	int supported_groups[4];
	size_t supported_groups_cnt = 0;

	char *sig_alg_name;
	int sig_alg;
	int sig_algs[4];
	size_t sig_algs_cnt = 0;

	size_t i;


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

			if (certfiles_cnt >= sizeof(certfiles)/sizeof(certfiles[0])) {
				error_print();
				return -1;
			}
			certfiles[certfiles_cnt++] = certfile;

		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);

			if (keyfiles_cnt >= sizeof(keyfiles)/sizeof(keyfiles[0])) {
				error_print();
				return -1;
			}
			keyfiles[keyfiles_cnt++] = keyfile;

		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);

			if (passes_cnt >= sizeof(passes)/sizeof(passes[0])) {
				error_print();
				return -1;
			}
			passes[passes_cnt++] = pass;

		} else if (!strcmp(*argv, "-cacert")) {
			if (--argc < 1) goto bad;
			cacertfile = *(++argv);
		} else if (!strcmp(*argv, "-new_session_ticket")) {
			if (--argc < 1) goto bad;
			new_session_ticket = atoi(*(++argv));
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
			if (--argc < 1) goto bad;
			cipher_suite_name = *(++argv);
			if ((cipher_suite = tls_cipher_suite_from_name(cipher_suite_name)) == 0) {
				error_print();
				fprintf(stderr, "%s: cipher suite '%s' not supported\n", prog, cipher_suite_name);
				return -1;
			}
			if (cipher_suites_cnt >= sizeof(cipher_suites)/sizeof(cipher_suites[0])) {
				error_print();
				fprintf(stderr, "%s: too much cipher suites\n", prog);
				return -1;
			}
			cipher_suites[cipher_suites_cnt] = cipher_suite;
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

	if (certfiles_cnt != keyfiles_cnt || keyfiles_cnt != passes_cnt) {
		error_print();
		return -1;
	}

	/*
	if (!cipher_suites_cnt) {
		error_print();
		goto end;
	}
	*/

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

	if (tls_ctx_set_cipher_suites(&ctx, cipher_suites, cipher_suites_cnt) != 1) {
		fprintf(stderr, "%s: context init error\n", prog);
		goto end;
	}

	for (i = 0; i < certfiles_cnt; i++) {

		fprintf(stderr, "add_certificate_chain_and_key\n");
		if (tls_ctx_add_certificate_chain_and_key(&ctx, certfiles[i], keyfiles[i], passes[i]) != 1) {
			error_print();
			return -1;
		}
	}

	/*
	if (certfile) {
		if (!keyfile) {
			fprintf(stderr, "%s: '-key' option required\n", prog);
			return 1;
		}
		if (!pass) {
			fprintf(stderr, "%s: '-pass' option required\n", prog);
			return 1;
		}
		if (tls_ctx_add_certificate_chain_and_key(&ctx, certfile, keyfile, pass) != 1) {
			error_print();
			return -1;
		}
	}
	*/

	if (supported_groups_cnt > 0) {
		if (tls_ctx_set_supported_groups(&ctx, supported_groups, supported_groups_cnt) != 1) {
			error_print();
			return -1;
		}
	}

	if (sig_algs_cnt > 0) {
		if (tls_ctx_set_signature_algorithms(&ctx, sig_algs, sig_algs_cnt) != 1) {
			error_print();
			return -1;
		}
	}

	if (cacertfile) {
		if (tls_ctx_set_ca_certificates(&ctx, cacertfile, TLS_DEFAULT_VERIFY_DEPTH) != 1) {
			error_print();
			return -1;
		}
	}

	if (psk_ke || psk_dhe_ke) {
		if (tls13_ctx_set_psk_key_exchange_modes(&ctx, psk_ke, psk_dhe_ke) != 1) {
			error_print();
			return -1;
		}
	}

	if (new_session_ticket < 0) {
		fprintf(stderr, "%s: '-ticket_key' is required by '-new_session_ticket'\n", prog);
		return -1;
	}
	if (new_session_ticket > 0) {
		if (!ticket_key) {
			error_print();

			return -1;
		}
		if (tls13_ctx_enable_new_session_ticket(&ctx, new_session_ticket) != 1) {
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
	}

	if (early_data) {
		ctx.early_data = 1;
	}


	if (max_early_data_size > 0) {
		if (tls13_ctx_set_max_early_data_size(&ctx, max_early_data_size) != 1) {
			error_print();
			return -1;
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

	if (tls13_init(&conn, &ctx) != 1) {
		error_print();
		return -1;
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

	if (tls_set_socket(&conn, conn_sock) != 1) {
		error_print();
		return -1;
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

	if (tls_do_handshake(&conn) != 1) {
		error_print();
		return -1;
	}


	for (;;) {

		fd_set fds;
		size_t sentlen;

		FD_ZERO(&fds);

		// listen socket
		FD_SET(conn.sock, &fds);

		// 等待阻塞
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

			fprintf(stderr, ">>>>>>>> send back\n");

			if (tls13_send(&conn, (uint8_t *)buf, len, &sentlen) != 1) {
				fprintf(stderr, "%s: send error\n", prog);
				goto end;
			}
		}
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
