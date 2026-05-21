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


// 服务器在启动时是否检查密码参数和证书适配的问题
// 服务器设置 -psk_dhe_ke，启动的时候没有检查是否提供了 supported_group 参数
// psk_cipher_suite 和 cipher_suite 是冗余的


// 重新思考一下，各个层次如何将各自的输入输出打印出来，特别是在record层
// 每个报文包括密文和明文，应该将两者紧密连在一起，没有空格
// 在报文层，只显示明文的16进制，但是在上层，应该显示明文的ASCII和HEX，能够看清楚消息


// 为了保证能够和openssl互通，需要将PKCS8的私钥导出为openssl可以识别的格式。
// 或者P256的私钥应该用AES-128 + SHA-256加密


// 应该首先打印openssl的密钥序列，early_secret, pre_master_secret, 以及 handshake_secret 等


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
"    -new_session_ticket num   Send NewSessionTicket <num> times\n"
"    -ticket_key hex           Session ticket encrypt/decrypt key in HEX format\n"
"    -psk_ke                   Support PSK-only key exchange\n"
"    -psk_dhe_ke               Support PSK with (EC)DHE key exchange\n"
"    -psk_identity str         PSK Identity\n"
"    -psk_cipher_suite str     PSK cipher suite\n"
"    -psk_key hex              PSK key in HEX format, of PSK hash length\n"
"    -early_data               Accept EarlyData, support 0-RTT\n"
"    -max_early_data_size num  Set extension max_early_data_size\n"
"    -cert_request             Client certificate request\n"
"    -cacert file              CA certificate for client certificate verification\n"
"    -key_update_seq_num num   Send KeyUpdate handshake after sending/receiving <num> records\n"
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
"Generate SM2 certificates\n"
"\n"
"    gmssl sm2keygen -pass 1234 -out sm2rootcakey.pem\n"
"    gmssl certgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN ROOTCA -days 3650 \\\n"
"            -key sm2rootcakey.pem -pass 1234 -out sm2rootcacert.pem \\\n"
"            -key_usage keyCertSign -key_usage cRLSign -ca\n"
"\n"
"    gmssl sm2keygen -pass 1234 -out sm2cakey.pem\n"
"    gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN \"Sub CA\" \\\n"
"            -key sm2cakey.pem -pass 1234 -out sm2careq.pem\n"
"    gmssl reqsign -in sm2careq.pem -days 365 -key_usage keyCertSign \\\n"
"            -cacert sm2rootcacert.pem -key sm2rootcakey.pem -pass 1234 \\\n"
"            -ca -path_len_constraint 0 \\\n"
"            -out sm2cacert.pem\n"
"\n"
"    gmssl sm2keygen -pass 1234 -out sm2signkey.pem\n"
"    gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost \\\n"
"           -key sm2signkey.pem -pass 1234 -out sm2signreq.pem\n"
"    gmssl reqsign -in sm2signreq.pem -days 365 -key_usage digitalSignature \\\n"
"           -cacert sm2cacert.pem -key sm2cakey.pem -pass 1234 \\\n"
"           -out sm2signcert.pem\n"
"\n"
"    cat sm2signcert.pem > sm2certs.pem\n"
"    cat sm2cacert.pem >> sm2certs.pem\n"
"\n"
"TLS 1.3 with TLS_SM4_GCM_SM3 cipher suite\n"
"\n"
"    sudo gmssl tls13_server -port 4430 -cert sm2certs.pem -key sm2signkey.pem -pass 1234 \\\n"
"       -cipher_suite TLS_SM4_GCM_SM3 -supported_group sm2p256v1 -sig_alg sm2sig_sm3\n"
"\n"
"    gmssl tls13_client -host 127.0.0.1 -port 4430 -cacert sm2rootcacert.pem \\\n"
"       -cipher_suite TLS_SM4_GCM_SM3 -supported_group sm2p256v1 -sig_alg sm2sig_sm3\n"
"\n"
"Generate P-256 certificates\n"
"\n"
"    gmssl p256keygen -pass 1234 -out p256rootcakey.pem -export p256rootcakey.exp\n"
"    gmssl certgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN P256ROOTCA -days 3650 \\\n"
"            -key p256rootcakey.pem -pass 1234 -out p256rootcacert.pem \\\n"
"            -key_usage keyCertSign -key_usage cRLSign -ca\n"
"\n"
"    gmssl p256keygen -pass 1234 -out p256cakey.pem -export p256cakey.exp\n"
"    gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN \"P256 Sub CA\" \\\n"
"            -key p256cakey.pem -pass 1234 -out p256careq.pem\n"
"    gmssl reqsign -in p256careq.pem -days 365 -key_usage keyCertSign \\\n"
"            -cacert p256rootcacert.pem -key p256rootcakey.pem -pass 1234 \\\n"
"            -ca -path_len_constraint 0 \\\n"
"            -out p256cacert.pem\n"
"\n"
"    gmssl p256keygen -pass 1234 -out p256signkey.pem -export p256signkey.exp\n"
"    gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN 127.0.0.1 \\\n"
"           -key p256signkey.pem -pass 1234 -out p256signreq.pem\n"
"    gmssl reqsign -in p256signreq.pem -days 365 -key_usage digitalSignature \\\n"
"           -cacert p256cacert.pem -key p256cakey.pem -pass 1234 \\\n"
"           -subject_dns_name 127.0.0.1 \\\n"
"           -out p256signcert.pem\n"
"\n"
"    cat p256signcert.pem > p256certs.pem\n"
"    cat p256cacert.pem >> p256certs.pem\n"
"\n"
"    cat sm2rootcacert.pem > rootcacerts.pem\n"
"    cat p256rootcacert.pem >> rootcacerts.pem\n"
"\n"
"TLS 1.3 with TLS_AES_128_GCM_SHA256\n"
"    sudo gmssl tls13_server -port 4430 \\\n"
"       -cipher_suite TLS_AES_128_GCM_SHA256 -supported_group prime256v1 -sig_alg ecdsa_secp256r1_sha256 \\\n"
"       -cert p256certs.pem -key p256signkey.pem -pass 1234\n"
"\n"
"    gmssl tls13_client -host 127.0.0.1 -port 4430 -cacert rootcacerts.pem \\\n"
"       -cipher_suite TLS_AES_128_GCM_SHA256 -supported_group prime256v1 -sig_alg ecdsa_secp256r1_sha256\n"
"\n"
"    add `SSL_CTX_clear_options(ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);` to openssl apps/s_server.c\n"
"    add `SSL_CTX_clear_options(ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);` to openssl apps/s_client.c\n"
"\n"
"    /usr/local/bin/openssl s_server -accept 4430 -cert p256signcert.pem -cert_chain p256cacert.pem -key p256signkey.exp \\\n"
"       -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -named_curve prime256v1 \\\n"
"       -trace -keylogfile sslkeys.log\n"
"\n"
"    /usr/local/bin/openssl s_client -connect 127.0.0.1:4430 -tls1_3 -CAfile p256rootcacert.pem -groups prime256v1 -trace\n"
"\n"
"TLS 1.3 SNI\n"
"\n"
"    sudo gmssl tls13_server -port 4430 \\\n"
"       -cipher_suite TLS_SM4_GCM_SM3 -supported_group sm2p256v1 -sig_alg sm2sig_sm3 \\\n"
"       -cert sm2certs.pem -key sm2signkey.pem -pass 1234 \\\n"
"       -cipher_suite TLS_AES_128_GCM_SHA256 -supported_group prime256v1 -sig_alg ecdsa_secp256r1_sha256\n"
"       -cert p256certs.pem -key p256signkey.pem -pass 1234 \\\n"
"\n"
"    gmssl tls13_client -host 127.0.0.1 -port 4430 -cacert rootcacerts.pem \\\n"
"       -cipher_suite TLS_SM4_GCM_SM3 -supported_group sm2p256v1 -sig_alg sm2sig_sm3 \\\n"
"       -cipher_suite TLS_AES_128_GCM_SHA256 -supported_group prime256v1 -sig_alg ecdsa_secp256r1_sha256\n"
"       -server_name\n"
"\n"
"HelloRetryRequest\n"
"\n"
"    sudo gmssl tls13_server -port 4430 \\\n"
"       -cipher_suite TLS_SM4_GCM_SM3 -supported_group sm2p256v1 -sig_alg sm2sig_sm3 \\\n"
"       -cert sm2certs.pem -key sm2signkey.pem -pass 1234\n"
"\n"
"    gmssl tls13_client -host 127.0.0.1 -port 4430 -cacert rootcacerts.pem \\\n"
"       -cipher_suite TLS_AES_128_GCM_SHA256 -supported_group prime256v1 -sig_alg ecdsa_secp256r1_sha256 \\\n"
"       -cipher_suite TLS_SM4_GCM_SM3 -supported_group sm2p256v1 -sig_alg sm2sig_sm3 \\\n"
"       -max_key_exchanges 1 # or -max_key_exchanges 0 \n"
"\n"
"ClientHello with OCSP request, CT, and other extensions\n"
"\n"
"    sudo gmssl tls13_server -port 4430 \\\n"
"       -cipher_suite TLS_SM4_GCM_SM3 -cipher_suite TLS_AES_128_GCM_SHA256 \\\n"
"       -supported_group sm2p256v1 -supported_group prime256v1 \\\n"
"       -sig_alg sm2sig_sm3 -sig_alg ecdsa_secp256r1_sha256 \\\n"
"       -cert sm2certs.pem -key sm2signkey.pem -pass 1234\n"
"\n"
"    gmssl tls13_client -host 127.0.0.1 -port 4430 -cacert rootcacerts.pem \\\n"
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
"NewSessionTicket\n"
"\n"
"    TICKET_KEY=11223344556677881122334455667788\n"
"\n"
"    sudo gmssl tls13_server -port 4430 -cert sm2certs.pem -key sm2signkey.pem -pass 1234 \\\n"
"       -cipher_suite TLS_SM4_GCM_SM3 -supported_group sm2p256v1 -sig_alg sm2sig_sm3 \\\n"
"       -new_session_ticket 2 -ticket_key $TICKET_KEY\n"
"\n"
"    gmssl tls13_client -host 127.0.0.1 -port 4430 -cacert rootcacerts.pem \\\n"
"       -cipher_suite TLS_SM4_GCM_SM3 -supported_group sm2p256v1 -sig_alg sm2sig_sm3 \\\n"
"       -sess_out session.bin\n"
"\n"
"PSK-DHE from session ticket\n"
"\n"
"    sudo gmssl tls13_server -port 4430 -cert sm2certs.pem -key sm2signkey.pem -pass 1234 \\\n"
"       -cipher_suite TLS_SM4_GCM_SM3 -supported_group sm2p256v1 \\\n"
"       -psk_dhe_ke -ticket_key $TICKET_KEY\n"
"\n"
"    gmssl tls13_client -host 127.0.0.1 -port 4430 \\\n"
"       -cipher_suite TLS_SM4_GCM_SM3 -supported_group sm2p256v1 \\\n"
"       -psk_dhe_ke -sess_in session.bin\n"
"\n"
"PSK-DHE/PSK from external\n"
"\n"
"    PSK=1122334455667788112233445566778811223344556677881122334455667788\n"
"\n"
"    sudo gmssl tls13_server -port 4430 -cipher_suite TLS_SM4_GCM_SM3 \\\n"
"       -supported_group sm2p256v1 -psk_dhe_ke \\\n"
"       -psk_identity 001 -psk_cipher_suite TLS_SM4_GCM_SM3 -psk_key $PSK\n"
"\n"
"    gmssl tls13_client -host 127.0.0.1 -port 4430 -cipher_suite TLS_SM4_GCM_SM3 \\\n"
"       -supported_group sm2p256v1 -psk_dhe_ke \\\n"
"       -psk_identity 001 -psk_cipher_suite TLS_SM4_GCM_SM3 -psk_key $PSK\n"
"\n"
"    sudo gmssl tls13_server -port 4430 -cipher_suite TLS_SM4_GCM_SM3 \\\n"
"       -psk_ke -psk_identity 001 -psk_cipher_suite TLS_SM4_GCM_SM3 -psk_key $PSK\n"
"\n"
"    gmssl tls13_client -host 127.0.0.1 -port 4430 -cipher_suite TLS_SM4_GCM_SM3 \\\n"
"       -psk_ke -psk_identity 001 -psk_cipher_suite TLS_SM4_GCM_SM3 -psk_key $PSK\n"
"\n"
"EarlyData (0-RTT)\n"
"\n"
"    sudo gmssl tls13_server -port 4430 -cipher_suite TLS_SM4_GCM_SM3 \\\n"
"       -psk_ke -psk_identity 001 -psk_cipher_suite TLS_SM4_GCM_SM3 -psk_key $PSK \\\n"
"       -early_data\n"
"\n"
"    gmssl tls13_client -host 127.0.0.1 -port 4430 -cipher_suite TLS_SM4_GCM_SM3 \\\n"
"       -psk_ke -psk_identity 001 -psk_cipher_suite TLS_SM4_GCM_SM3 -psk_key $PSK \\\n"
"       -early_data early_data.txt\n"
"\n"
"CertificateRequest\n"
"\n"
"    sudo gmssl tls13_server -port 4430 -cert sm2certs.pem -key sm2signkey.pem -pass 1234 \\\n"
"       -cipher_suite TLS_SM4_GCM_SM3 -supported_group sm2p256v1 -sig_alg sm2sig_sm3 \\\n"
"       -cert_request -cacert sm2rootcacert.pem\n"
"\n"
"    gmssl tls13_client -host 127.0.0.1 -port 4430 -cacert sm2rootcacert.pem \\\n"
"       -cipher_suite TLS_SM4_GCM_SM3 -supported_group sm2p256v1 -sig_alg sm2sig_sm3 \\\n"
"       -cert sm2certs.pem -key sm2signkey.pem -pass 1234\n"
"\n"
"CertificateRequest without CertificateVerify\n"
"\n"
"    gmssl tls13_client -host 127.0.0.1 -port 4430 -cacert sm2rootcacert.pem \\\n"
"       -cipher_suite TLS_SM4_GCM_SM3 -supported_group sm2p256v1 -sig_alg sm2sig_sm3\n"
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

	int key_update_seq_num = 0;


	size_t i;




	int cert_request = 0;
	char *cacertfile = NULL;

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

			error_print();

			if (certfiles_cnt >= sizeof(certfiles)/sizeof(certfiles[0])) {
				error_print();
				return -1;
			}
			certfiles[certfiles_cnt++] = certfile;


			fprintf(stderr, "111certfiles_cnt = %zu\n", certfiles_cnt);

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

		} else if (!strcmp(*argv, "-cert_request")) {
			cert_request = 1;
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
		} else if (!strcmp(*argv, "-key_update_seq_num")) {
			if (--argc < 1) goto bad;
			key_update_seq_num = atoi(*(++argv));
			if (key_update_seq_num < 0) {
				error_print();
				fprintf(stderr, "%s: invalid '-key_update_seq_num' value\n", prog);
				return -1;
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

	// FIXME: 打印载入的证书信息
	for (i = 0; i < certfiles_cnt; i++) {
		if (tls_ctx_add_certificate_chain_and_key(&ctx, certfiles[i], keyfiles[i], passes[i]) != 1) {
			error_print();
			return -1;
		}
	}

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

	if (cert_request) {

		if (!cacertfile) {
			error_print();
			return -1;
		}
		if (tls_ctx_set_ca_certificates(&ctx, cacertfile, TLS_DEFAULT_VERIFY_DEPTH) != 1) {
			error_print();
			return -1;
		}

		// 在发送CertificateRequest的时候，需要把CA的DN发送给客户端
		// 这里dn_names是在什么时候设置好的？

		if (tls_ctx_enable_certificate_request(&ctx, 1) != 1) {
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

	if (key_update_seq_num > 0) {
		if (tls_ctx_set_key_update_seq_num_limit(&ctx, key_update_seq_num) != 1) {
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

	if (conn.early_data && conn.early_data_len) {
		format_string(stderr, 0, 0, "EarlyData", conn.early_data_buf, conn.early_data_len);
	}

	size_t send_len = 0;
	size_t send_offset = 0;



	// 如果客户端发送的数据比较长，会被切分为多个record
	// 服务器在接收到record之后，必须做同步，就是每收到一个record必须返回一个record
	// 也就是server必须有一个同步机制

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


			format_bytes(stderr, 0, 0, "tls13_send", buf + send_offset, send_len);


			if ((ret = tls13_send(&conn, (uint8_t *)buf + send_offset, send_len, &sentlen)) != 1) {
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

			if ((ret = tls13_recv(&conn, (uint8_t *)buf, sizeof(buf), &len)) != 1) {
				if (ret == TLS_ERROR_SEND_AGAIN || ret == TLS_ERROR_RECV_AGAIN) {
					continue;
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
