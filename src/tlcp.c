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


#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <gmssl/rand.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/pem.h>
#include <gmssl/tls.h>


static const int tlcp_ciphers[] = { TLCP_cipher_ecc_sm4_cbc_sm3 };
static const size_t tlcp_ciphers_count = sizeof(tlcp_ciphers)/sizeof(tlcp_ciphers[0]);


int tlcp_record_set_handshake_server_key_exchange_pke(uint8_t *record, size_t *recordlen,
	const uint8_t *sig, size_t siglen)
{
	int type = TLS_handshake_server_key_exchange;
	uint8_t *p = record + 5 + 4;
	size_t hslen = 0;

	if (!record || !recordlen
		|| !sig || !siglen || siglen > 2048) {
		error_print();
		return -1;
	}
	if (record[1] != TLCP_VERSION_MAJOR || record[2] != TLCP_VERSION_MINOR) {
		error_print();
		return -1;
	}
	tls_array_to_bytes(sig, siglen, &p, &hslen);
	tls_record_set_handshake(record, recordlen, type, NULL, hslen);
	return 1;
}

int tlcp_record_get_handshake_server_key_exchange_pke(const uint8_t *record,
	uint8_t *sig, size_t *siglen)
{
	int type;
	const uint8_t *p;
	size_t len;

	if (!record || !sig || !siglen) {
		error_print();
		return -1;
	}

	if (tls_record_get_handshake(record, &type, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_server_key_exchange) {
		error_print();
		return -1;
	}
	if (record[1] != TLCP_VERSION_MAJOR || record[2] != TLCP_VERSION_MINOR) {
		error_print();
		return -1;
	}
	/*
	if (tls_uint16array_copy_from_bytes(sig, siglen, *siglen, &p, &len) != 1
		|| len > 0) {
		error_print();
		return -1;
	}
	*/
	// FIXME: check *siglen >= len
	memcpy(sig, p, len);
	*siglen = len;
	return 1;
}

int tlcp_certificate_chain_verify(const uint8_t *data, size_t datalen, FILE *ca_certs_fp, int depth)
{
	const uint8_t *certs;
	size_t certslen;
	const uint8_t *der;
	size_t derlen;
	X509_CERTIFICATE sign_cert;
	X509_CERTIFICATE enc_cert;
	X509_CERTIFICATE ca_cert;

	if (tls_uint24array_from_bytes(&certs, &certslen, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	if (tls_uint24array_from_bytes(&der, &derlen, &certs, &certslen) != 1
		|| x509_certificate_from_der(&sign_cert, &der, &derlen) != 1
		|| derlen > 0) {
		error_print();
		return -1;
	}
	if (tls_uint24array_from_bytes(&der, &derlen, &certs, &certslen) != 1
		|| x509_certificate_from_der(&enc_cert, &der, &derlen) != 1
		|| derlen > 0) {
		error_print();
		return -1;
	}
	if (x509_name_equ(&sign_cert.tbs_certificate.issuer,
		&enc_cert.tbs_certificate.issuer) != 1) {
		error_print();
		return -1;
	}

	if (certslen) {
		const uint8_t *chain = certs;
		size_t chainlen = certslen;
		if (tls_uint24array_from_bytes(&der, &derlen, &certs, &certslen) != 1
			|| x509_certificate_from_der(&ca_cert, &der, &derlen) != 1
			|| derlen > 0) {
			error_print();
			return -1;
		}
		if (x509_certificate_verify_by_certificate(&sign_cert, &ca_cert) != 1
			|| x509_certificate_verify_by_certificate(&enc_cert, &ca_cert) != 1) {
			error_print();
			return -1;
		}
		if (tls_certificate_chain_verify(chain, chainlen, ca_certs_fp, depth - 1) != 1) {
			error_print();
			return -1;
		}
	} else {
		if (x509_certificate_from_pem_by_name(&ca_cert, ca_certs_fp, &sign_cert.tbs_certificate.issuer) != 1
			|| x509_certificate_verify_by_certificate(&sign_cert, &ca_cert) != 1) {
			error_print();
			return -1;
		}
		if (x509_certificate_from_pem_by_name(&ca_cert, ca_certs_fp, &enc_cert.tbs_certificate.issuer) != 1
			|| x509_certificate_verify_by_certificate(&enc_cert, &ca_cert) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int tlcp_connect(TLS_CONNECT *conn, const char *hostname, int port,
	FILE *ca_certs_fp, FILE *client_certs_fp, const SM2_KEY *client_sign_key)
{
	uint8_t record[1600];
	size_t recordlen;
	uint8_t finished[256];
	size_t finishedlen;
	int type;
	const uint8_t *data;
	size_t datalen;

	uint8_t client_random[32];
	uint8_t server_random[32];
	const uint8_t *server_enc_cert;
	size_t server_enc_cert_len;
	SM2_KEY server_enc_key;
	SM2_KEY server_sign_key;
	SM2_SIGN_CTX verify_ctx; // for server_key_exchange signature verification
	SM2_SIGN_CTX sign_ctx; // for certificate_verify signature generation
	uint8_t sig[TLS_MAX_SIGNATURE_SIZE];
	size_t siglen = sizeof(sig);
	uint8_t pre_master_secret[48];
	uint8_t enced_pre_master_secret[256];
	size_t enced_pre_master_secret_len;
	SM3_CTX sm3_ctx;
	SM3_CTX tmp_sm3_ctx;
	uint8_t sm3_hash[32];
	uint8_t verify_data[12];
	uint8_t local_verify_data[12];

	struct sockaddr_in server;
	server.sin_addr.s_addr = inet_addr(hostname);
	server.sin_family = AF_INET;
	server.sin_port = htons(port);
	if ((conn->sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		error_print();
		return -1;
	}
	if (connect(conn->sock, (struct sockaddr *)&server , sizeof(server)) < 0) {
		error_print();
		return -1;
	}

	conn->is_client = 1;

	sm3_init(&sm3_ctx);
	if (client_sign_key)
		sm2_sign_init(&sign_ctx, client_sign_key, SM2_DEFAULT_ID);
	tls_record_set_version(record, TLS_version_tlcp);
	tls_record_set_version(finished, TLS_version_tlcp);

	tls_trace(">>>> ClientHello\n");
	tls_random_generate(client_random);
	if (tls_record_set_handshake_client_hello(record, &recordlen,
		TLS_version_tlcp, client_random, NULL, 0,
		tlcp_ciphers, tlcp_ciphers_count, NULL, 0) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, 0, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (client_sign_key)
		sm2_sign_update(&sign_ctx, record + 5, recordlen - 5);

	tls_trace("<<<< ServerHello\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_version(record) != TLS_version_tlcp) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, 0, 0);
	if (tls_record_get_handshake_server_hello(record,
		&conn->version, server_random, conn->session_id, &conn->session_id_len,
		&conn->cipher_suite, NULL, 0) != 1) {
		error_print();
		return -1;
	}
	if (conn->version != TLS_version_tlcp) {
		error_print();
		return -1;
	}
	if (tls_cipher_suite_in_list(conn->cipher_suite, tlcp_ciphers, tlcp_ciphers_count) != 1) {
		error_print();
		return -1;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (client_sign_key)
		sm2_sign_update(&sign_ctx, record + 5, recordlen - 5);

	tls_trace("<<<< ServerCertificate\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_version(record) != TLS_version_tlcp) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, 0, 0);
	if (tls_record_get_handshake_certificate(record,
		conn->server_certs, &conn->server_certs_len) != 1) {
		error_print();
		return -1;
	}
	if (tlcp_certificate_chain_verify(conn->server_certs, conn->server_certs_len, ca_certs_fp, 5) != 1) {
		error_print();
		return -1;
	}
	if (tls_certificate_get_public_keys(conn->server_certs, conn->server_certs_len,
		&server_sign_key, &server_enc_key) != 1) {
		error_print();
		return -1;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (client_sign_key)
		sm2_sign_update(&sign_ctx, record + 5, recordlen - 5);

	tls_trace("<<<< ServerKeyExchange\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_version(record) != TLS_version_tlcp) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, conn->cipher_suite << 8, 0);
	if (tlcp_record_get_handshake_server_key_exchange_pke(record, sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (client_sign_key)
		sm2_sign_update(&sign_ctx, record + 5, recordlen - 5);

	tls_trace("++++ process ServerKeyExchange\n");
	if (tls_certificate_get_second(conn->server_certs, conn->server_certs_len,
		&server_enc_cert, &server_enc_cert_len) != 1) {
		error_print();
		return -1;
	}
	if (sm2_verify_init(&verify_ctx, &server_sign_key, SM2_DEFAULT_ID) != 1
		|| sm2_verify_update(&verify_ctx, client_random, 32) != 1
		|| sm2_verify_update(&verify_ctx, server_random, 32) != 1
		|| sm2_verify_update(&verify_ctx, server_enc_cert, server_enc_cert_len) != 1) {
		error_print();
		return -1;
	}
	if ( sm2_verify_finish(&verify_ctx, sig, siglen) != 1) {
		error_puts("ServerKeyExchange signature verification failure");
		return -1;
	}

	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_version(record) != TLS_version_tlcp
		|| tls_record_get_handshake(record, &type, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	if (type == TLS_handshake_certificate_request) {
		tls_trace("<<<< CertificateRequest\n");
		int cert_types[TLS_MAX_CERTIFICATE_TYPES];
		size_t cert_types_count;;
		uint8_t ca_names[TLS_MAX_CA_NAMES_SIZE];
		size_t ca_names_len;
		if (tls_record_get_handshake_certificate_request(record,
			cert_types, &cert_types_count,
			ca_names, &ca_names_len) != 1) {
			error_print();
			return -1;
		}
		tls_record_print(stderr, record, recordlen, 0, 0);
		sm3_update(&sm3_ctx, record + 5, recordlen - 5);
		if (client_sign_key)
			sm2_sign_update(&sign_ctx, record + 5, recordlen - 5);

		if (tls_record_recv(record, &recordlen, conn->sock) != 1
			|| tls_record_version(record) != TLS_version_tlcp) {
			error_print();
			return -1;
		}
	} else {
		memset(&sign_ctx, 0, sizeof(SM2_SIGN_CTX));
		client_sign_key = NULL;
	}
	tls_trace("<<<< ServerHelloDone\n");
	tls_record_print(stderr, record, recordlen, 0, 0);
	if (tls_record_get_handshake_server_hello_done(record) != 1) {
		error_print();
		return -1;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (client_sign_key) {
		sm2_sign_update(&sign_ctx, record + 5, recordlen - 5);

		tls_trace(">>>> ClientCertificate\n");
		if (tls_record_set_handshake_certificate_from_pem(record, &recordlen, client_certs_fp) != 1) {
			error_print();
			return -1;
		}
		tls_record_print(stderr, record, recordlen, 0, 0);
		if (tls_record_send(record, recordlen, conn->sock) != 1) {
			error_print();
			return -1;
		}
		sm3_update(&sm3_ctx, record + 5, recordlen - 5);
		sm2_sign_update(&sign_ctx, record + 5, recordlen - 5);
	}

	tls_trace("++++ generate secrets\n");
	if (tls_pre_master_secret_generate(pre_master_secret, TLS_version_tlcp) != 1
		|| tls_prf(pre_master_secret, 48, "master secret",
			client_random, 32, server_random, 32,
			48, conn->master_secret) != 1
		|| tls_prf(conn->master_secret, 48, "key expansion",
			server_random, 32, client_random, 32,
			96, conn->key_block) != 1) {
		error_print();
		return -1;
	}
	sm3_hmac_init(&conn->client_write_mac_ctx, conn->key_block, 32);
	sm3_hmac_init(&conn->server_write_mac_ctx, conn->key_block + 32, 32);
	sm4_set_encrypt_key(&conn->client_write_enc_key, conn->key_block + 64);
	sm4_set_decrypt_key(&conn->server_write_enc_key, conn->key_block + 80);
	format_bytes(stderr, 0, 0, "pre_master_secret : ", pre_master_secret, 48);
	format_bytes(stderr, 0, 0, "master_secret : ", conn->master_secret, 48);
	format_bytes(stderr, 0, 0, "client_write_mac_key : ", conn->key_block, 32);
	format_bytes(stderr, 0, 0, "server_write_mac_key : ", conn->key_block + 32, 32);
	format_bytes(stderr, 0, 0, "client_write_enc_key : ", conn->key_block + 64, 16);
	format_bytes(stderr, 0, 0, "server_write_enc_key : ", conn->key_block + 80, 16);
	format_print(stderr, 0, 0, "\n");

	tls_trace(">>>> ClientKeyExchange\n");
	if (sm2_encrypt(&server_enc_key, pre_master_secret, 48,
		enced_pre_master_secret, &enced_pre_master_secret_len) != 1) {
		error_print();
		return -1;
	}
	if (tls_record_set_handshake_client_key_exchange_pke(record, &recordlen,
		enced_pre_master_secret, enced_pre_master_secret_len) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, conn->cipher_suite << 8, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (client_sign_key)
		sm2_sign_update(&sign_ctx, record + 5, recordlen - 5);

	if (client_sign_key) {
		tls_trace(">>>> CertificateVerify\n");
		sm2_sign_finish(&sign_ctx, sig, &siglen);
		if (tls_record_set_handshake_certificate_verify(record, &recordlen, sig, siglen) != 1) {
			error_print();
			return -1;
		}
		tls_record_print(stderr, record, recordlen, 0, 0);
		if (tls_record_send(record, recordlen, conn->sock) != 1) {
			error_print();
			return -1;
		}
		sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	}

	tls_trace(">>>> [ChangeCipherSpec]\n");
	if (tls_record_set_change_cipher_spec(record, &recordlen) !=1) {
		error_print();
		return -1;
	}
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, 0, 0);

	tls_trace(">>>> Finished\n");
	memcpy(&tmp_sm3_ctx, &sm3_ctx, sizeof(sm3_ctx));
	sm3_finish(&tmp_sm3_ctx, sm3_hash);

	if (tls_prf(conn->master_secret, 48, "client finished",
		sm3_hash, 32, NULL, 0,
		sizeof(verify_data), verify_data) != 1) {
		error_print();
		return -1;
	}
	if (tls_record_set_handshake_finished(finished, &finishedlen, verify_data) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, finished, finishedlen, 0, 0);
	sm3_update(&sm3_ctx, finished + 5, finishedlen - 5);

	if (tls_record_encrypt(&conn->client_write_mac_ctx, &conn->client_write_enc_key,
		conn->client_seq_num, finished, finishedlen, record, &recordlen) != 1) {
		error_print();
		return -1;
	}
	tls_seq_num_incr(conn->client_seq_num);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}

	tls_trace("<<<< [ChangeCipherSpec]\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_version(record) != TLS_version_tlcp) {
		error_print();
		return -1;
	}
	if (tls_record_get_change_cipher_spec(record) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, 0, 0);

	tls_trace("<<<< Finished\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_version(record) != TLS_version_tlcp) {
		error_print();
		return -1;
	}
	if (tls_record_decrypt(&conn->server_write_mac_ctx, &conn->server_write_enc_key,
		conn->server_seq_num, record, recordlen, finished, &finishedlen) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, finished, finishedlen, 0, 0);
	tls_seq_num_incr(conn->server_seq_num);
	if (tls_record_get_handshake_finished(finished, verify_data) != 1) {
		error_print();
		return -1;
	}
	sm3_finish(&sm3_ctx, sm3_hash);
	if (tls_prf(conn->master_secret, 48, "server finished",
		sm3_hash, 32, NULL, 0,
		sizeof(local_verify_data), local_verify_data) != 1) {
		error_print();
		return -1;
	}
	if (memcmp(local_verify_data, verify_data, 12) != 0) {
		error_puts("server_finished.verify_data verification failure");
		return -1;
	}

	tls_trace("++++ Connection established\n");
	return 1;
}

int tlcp_accept(TLS_CONNECT *conn, int port,
	FILE *certs_fp, const SM2_KEY *server_sign_key, const SM2_KEY *server_enc_key,
	FILE *client_cacerts_fp, uint8_t *handshakes_buf, size_t handshakes_buflen)
{
	uint8_t *handshakes = handshakes_buf;
	size_t handshakeslen = 0;
	uint8_t record[TLS_MAX_RECORD_SIZE];
	size_t recordlen;
	uint8_t finished[256];
	size_t finishedlen = sizeof(finished);

	uint8_t client_random[32];
	uint8_t server_random[32];
	uint8_t session_id[32];
	size_t session_id_len;
	int client_ciphers[12] = {0};
	size_t client_ciphers_count = sizeof(client_ciphers)/sizeof(client_ciphers[0]);
	const uint8_t *server_enc_cert;
	size_t server_enc_certlen;
	SM2_KEY client_sign_key;
	SM2_SIGN_CTX sign_ctx;
	uint8_t sig[TLS_MAX_SIGNATURE_SIZE];
	size_t siglen = sizeof(sig);
	uint8_t enced_pms[256];
	size_t enced_pms_len = sizeof(enced_pms);
	uint8_t pre_master_secret[48];
	size_t pre_master_secret_len = 48;
	SM3_CTX sm3_ctx;
	SM3_CTX tmp_sm3_ctx;
	uint8_t sm3_hash[32];
	uint8_t verify_data[12];
	uint8_t local_verify_data[12];
	size_t i;

	int sock;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	socklen_t client_addrlen;

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		error_print();
		return -1;
	}
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(port);

	if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		error_print();
		return -1;
	}

	error_puts("start listen ...");
	listen(sock, 5);

	memset(conn, 0, sizeof(*conn));



	client_addrlen = sizeof(client_addr);
	if ((conn->sock = accept(sock, (struct sockaddr *)&client_addr, &client_addrlen)) < 0) {
		error_print();
		return -1;
	}

	error_puts("connected\n");



	sm3_init(&sm3_ctx);

	tls_trace("<<<< ClientHello\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_version(record) != TLS_version_tlcp) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, 0, 0);
	if (tls_record_get_handshake_client_hello(record,
		&conn->version, client_random, session_id, &session_id_len,
		client_ciphers, &client_ciphers_count, NULL, 0) != 1) {
		error_print();
		return -1;
	}
	if (conn->version != TLS_version_tlcp) {
		error_print();
		return -1;
	}
	for (i = 0; i < tlcp_ciphers_count; i++) {
		if (tls_cipher_suite_in_list(tlcp_ciphers[i], client_ciphers, client_ciphers_count) == 1) {
			conn->cipher_suite = tlcp_ciphers[i];
			break;
		}
	}
	if (conn->cipher_suite == 0) {
		error_puts("no common cipher_suite");
		return -1;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (handshakes) {
		memcpy(handshakes, record + 5, recordlen - 5);
		handshakes += recordlen - 5;
		handshakeslen += recordlen - 5;
	}

	tls_trace(">>>> ServerHello\n");
	tls_random_generate(server_random);
	if (tls_record_set_handshake_server_hello(record, &recordlen,
		TLS_version_tlcp, server_random, NULL, 0,
		conn->cipher_suite, NULL, 0) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, 0, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (handshakes) {
		memcpy(handshakes, record + 5, recordlen - 5);
		handshakes += recordlen - 5;
		handshakeslen += recordlen - 5;
	}

	tls_trace(">>>> ServerCertificate\n");
	if (tls_record_set_handshake_certificate_from_pem(record, &recordlen, certs_fp) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, 0, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake_certificate(record, conn->server_certs, &conn->server_certs_len) != 1
		|| tls_certificate_get_second(conn->server_certs, conn->server_certs_len,
			&server_enc_cert, &server_enc_certlen) != 1) {
		error_print();
		return -1;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (handshakes) {
		memcpy(handshakes, record + 5, recordlen - 5);
		handshakes += recordlen - 5;
		handshakeslen += recordlen - 5;
	}

	tls_trace(">>>> ServerKeyExchange\n");
	if (sm2_sign_init(&sign_ctx, server_sign_key, SM2_DEFAULT_ID) != 1
		|| sm2_sign_update(&sign_ctx, client_random, 32) != 1
		|| sm2_sign_update(&sign_ctx, server_random, 32) != 1
		|| sm2_sign_update(&sign_ctx, server_enc_cert, server_enc_certlen) != 1
		|| sm2_sign_finish(&sign_ctx, sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	if (tlcp_record_set_handshake_server_key_exchange_pke(record, &recordlen, sig, siglen) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, conn->cipher_suite << 8, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (handshakes) {
		memcpy(handshakes, record + 5, recordlen - 5);
		handshakes += recordlen - 5;
		handshakeslen += recordlen - 5;
	}

	if (client_cacerts_fp) {
		tls_trace(">>>> CertificateRequest\n");
		const int cert_types[] = { TLS_cert_type_ecdsa_sign, };
		uint8_t ca_names[TLS_MAX_CA_NAMES_SIZE] = {0};
		size_t cert_types_count = sizeof(cert_types)/sizeof(cert_types[0]);
		size_t ca_names_len = 0;
		if (tls_record_set_handshake_certificate_request(record, &recordlen,
			cert_types, cert_types_count,
			ca_names, ca_names_len) != 1) {
			error_print();
			return -1;
		}
		tls_record_print(stderr, record, recordlen, 0, 0);

		if (tls_record_send(record, recordlen, conn->sock) != 1) {
			error_print();
			return -1;
		}
		sm3_update(&sm3_ctx, record + 5, recordlen - 5);
		if (handshakes) {
			memcpy(handshakes, record + 5, recordlen - 5);
			handshakes += recordlen - 5;
			handshakeslen += recordlen - 5;
		}
	}

	tls_trace(">>>> ServerHelloDone\n");
	if (tls_record_set_handshake_server_hello_done(record, &recordlen) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, 0, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (handshakes) {
		memcpy(handshakes, record + 5, recordlen - 5);
		handshakes += recordlen - 5;
		handshakeslen += recordlen - 5;
	}

	if (handshakes) {
		tls_trace("<<<< ClientCertificate\n");
		if (tls_record_recv(record, &recordlen, conn->sock) != 1
			|| tls_record_version(record) != TLS_version_tlcp) {
			error_print();
			return -1;
		}
		tls_record_print(stderr, record, recordlen, 0, 0);
		if (tls_record_get_handshake_certificate(record,
			conn->client_certs, &conn->client_certs_len) != 1) {
			error_print();
			return -1;
		}
		// FIXME: verify client's certificate with ca certs		
		if (tls_certificate_get_public_keys(conn->client_certs, conn->client_certs_len,
			&client_sign_key, NULL) != 1) {
			error_print();
			return -1;
		}
		sm3_update(&sm3_ctx, record + 5, recordlen - 5);
		memcpy(handshakes, record + 5, recordlen - 5);
		handshakes += recordlen - 5;
		handshakeslen += recordlen - 5;
	}

	tls_trace("<<<< ClientKeyExchange\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_version(record) != TLS_version_tlcp) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, conn->cipher_suite << 8, 0);
	if (tls_record_get_handshake_client_key_exchange_pke(record, enced_pms, &enced_pms_len) != 1) {
		error_print();
		return -1;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (handshakes) {
		memcpy(handshakes, record + 5, recordlen - 5);
		handshakes += recordlen - 5;
		handshakeslen += recordlen - 5;
	}
	if (sm2_decrypt(server_enc_key, enced_pms, enced_pms_len,
		pre_master_secret, &pre_master_secret_len) != 1) {
		error_print();
		return -1;
	}

	if (handshakes) {
		tls_trace("<<<< CertificateVerify\n");
		if (tls_record_recv(record, &recordlen, conn->sock) != 1
			|| tls_record_version(record) != TLS_version_tlcp) {
			error_print();
			return -1;
		}
		tls_record_print(stderr, record, recordlen, 0, 0);
		if (tls_record_get_handshake_certificate_verify(record, sig, &siglen) != 1) {
			error_print();
			return -1;
		}
		sm3_update(&sm3_ctx, record + 5, recordlen - 5);
		sm2_verify_init(&sign_ctx, &client_sign_key, SM2_DEFAULT_ID);
		sm2_verify_update(&sign_ctx, handshakes_buf, handshakeslen);
		if (sm2_verify_finish(&sign_ctx, sig, siglen) != 1) {
			error_print();
			return -1;
		}
	}

	tls_trace("++++ generate secrets\n");
	if (tls_prf(pre_master_secret, 48, "master secret",
		client_random, 32, server_random, 32,
		48, conn->master_secret) != 1) {
		error_print();
		return -1;
	}
	if (tls_prf(conn->master_secret, 48, "key expansion",
		server_random, 32, client_random, 32,
		96, conn->key_block) != 1) {
		error_print();
		return -1;
	}
	sm3_hmac_init(&conn->client_write_mac_ctx, conn->key_block, 32);
	sm3_hmac_init(&conn->server_write_mac_ctx, conn->key_block + 32, 32);
	sm4_set_decrypt_key(&conn->client_write_enc_key, conn->key_block + 64);
	sm4_set_encrypt_key(&conn->server_write_enc_key, conn->key_block + 80);
	format_bytes(stderr, 0, 0, "pre_master_secret : ", pre_master_secret, 48);
	format_bytes(stderr, 0, 0, "master_secret : ", conn->master_secret, 48);
	format_bytes(stderr, 0, 0, "client_write_mac_key : ", conn->key_block, 32);
	format_bytes(stderr, 0, 0, "server_write_mac_key : ", conn->key_block + 32, 32);
	format_bytes(stderr, 0, 0, "client_write_enc_key : ", conn->key_block + 64, 16);
	format_bytes(stderr, 0, 0, "server_write_enc_key : ", conn->key_block + 80, 16);
	format_print(stderr, 0, 0, "\n");


	tls_trace("<<<< [ChangeCipherSpec]\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_version(record) != TLS_version_tlcp) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, 0, 0);
	if (tls_record_get_change_cipher_spec(record) != 1) {
		error_print();
		return -1;
	}

	tls_trace("<<<< ClientFinished\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_version(record) != TLS_version_tlcp) {
		error_print();
		return -1;
	}
	if (tls_record_decrypt(&conn->client_write_mac_ctx, &conn->client_write_enc_key,
		conn->client_seq_num, record, recordlen, finished, &finishedlen) != 1) {
		error_print();
		return -1;
	}
	tls_seq_num_incr(conn->client_seq_num);
	if (tls_record_get_handshake_finished(finished, verify_data) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, finished, finishedlen, 0, 0);
	memcpy(&tmp_sm3_ctx, &sm3_ctx, sizeof(SM3_CTX));
	sm3_update(&sm3_ctx, finished + 5, finishedlen - 5);

	sm3_finish(&tmp_sm3_ctx, sm3_hash);
	if (tls_prf(conn->master_secret, 48, "client finished", sm3_hash, 32, NULL, 0,
		12, local_verify_data) != 1) {
		error_print();
		return -1;
	}
	if (memcmp(local_verify_data, verify_data, 12) != 0) {
		error_puts("client_finished.verify_data verification failure");
		return -1;
	}

	tls_trace(">>>> [ChangeCipherSpec]\n");
	if (tls_record_set_change_cipher_spec(record, &recordlen) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, 0, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}

	tls_trace(">>>> ServerFinished\n");
	sm3_finish(&sm3_ctx, sm3_hash);
	if (tls_prf(conn->master_secret, 48, "server finished", sm3_hash, 32, NULL, 0,
		12, verify_data) != 1) {
		error_print();
		return -1;
	}
	if (tls_record_set_handshake_finished(finished, &finishedlen, verify_data) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, finished, finishedlen, 0, 0);
	if (tls_record_encrypt(&conn->server_write_mac_ctx, &conn->server_write_enc_key,
		conn->server_seq_num, finished, finishedlen, record, &recordlen) != 1) {
		error_print();
		return -1;
	}
	tls_seq_num_incr(conn->server_seq_num);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}

	tls_trace("Connection Established!\n\n");
	return 1;
}
