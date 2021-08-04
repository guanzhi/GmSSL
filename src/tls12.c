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




static const int tls12_ciphers[] = {
	GMSSL_cipher_ecdhe_sm2_with_sm4_sm3,
};

static const size_t tls12_ciphers_count = sizeof(tls12_ciphers)/sizeof(tls12_ciphers[0]);

static const uint8_t tls12_exts[] = {
	/* supported_groups */ 0x00,0x0A, 0x00,0x04, 0x00,0x02, 0x00,30,//0x29, // curveSM2
	/* ec_point_formats */ 0x00,0x0B, 0x00,0x02, 0x01,      0x00, // uncompressed
	/* signature_algors */ 0x00,0x0D, 0x00,0x04, 0x00,0x02, 0x07,0x07,//0x08, // sm2sig_sm3
};

/*
int tls_server_extensions_check(const uint8_t *exts, size_t extslen)
{
	return -1;
}

int tls_construct_server_extensions(const uint8_t *client_exts, size_t client_exts_len,
	uint8_t *server_exts, size_t *server_exts_len)
{
	uint16_t type;
	const uint8_t *p;
	size_t len;

	while (client_exts_len) {
		if (tls_uint16_from_bytes(&ext_type, &client_exts, &client_exts_len) != 1
			|| tls_uint16array_from_bytes(&ext_data, &ext_datalen, &client_exts, &client_exts_len) != 1) {
			error_print();
			return -1;
		}
	}
}
*/

int tls_record_set_handshake_server_key_exchange_ecdhe(uint8_t *record, size_t *recordlen,
	int curve, const SM2_POINT *point, const uint8_t *sig, size_t siglen)
{
	int type = TLS_handshake_server_key_exchange;
	uint8_t *server_ecdh_params = record + 9;
	uint8_t *p = server_ecdh_params + 69;
	size_t len = 69;

	if (!record || !recordlen || !tls_named_curve_name(curve) || !point
		|| !sig || !siglen || siglen > TLS_MAX_SIGNATURE_SIZE) {
		error_print();
		return -1;
	}
	server_ecdh_params[0] = TLS_curve_type_named_curve;
	server_ecdh_params[1] = curve >> 8;
	server_ecdh_params[2] = curve;
	server_ecdh_params[3] = 65;
	sm2_point_to_uncompressed_octets(point, server_ecdh_params + 4);
	tls_uint16_to_bytes(TLS_sig_sm2sig_sm3, &p, &len);
	tls_uint16array_to_bytes(sig, siglen, &p, &len);
	tls_record_set_handshake(record, recordlen, type, NULL, len);
	return 1;
}

int tls_record_get_handshake_server_key_exchange_ecdhe(const uint8_t *record,
	int *curve, SM2_POINT *point, uint8_t *sig, size_t *siglen)
{
	int type;
	const uint8_t *p;
	size_t len;
	uint8_t curve_type;
	const uint8_t *octets;
	size_t octetslen;
	uint16_t sig_alg;

	if (!record || !curve || !point || !sig || !siglen) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, &p, &len) != 1
		|| type != TLS_handshake_server_key_exchange) {
		error_print();
		return -1;
	}
	*curve = 0;
	if (tls_uint8_from_bytes(&curve_type, &p, &len) != 1
		|| tls_uint16_from_bytes((uint16_t *)curve, &p, &len) != 1
		|| tls_uint8array_from_bytes(&octets, &octetslen, &p, &len) != 1
		|| tls_uint16_from_bytes(&sig_alg, &p, &len) != 1
		|| tls_uint16array_copy_from_bytes(sig, siglen, TLS_MAX_SIGNATURE_SIZE, &p, &len) != 1
		|| len > 0) {
		error_print();
		return -1;
	}
	if (curve_type != TLS_curve_type_named_curve
		|| *curve != TLS_curve_sm2p256v1
		|| octetslen != 65
		|| sm2_point_from_octets(point, octets, octetslen) != 1) {
		error_print();
		return -1;
	}
	if (sig_alg != TLS_sig_sm2sig_sm3) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_record_set_handshake_client_key_exchange_ecdhe(uint8_t *record, size_t *recordlen,
	const SM2_POINT *point)
{
	int type = TLS_handshake_client_key_exchange;
	record[9] = 65;
	sm2_point_to_uncompressed_octets(point, record + 9 + 1);
	tls_record_set_handshake(record, recordlen, type, NULL, 1 + 65);
	return 1;
}

int tls_record_get_handshake_client_key_exchange_ecdhe(const uint8_t *record, SM2_POINT *point)
{
	int type;
	const uint8_t *p;
	size_t len;
	const uint8_t *octets;
	size_t octetslen;

	if (tls_record_get_handshake(record, &type, &p, &len) != 1
		|| type != TLS_handshake_client_key_exchange) {
		error_print();
		return -1;
	}
	if (tls_uint8array_from_bytes(&octets, &octetslen, &p, &len) != 1
		|| len > 0) {
		error_print();
		return -1;
	}
	if (octetslen != 65
		|| sm2_point_from_octets(point, octets, octetslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls12_record_recv(uint8_t *record, size_t *recordlen, int sock)
{
	if (tls_record_recv(record, recordlen, sock) != 1) {
		error_print();
		return -1;
	}
	if (tls_record_version(record) != TLS_version_tls12) {
		error_print();
		return -1;
	}
	return 1;
}

int tls12_connect(TLS_CONNECT *conn, const char *hostname, int port,
	FILE *ca_certs_fp, FILE *client_certs_fp, const SM2_KEY *client_sign_key)
{
	uint8_t *record = conn->record;
	size_t recordlen;
	uint8_t finished[256];
	size_t finishedlen;

	int type;
	const uint8_t *data;
	size_t datalen;

	uint8_t client_random[32];
	uint8_t server_random[32];
	uint8_t exts[TLS_MAX_EXTENSIONS_SIZE];
	size_t exts_len;

	SM2_KEY server_sign_key;
	SM2_SIGN_CTX verify_ctx;
	SM2_SIGN_CTX sign_ctx;   // for certificate_verify signature generation
	uint8_t sig[TLS_MAX_SIGNATURE_SIZE];
	size_t siglen = sizeof(sig);


	int curve;
	SM2_KEY client_ecdh;
	SM2_POINT server_ecdh_public;

	uint8_t pre_master_secret[64];

	SM3_CTX sm3_ctx;
	SM3_CTX tmp_sm3_ctx;
	uint8_t sm3_hash[32];
	uint8_t verify_data[12];
	uint8_t local_verify_data[12];

	struct sockaddr_in server;
	server.sin_addr.s_addr = inet_addr(hostname);
	server.sin_family = AF_INET;
	server.sin_port = htons(port);


	sm3_init(&sm3_ctx);
	if (client_sign_key)
		sm2_sign_init(&sign_ctx, client_sign_key, SM2_DEFAULT_ID);
	tls_record_set_version(record, TLS_version_tls1);
	tls_record_set_version(finished, TLS_version_tls12);



	if ((conn->sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		error_print();
		return -1;
	}


	if (connect(conn->sock, (struct sockaddr *)&server , sizeof(server)) < 0) {
		error_print();
		return -1;
	}

	conn->is_client = 1;


	tls_trace(">>>> ClientHello\n");
	tls_random_generate(client_random);
	if (tls_record_set_handshake_client_hello(record, &recordlen,
		TLS_version_tls12, client_random, NULL, 0,
		tls12_ciphers, tls12_ciphers_count, tls12_exts, sizeof(tls12_exts)) != 1) {
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
	if (tls12_record_recv(record, &recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, 0, 0);
	if (tls_record_get_handshake_server_hello(record,
		&conn->version, server_random, conn->session_id, &conn->session_id_len,
		&conn->cipher_suite, exts, &exts_len) != 1) {
		error_print();
		return -1;
	}
	if (conn->version != TLS_version_tls12) {
		error_print();
		return -1;
	}
	if (tls_cipher_suite_in_list(conn->cipher_suite, tls12_ciphers, tls12_ciphers_count) != 1) {
		error_print();
		return -1;
	}
	// FIXME: check extensions			
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (client_sign_key)
		sm2_sign_update(&sign_ctx, record + 5, recordlen - 5);

	tls_trace("<<<< ServerCertificate\n");
	if (tls12_record_recv(record, &recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, 0, 0);
	if (tls_record_get_handshake_certificate(record, conn->server_certs, &conn->server_certs_len) != 1) {
		error_print();
		return -1;
	}

	/*
	// FIXME: review cert chain verification		
	if (tls_certificate_chain_verify(conn->server_certs, conn->server_certs_len, ca_certs_fp, 5) != 1) {
		error_print();
		return -1;
	}
	*/
	if (tls_certificate_get_public_keys(conn->server_certs, conn->server_certs_len,
		&server_sign_key, NULL) != 1) {
		error_print();
		return -1;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (client_sign_key)
		sm2_sign_update(&sign_ctx, record + 5, recordlen - 5);

	tls_trace("<<<< ServerKeyExchange\n");
	if (tls12_record_recv(record, &recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, conn->cipher_suite << 8, 0);
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (client_sign_key)
		sm2_sign_update(&sign_ctx, record + 5, recordlen - 5);

	if (tls_record_get_handshake_server_key_exchange_ecdhe(record, &curve, &server_ecdh_public, sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	if (curve != TLS_curve_sm2p256v1) {
		error_print();
		return -1;
	}
	if (tls_verify_server_ecdh_params(&server_sign_key,
		client_random, server_random, curve, &server_ecdh_public, sig, siglen) != 1) {
		error_print();
		return -1;
	}

	tls_trace("++++ generate secrets\n");
	sm2_keygen(&client_ecdh);
	sm2_ecdh(&client_ecdh, &server_ecdh_public, &server_ecdh_public);
	memcpy(pre_master_secret, &server_ecdh_public, 32);


	tls_prf(pre_master_secret, 32, "master secret",
		client_random, 32,
		server_random, 32,
		48, conn->master_secret);
	tls_prf(conn->master_secret, 48, "key expansion",
		server_random, 32,
		client_random, 32,
		96, conn->key_block);
	sm3_hmac_init(&conn->client_write_mac_ctx, conn->key_block, 32);
	sm3_hmac_init(&conn->server_write_mac_ctx, conn->key_block + 32, 32);
	sm4_set_encrypt_key(&conn->client_write_enc_key, conn->key_block + 64);
	sm4_set_decrypt_key(&conn->server_write_enc_key, conn->key_block + 80);
	tls_secrets_print(stderr, pre_master_secret, 32, client_random, server_random,
		conn->master_secret, conn->key_block, 96, 0, 0);


	if (tls12_record_recv(record, &recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, 0, 0);
	if (tls_record_get_handshake(record, &type, &data, &datalen) != 1) {
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
		sm3_update(&sm3_ctx, record + 5, recordlen - 5);
		if (client_sign_key)
			sm2_sign_update(&sign_ctx, record + 5, recordlen - 5);

		if (tls_record_recv(record, &recordlen, conn->sock) != 1) {
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


	tls_trace(">>>> ClientKeyExchange\n");


	// 客户端的临时公钥
	if (tls_record_set_handshake_client_key_exchange_ecdhe(record, &recordlen,
		&client_ecdh.public_key) != 1) {
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

	tls_prf(conn->master_secret, 48, "client finished",
		sm3_hash, 32, NULL, 0,
		sizeof(verify_data), verify_data);
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
	if (tls12_record_recv(record, &recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, 0, 0);
	if (tls_record_get_change_cipher_spec(record) != 1) {
		error_print();
		return -1;
	}

	tls_trace("<<<< Finished\n");
	if (tls12_record_recv(record, &recordlen, conn->sock) != 1) {
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
	tls_prf(conn->master_secret, 48, "server finished",
		sm3_hash, 32, NULL, 0,
		12, local_verify_data);
	if (memcmp(local_verify_data, verify_data, 12) != 0) {
		error_puts("server_finished.verify_data verification failure");
		return -1;
	}

	tls_trace("++++ Connection established\n");
	return 1;
}

// 实际上我们需要好几个比较大的buffer
// 一个是记录的buffer
// 还有就是server端需要一个握手buffer


int tls12_accept(TLS_CONNECT *conn, int port,
	FILE *server_certs_fp, const SM2_KEY *server_sign_key,
	FILE *client_cacerts_fp, uint8_t *handshakes_buf, size_t handshakes_buflen)
{
	uint8_t *handshakes = handshakes_buf;
	size_t handshakeslen = 0;
	uint8_t *record = conn->record;
	size_t recordlen;
	uint8_t finished[256];
	size_t finishedlen = sizeof(finished);

	uint8_t client_random[32];
	uint8_t server_random[32];
	uint8_t session_id[32];
	size_t session_id_len;
	int client_ciphers[12] = {0};
	size_t client_ciphers_count = sizeof(client_ciphers)/sizeof(client_ciphers[0]);
	uint8_t exts[TLS_MAX_EXTENSIONS_SIZE];
	size_t exts_len;

	SM2_KEY client_sign_key;
	SM2_KEY server_ecdh;
	SM2_POINT client_ecdh_public;
	SM2_SIGN_CTX sign_ctx;
	uint8_t sig[TLS_MAX_SIGNATURE_SIZE];
	size_t siglen = sizeof(sig);
	uint8_t pre_master_secret[64];
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
	if (tls_record_recv(record, &recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, 0, 0);
	if (tls_record_version(record) != TLS_version_tls1
		&& tls_record_version(record) != TLS_version_tls12) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake_client_hello(record,
		&conn->version, client_random, session_id, &session_id_len,
		client_ciphers, &client_ciphers_count, exts, &exts_len) != 1) {
		error_print();
		return -1;
	}
	if (conn->version != TLS_version_tls12) {
		error_print();
		return -1;
	}
	for (i = 0; i < tls12_ciphers_count; i++) {
		if (tls_cipher_suite_in_list(tls12_ciphers[i], client_ciphers, client_ciphers_count) == 1) {
			conn->cipher_suite = tls12_ciphers[i];
			break;
		}
	}
	if (conn->cipher_suite == 0) {
		error_puts("no common cipher_suite");
		return -1;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	tls_array_to_bytes(record + 5, recordlen - 5, &handshakes, &handshakeslen);
	if (handshakes) {
		/*
		memcpy(handshakes, record + 5, recordlen - 5);
		handshakes += recordlen - 5;
		handshakeslen += recordlen - 5;
		*/
	}

	tls_trace(">>>> ServerHello\n");
	tls_random_generate(server_random);
	tls_record_set_version(record, conn->version);
	if (tls_record_set_handshake_server_hello(record, &recordlen,
		conn->version, server_random, NULL, 0,
		conn->cipher_suite, exts, exts_len) != 1) {
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
	if (tls_record_set_handshake_certificate_from_pem(record, &recordlen, server_certs_fp) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, 0, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake_certificate(record, conn->server_certs, &conn->server_certs_len) != 1) {
		error_print();
		return -1;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	tls_array_to_bytes(record + 5, recordlen - 5, &handshakes, &handshakeslen);
	if (handshakes) {
		/*
		memcpy(handshakes, record + 5, recordlen - 5);
		handshakes += recordlen - 5;
		handshakeslen += recordlen - 5;
		*/
	}

	tls_trace(">>>> ServerKeyExchange\n");
	sm2_keygen(&server_ecdh);
	if (tls_sign_server_ecdh_params(server_sign_key,
		client_random, server_random,
		TLS_curve_sm2p256v1, &server_ecdh.public_key, sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	if (tls_record_set_handshake_server_key_exchange_ecdhe(record, &recordlen,
		TLS_curve_sm2p256v1, &server_ecdh.public_key, sig, siglen) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, conn->cipher_suite << 8, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	tls_array_to_bytes(record + 5, recordlen - 5, &handshakes, &handshakeslen);
	if (handshakes) {
		/*
		memcpy(handshakes, record + 5, recordlen - 5);
		handshakes += recordlen - 5;
		handshakeslen += recordlen - 5;
		*/
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
		tls_array_to_bytes(record + 5, recordlen - 5, &handshakes, &handshakeslen);
		if (handshakes) {
			/*
			memcpy(handshakes, record + 5, recordlen - 5);
			handshakes += recordlen - 5;
			handshakeslen += recordlen - 5;
			*/
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
	tls_array_to_bytes(record + 5, recordlen - 5, &handshakes, &handshakeslen);
	if (handshakes) {
		/*
		memcpy(handshakes, record + 5, recordlen - 5);
		handshakes += recordlen - 5;
		handshakeslen += recordlen - 5;
		*/
	}

	if (handshakes) {
		tls_trace("<<<< ClientCertificate\n");
		if (tls12_record_recv(record, &recordlen, conn->sock) != 1) {
			error_print();
			return -1;
		}
		tls_record_print(stderr, record, recordlen, 0, 0);
		if (tls_record_version(record) != TLS_version_tls12) {
			error_print();
			return -1;
		}
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
		tls_array_to_bytes(record + 5, recordlen - 5, &handshakes, &handshakeslen);
		/*
		memcpy(handshakes, record + 5, recordlen - 5);
		handshakes += recordlen - 5;
		handshakeslen += recordlen - 5;
		*/
	}

	tls_trace("<<<< ClientKeyExchange\n");
	if (tls12_record_recv(record, &recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, conn->cipher_suite << 8, 0);
	if (tls_record_get_handshake_client_key_exchange_ecdhe(record, &client_ecdh_public) != 1) {
		error_print();
		return -1;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	tls_array_to_bytes(record + 5, recordlen - 5, &handshakes, &handshakeslen);
	if (handshakes) {
		/*
		memcpy(handshakes, record + 5, recordlen - 5);
		handshakes += recordlen - 5;
		handshakeslen += recordlen - 5;
		*/
	}

	tls_trace("++++ generate secrets\n");
	sm2_ecdh(&server_ecdh, &client_ecdh_public, (SM2_POINT *)pre_master_secret);
	tls_prf(pre_master_secret, 32, "master secret",
		client_random, 32, server_random, 32,
		48, conn->master_secret);
	tls_prf(conn->master_secret, 48, "key expansion",
		server_random, 32, client_random, 32,
		96, conn->key_block);
	sm3_hmac_init(&conn->client_write_mac_ctx, conn->key_block, 32);
	sm3_hmac_init(&conn->server_write_mac_ctx, conn->key_block + 32, 32);
	sm4_set_decrypt_key(&conn->client_write_enc_key, conn->key_block + 64);
	sm4_set_encrypt_key(&conn->server_write_enc_key, conn->key_block + 80);
	tls_secrets_print(stderr, pre_master_secret, 32, client_random, server_random,
		conn->master_secret, conn->key_block, 96, 0, 0);


	if (handshakes) {
		tls_trace("<<<< CertificateVerify\n");
		if (tls_record_recv(record, &recordlen, conn->sock) != 1
			|| tls_record_version(record) != TLS_version_tls12) {
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

	tls_trace("<<<< [ChangeCipherSpec]\n");
	if (tls12_record_recv(record, &recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, 0, 0);
	if (tls_record_get_change_cipher_spec(record) != 1) {
		error_print();
		return -1;
	}

	tls_trace("<<<< ClientFinished\n");
	if (tls12_record_recv(record, &recordlen, conn->sock) != 1) {
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
	tls_prf(conn->master_secret, 48, "client finished",
		sm3_hash, 32, NULL, 0,
		12, local_verify_data);
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
	tls_prf(conn->master_secret, 48, "server finished",
		sm3_hash, 32, NULL, 0,
		12, verify_data);
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
