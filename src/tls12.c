/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <gmssl/rand.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/pem.h>
#include <gmssl/mem.h>
#include <gmssl/tls.h>



// 实际上这个功能本质上是把缓冲区的数据发出去
static const int tls12_ciphers[] = {
	TLS_cipher_ecdhe_sm4_cbc_sm3,
	TLS_cipher_ecdhe_sm4_gcm_sm3,
	TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256,
};


int tls12_record_print(FILE *fp, const uint8_t *record,  size_t recordlen, int format, int indent)
{
	// 目前只支持TLCP的ECC公钥加密套件，因此不论用哪个套件解析都是一样的
	// 如果未来支持ECDHE套件，可以将函数改为宏，直接传入 (conn->cipher_suite << 8)
	format |= tls12_ciphers[0] << 8; // 应该是KeyExchange需要这个参数			
	return tls_record_print(fp, record, recordlen, format, indent);
}

// 这里主要的问题是我们没有 cbc_encrypt_blocks 这个函数啊


void cbc_encrypt_blocks(const BLOCK_CIPHER_KEY *key, uint8_t iv[16],
	const uint8_t *in, size_t nblocks, uint8_t *out)
{
	const uint8_t *piv = iv;

	while (nblocks--) {
		size_t i;
		for (i = 0; i < 16; i++) {
			out[i] = in[i] ^ piv[i];
		}
		block_cipher_encrypt(key, out, out);
		piv = out;
		in += 16;
		out += 16;
	}

	memcpy(iv, piv, 16);
}

void cbc_decrypt_blocks(const BLOCK_CIPHER_KEY *key, uint8_t iv[16],
	const uint8_t *in, size_t nblocks, uint8_t *out)
{
	const uint8_t *piv = iv;

	while (nblocks--) {
		size_t i;
		block_cipher_decrypt(key, in, out);
		for (i = 0; i < 16; i++) {
			out[i] ^= piv[i];
		}
		piv = in;
		in += 16;
		out += 16;
	}

	memcpy(iv, piv, 16);
}


// 这个函数只有在哈希函数为HASH256时才是正确的
int tls12_cbc_encrypt(const HMAC_CTX *inited_hmac_ctx, const BLOCK_CIPHER_KEY *enc_key,
	const uint8_t seq_num[8], const uint8_t header[5],
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	HMAC_CTX hmac_ctx;
	uint8_t last_blocks[32 + 16] = {0};
	uint8_t iv[16];
	uint8_t *mac, *padding;
	size_t maclen;
	int rem, padding_len;
	int i;

	if (!inited_hmac_ctx || !enc_key || !seq_num || !header || (!in && inlen) || !out || !outlen) {
		error_print();
		return -1;
	}
	if (inlen > (1 << 14)) {
		error_print();
		return -1;
	}
	if ((((size_t)header[3]) << 8) + header[4] != inlen) {
		error_print();
		return -1;
	}

	rem = (inlen + 32) % 16;
	memcpy(last_blocks, in + inlen - rem, rem);
	mac = last_blocks + rem;

	memcpy(&hmac_ctx, inited_hmac_ctx, sizeof(HMAC_CTX));
	hmac_update(&hmac_ctx, seq_num, 8);
	hmac_update(&hmac_ctx, header, 5);
	hmac_update(&hmac_ctx, in, inlen);
	hmac_finish(&hmac_ctx, mac, &maclen);

	padding = mac + 32;
	padding_len = 16 - rem - 1;
	for (i = 0; i <= padding_len; i++) {
		padding[i] = (uint8_t)padding_len;
	}

	if (rand_bytes(iv, 16) != 1) {
		error_print();
		return -1;
	}
	memcpy(out, iv, 16);
	out += 16;

	if (inlen >= 16) {
		cbc_encrypt_blocks(enc_key, iv, in, inlen/16, out);
		out += inlen - rem;
	}
	cbc_encrypt_blocks(enc_key, iv, last_blocks, sizeof(last_blocks)/16, out);

	*outlen = 16 + inlen - rem + sizeof(last_blocks);
	return 1;
}

int tls12_cbc_decrypt(const HMAC_CTX *inited_hmac_ctx, const BLOCK_CIPHER_KEY *dec_key,
	const uint8_t seq_num[8], const uint8_t enced_header[5],
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	HMAC_CTX hmac_ctx;
	uint8_t iv[16];
	const uint8_t *padding;
	const uint8_t *mac;
	uint8_t header[5];
	int padding_len;
	uint8_t hmac[32];
	size_t hmaclen;
	int i;

	if (!inited_hmac_ctx || !dec_key || !seq_num || !enced_header || !in || !inlen || !out || !outlen) {
		error_print();
		return -1;
	}
	if (inlen % 16
		|| inlen < (16 + 0 + 32 + 16) // iv + data +  mac + padding
		|| inlen > (16 + (1<<14) + 32 + 256)) {
		error_print_msg("invalid tls cbc ciphertext length %zu\n", inlen);
		return -1;
	}

	memcpy(iv, in, 16);
	in += 16;
	inlen -= 16;

	cbc_decrypt_blocks(dec_key, iv, in, inlen/16, out);

	padding_len = out[inlen - 1];
	padding = out + inlen - padding_len - 1;
	if (padding < out + 32) {
		error_print();
		return -1;
	}
	for (i = 0; i < padding_len; i++) {
		if (padding[i] != padding_len) {
			error_puts("tls ciphertext cbc-padding check failure");
			return -1;
		}
	}

	*outlen = inlen - 32 - padding_len - 1;

	header[0] = enced_header[0];
	header[1] = enced_header[1];
	header[2] = enced_header[2];
	header[3] = (uint8_t)((*outlen) >> 8);
	header[4] = (uint8_t)(*outlen);
	mac = padding - 32;

	memcpy(&hmac_ctx, inited_hmac_ctx, sizeof(HMAC_CTX));
	hmac_update(&hmac_ctx, seq_num, 8);
	hmac_update(&hmac_ctx, header, 5);
	hmac_update(&hmac_ctx, out, *outlen);
	hmac_finish(&hmac_ctx, hmac, &hmaclen);

	if (gmssl_secure_memcmp(mac, hmac, sizeof(hmac)) != 0) {
		error_puts("tls ciphertext mac check failure\n");
		return -1;
	}
	return 1;
}

int tls12_record_encrypt(const HMAC_CTX *hmac_ctx, const BLOCK_CIPHER_KEY *cbc_key,
	const uint8_t seq_num[8], const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	if (tls12_cbc_encrypt(hmac_ctx, cbc_key, seq_num, in,
		in + 5, inlen - 5,
		out + 5, outlen) != 1) {
		error_print();
		return -1;
	}

	out[0] = in[0];
	out[1] = in[1];
	out[2] = in[2];
	out[3] = (uint8_t)((*outlen) >> 8);
	out[4] = (uint8_t)(*outlen);
	(*outlen) += 5;
	return 1;
}

int tls12_record_decrypt(const HMAC_CTX *hmac_ctx, const BLOCK_CIPHER_KEY *cbc_key,
	const uint8_t seq_num[8], const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	if (tls12_cbc_decrypt(hmac_ctx, cbc_key, seq_num, in,
		in + 5, inlen - 5,
		out + 5, outlen) != 1) {
		error_print();
		return -1;
	}

	out[0] = in[0];
	out[1] = in[1];
	out[2] = in[2];
	out[3] = (uint8_t)((*outlen) >> 8);
	out[4] = (uint8_t)(*outlen);
	(*outlen) += 5;

	return 1;
}

// 这个函数只依赖哈希
int tls12_prf(const DIGEST *digest, const uint8_t *secret, size_t secretlen, const char *label,
	const uint8_t *seed, size_t seedlen,
	const uint8_t *more, size_t morelen,
	size_t outlen, uint8_t *out)
{
	HMAC_CTX inited_hmac_ctx;
	HMAC_CTX hmac_ctx;
	uint8_t A[32];
	uint8_t hmac[32];
	size_t len;

	if (!secret || !secretlen || !label || !seed || !seedlen
		|| (!more && morelen) || !outlen || !out) {
		error_print();
		return -1;
	}

	hmac_init(&inited_hmac_ctx, digest, secret, secretlen);

	memcpy(&hmac_ctx, &inited_hmac_ctx, sizeof(HMAC_CTX));
	hmac_update(&hmac_ctx, (uint8_t *)label, strlen(label));
	hmac_update(&hmac_ctx, seed, seedlen);
	hmac_update(&hmac_ctx, more, morelen);
	hmac_finish(&hmac_ctx, A, &len); // 检查或者使用长度len

	memcpy(&hmac_ctx, &inited_hmac_ctx, sizeof(HMAC_CTX));
	hmac_update(&hmac_ctx, A, sizeof(A));
	hmac_update(&hmac_ctx, (uint8_t *)label, strlen(label));
	hmac_update(&hmac_ctx, seed, seedlen);
	hmac_update(&hmac_ctx, more, morelen);
	hmac_finish(&hmac_ctx, hmac, &len);

	len = outlen < sizeof(hmac) ? outlen : sizeof(hmac);
	memcpy(out, hmac, len);
	out += len;
	outlen -= len;

	while (outlen) {
		memcpy(&hmac_ctx, &inited_hmac_ctx, sizeof(HMAC_CTX));
		hmac_update(&hmac_ctx, A, sizeof(A));
		hmac_finish(&hmac_ctx, A, &len);

		memcpy(&hmac_ctx, &inited_hmac_ctx, sizeof(HMAC_CTX));
		hmac_update(&hmac_ctx, A, sizeof(A));
		hmac_update(&hmac_ctx, (uint8_t *)label, strlen(label));
		hmac_update(&hmac_ctx, seed, seedlen);
		hmac_update(&hmac_ctx, more, morelen);
		hmac_finish(&hmac_ctx, hmac, &len);

		len = outlen < sizeof(hmac) ? outlen : sizeof(hmac);
		memcpy(out, hmac, len);
		out += len;
		outlen -= len;
	}
	return 1;
}




// modify: conn->record_offset
int tls_send_record(TLS_CONNECT *conn)
{
	size_t left;
	tls_ret_t n;

	left = tls_record_length(conn->record) - conn->record_offset;
	while (left) {
		n = tls_socket_send(conn->sock, conn->record + conn->record_offset, left, 0);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return TLS_ERROR_SEND_AGAIN;
			} else if (errno == EINTR) {
				continue;
			} else {
				fprintf(stderr, "%s %d: send() error: %s\n", __FILE__, __LINE__, strerror(errno));
				error_print();
				return -1;
			}
		}
		conn->record_offset += n;
		left -= n;
	}
	return 1;
}

int tls_recv_record(TLS_CONNECT *conn)
{
	size_t left;
	tls_ret_t n;

	if (conn->recordlen) {
		return 1;
	}

	if (conn->record_offset < 5) {
		left = 5 - conn->record_offset;
		while (left) {
			n = tls_socket_recv(conn->sock, conn->record + conn->record_offset, left, 0);
			if (n < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					return TLS_ERROR_RECV_AGAIN;
				} else if (errno == EINTR) {
					continue;
				} else {
					error_print();
					// TODO: check the usage of OpenSSL SSL_ERR_SYSCALL
					// if applications such as Nginx, HTTPD do not use this error, we just return -1
					return TLS_ERROR_SYSCALL;
				}
			} else if (n == 0) {
				error_print();
				return TLS_ERROR_TCP_CLOSED;
			}
			conn->record_offset += n;
			left -= n;
		}
	}

	if (conn->record_offset == 5) {
		if (!tls_record_type_name(tls_record_type(conn->record))) {
			error_print();
			return -1;
		}
		if (!tls_protocol_name(tls_record_protocol(conn->record))) {
			error_print();
			return -1;
		}
		if (tls_record_length(conn->record) > TLS_MAX_RECORD_SIZE) {
			error_print();
			return -1;
		}
	}

	if (conn->record_offset >= tls_record_length(conn->record)) {
		error_print();
		return -1;
	}
	left = tls_record_length(conn->record) - conn->record_offset;
	while (left) {
		n = tls_socket_recv(conn->sock, conn->record + conn->record_offset, left, 0);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return TLS_ERROR_RECV_AGAIN;
			} else if (errno == EINTR) {
				continue;
			} else {
				error_print();
				return TLS_ERROR_SYSCALL;
			}
		} else if (n == 0) {
			error_print();
			return TLS_ERROR_TCP_CLOSED;
		}
		conn->record_offset += n;
		left -= n;

	}

	conn->recordlen = conn->record_offset;


	// 应该判断是否为Alert这种异常状况

	return 1;
}

int tls_named_curve_oid(int named_curve)
{
	switch (named_curve) {
	case TLS_curve_secp256r1: return OID_secp256r1;
	case TLS_curve_sm2p256v1: return OID_sm2;
	}
	return OID_undef;
}

int tls_named_curve_from_oid(int oid)
{
	switch (oid) {
	case OID_secp256r1: return TLS_curve_secp256r1;
	case OID_sm2: return TLS_curve_sm2p256v1;
	}
	return 0;
}




















// 这个是必选的

// 服务器通常推荐返回这个值
const int supported_groups[] = {
	TLS_curve_sm2p256v1,
	TLS_curve_secp256r1,
};
size_t supported_groups_cnt = sizeof(supported_groups)/sizeof(supported_groups[0]);

// 仍旧是不可设置的
const int signature_algors[] = {
	TLS_sig_sm2sig_sm3,
	TLS_sig_ecdsa_secp256r1_sha256,
};
size_t signature_algors_cnt = sizeof(signature_algors)/sizeof(signature_algors[0]);



int tls_record_set_handshake_server_key_exchange(uint8_t *record, size_t *recordlen,
	const uint8_t *server_ecdh_params, size_t server_ecdh_params_len,
	uint16_t sig_alg, const uint8_t *sig, size_t siglen)
{
	const int type = TLS_handshake_server_key_exchange;
	uint8_t *p = tls_handshake_data(tls_record_data(record));
	size_t len = 0;

	if (server_ecdh_params_len != 69) {
		error_print();
		return -1;
	}
	if (siglen > TLS_MAX_SIGNATURE_SIZE) {
		error_print();
		return -1;
	}
	tls_array_to_bytes(server_ecdh_params, server_ecdh_params_len, &p, &len);
	tls_uint16_to_bytes(sig_alg, &p, &len);
	tls_uint16array_to_bytes(sig, siglen, &p, &len);
	tls_record_set_handshake(record, recordlen, type, NULL, len);
	return 1;
}

// 这个函数是有问题的，因为tlcp的格式和TLS不一样
int tls_record_get_handshake_server_key_exchange(const uint8_t *record,
	uint8_t *curve_type, uint16_t *named_curve,
	const uint8_t **point_octets, size_t *point_octets_len,
	const uint8_t **server_ecdh_params, size_t *server_ecdh_params_len,
	uint16_t *sig_alg, const uint8_t **sig, size_t *siglen)
{
	int type;
	const uint8_t *p;
	size_t len;

	if (tls_record_get_handshake(record, &type, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_server_key_exchange) {
		error_print();
		return -1;
	}

	*server_ecdh_params = p;
	if (tls_uint8_from_bytes(curve_type, &p, &len) != 1
		|| tls_uint16_from_bytes(named_curve, &p, &len) != 1
		|| tls_uint8array_from_bytes(point_octets, point_octets_len, &p, &len) != 1) {
		error_print();
		return -1;
	}
	*server_ecdh_params_len = p - *server_ecdh_params;
	if (*server_ecdh_params_len != 69) {
		error_print();
		return -1;
	}
	if (tls_uint16_from_bytes(sig_alg, &p, &len) != 1
		|| tls_uint16array_from_bytes(sig, siglen, &p, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	if (*curve_type != TLS_curve_type_named_curve) {
		error_print();
		return -1;
	}
	if (!tls_named_curve_name(*named_curve)) {
		error_print();
		return -1;
	}
	if (!tls_signature_scheme_name(*sig_alg)) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_record_set_handshake_client_key_exchange(uint8_t *record, size_t *recordlen,
	const uint8_t *point_octets, size_t point_octets_len)
{
	int type = TLS_handshake_client_key_exchange;
	uint8_t *p = tls_handshake_data(tls_record_data(record));
	size_t len = 0;

	if (point_octets_len != 65) {
		error_print();
		return -1;
	}
	tls_uint8array_to_bytes(point_octets, (uint8_t)point_octets_len, &p, &len);
	tls_record_set_handshake(record, recordlen, type, NULL, len);
	return 1;
}

int tls_record_get_handshake_client_key_exchange(const uint8_t *record,
	const uint8_t **point_octets, size_t *point_octets_len)
{
	int type;
	const uint8_t *p;
	size_t len;

	if (tls_record_get_handshake(record, &type, &p, &len) != 1
		|| type != TLS_handshake_client_key_exchange) {
		error_print();
		return -1;
	}
	if (tls_uint8array_from_bytes(point_octets, point_octets_len, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (*point_octets_len != 65) {
		error_print();
		return -1;
	}
	if (len) {
		error_print();
		return -1;
	}
	return 1;
}

void tls_clean_record(TLS_CONNECT *conn)
{
	conn->record_offset = 0;
	conn->recordlen = 0;
}


int tls_handshake_init(TLS_CONNECT *conn)
{

	//sm3_init(&conn->sm3_ctx);
	digest_init(&conn->dgst_ctx, DIGEST_sm3());


	if (conn->client_certs_len) {
		//sm2_sign_init(&conn->sign_ctx, &conn->sign_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH);
	}

	return 1;
}



int tls_send_client_hello(TLS_CONNECT *conn)
{
	int ret;

	if (!conn->recordlen) {
		const int ec_point_formats[] = { TLS_point_uncompressed };
		size_t ec_point_formats_cnt = sizeof(ec_point_formats)/sizeof(ec_point_formats[0]);
		uint8_t exts[TLS_MAX_EXTENSIONS_SIZE];
		uint8_t *pexts = exts;
		size_t extslen = 0;

		tls_trace("send ClientHello\n");

		tls_record_set_protocol(conn->record, TLS_protocol_tls1);

		if (tls_random_generate(conn->client_random) != 1) {
			error_print();
			return -1;
		}

		// ec_point_formats
		if (tls_ec_point_formats_ext_to_bytes(
			ec_point_formats, ec_point_formats_cnt, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}

		// supported_groups
		if (conn->ctx->supported_groups_cnt) {
			if (tls_supported_groups_ext_to_bytes(conn->ctx->supported_groups,
				conn->ctx->supported_groups_cnt, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// signature_algorithms
		if (conn->ctx->signature_algorithms_cnt) {
			if (tls_signature_algorithms_ext_to_bytes(conn->ctx->signature_algorithms,
				conn->ctx->signature_algorithms_cnt, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		if (tls_record_set_handshake_client_hello(conn->record, &conn->recordlen,
			conn->protocol, conn->client_random, NULL, 0,
			conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt,
			exts, extslen) != 1) {
			error_print();
			return -1;
		}

		tls12_record_print(stderr, conn->record, conn->recordlen, 0, 0);

		// backup ClientHello
		memcpy(conn->plain_record, conn->record, conn->recordlen);
		conn->plain_recordlen = conn->recordlen;
	}

	/*
	if (conn->client_certificate_verify) {
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);
	}
	*/

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	tls_clean_record(conn);
	return 1;
}

/*
const int server_ciphers[] = { TLS_cipher_ecdhe_sm4_cbc_sm3 };
const size_t server_ciphers_cnt = 1;
*/
const int curve = TLS_curve_sm2p256v1;


int tls_recv_client_hello(TLS_CONNECT *conn)
{
	int ret;

	int client_verify = 0;

	int protocol;
	const uint8_t *client_random;
	const uint8_t *session_id;
	size_t session_id_len;
	const uint8_t *cipher_suites;
	size_t cipher_suites_len;
	const uint8_t *exts;
	size_t extslen;

	/*
	if (client_verify)
		tls_client_verify_init(&conn->client_verify_ctx);
	*/


	tls_trace("recv ClientHello\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);

	if (tls_record_protocol(conn->record) != TLS_protocol_tls1) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	if ((ret = tls_record_get_handshake_client_hello(conn->record,
		&protocol, &client_random, &session_id, &session_id_len,
		&cipher_suites, &cipher_suites_len, &exts, &extslen)) < 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	if (protocol != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	memcpy(conn->client_random, client_random, 32);

	if ((ret = tls_cipher_suites_select(cipher_suites, cipher_suites_len,
		conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt,
		&conn->cipher_suite)) < 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_handshake_failure);
		return -1;
	}

	/*
	TLS_cipher_ecdhe_sm4_cbc_sm3
	TLS_cipher_ecdhe_sm4_gcm_sm3
	TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256
	*/

	conn->cipher = BLOCK_CIPHER_sm4();
	conn->digest = DIGEST_sm3();

	/*
	switch (conn->cipher_suite) {
	case TLS_cipher_ecdhe_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_sm4_gcm_sm3:
		conn->signature_algorithms[0] = TLS_sig_sm2sig_sm3;
		conn->ecdh_named_curve = TLS_curve_sm2p256v1;
		break;
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
		conn->signature_algorithms[0] = TLS_sig_ecdsa_secp256r1_sha256;
		conn->ecdh_named_curve = TLS_curve_secp256r1;
		break;
	default:
		error_print();
		return -1;
	}
	*/

	while (extslen) {
		int ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;

		if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}


		// 这些扩展都不是必须的


	}


	if (digest_init(&conn->dgst_ctx, conn->digest) != 1) {
		error_print();
		return -1;
	}
	if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
		error_print();
		return -1;
	}

	/*
	if (client_verify)
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);

	*/

	fprintf(stderr, "end of recv_client_hello\n");
	tls_clean_record(conn);
	return 1;
}

int tls_send_server_hello(TLS_CONNECT *conn)
{
	int ret;

	tls_trace("send ServerHello\n");

	if (conn->recordlen == 0) {
		const uint8_t *server_exts = NULL;
		size_t server_exts_len = 0;

		tls_record_set_protocol(conn->record, conn->protocol);
		if (tls_random_generate(conn->server_random) != 1) {
			error_print();
			return -1;
		}
		// 修改处理扩展的逻辑，把ClientHello的每个扩展处理结果分别放在conn的各个变量中
		/*
		if (conn->server_exts_len) {
			server_exts = conn->server_exts;
			server_exts_len = conn->server_exts_len;
		}
		*/
		if (tls_record_set_handshake_server_hello(conn->record, &conn->recordlen,
			conn->protocol, conn->server_random, NULL, 0,
			conn->cipher_suite,
			server_exts, server_exts_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	//sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	if (conn->ctx->cacertslen) {
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);
	}

	tls_clean_record(conn);
	return 1;
}

int tls_recv_server_hello(TLS_CONNECT *conn)
{
	int ret;
	int protocol;
	int cipher_suite;
	const uint8_t *server_random;
	const uint8_t *session_id;
	size_t session_id_len;
	const uint8_t *exts;
	size_t extslen;

	const uint8_t *ec_point_formats = NULL;
	size_t ec_point_formats_len;
	const uint8_t *supported_groups = NULL;
	size_t supported_groups_len;
	const uint8_t *signature_algorithms = NULL;
	size_t signature_algorithms_len;

	tls_trace("recv ServerHello\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	tls12_record_print(stderr, conn->record, conn->recordlen, 0, 0);

	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	if ((ret = tls_record_get_handshake_server_hello(conn->record,
		&protocol, &server_random, &session_id, &session_id_len, &cipher_suite,
		&exts, &extslen)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	// version
	if (protocol != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	// random
	memcpy(conn->server_random, server_random, 32);

	// session_id
	memcpy(conn->session_id, session_id, session_id_len);

	// cipher_suite
	if (tls_type_is_in_list(cipher_suite, conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_handshake_failure);
		return -1;
	}
	conn->cipher_suite = cipher_suite;


	// 初始化digest
	conn->digest = DIGEST_sha256();

	conn->cipher = BLOCK_CIPHER_aes128();


	if (digest_init(&conn->dgst_ctx, conn->digest) != 1) {
		error_print();
		return -1;
	}


	while (extslen) {
		int ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;

		if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}

		// extensions in ServerHello
		//  * ec_point_formats
		//  * supported_groups
		//  * signature_algorithms

		switch (ext_type) {
		case TLS_extension_ec_point_formats:
		case TLS_extension_supported_groups:
		case TLS_extension_signature_algorithms:
			if (!ext_data) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			break;
		default:
			error_print();
			return -1;
		}

		switch (ext_type) {
		case TLS_extension_ec_point_formats:
			if (ec_point_formats) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			ec_point_formats = ext_data;
			ec_point_formats_len = ext_datalen;
			break;

		case TLS_extension_supported_groups:
			if (supported_groups) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			supported_groups = ext_data;
			supported_groups_len = ext_datalen;
			break;

		case TLS_extension_signature_algorithms:
			if (signature_algorithms) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			signature_algorithms = ext_data;
			signature_algorithms_len = ext_datalen;
			break;
		}
	}

	if (!ec_point_formats) {
		error_print();
		tls13_send_alert(conn, TLS_alert_missing_extension);
		return -1;
	}

	if (supported_groups) {
	}

	if (signature_algorithms) {
	}



	if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	tls_handshake_digest_print(stderr, 0, 0, "ClientHello", &conn->dgst_ctx);

	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	tls_handshake_digest_print(stderr, 0, 0, "ServerHello", &conn->dgst_ctx);



	//sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	if (conn->client_certs_len) {
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);
	}

	return 1;
}

// TLS12 发送的是常规的证书链
// TLCP SM2 发送的是SM2的双证书链，但是在数据格式上没有区别
// TLCP SM9 发送的是服务器的ID和SM9公开参数（这个格式是不同的），但是存储上可能也是一样的
// 我不确定SM2和SM9的格式是否是相容的			
int tls_send_server_certificate(TLS_CONNECT *conn)
{
	int ret;
	tls_trace("send ServerCertificate\n");

	if (conn->recordlen == 0) {
		if (tls_record_set_handshake_certificate(conn->record, &conn->recordlen,
			conn->server_certs, conn->server_certs_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	//sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	if (conn->client_certificate_verify) {
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);
	}
	return 1;
}

int tls_recv_server_certificate(TLS_CONNECT *conn)
{
	int ret;
	int verify_result;
	const uint8_t *server_cert;
	size_t server_cert_len;
	X509_KEY server_sign_key;


	tls_trace("recv server Certificate\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);

	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	if ((ret = tls_record_get_handshake_certificate(conn->record,
		conn->peer_cert_chain, &conn->peer_cert_chain_len)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return 0;
	}

	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	tls_handshake_digest_print(stderr, 0, 0, "Certificate", &conn->dgst_ctx);


	// 这里取服务器证书似乎没有什么用处啊
	if (x509_certs_get_cert_by_index(conn->peer_cert_chain, conn->peer_cert_chain_len, 0,
		&server_cert, &server_cert_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}
	if (x509_cert_get_subject_public_key(server_cert, server_cert_len, &server_sign_key) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}


	// 这里的逻辑需要统筹考虑				
	// cipher_suite，扩展，证书之间的关系

	// set conn->server_sig_alg (decided by cipher_suite and server_cert.sign_key.algor, algor_param)
	if (server_sign_key.algor != OID_ec_public_key) {
		error_print();
		return -1;
	}
	switch (conn->cipher_suite) {
	case TLS_cipher_ecdhe_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_sm4_gcm_sm3:
	case TLS_cipher_ecc_sm4_cbc_sm3:
	case TLS_cipher_ecc_sm4_gcm_sm3:
		if (server_sign_key.algor_param != OID_sm2) {
			error_print();
			return -1;
		}
		conn->signature_algorithms[0] = TLS_sig_sm2sig_sm3;
		break;

	case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
		if (server_sign_key.algor_param != OID_secp256r1) {
			error_print();
			return -1;
		}
		conn->signature_algorithms[0] = TLS_sig_ecdsa_secp256r1_sha256;
		break;
	default:
		error_print();
		return -1;
	}

	if (conn->client_certs_len) {
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);
	}

	assert(conn->ctx->verify_depth > 0 && conn->ctx->verify_depth < 10);

	// verify ServerCertificate

	if (conn->ctx->cacertslen) {

		// 按道理来说，这只是验证证书，并应该出错啊
		if (x509_certs_verify_tlcp(conn->peer_cert_chain, conn->peer_cert_chain_len, X509_cert_chain_server,
			conn->ctx->cacerts, conn->ctx->cacertslen, conn->ctx->verify_depth, &verify_result) != 1) {
			error_print();
			//tls_send_alert(conn, TLS_alert_bad_certificate);
			//return -1;
		}
	}

	return 1;
}



int tls_send_server_key_exchange(TLS_CONNECT *conn)
{
	int ret;
	uint8_t server_ecdh_params[69];
	uint8_t *p = server_ecdh_params + 4;
	size_t len = 0;
	X509_SIGN_CTX sign_ctx;
	const void *sign_args = NULL;
	size_t sign_argslen = 0;
	uint8_t sig[X509_SIGNATURE_MAX_SIZE];
	size_t siglen;

	tls_trace("send ServerKeyExchange\n");

	if (conn->recordlen == 0) {
		int curve_oid = tls_named_curve_oid(conn->ecdh_named_curve);
		// generate server ecdh_key
		if (x509_key_generate(&conn->ecdh_key, OID_ec_public_key, &curve_oid, sizeof(curve_oid)) != 1) {
			error_print();
			return -1;
		}

		// build server_ecdh_params
		server_ecdh_params[0] = TLS_curve_type_named_curve;
		server_ecdh_params[1] = conn->ecdh_named_curve >> 8;
		server_ecdh_params[2] = (uint8_t)conn->ecdh_named_curve;
		server_ecdh_params[3] = 65;
		if (x509_public_key_to_bytes(&conn->ecdh_key, &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (len != 65) {
			error_print();
			return -1;
		}

		// sign server_ecdh_params
		if (conn->sign_key.algor == OID_ec_public_key && conn->sign_key.algor_param == OID_sm2) {
			sign_args = SM2_DEFAULT_ID;
			sign_argslen = SM2_DEFAULT_ID_LENGTH;
		}
		if (x509_sign_init(&sign_ctx, &conn->sign_key, sign_args, sign_argslen) != 1
			|| x509_sign_update(&sign_ctx, conn->client_random, 32) != 1
			|| x509_sign_update(&sign_ctx, conn->server_random, 32) != 1
			|| x509_sign_update(&sign_ctx, server_ecdh_params, 69) != 1
			|| x509_sign_finish(&sign_ctx, sig, &siglen) != 1) {
			x509_sign_ctx_cleanup(&sign_ctx);
			error_print();
			return -1;
		}
		x509_sign_ctx_cleanup(&sign_ctx);

		if (tls_record_set_handshake_server_key_exchange(conn->record, &conn->recordlen,
			server_ecdh_params, sizeof(server_ecdh_params),
			conn->signature_algorithms[0], sig, siglen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);
	}


	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	//sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	if (conn->client_certificate_verify) {
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);
	}

	return 1;
}

// match the ecdhe of cipher_suite
int tls_curve_match_cipher_suite(int named_curve, int cipher_suite)
{
	switch (named_curve) {
	case TLS_curve_sm2p256v1:
		switch (cipher_suite) {
		case TLS_cipher_ecdhe_sm4_cbc_sm3:
		case TLS_cipher_ecdhe_sm4_gcm_sm3:
			break;
		default:
			error_print();
			return -1;
		}
		break;
	case TLS_curve_secp256r1:
		if (cipher_suite != TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

int tls_signature_scheme_match_cipher_suite(int sig_alg, int cipher_suite)
{
	switch (sig_alg) {
	case TLS_sig_sm2sig_sm3:
		switch (cipher_suite) {
		case TLS_cipher_ecdhe_sm4_cbc_sm3:
		case TLS_cipher_ecdhe_sm4_gcm_sm3:
		case TLS_cipher_ecc_sm4_cbc_sm3:
		case TLS_cipher_ecc_sm4_gcm_sm3:
			break;
		default:
			error_print();
			return -1;
		}
		break;
	case TLS_sig_ecdsa_secp256r1_sha256:
		switch (cipher_suite) {
		case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
			break;
		default:
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

int tls_recv_server_key_exchange(TLS_CONNECT *conn)
{
	int ret;
	uint8_t curve_type;
	uint16_t named_curve;
	const uint8_t *point_octets;
	size_t point_octets_len;
	const uint8_t *server_ecdh_params;
	size_t server_ecdh_params_len;
	uint16_t sig_alg;
	const uint8_t *sig;
	size_t siglen;

	// verify ServerKeyExchange
	X509_KEY server_sign_key;

	int server_cert_index = 0;
	const uint8_t *server_cert;
	size_t server_cert_len;

	X509_SIGN_CTX sign_ctx;
	const void *sign_args = NULL;
	size_t sign_argslen = 0;

	tls_trace("recv ServerKeyExchange\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);


	// 这个函数可能是有问题的，如果cipher_suite不同，ServerKeyExchange可能也是不同的
	if ((ret = tls_record_get_handshake_server_key_exchange(conn->record,
		&curve_type, &named_curve, &point_octets, &point_octets_len,
		&server_ecdh_params, &server_ecdh_params_len,
		&sig_alg, &sig, &siglen)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return 0;
	}

	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	tls_handshake_digest_print(stderr, 0, 0, "ServerKeyExchange", &conn->dgst_ctx);

	if (curve_type != TLS_curve_type_named_curve) {
		error_print();
		return -1;
	}
	// named_curve应该在supported_groups里面

	//conn->ecdh_named_curve = named_curve;


	conn->key_exchange_group = named_curve;
	memcpy(conn->peer_key_exchange, point_octets, point_octets_len);
	conn->peer_key_exchange_len = point_octets_len;



	if (point_octets_len != 65) {
		error_print();
		return -1;
	}


	if (tls_curve_match_cipher_suite(named_curve, conn->cipher_suite) != 1) {
		error_print();
		return -1;
	}
	if (point_octets_len != 65) {
		error_print();
		return -1;
	}
	if (tls_signature_scheme_match_cipher_suite(sig_alg, conn->cipher_suite) != 1) {
		error_print();
		return -1;
	}

	// 解析server_key_exchange, curve_type, curve_name, point 这三个信息
	// 判断curve_type == named_curve
	// 判断curve_name在supported_groups中并记录这个信息
	// 验证point确实在curve_name的group中

	//sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	if (conn->client_certs_len)
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);





	if (x509_certs_get_cert_by_index(conn->peer_cert_chain, conn->peer_cert_chain_len,
		server_cert_index, &server_cert, &server_cert_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}
	if (x509_cert_get_subject_public_key(server_cert, server_cert_len, &server_sign_key) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}





	// 这个检查是否是多余的？			
	// 这个值是签名算法和椭圆曲线名字的结合
	// cipher_suite只能决定签名算法类型
	// 公钥证书里面的公钥实际上只包含曲线的类型（而不决定签名算法，因为一个椭圆曲线本质上支持多种不同的签名算法）
	switch (sig_alg) {
	case TLS_sig_sm2sig_sm3:
		if (server_sign_key.algor != OID_ec_public_key
			|| server_sign_key.algor_param != OID_sm2) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_certificate);
			return -1;
		}
		break;
	case TLS_sig_ecdsa_secp256r1_sha256:
		if (server_sign_key.algor != OID_ec_public_key
			|| server_sign_key.algor_param != OID_secp256r1) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_certificate);
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}

	if (server_sign_key.algor == OID_ec_public_key && server_sign_key.algor_param == OID_sm2) {
		sign_args = SM2_DEFAULT_ID;
		sign_argslen = SM2_DEFAULT_ID_LENGTH;
	}

	// 这里应该是SM2的签名和验证
	if (x509_verify_init(&sign_ctx, &server_sign_key, sign_args, sign_argslen, sig, siglen) != 1
		|| x509_verify_update(&sign_ctx, conn->client_random, 32) != 1
		|| x509_verify_update(&sign_ctx, conn->server_random, 32) != 1
		|| x509_verify_update(&sign_ctx, server_ecdh_params, 69) != 1
		|| x509_verify_finish(&sign_ctx) != 1) {
		error_print();
		return -1;
	}

	fprintf(stderr, ">>>>>> ServerKeyExchange verify success\n");


	// xxxx
	// 这里的签名错了，肯定是sign_ctx就是不对的，因此是不可能正确的
	// 现在要做的是，必须确定server_key_exchange中都包括了哪些被签名的消息

	return 1;
}


int tls_send_certificate_request(TLS_CONNECT *conn)
{
	int ret;

	// 如果要进行客户端证书验证，服务器要提供验证的证书，但是所有证书的
	const uint8_t cert_types[] = { TLS_cert_type_ecdsa_sign };
	uint8_t ca_names[TLS_MAX_CA_NAMES_SIZE] = {0}; // TODO: 根据客户端验证CA证书列计算缓冲大小，或直接输出到record缓冲
	size_t ca_names_len = 0;


	if (!conn->client_certificate_verify) {
		error_print();
		return -1;
	}

	if (conn->recordlen == 0) {
		tls_trace("send CertificateRequest\n");
		if (tls_authorities_from_certs(ca_names, &ca_names_len, sizeof(ca_names),
			conn->ctx->cacerts, conn->ctx->cacertslen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		if (tls_record_set_handshake_certificate_request(conn->record, &conn->recordlen,
			cert_types, sizeof(cert_types),
			ca_names, ca_names_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	//sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);

	return 1;
}

int tls_recv_certificate_request(TLS_CONNECT *conn)
{
	int ret;
	uint8_t *record = conn->record;
	const uint8_t *cp;
	size_t len;
	int handshake_type;

	const uint8_t *cert_types;
	size_t cert_types_len;
	const uint8_t *ca_names;
	size_t ca_names_len;

	tls_trace("recv CertificateRequest*\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}

	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (tls_record_get_handshake(record, &handshake_type, &cp, &len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	if (handshake_type != TLS_handshake_certificate_request) {
		tls_trace("    no CertificateRequest\n");
		return 0; // 表明对方没有发送预期的报文
	}
	tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);


	if (tls_record_get_handshake_certificate_request(conn->record,
		&cert_types, &cert_types_len, &ca_names, &ca_names_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}

	// 这里要检查一下服务器发送的，和本地的是否保持一致
	/*
	if(!conn->client_certs_len) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}

	if (tls_cert_types_accepted(cert_types, cert_types_len, conn->client_certs, conn->client_certs_len) != 1
		|| tls_authorities_issued_certificate(ca_names, ca_names_len, conn->client_certs, conn->client_certs_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unsupported_certificate);
		return -1;
	}
	*/


	sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);

	conn->recordlen = 0;
	return 1;
}

int tls_send_server_hello_done(TLS_CONNECT *conn)
{
	int ret;
	tls_trace("send ServerHelloDone\n");


	if (conn->recordlen == 0) {
		tls_record_set_handshake_server_hello_done(conn->record, &conn->recordlen);
		tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);
	}


	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}
	//sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);

	if (conn->client_certs_len) {
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);
	}
	return 1;
}


// 这是一个非常特殊的状态，其他的所有recv状态都是要读取的
// 但是这个状态在大多数情况下，之前已经读取完了，但是我们无法判断这个信息
int tls_recv_server_hello_done(TLS_CONNECT *conn)
{
	int ret;
	tls_trace("recv ServerHelloDone\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);

	if (tls_record_get_handshake_server_hello_done(conn->record) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	tls_handshake_digest_print(stderr, 0, 0, "ServerHelloDone", &conn->dgst_ctx);



	if (conn->client_certs_len)
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);


	return 1;
}

int tls_send_client_certificate(TLS_CONNECT *conn)
{
	int ret;
	tls_trace("send ClientCertificate\n");

	if (conn->client_certs_len == 0) {
		error_print();
		return -1;
	}

	if (conn->recordlen == 0) {
		if (tls_record_set_handshake_certificate(conn->record, &conn->recordlen,
			conn->client_certs, conn->client_certs_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}


	//sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);

	return 1;
}

// 只有在需要验证客户端证书的时候这个函数才执行，是否内部要判断一下
int tls_recv_client_certificate(TLS_CONNECT *conn)
{
	int ret;
	const int verify_depth = 5;
	int verify_result;

	tls_trace("recv ClientCertificate\n");

	if (conn->ctx->cacertslen == 0) {
		error_print();
		return -1;
	}

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (tls_record_protocol(conn->record) != conn->protocol) { // protocol检查应该在trace之后
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);
	if (tls_record_get_handshake_certificate(conn->record, conn->client_certs, &conn->client_certs_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (x509_certs_verify(conn->client_certs, conn->client_certs_len, X509_cert_chain_client,
		conn->ctx->cacerts, conn->ctx->cacertslen, verify_depth, &verify_result) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}
	//sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);

	return 1;
}

/*
不同密码套件中使用的密钥生成方法不一样，需要的输入也不一样。
应该考虑在CONN中维护union版本的ServerKeyExchange和ClientKeyExchange

			ServerKeyExchange	ClientKeyExchange
	ECDHE Server	X509_KEY		X509_KEY public
	ECDHE Client	X509_KEY		X509_KEY public
	ECC Server	N/A			SM2Cipher
	ECC Client	N/A			N/A		客户端可能需要服务器公钥的类型


我们现在还不支持SM2的ECDH呢！
SM9相关的密码套件呢？





*/

int tls_generate_keys(TLS_CONNECT *conn)
{
	uint8_t pre_master_secret[32];
	size_t pre_master_secret_len;



	if (x509_key_exchange(&conn->key_exchanges[0],
		conn->peer_key_exchange, conn->peer_key_exchange_len,
		pre_master_secret, &pre_master_secret_len) != 1) {
		error_print();
		return -1;
	}
	if (pre_master_secret_len != sizeof(pre_master_secret)) {
		error_print();
		return -1;
	}

	if (tls12_prf(conn->digest, pre_master_secret, 32, "master secret",
			conn->client_random, 32,
			conn->server_random, 32,
			48, conn->master_secret) != 1) {
		error_print();
		return -1;
	}

	if (tls12_prf(conn->digest, conn->master_secret, 48, "key expansion",
			conn->server_random, 32,
			conn->client_random, 32,
			96, conn->key_block) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}

	if (hmac_init(&conn->client_write_mac_ctx, conn->digest, conn->key_block, 32) != 1) {
		error_print();
		return -1;
	}
	if (hmac_init(&conn->server_write_mac_ctx, conn->digest, conn->key_block + 32, 32) != 1) {
		error_print();
		return -1;
	}

	if (conn->is_client) {
		block_cipher_set_encrypt_key(&conn->client_write_key, conn->cipher, conn->key_block + 64);
		block_cipher_set_decrypt_key(&conn->server_write_key, conn->cipher, conn->key_block + 80);


	} else {
		block_cipher_set_decrypt_key(&conn->client_write_key, conn->cipher, conn->key_block + 64);
		block_cipher_set_encrypt_key(&conn->server_write_key, conn->cipher, conn->key_block + 80);
	}

	tls_seq_num_reset(conn->client_seq_num);
	tls_seq_num_reset(conn->server_seq_num);




	tls_secrets_print(stderr,
		pre_master_secret, 48,
		conn->client_random, conn->server_random,
		conn->master_secret,
		conn->key_block, 96,
		0, 4);

	return 1;
}


int tls_send_client_key_exchange(TLS_CONNECT *conn)
{
	int ret;

	// 客户端的ECDHE的公钥肯定和服务器是保持一致的
	// 因此在接收到服务器的公钥之后，应该保存这个信息


	// 客户端是怎么确定密钥交换的group的？大概是从ServerKeyExchange中确定的

	if (conn->recordlen == 0) {
		uint8_t point_octets[65];
		uint8_t *p = point_octets;
		size_t len = 0;
		int curve_oid = tls_named_curve_oid(conn->key_exchange_group);

		if (x509_key_generate(&conn->key_exchanges[0], OID_ec_public_key, &curve_oid, sizeof(curve_oid)) != 1) {
			error_print();
			return -1;
		}
		if (x509_public_key_to_bytes(&conn->key_exchanges[0], &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (len != sizeof(point_octets)) {
			error_print();
			return -1;
		}

		tls_trace("send ClientKeyExchange\n");
		if (tls_record_set_handshake_client_key_exchange(conn->record, &conn->recordlen,
			point_octets, len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);

		if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		tls_handshake_digest_print(stderr, 0, 0, "ClientKeyExchange", &conn->dgst_ctx);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	if (conn->client_certs_len)
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);

	return 1;
}

int tls_recv_client_key_exchange(TLS_CONNECT *conn)
{
	int ret;
	const uint8_t *point_octets;
	size_t point_octets_len;

	tls_trace("recv ClientKeyExchange\n");
	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);

	if (tls_record_get_handshake_client_key_exchange(conn->record,
		&point_octets, &point_octets_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (point_octets_len != 65) {
		error_print();
		return -1;
	}

	memcpy(conn->peer_ecdh_point, point_octets, point_octets_len);
	conn->peer_ecdh_point_len = point_octets_len;

	//sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	if (conn->ctx->cacertslen)
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);

	return 1;
}




int tls_send_certificate_verify(TLS_CONNECT *conn)
{
	int ret;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;

	tls_trace("send CertificateVerify\n");

	if (!conn->client_certificate_verify) {
		error_print();
		return -1;
	}

	if (conn->recordlen == 0) {
		if (sm2_sign_finish(&conn->sign_ctx, sig, &siglen) != 1) {
			error_print();
			return -1;
		}
		if (tls_record_set_handshake_certificate_verify(conn->record, &conn->recordlen, sig, siglen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	//sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	return 1;
}

int tls_recv_certificate_verify(TLS_CONNECT *conn)
{
	int ret;
	X509_KEY client_sign_key;

	const uint8_t *sig;
	size_t siglen;

	const uint8_t *client_cert;
	size_t client_cert_len;

	if (!conn->client_certificate_verify) {
		error_print();
		return -1;
	}

	tls_trace("recv CertificateVerify\n");
	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (tls_record_protocol(conn->record) != conn->protocol) {
		tls_send_alert(conn, TLS_alert_unexpected_message);
		error_print();
		return -1;
	}
	tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);

	// get signature from certificate_verify
	if (tls_record_get_handshake_certificate_verify(conn->record, &sig, &siglen) != 1) {
		tls_send_alert(conn, TLS_alert_unexpected_message);
		error_print();
		return -1;
	}

	// get sign_key from client certificate
	if (x509_certs_get_cert_by_index(conn->client_certs, conn->client_certs_len, 0,
		&client_cert, &client_cert_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}
	if (x509_cert_get_subject_public_key(client_cert, client_cert_len, &client_sign_key) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}
	// 这里是否要验证证书的类型呢？我们现在还不支持其他签名算法
	if (client_sign_key.algor != OID_ec_public_key
		|| client_sign_key.algor_param != OID_sm2) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}

	if (tls_client_verify_finish(&conn->client_verify_ctx, sig, siglen, &client_sign_key.u.sm2_key) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_decrypt_error);
		return -1;
	}
	//sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);

	return 1;
}

int tls_send_change_cipher_spec(TLS_CONNECT *conn)
{
	int ret;
	if (conn->recordlen == 0) {
		tls_trace("send [ChangeCipherSpec]\n");
		if (tls_record_set_change_cipher_spec(conn->record, &conn->recordlen) !=1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);
	}
	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}
	return 1;
}

int tls_recv_change_cipher_spec(TLS_CONNECT *conn)
{
	int ret;

	tls_trace("recv [ChangeCipherSpec]\n");
	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}

	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);
	if (tls_record_get_change_cipher_spec(conn->record) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	return 1;
}

int tls_send_client_finished(TLS_CONNECT *conn)
{
	int ret;


	if (conn->recordlen == 0) {
		tls_trace("send client {Finished}\n");

		uint8_t local_verify_data[12];


		DIGEST_CTX tmp_ctx;
		uint8_t dgst[32];
		size_t dgstlen;

		tmp_ctx = conn->dgst_ctx;

		digest_finish(&tmp_ctx, dgst, &dgstlen);

		if (tls12_prf(conn->digest,
			conn->master_secret, 48,
			"client finished", dgst, dgstlen, NULL, 0,
			sizeof(local_verify_data), local_verify_data) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

		tls_record_set_protocol(conn->plain_record, conn->protocol);

		// finished_record是没有问题的
		if (tls_record_set_handshake_finished(conn->plain_record, &conn->plain_recordlen,
			local_verify_data, sizeof(local_verify_data)) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

		// 此时finished_record中的头部应该是完整的
		tls12_record_trace(stderr, conn->plain_record, conn->plain_recordlen, 0, 0);

		if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		tls_handshake_digest_print(stderr, 0, 0, "Finished", &conn->dgst_ctx);

		if (tls12_record_encrypt(&conn->client_write_mac_ctx, &conn->client_write_key,
			conn->client_seq_num, conn->plain_record, conn->plain_recordlen,
			conn->record, &conn->recordlen) != 1) {

			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls_seq_num_incr(conn->client_seq_num);

	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	return 1;
}

int tls_recv_client_finished(TLS_CONNECT *conn)
{
	int ret;

	uint8_t finished_record[TLS_FINISHED_RECORD_BUF_SIZE];
	size_t finished_record_len;
	const uint8_t *verify_data;
	size_t verify_data_len;

	uint8_t local_verify_data[12];

	SM3_CTX tmp_sm3_ctx;
	uint8_t sm3_hash[32];

	// recv ClientFinished
	tls_trace("recv Finished\n");
	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (conn->recordlen > sizeof(finished_record)) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	tls_encrypted_record_trace(stderr, conn->record, conn->recordlen, (1<<24), 0); // 强制打印密文原数据

	// decrypt ClientFinished
	tls_trace("decrypt Finished\n");


	if (tls12_record_decrypt(&conn->client_write_mac_ctx, &conn->client_write_key,
		conn->client_seq_num, conn->record, conn->recordlen,
		finished_record, &finished_record_len) != 1) {


		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	tls12_record_trace(stderr, finished_record, finished_record_len, 0, 0);
	tls_seq_num_incr(conn->client_seq_num);
	if (tls_record_get_handshake_finished(finished_record, &verify_data, &verify_data_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	if (verify_data_len != sizeof(local_verify_data)) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}

	// verify ClientFinished
	//memcpy(&tmp_sm3_ctx, &conn->sm3_ctx, sizeof(SM3_CTX));
	//sm3_update(&conn->sm3_ctx, finished_record + 5, finished_record_len - 5);
	//sm3_finish(&tmp_sm3_ctx, sm3_hash);
	if (tls_prf(conn->master_secret, 48, "client finished", sm3_hash, 32, NULL, 0,
		sizeof(local_verify_data), local_verify_data) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}
	if (memcmp(verify_data, local_verify_data, sizeof(local_verify_data)) != 0) {
		error_puts("client_finished.verify_data verification failure");
		tls_send_alert(conn, TLS_alert_decrypt_error);
		return -1;
	}

	return 1;
}

int tls_send_server_finished(TLS_CONNECT *conn)
{
	int ret;
	uint8_t *record = conn->record;
	size_t recordlen;
	uint8_t sm3_hash[32];
	uint8_t local_verify_data[12];

	uint8_t finished_record[TLS_FINISHED_RECORD_BUF_SIZE];
	size_t finished_record_len;

	tls_record_set_protocol(finished_record, conn->protocol);

	if (conn->recordlen == 0) {
		tls_trace("send Finished\n");
	//	sm3_finish(&conn->sm3_ctx, sm3_hash);
		if (tls_prf(conn->master_secret, 48, "server finished", sm3_hash, 32, NULL, 0,
				sizeof(local_verify_data), local_verify_data) != 1
			|| tls_record_set_handshake_finished(finished_record, &finished_record_len,
				local_verify_data, sizeof(local_verify_data)) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls12_record_trace(stderr, finished_record, finished_record_len, 0, 0);
		if (tls12_record_encrypt(&conn->server_write_mac_ctx, &conn->server_write_key,
			conn->server_seq_num, finished_record, finished_record_len, record, &recordlen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls_trace("encrypt Finished\n");
		tls_encrypted_record_trace(stderr, record, recordlen, (1<<24), 0); // 强制打印密文原数据
		tls_seq_num_incr(conn->server_seq_num);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}


	return 1;
}

int tls_recv_server_finished(TLS_CONNECT *conn)
{
	int ret;
	uint8_t finished_record[TLS_FINISHED_RECORD_BUF_SIZE];
	size_t finished_record_len;

	uint8_t dgst[32];
	size_t dgstlen;

	const uint8_t *verify_data;
	size_t verify_data_len;
	uint8_t local_verify_data[12];


	// Finished
	tls_trace("recv server Finished\n");
	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}


	tls_trace("decrypt Finished\n");
	if (tls12_record_decrypt(&conn->server_write_mac_ctx, &conn->server_write_key,
		conn->server_seq_num, conn->record, conn->recordlen,
		conn->plain_record, &conn->plain_recordlen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	tls12_record_print(stderr, conn->plain_record, conn->plain_recordlen, 0, 0);

	tls_seq_num_incr(conn->server_seq_num);

	if (tls_record_get_handshake_finished(finished_record, &verify_data, &verify_data_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (verify_data_len != sizeof(local_verify_data)) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	if (digest_finish(&conn->dgst_ctx, dgst, &dgstlen) != 1) {
		error_print();
		return -1;
	}

	if (tls12_prf(conn->digest, conn->master_secret, 48, "server finished",
		dgst, dgstlen, NULL, 0,
		sizeof(local_verify_data), local_verify_data) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}
	if (memcmp(verify_data, local_verify_data, sizeof(local_verify_data)) != 0) {
		error_puts("server_finished.verify_data verification failure");
		tls_send_alert(conn, TLS_alert_decrypt_error);
		return -1;
	}

	if (!conn->ctx->quiet)
		fprintf(stderr, "Connection established!\n");

	return 1;
}



/*
      Client                                               Server

      ClientHello                  -------->
                                                      ServerHello
                                                      Certificate
                                                ServerKeyExchange
                                              CertificateRequest*
                                   <--------      ServerHelloDone
      Certificate*
      ClientKeyExchange
      CertificateVerify*
      [ChangeCipherSpec]
      Finished                     -------->
                                               [ChangeCipherSpec]
                                   <--------             Finished
      Application Data             <------->     Application Data

*/

int tls12_do_client_handshake(TLS_CONNECT *conn)
{
	int ret;
	int next_state;

	switch (conn->state) {
	case TLS_state_client_hello:
		ret = tls_send_client_hello(conn);
		next_state = TLS_state_server_hello;
		break;

	case TLS_state_server_hello:
		ret = tls_recv_server_hello(conn);
		next_state = TLS_state_server_certificate;
		break;

	case TLS_state_server_certificate:
		ret = tls_recv_server_certificate(conn);
		next_state = TLS_state_server_key_exchange;
		break;

	case TLS_state_server_key_exchange:
		ret = tls_recv_server_key_exchange(conn);
		next_state = TLS_state_certificate_request;
		break;

	// the only optional state
	case TLS_state_certificate_request:
		fprintf(stderr, "TLS_state_certificate_request\n");
		ret = tls_recv_certificate_request(conn);
		fprintf(stderr, "    ret = %d\n", ret);

		if (ret == 1) conn->client_certificate_verify = 1;
		next_state = TLS_state_server_hello_done;
		break;

	case TLS_state_server_hello_done:
		fprintf(stderr, "TLS_state_server_hello_done\n");
		ret = tls_recv_server_hello_done(conn);
		if (conn->client_certificate_verify)
			next_state = TLS_state_client_certificate;
		else	next_state = TLS_state_client_key_exchange;
		break;

	case TLS_state_client_certificate:
		ret = tls_send_client_certificate(conn);
		next_state = TLS_state_client_key_exchange;
		break;

	case TLS_state_client_key_exchange:
		ret = tls_send_client_key_exchange(conn);
		next_state = TLS_state_generate_keys;
		break;

	case TLS_state_generate_keys:
		ret = tls_generate_keys(conn);
		if (conn->client_certificate_verify)
			next_state = TLS_state_certificate_verify;
		else	next_state = TLS_state_client_change_cipher_spec;
		break;

	case TLS_state_certificate_verify:
		ret = tls_send_certificate_verify(conn);
		next_state = TLS_state_client_change_cipher_spec;

	case TLS_state_client_change_cipher_spec:
		ret = tls_send_change_cipher_spec(conn);
		next_state = TLS_state_client_finished;
		break;

	case TLS_state_client_finished:
		ret = tls_send_client_finished(conn);
		next_state = TLS_state_server_change_cipher_spec;
		break;

	case TLS_state_server_change_cipher_spec:
		ret = tls_recv_change_cipher_spec(conn);
		next_state = TLS_state_server_finished;
		break;

	case TLS_state_server_finished:
		ret = tls_recv_server_finished(conn);
		next_state = TLS_state_handshake_over;
		break;

	default:
		error_print();
		return -1;
	}

	if (ret < 0) {
		if (ret == TLS_ERROR_RECV_AGAIN || ret == TLS_ERROR_SEND_AGAIN) {
			return ret;
		} else {
			error_print();
			return ret;
		}
	}

	conn->state = next_state;

	// ret == 0 means this step is bypassed
	if (ret == 1) {
		tls_clean_record(conn);
	}

	return 1;
}

int tls12_do_server_handshake(TLS_CONNECT *conn)
{
	int ret;
	int next_state;

	switch (conn->state) {
	case TLS_state_client_hello:
		ret = tls_recv_client_hello(conn);
		next_state = TLS_state_server_hello;
		break;

	case TLS_state_server_hello:
		ret = tls_send_server_hello(conn);
		next_state = TLS_state_server_certificate;
		break;

	case TLS_state_server_certificate:
		ret = tls_send_server_certificate(conn);
		next_state = TLS_state_server_key_exchange;
		break;

	case TLS_state_server_key_exchange:
		ret = tls_send_server_key_exchange(conn);
		if (conn->client_certificate_verify)
			next_state = TLS_state_certificate_request;
		else	next_state = TLS_state_server_hello_done;
		break;

	case TLS_state_certificate_request:
		ret = tls_send_certificate_request(conn);
		next_state = TLS_state_server_hello_done;
		break;

	case TLS_state_server_hello_done:
		ret = tls_send_server_hello_done(conn);
		if (conn->client_certificate_verify)
			next_state = TLS_state_client_certificate;
		else	next_state = TLS_state_client_key_exchange;
		break;

	case TLS_state_client_certificate:
		ret = tls_recv_client_certificate(conn);
		next_state = TLS_state_client_key_exchange;
		break;

	case TLS_state_client_key_exchange:
		ret = tls_recv_client_key_exchange(conn);
		if (conn->client_certificate_verify)
			next_state = TLS_state_certificate_verify;
		else	next_state = TLS_state_generate_keys;
		break;

	case TLS_state_certificate_verify:
		ret = tls_recv_certificate_verify(conn);
		next_state = TLS_state_generate_keys;
		break;

	case TLS_state_generate_keys:
		ret = tls_generate_keys(conn);
		next_state = TLS_state_client_change_cipher_spec;
		break;

	case TLS_state_client_change_cipher_spec:
		ret = tls_recv_change_cipher_spec(conn);
		next_state = TLS_state_client_finished;
		break;

	case TLS_state_client_finished:
		ret = tls_recv_client_finished(conn);
		next_state = TLS_state_server_change_cipher_spec;
		break;

	case TLS_state_server_change_cipher_spec:
		ret = tls_send_change_cipher_spec(conn);
		next_state = TLS_state_server_finished;
		break;

	case TLS_state_server_finished:
		ret = tls_send_server_finished(conn);
		next_state = TLS_state_handshake_over;
		break;

	default:
		error_print();
		return -1;
	}

	if (ret != 1) {
		if (ret == TLS_ERROR_RECV_AGAIN || ret == TLS_ERROR_SEND_AGAIN) {
			return ret;
		} else {
			error_print();
			return ret;
		}

	}

	conn->state = next_state;

	tls_clean_record(conn);

	return 1;
}


// 这个函数显然是不对的，因为这个函数就是一个重入的函数，重入函数不应该自己设置状态啊
int tls12_client_handshake(TLS_CONNECT *conn)
{
	int ret;

	while (conn->state != TLS_state_handshake_over) {

		ret = tls12_do_client_handshake(conn);

		if (ret != 1) {
			if (ret != TLS_ERROR_RECV_AGAIN && ret != TLS_ERROR_SEND_AGAIN) {
				error_print();
			}
			return ret;
		}
	}

	// TODO: cleanup conn?

	return 1;
}

int tls12_server_handshake(TLS_CONNECT *conn)
{
	int ret;


	while (conn->state != TLS_state_handshake_over) {

		ret = tls12_do_server_handshake(conn);

		if (ret != 1) {
			if (ret != TLS_ERROR_RECV_AGAIN && ret != TLS_ERROR_SEND_AGAIN) {
				error_print();
			}
			return ret;
		}
	}

	// TODO: cleanup conn?

	return 1;
}

int tls12_do_connect(TLS_CONNECT *conn)
{
	int ret;
	fd_set rfds;
	fd_set wfds;

	conn->state = TLS_state_client_hello;
	//sm3_init(&conn->sm3_ctx);


	digest_init(&conn->dgst_ctx, DIGEST_sm3());

	while (1) {

		ret = tls12_client_handshake(conn);
		if (ret == 1) {
			break;

		} else if (ret == TLS_ERROR_SEND_AGAIN) {
			FD_ZERO(&rfds);
			FD_ZERO(&wfds);
			FD_SET(conn->sock, &wfds);
			select(conn->sock + 1, &rfds, &wfds, NULL, NULL);

		} else if (ret == TLS_ERROR_RECV_AGAIN) {
			FD_ZERO(&rfds);
			FD_ZERO(&wfds);
			FD_SET(conn->sock, &rfds);
			select(conn->sock + 1, &rfds, &wfds, NULL, NULL);

		} else {
			error_print();
			return -1;
		}
	}

	return 1;
}

int tls12_do_accept(TLS_CONNECT *conn)
{
	int ret;
	fd_set rfds;
	fd_set wfds;

	conn->state = TLS_state_client_hello;

	//sm3_init(&conn->sm3_ctx);
	digest_init(&conn->dgst_ctx, DIGEST_sm3());

	while (1) {

		ret = tls12_server_handshake(conn);

		if (ret == 1) {
			break;

		} else if (ret == TLS_ERROR_SEND_AGAIN) {
			FD_ZERO(&rfds);
			FD_ZERO(&wfds);
			FD_SET(conn->sock, &rfds);
			select(conn->sock + 1, &rfds, &wfds, NULL, NULL);

		} else if (ret == TLS_ERROR_RECV_AGAIN) {
			FD_ZERO(&rfds);
			FD_ZERO(&wfds);
			FD_SET(conn->sock, &wfds);
			select(conn->sock + 1, &rfds, &wfds, NULL, NULL);

		} else {
			error_print();
			return -1;
		}
	}

	return 1;
}
