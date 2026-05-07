/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmssl/rand.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/pem.h>
#include <gmssl/tls.h>
#include <gmssl/digest.h>
#include <gmssl/hmac.h>
#include <gmssl/hkdf.h>
#include <gmssl/mem.h>
#include <gmssl/endian.h>



static const int tls13_ciphers[] = { TLS_cipher_sm4_gcm_sm3 };
static size_t tls13_ciphers_count = sizeof(tls13_ciphers)/sizeof(int);

static int tls13_client_hello_exts[] = {
	TLS_extension_supported_versions,
	TLS_extension_padding,
};

int tls13_random_generate(uint8_t random[32])
{
	if (rand_bytes(random, 32) != 1) {
		error_print();
		return -1;
	}
	return 1;
}


int tls13_cipher_suite_get(int cipher_suite, const BLOCK_CIPHER **cipher, const DIGEST **digest)
{
	switch (cipher_suite) {
	case TLS_cipher_sm4_gcm_sm3:
		*digest = DIGEST_sm3();
		*cipher = BLOCK_CIPHER_sm4();
		break;
#if defined(ENABLE_AES) && defined(ENABLE_SHA2)
	case TLS_cipher_aes_128_gcm_sha256:
		*digest = DIGEST_sha256();
		*cipher = BLOCK_CIPHER_aes128();
		break;
#endif
	default:
		error_print();
		return -1;
	}
	return 1;
}


int tls13_padding_len_rand(size_t *padding_len)
{
	uint8_t val;
	rand_bytes(&val, 1);
	*padding_len = val % 128;
	return 1;
}




int gcm_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	uint8_t *out, size_t taglen, uint8_t *tag)
{
	if (key->cipher == BLOCK_CIPHER_sm4()) {
		if (sm4_gcm_encrypt(&(key->u.sm4_key), iv, ivlen, aad, aadlen,  in, inlen, out, taglen, tag) != 1) {
			error_print();
			return -1;
		}
// 避免在tls13.c中引入宏
#ifdef ENABLE_AES
	} else if (key->cipher == BLOCK_CIPHER_aes128()) {
		if (aes_gcm_encrypt(&(key->u.aes_key), iv, ivlen, aad, aadlen,  in, inlen, out, taglen, tag) != 1) {
			error_print();
			return -1;
		}
#endif
	} else {
		error_print();
		return -1;
	}
	return 1;
}

int gcm_decrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	const uint8_t *tag, size_t taglen, uint8_t *out)
{
	if (key->cipher == BLOCK_CIPHER_sm4()) {
		if (sm4_gcm_decrypt(&(key->u.sm4_key), iv, ivlen, aad, aadlen,  in, inlen, tag, taglen, out) != 1) {
			error_print();
			return -1;
		}
#ifdef ENABLE_AES
	} else if (key->cipher == BLOCK_CIPHER_aes128()) {
		if (aes_gcm_decrypt(&(key->u.aes_key), iv, ivlen, aad, aadlen,  in, inlen, tag, taglen, out) != 1) {
			error_print();
			return -1;
		}
#endif
	} else {
		error_print();
		return -1;
	}
	return 1;
}

/*
struct {
	opaque content[TLSPlaintext.length];
	ContentType type;
	uint8 zeros[length_of_padding];
} TLSInnerPlaintext;

struct {
	ContentType opaque_type = application_data; // 23
	ProtocolVersion legacy_record_version = 0x0303; // TLS v1.2
	uint16 length;
	opaque encrypted_record[TLSCiphertext.length];
} TLSCiphertext;
*/
int tls13_gcm_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t iv[12],
	const uint8_t seq_num[8], int record_type,
	const uint8_t *in, size_t inlen, size_t padding_len, // TLSInnerPlaintext.content
	uint8_t *out, size_t *outlen) // TLSCiphertext.encrypted_record
{
	uint8_t nonce[12];
	uint8_t aad[5];
	uint8_t *gmac;
	uint8_t *mbuf = NULL; // FIXME: update gcm_encrypt API
	size_t mlen, clen;

	if (!(mbuf = malloc(inlen + 256))) {
		error_print();
		return -1;
	}

	// nonce = (zeros|seq_num) xor (iv)
	nonce[0] = nonce[1] = nonce[2] = nonce[3] = 0;
	memcpy(nonce + 4, seq_num, 8);
	gmssl_memxor(nonce, nonce, iv, 12);

	// TLSInnerPlaintext
	memcpy(mbuf, in, inlen);
	mbuf[inlen] = record_type;
	memset(mbuf + inlen + 1, 0, padding_len);
	mlen = inlen + 1 + padding_len;
	clen = mlen + GHASH_SIZE;

	// aad = TLSCiphertext header
	aad[0] = TLS_record_application_data;
	aad[1] = 0x03; //TLS_protocol_tls12_major;
	aad[2] = 0x03; //TLS_protocol_tls12_minor;
	aad[3] = (uint8_t)(clen >> 8);
	aad[4] = (uint8_t)(clen);

	gmac = out + mlen;
	if (gcm_encrypt(key, nonce, sizeof(nonce), aad, sizeof(aad), mbuf, mlen, out, 16, gmac) != 1) {
		error_print();
		free(mbuf);
		return -1;
	}
	*outlen = clen;
	free(mbuf);

	return 1;
}

int tls13_gcm_decrypt(const BLOCK_CIPHER_KEY *key, const uint8_t iv[12],
	const uint8_t seq_num[8], const uint8_t *in, size_t inlen,
	int *record_type, uint8_t *out, size_t *outlen)
{
	uint8_t nonce[12];
	uint8_t aad[5];
	size_t mlen;
	const uint8_t *gmac;

	// nonce = (zeros|seq_num) xor (iv)
	nonce[0] = nonce[1] = nonce[2] = nonce[3] = 0;
	memcpy(nonce + 4, seq_num, 8);
	gmssl_memxor(nonce, nonce, iv, 12);

	// aad = TLSCiphertext header
	aad[0] = TLS_record_application_data;
	aad[1] = 0x03; //TLS_protocol_tls12_major;
	aad[2] = 0x03; //TLS_protocol_tls12_minor;
	aad[3] = (uint8_t)(inlen >> 8);
	aad[4] = (uint8_t)(inlen);

	if (inlen < GHASH_SIZE) {
		error_print();
		return -1;
	}
	mlen = inlen - GHASH_SIZE;
	gmac = in + mlen;

	if (gcm_decrypt(key, nonce, 12, aad, 5, in, mlen, gmac, GHASH_SIZE, out) != 1) {
		error_print();
		return -1;
	}
	// remove padding, get record_type
	*record_type = 0;
	while (mlen--) {
		if (out[mlen] != 0) {
			*record_type = out[mlen];
			break;
		}
	}
	*outlen = mlen;
	if (!tls_record_type_name(*record_type)) {
		error_print();
		return -1;
	}
	return 1;
}


int tls13_record_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t iv[12],
	const uint8_t seq_num[8], const uint8_t *record, size_t recordlen, size_t padding_len,
	uint8_t *enced_record, size_t *enced_recordlen)
{
	if (tls13_gcm_encrypt(key, iv,
		seq_num, record[0], record + 5, recordlen - 5, padding_len,
		enced_record + 5, enced_recordlen) != 1) {
		error_print();
		return -1;
	}

	// in tls1.3, type of encrypted records must be application_data
	enced_record[0] = TLS_record_application_data;
	enced_record[1] = 0x03; //TLS_protocol_tls12_major;
	enced_record[2] = 0x03; //TLS_protocol_tls12_minor;
	enced_record[3] = (uint8_t)((*enced_recordlen) >> 8);
	enced_record[4] = (uint8_t)(*enced_recordlen);

	(*enced_recordlen) += 5;
	return 1;
}

int tls13_record_decrypt(const BLOCK_CIPHER_KEY *key, const uint8_t iv[12],
	const uint8_t seq_num[8], const uint8_t *enced_record, size_t enced_recordlen,
	uint8_t *record, size_t *recordlen)
{
	int record_type;

	if (tls13_gcm_decrypt(key, iv,
		seq_num, enced_record + 5, enced_recordlen - 5,
		&record_type, record + 5, recordlen) != 1) {
		error_print();
		return -1;
	}
	record[0] = record_type;
	record[1] = 0x03; //TLS_protocol_tls12_major;
	record[2] = 0x03; //TLS_protocol_tls12_minor;
	record[3] = (uint8_t)((*recordlen) >> 8);
	record[4] = (uint8_t)(*recordlen);

	(*recordlen) += 5;
	return 1;
}

/*
KeyUpate的流程


	客户端发现需要KeyUpdate （可能是C->S 或者C <- S某个方向需要）
	如果是自己方向的需要更新，或者对方需要更新，那么就一定要发送KeyUpdate
	如果对方不需要更新，那么不要求对方更新

	客户端更新自己的密钥

	服务器端在收到通知后，更新客户端的密钥
	服务器端查看是否要求自己也更新密钥，如果要求
		因此向客户端发送KeyUpdate
	注意因为客户端的密钥刚更新过，作为响应方的服务器一定不能要求对方再更新了

	客户端接受到服务器的请求，如果自己才刚刚更新过，就不再发送反馈了


	这里一个主要的状态判断是，
	某一方在接收到对方的KeyUpdate请求后，是否响。




*/


int tls13_send(TLS_CONNECT *conn, const uint8_t *data, size_t datalen, size_t *sentlen)
{
	int key_update = 0;

	tls_trace("send {ApplicationData}\n");
	format_print(stderr, 0, 0, "data = %p, datalen = %zu\n", data, datalen);

	*sentlen = 0;

	// 这个可能是有问题的
	if (!conn->recordlen) {
		const BLOCK_CIPHER_KEY *key;
		const uint8_t *iv;
		uint8_t *seq_num;
		size_t padding_len = 0;
		size_t record_datalen;

		if (!data || !datalen) {
			return 0;
		}

		if (datalen > TLS_MAX_PLAINTEXT_SIZE) {
			datalen = TLS_MAX_PLAINTEXT_SIZE;
		}

		if (conn->is_client) {
			key = &conn->client_write_key;
			iv = conn->client_write_iv;
			seq_num = conn->client_seq_num;
			format_bytes(stderr, 0, 4, "client_write_iv", iv, 12);
			format_bytes(stderr, 0, 4, "client_seq_num", seq_num, 8);
			format_print(stderr, 0, 0, "\n");

		} else {
			key = &conn->server_write_key;
			iv = conn->server_write_iv;
			seq_num = conn->server_seq_num;
			format_bytes(stderr, 0, 4, "server_write_iv", iv, 12);
			format_bytes(stderr, 0, 4, "server_seq_num", seq_num, 8);
			format_print(stderr, 0, 0, "\n");
		}

		tls13_padding_len_rand(&padding_len);


		// 这个其实不太好，最好是直接加密一个record，这样我们可以打印出record
		if (tls13_gcm_encrypt(key, iv,
			seq_num, TLS_record_application_data, data, datalen, padding_len,
			conn->record + 5, &record_datalen) != 1) {
			error_print();
			return -1;
		}
		tls_seq_num_incr(seq_num);
		tls_record_set_type(conn->record, TLS_record_application_data);
		tls_record_set_protocol(conn->record, TLS_protocol_tls12);
		tls_record_set_data_length(conn->record, record_datalen);

		conn->recordlen = 5 + record_datalen;
		conn->record_offset = 0;
		conn->plain_recordlen = datalen + 5;


		tls13_record_print(stderr, 0, 0, conn->record, conn->recordlen);



		/*
		KeyUpdate有两个原因
			* 我们自己检查，应该KeyUpdate了，那么发送KeyUpdate并且要求对方也Update
			* 对方要求KeyUpdate，那么我们只是通知对方，我方KeyUPdate，不要求对方再次Update

		*/

		// check if KeyUpdate
		/*
		// key_update_seq_num_limit 似乎还没有设置
		if (GETU64(seq_num) >= conn->ctx->key_update_seq_num_limit) {
			key_update = 1;
		}
		*/
	}

	while (conn->recordlen) {
		tls_ret_t n;

		if ((n = tls_socket_send(conn->sock, conn->record + conn->record_offset, conn->recordlen, 0)) <= 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return EAGAIN;
			} else {
				if (n == 0) {
					error_puts("TCP connection closed");
				}
				error_print();
				return -1;
			}
		}
		conn->recordlen -= n;
		conn->record_offset += n;
	}

	/*
	if (key_update) {
		int ret;

		if (conn->is_client) {
			if ((ret = tls13_send_client_key_update(conn, 1)) <= 0) {
				if (ret == TLS_ERROR_SEND_AGAIN) {
					return ret;
				}
			} else {
				error_print();
				return -1;
			}

		} else {
			if ((ret = tls13_send_server_key_update(conn, 1)) <= 0) {
				if (ret == TLS_ERROR_SEND_AGAIN) {
					return ret;
				}
			} else {
				error_print();
				return -1;
			}


		}
	}
	*/

	*sentlen = conn->plain_recordlen - 5;

	return 1;
}

int tls13_do_recv(TLS_CONNECT *conn)
{
	tls_ret_t n;
	const BLOCK_CIPHER_KEY *key;
	const uint8_t *iv;
	uint8_t *seq_num;

	tls_trace("recv {ApplicationData}\n");

	switch (conn->state) {
	case 0:
		error_print();
		fprintf(stderr, "----------------------------------------------------------------\n");
		conn->record_offset = 0;
		conn->recordlen = TLS_RECORD_HEADER_SIZE;
		conn->state = TLS_state_recv_record_header;
		error_print();

	case TLS_state_recv_record_header:
		error_print();
		while (conn->recordlen) {
			if ((n = tls_socket_recv(conn->sock, conn->record + conn->record_offset, conn->recordlen, 0)) <= 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					return TLS_ERROR_RECV_AGAIN;
				} else {
					error_print();
					return -1;
				}
			}
			conn->recordlen -= n;
			conn->record_offset += n;
		}
		if (tls_record_type(conn->record) != TLS_record_application_data) {
			error_print();
			return -1;
		}
		if (tls_record_protocol(conn->record) != TLS_protocol_tls12) {
			error_print();
			return -1;
		}
		conn->recordlen = tls_record_data_length(conn->record);

		fprintf(stderr, "%d: recordlen = %zu\n", __LINE__, conn->recordlen);

		fprintf(stderr, "record_offset = %zu\n", conn->record_offset);

		conn->state = TLS_state_recv_record_data;

	case TLS_state_recv_record_data:
		error_print();

		while (conn->recordlen) {
			if ((n = tls_socket_recv(conn->sock, conn->record + conn->record_offset, conn->recordlen, 0)) <= 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					return TLS_ERROR_RECV_AGAIN;
				} else {
					error_print();
					return -1;
				}
			}
			conn->recordlen -= n;
			conn->record_offset += n;
		}
		conn->state = 0;
		break;

	default:
		error_print();
		return -1;
	}

	conn->recordlen = tls_record_length(conn->record);

	fprintf(stderr, "%d: recordlen = %zu\n", __LINE__, conn->recordlen);


	tls13_record_print(stderr, 0, 0, conn->record, conn->recordlen);


	if (conn->is_client) {
		key = &conn->server_write_key;
		iv = conn->server_write_iv;
		seq_num = conn->server_seq_num;

		format_bytes(stderr, 0, 4, "server_write_iv", iv, 12);
		format_bytes(stderr, 0, 4, "server_seq_num", seq_num, 8);
		format_print(stderr, 0, 0, "\n");


	} else {
		key = &conn->client_write_key;
		iv = conn->client_write_iv;
		seq_num = conn->client_seq_num;
		format_bytes(stderr, 0, 4, "client_write_iv", iv, 12);
		format_bytes(stderr, 0, 4, "client_seq_num", seq_num, 8);
		format_print(stderr, 0, 0, "\n");
	}


	if (tls13_record_decrypt(key, iv, seq_num, conn->record, conn->recordlen,
		conn->plain_record, &conn->plain_recordlen) != 1) {
		error_print();
		return -1;
	}
	tls_seq_num_incr(seq_num);

	tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

	switch (tls_record_type(conn->plain_record)) {
	case TLS_record_application_data:
		conn->data = conn->plain_record + 5;
		conn->datalen = conn->plain_recordlen - 5;
		break;

	case TLS_record_handshake:
		{
		int handshake_type;
		const uint8_t *handshake_data;
		size_t handshake_datalen;
		int update_requested;

		if (tls_record_get_handshake(conn->plain_record, &handshake_type, &handshake_data, &handshake_datalen) != 1) {
			error_print();
			return -1;
		}
		switch (handshake_type) {

		// NewSessionTicket 也不应该是被单独接收的，只能在解密并解析了handshake之后才可以
		case TLS_handshake_new_session_ticket:

			error_print();
			fprintf(stderr, "tls13_process_new_session_ticket\n");

			if (tls13_process_new_session_ticket(conn) != 1) {
				error_print();
				return -1;
			}
			break;


		case TLS_handshake_key_update:
			if (tls13_record_get_handshake_key_update(conn->plain_record, &update_requested) != 1) {
				error_print();
				return -1;
			}

			// 对方的密钥已经更新了，我方必须更新
			// 但是我方密钥是否更新（以及发送KeyUpdate通知呢？），要看当前密钥使用了多久
			if (conn->is_client) {
				uint64_t seq_num;
				int ret;

				tls13_update_server_application_keys(conn);

				seq_num = GETU64(conn->client_seq_num);

				if (seq_num > 1 && update_requested) {

					if ((ret = tls13_send_client_key_update(conn, 0)) <= 0) {
						if (ret == TLS_ERROR_SEND_AGAIN) {
							return ret;
						}
					}
				}


			} else {
				uint64_t seq_num;
				int ret;

				tls13_update_client_application_keys(conn);


				seq_num = GETU64(conn->server_seq_num);

				if (seq_num > 1 && update_requested) {
					if ((ret = tls13_send_server_key_update(conn, 0)) <= 0) {
						if (ret == TLS_ERROR_SEND_AGAIN) {
							return ret;
						} else {
							error_print();
							return -1;
						}
					}
				}
			}

			break;
		default:
			error_print();
			return -1;
		}
		}
		break;

	case TLS_record_alert:
		{
		int alert_level;
		int alert_description;

		if (tls_record_get_alert(conn->plain_record, &alert_level, &alert_description) != 1) {
			error_print();
			return -1;
		}
		tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);
		}
		return -1;

	default:
		error_print();
		return -1;
	}

	return 1;
}

int tls13_recv(TLS_CONNECT *conn, uint8_t *out, size_t outlen, size_t *recvlen)
{
	if (!conn || !out || !outlen || !recvlen) {
		error_print();
		return -1;
	}
	fprintf(stderr, "%d: conn->state %d\n", __LINE__, conn->state);


	if (conn->datalen == 0) {
		int ret;
		if ((ret = tls13_do_recv(conn)) != 1) {
			if (ret) error_print();
			return ret;
		}
	}
	*recvlen = outlen <= conn->datalen ? outlen : conn->datalen;
	memcpy(out, conn->data, *recvlen);
	conn->data += *recvlen;
	conn->datalen -= *recvlen;

	// 这里接受完成之后，应该recordlen = 0

	conn->recordlen = 0;


	return 1;
}

// 这里需要考虑max_early_data_size的问题
int tls13_recv_early_data(TLS_CONNECT *conn)
{
	tls_trace("recv EarlyData\n");

	if (tls13_do_recv(conn) != 1) {
		error_print();
		return -1;
	}
	memcpy(conn->early_data_buf, conn->data, conn->datalen);
	conn->early_data_len = conn->datalen;

	format_string(stderr, 0, 4, "EarlyData", conn->early_data_buf, conn->early_data_len);

	return 1;
}


/*
HKDF-Expand-Label(Secret, Label, Context, Length) =
	HKDF-Expand(Secret, HkdfLabel, Length);

	HkdfLabel = struct {
		uint16 length = Length;
		opaque label<7..255> = "tls13 " + Label;
		opaque context<0..255> = Context; }

Derive-Secret(Secret, Label, Messages) =
	HKDF-Expand-Label(Secret, Label, Hash(Messages), Hash.length)

*/

int tls13_hkdf_extract(const DIGEST *digest, const uint8_t salt[32], const uint8_t in[32], uint8_t out[32])
{
	size_t dgstlen;

	if (hkdf_extract(digest, salt, 32, in, 32, out, &dgstlen) != 1
		|| dgstlen != 32) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_hkdf_expand_label(const DIGEST *digest, const uint8_t secret[32],
	const char *label, const uint8_t *context, size_t context_len,
	size_t outlen, uint8_t *out)
{
	uint8_t label_len;
	uint8_t hkdf_label[2 + 256 + 256];
	uint8_t *p = hkdf_label;
	size_t hkdf_label_len = 0;

	label_len = (uint8_t)(strlen("tls13 ") + strlen(label)); //FIXME: check length < 255
	tls_uint16_to_bytes((uint16_t)outlen, &p, &hkdf_label_len);
	tls_uint8_to_bytes(label_len, &p, &hkdf_label_len);
	tls_array_to_bytes((uint8_t *)"tls13 ", strlen("tls13 "), &p, &hkdf_label_len);
	tls_array_to_bytes((uint8_t *)label, strlen(label), &p, &hkdf_label_len);
	tls_uint8array_to_bytes(context, context_len, &p, &hkdf_label_len);

	hkdf_expand(digest, secret, 32, hkdf_label, hkdf_label_len, outlen, out);

	return 1;
}

// 输入参数都需要提供长度			
int tls13_derive_secret(const uint8_t secret[32], const char *label, const DIGEST_CTX *dgst_ctx, uint8_t out[32])
{
	DIGEST_CTX ctx = *dgst_ctx;
	uint8_t dgst[64];
	size_t dgstlen;

	if (digest_finish(&ctx, dgst, &dgstlen) != 1) {
		error_print();
		return -1;
	}

	if (tls13_hkdf_expand_label(dgst_ctx->digest, secret, label, dgst, 32, dgstlen, out) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static const uint8_t TLS13_client_context_str_and_zero[] = "TLS 1.3, client CertificateVerify";
static const uint8_t TLS13_server_context_str_and_zero[] = "TLS 1.3, server CertificateVerify";
static size_t TLS13_client_context_str_and_zero_size = sizeof(TLS13_client_context_str_and_zero);
static size_t TLS13_server_context_str_and_zero_size = sizeof(TLS13_server_context_str_and_zero);


int tls13_sign_certificate_verify(int tls_mode, int sig_alg,
	X509_KEY *sign_key, const DIGEST_CTX *tbs_dgst_ctx,
	uint8_t *sig, size_t *siglen)
{
	uint8_t prefix[64];
	const uint8_t *context_str_and_zero;
	size_t context_str_and_zero_len;
	DIGEST_CTX dgst_ctx;
	uint8_t dgst[64];
	size_t dgstlen;
	X509_SIGN_CTX sign_ctx;
	const char *signer_id = NULL;
	size_t signer_id_len = 0;

	if (!sign_key || !tbs_dgst_ctx || !sig || !siglen) {
		error_print();
		return -1;
	}

	memset(prefix, 0x20, 64);

	switch (tls_mode) {
	case TLS_client_mode:
		context_str_and_zero = TLS13_client_context_str_and_zero;
		context_str_and_zero_len = TLS13_client_context_str_and_zero_size;
		break;
	case TLS_server_mode:
		context_str_and_zero = TLS13_server_context_str_and_zero;
		context_str_and_zero_len = TLS13_server_context_str_and_zero_size;
		break;
	default:
		error_print();
		return -1;
	}

	switch (sig_alg) {
	case TLS_sig_sm2sig_sm3:
		if (sign_key->algor != OID_ec_public_key
			&& sign_key->algor_param != OID_sm2) {
			error_print();
			return -1;
		}
		if (tbs_dgst_ctx->digest->oid != OID_sm3) {
			error_print();
			return -1;
		}
		signer_id = TLS13_SM2_ID;
		signer_id_len = TLS13_SM2_ID_LENGTH;
		break;

	case TLS_sig_ecdsa_secp256r1_sha256:
		if (sign_key->algor != OID_ec_public_key
			&& sign_key->algor_param != OID_secp256r1) {
			error_print();
			return -1;
		}
		if (tbs_dgst_ctx->digest->oid != OID_sha256) {
			error_print();
			return -1;
		}
		break;

	default:
		error_print();
		return -1;
	}

	dgst_ctx = *tbs_dgst_ctx;
	if (digest_finish(&dgst_ctx, dgst, &dgstlen) != 1) {
		error_print();
		return -1;
	}

	if (x509_sign_init(&sign_ctx, sign_key, signer_id, signer_id_len) !=  1
		|| x509_sign_update(&sign_ctx, prefix, 64) != 1
		|| x509_sign_update(&sign_ctx, context_str_and_zero, context_str_and_zero_len) != 1
		|| x509_sign_update(&sign_ctx, dgst, dgstlen) != 1
		|| x509_sign_finish(&sign_ctx, sig, siglen) != 1) {
		gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
		error_print();
		return -1;
	}

	gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
	return 1;
}

int tls13_verify_certificate_verify(int tls_mode, int sig_alg,
	const X509_KEY *public_key, const DIGEST_CTX *tbs_dgst_ctx,
	const uint8_t *sig, size_t siglen)
{
	int ret;
	uint8_t prefix[64];
	const uint8_t *context_str_and_zero;
	size_t context_str_and_zero_len;
	DIGEST_CTX dgst_ctx;
	uint8_t dgst[64];
	size_t dgstlen;
	X509_SIGN_CTX sign_ctx;
	const char *signer_id = NULL;
	size_t signer_id_len = 0;

	if (!public_key || !tbs_dgst_ctx || !sig || !siglen) {
		error_print();
		return -1;
	}

	memset(prefix, 0x20, 64);

	switch (tls_mode) {
	case TLS_client_mode:
		context_str_and_zero = TLS13_client_context_str_and_zero;
		context_str_and_zero_len = TLS13_client_context_str_and_zero_size;
		break;
	case TLS_server_mode:
		context_str_and_zero = TLS13_server_context_str_and_zero;
		context_str_and_zero_len = TLS13_server_context_str_and_zero_size;
		break;
	default:
		error_print();
		return -1;
	}

	switch (sig_alg) {
	case TLS_sig_sm2sig_sm3:
		if (public_key->algor != OID_ec_public_key
			&& public_key->algor_param != OID_sm2) {
			error_print();
			return -1;
		}
		if (tbs_dgst_ctx->digest->oid != OID_sm3) {
			error_print();
			return -1;
		}
		signer_id = TLS13_SM2_ID;
		signer_id_len = TLS13_SM2_ID_LENGTH;
		break;

	case TLS_sig_ecdsa_secp256r1_sha256:
		if (public_key->algor != OID_ec_public_key
			&& public_key->algor_param != OID_secp256r1) {
			error_print();
			return -1;
		}
		if (tbs_dgst_ctx->digest->oid != OID_sha256) {
			error_print();
			return -1;
		}
		break;

	default:
		error_print();
		return -1;
	}

	dgst_ctx = *tbs_dgst_ctx;
	if (digest_finish(&dgst_ctx, dgst, &dgstlen) != 1) {
		error_print();
		return -1;
	}

	if (x509_verify_init(&sign_ctx, public_key, signer_id, signer_id_len, sig, siglen) != 1
		|| x509_verify_update(&sign_ctx, prefix, 64) != 1
		|| x509_verify_update(&sign_ctx, context_str_and_zero, context_str_and_zero_len) != 1
		|| x509_verify_update(&sign_ctx, dgst, dgstlen) != 1) {
		error_print();
		return -1;
	}
	if ((ret = x509_verify_finish(&sign_ctx)) < 0) {
		error_print();
		return -1;
	}
	if (ret != 1) {
		error_print();
	}
	return ret;
}

/*
 verify_data in Finished

   finished_key =
       HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
   Structure of this message:
      struct {
          opaque verify_data[Hash.length];
      } Finished;
   The verify_data value is computed as follows:
      verify_data =
          HMAC(finished_key,
               Transcript-Hash(Handshake Context,
                               Certificate*, CertificateVerify*))
*/
int tls13_compute_verify_data(const uint8_t *handshake_traffic_secret,
	const DIGEST_CTX *dgst_ctx, uint8_t *verify_data, size_t *verify_data_len)
{
	DIGEST_CTX temp_dgst_ctx;
	uint8_t dgst[64];
	size_t dgstlen;
	uint8_t finished_key[64];
	size_t finished_key_len;

	temp_dgst_ctx = *dgst_ctx;
	digest_finish(&temp_dgst_ctx, dgst, &dgstlen);
	finished_key_len = dgstlen;

	tls13_hkdf_expand_label(dgst_ctx->digest, handshake_traffic_secret,
		"finished", NULL, 0, finished_key_len, finished_key);

	hmac(dgst_ctx->digest, finished_key, finished_key_len, dgst, dgstlen, verify_data, verify_data_len);
	return 1;
}



/*
CertificateEntry {
    select (certificate_type) {
        case X509: opaque cert_data<1..2^24-1>;    // DER编码的X.509证书
    };
    Extension extensions<0..2^16-1>;               // 这个证书的扩展列表
}
*/

int tls13_cert_list_get_count(const uint8_t *d, size_t dlen, size_t *cnt)
{
	int ret;
	ret = asn1_types_get_count(d, dlen, ASN1_TAG_SEQUENCE, cnt);
	if (ret < 0) error_print();
	return ret;
}

int tls13_cert_list_get_cert_by_index(const uint8_t *d, size_t dlen, int index, const uint8_t **cert, size_t *certlen)
{
	int i = 0;

	if (index < 0) {
		error_print();
		return -1;
	}
	while (dlen) {
		if (x509_cert_from_der(cert, certlen, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		if (i++ == index) {
			return 1;
		}
	}
	*cert = NULL;
	*certlen = 0;
	return 0;
}

int tls13_cert_list_get_last(const uint8_t *d, size_t dlen, const uint8_t **cert, size_t *certlen)
{
	if (dlen == 0) {
		return 0;
	}
	while (dlen) {
		if (x509_cert_from_der(cert, certlen, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

























// extensions


// 这个函数需要测试一下，看看是否支持ext_data == NULL， ext_datalen != 0时，可以只输出头部，并正确的修改输出长度
int tls_ext_to_bytes(int ext_type, const uint8_t *ext_data, size_t ext_datalen,
	uint8_t **out, size_t *outlen)
{
	tls_uint16_to_bytes(ext_type, out, outlen);
	tls_uint16array_to_bytes(ext_data, ext_datalen, out, outlen);
	return 1;
}



/*
struct {
	ProtocolVersion versions<2..254>;
} SupportedVersions; -- in ClientHello
*/
int tls13_client_supported_versions_ext_to_bytes(const int *versions, size_t versions_cnt,
	uint8_t **out, size_t *outlen)
{
	uint16_t ext_type = TLS_extension_supported_versions;
	size_t ext_datalen;
	size_t versions_len;
	size_t i;

	if (!versions || !versions_cnt || !outlen) {
		error_print();
		return -1;
	}
	if (versions_cnt > 254/2) {
		error_print();
		return -1;
	}
	for (i = 0; i < versions_cnt; i++) {
		if (!tls_protocol_name(versions[i])) {
			error_print();
			return -1;
		}
	}
 	versions_len = tls_uint16_size() * versions_cnt;
	ext_datalen = tls_uint8_size() + versions_len;
	tls_uint16_to_bytes(ext_type, out, outlen);
	tls_uint16_to_bytes((uint16_t)ext_datalen, out, outlen);
	tls_uint8_to_bytes((uint8_t)versions_len, out, outlen);
	for (i = 0; i < versions_cnt; i++) {
		tls_uint16_to_bytes((uint16_t)versions[i], out, outlen);
	}
	return 1;
}

int tls13_process_client_supported_versions(const uint8_t *ext_data, size_t ext_datalen,
	const int *server_versions, size_t server_versions_cnt,
	int *common_versions, size_t *common_versions_cnt, size_t max_cnt)
{
	const uint8_t *versions;
	size_t versions_len;
	const uint8_t *cp;
	size_t len;
	uint16_t version;
	size_t i, j = 0;

	if (tls_uint8array_from_bytes(&versions, &versions_len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	if (versions_len < 2 || versions_len > 254) {
		error_print();
		return -1;
	}

	cp = versions;
	len = versions_len;
	while (len) {
		if (tls_uint16_from_bytes(&version, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (!tls_protocol_name(version)) {
			error_print();
			return -1;
		}
		if (version == server_versions[0] && j < max_cnt) {
			common_versions[j++] = version;
		}
	}
	for (i = 1; i < server_versions_cnt && j < max_cnt; i++) {
		cp = versions;
		len = versions_len;
		while (len) {
			tls_uint16_from_bytes(&version, &cp, &len);
			if (version == server_versions[i]) {
				common_versions[j++] = version;
				break;
			}
		}
	}
	*common_versions_cnt = j;
	if (*common_versions_cnt == 0) {
		error_print();
		return 0;
	}
	return 1;
}

int tls13_client_supported_versions_print(FILE *fp, int fmt, int ind,
	const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *versions;
	size_t versions_len;

	format_print(fp, fmt, ind, "versions\n");
	ind += 4;

	if (tls_uint8array_from_bytes(&versions, &versions_len, &ext_data, &ext_datalen) != 1) {
		error_print();
		return -1;
	}
	if (versions_len < 2 || versions_len > 254) {
		error_print();
		return -1;
	}
	while (versions_len) {
		uint16_t version;
		if (tls_uint16_from_bytes(&version, &versions, &versions_len) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind, "%s (%04x)\n", tls_protocol_name(version), version);
	}
	if (ext_datalen) {
		error_print();
		return -1;
	}
	return 1;
}


/*
struct {
	ProtocolVersion selected_version;
} SupportedVersions; // in ServerHello and HelloRetryRequest
*/
int tls13_server_supported_versions_ext_to_bytes(int selected_version, uint8_t **out, size_t *outlen)
{
	uint16_t ext_type = TLS_extension_supported_versions;
	size_t ext_datalen;
	size_t i;

	if (!outlen) {
		error_print();
		return -1;
	}
	if (!tls_protocol_name(selected_version)) {
		error_print();
		return -1;
	}
	ext_datalen = tls_uint16_size();
	tls_uint16_to_bytes(ext_type, out, outlen);
	tls_uint16_to_bytes((uint16_t)ext_datalen, out, outlen);
	tls_uint16_to_bytes(selected_version, out, outlen);
	return 1;
}

// 这个函数可能用不上
int tls13_server_supported_versions_from_bytes(int *selected_version, const uint8_t *ext_data, size_t ext_datalen)
{
	uint16_t version;
	if (tls_uint16_from_bytes(&version, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	if (!tls_protocol_name(version)) {
		error_print();
		return -1;
	}
	*selected_version = version;
	return 1;
}

int tls13_server_supported_versions_print(FILE *fp, int fmt, int ind,
	const uint8_t *ext_data, size_t ext_datalen)
{
	uint16_t version;

	if (tls_uint16_from_bytes(&version, &ext_data, &ext_datalen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "selected_version: %s (%04x)\n", tls_protocol_name(version), version);
	if (ext_datalen) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_process_server_supported_versions(const int *client_versions, size_t client_versions_cnt,
	const uint8_t *server_ext_data, size_t server_ext_datalen,
	int *selected_version)
{
	uint16_t version;
	size_t i;

	if (tls_uint16_from_bytes(&version, &server_ext_data, &server_ext_datalen) != 1
		|| tls_length_is_zero(server_ext_datalen) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; i < client_versions_cnt; i++) {
		if (version == client_versions[i]) {
			*selected_version = version;
			return 1;
		}
	}
	error_print();
	return -1;
}



/*
struct {
	NamedGroup group;
	opaque key_exchange<1..2^16-1>;
} KeyShareEntry;
*/
int tls13_key_share_entry_to_bytes(const X509_KEY *key, uint8_t **out, size_t *outlen)
{
	uint16_t group;
	uint8_t key_exchange[65];

	if (!key || !outlen) {
		error_print();
		return -1;
	}
	if (key->algor != OID_ec_public_key) {
		error_print();
		return -1;
	}
	if (!(group = tls_named_curve_from_oid(key->algor_param))) {
		error_print();
		return -1;
	}
	if (out && *out) {
		uint8_t *p = key_exchange;
		size_t len = 0;
		if (x509_public_key_to_bytes(key, &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (len != 65) {
			error_print();
			return -1;
		}
	}
	tls_uint16_to_bytes(group, out, outlen);
	tls_uint16array_to_bytes(key_exchange, 65, out, outlen);
	return 1;
}

int tls13_key_share_entry_from_bytes(int *group, const uint8_t **key_exchange, size_t *key_exchange_len,
	const uint8_t **in, size_t *inlen)
{
	uint16_t named_curve;

	if (tls_uint16_from_bytes(&named_curve, in, inlen) != 1
		|| tls_uint16array_from_bytes(key_exchange, key_exchange_len, in, inlen) != 1) {
		error_print();
		return -1;
	}
	*group = named_curve;
	if (!tls_named_curve_name(named_curve)) {
		error_print();
		return -1;
	}
	if (*key_exchange_len != 65) {
		error_print();
		return -1;
	}
	return 1;
}

/*
struct {
	KeyShareEntry client_shares<0..2^16-1>;
} KeyShareClientHello;
*/
int tls13_key_share_client_hello_ext_to_bytes(const X509_KEY *keys, size_t keys_cnt, uint8_t **out, size_t *outlen)
{
	uint16_t ext_type = TLS_extension_key_share;
	size_t ext_datalen = 0;
	size_t client_shares_len = 0;
	size_t i;

	for (i = 0; i < keys_cnt; i++) {
		if (tls13_key_share_entry_to_bytes(&keys[i], NULL, &client_shares_len) != 1) {
			error_print();
			return -1;
		}
	}
	ext_datalen = 2 + client_shares_len;

	tls_uint16_to_bytes(ext_type, out, outlen);
	tls_uint16_to_bytes((uint16_t)ext_datalen, out, outlen);
	tls_uint16_to_bytes((uint16_t)client_shares_len, out, outlen);
	for (i = 0; i < keys_cnt; i++) {
		tls13_key_share_entry_to_bytes(&keys[i], out, outlen);
	}
	return 1;
}

// allow supported_groups, supported_groups_cnt == NULL, 0
int tls13_process_key_share_client_hello(const uint8_t *ext_data, size_t ext_datalen,
	const int *supported_groups, size_t supported_groups_cnt,
	int *group, const uint8_t **key_exchange, size_t *key_exchange_len)
{
	int ret = 0;
	const uint8_t *client_shares;
	size_t client_shares_len;
	size_t i;

	if (tls_uint16array_from_bytes(&client_shares, &client_shares_len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}

	for (i = 0; i < supported_groups_cnt; i++) {
		const uint8_t *cp = client_shares;
		size_t len = client_shares_len;
		int named_curve;
		const uint8_t *point;
		size_t pointlen;

		while (len) {
			if (tls13_key_share_entry_from_bytes(&named_curve, &point, &pointlen, &cp, &len) != 1) {
				error_print();
				return -1;
			}
			if (named_curve == supported_groups[i]) {
				*group = named_curve;
				*key_exchange = point;
				*key_exchange_len = pointlen;
				return 1;
			}
		}
	}
	return 0;
}

int tls13_process_key_share_client_hello_again(const uint8_t *ext_data, size_t ext_datalen,
	int key_exchange_group, const uint8_t **key_exchange, size_t *key_exchange_len)
{
	int ret = 0;
	const uint8_t *client_shares;
	size_t client_shares_len;
	int group;

	if (tls_uint16array_from_bytes(&client_shares, &client_shares_len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	if (tls13_key_share_entry_from_bytes(&group, key_exchange, key_exchange_len, &client_shares, &client_shares_len) != 1
		|| tls_length_is_zero(client_shares_len) != 1) {
		error_print();
		return -1;
	}
	if (group != key_exchange_group) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_key_share_client_hello_print(FILE *fp, int fmt, int ind,
	const uint8_t *data, size_t datalen)
{
	const uint8_t *client_shares;
	size_t client_shares_len;

	format_print(fp, fmt, ind, "client_shares\n");
	ind += 4;
	if (tls_uint16array_from_bytes(&client_shares, &client_shares_len, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	if (!client_shares_len) {
		format_print(fp, fmt, ind, "(null)\n");
	}
	while (client_shares_len) {
		uint16_t group;
		const uint8_t *key_exchange;
		size_t key_exchange_len;

		format_print(fp, fmt, ind, "KeyShareEntry\n");
		if (tls_uint16_from_bytes(&group, &client_shares, &client_shares_len) != 1
			|| tls_uint16array_from_bytes(&key_exchange, &key_exchange_len, &client_shares, &client_shares_len) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind + 4, "group: %s (%04x)\n", tls_named_curve_name(group), group);
		format_bytes(fp, fmt, ind + 4, "key_exchange", key_exchange, key_exchange_len);
	}
	if (datalen) {
		error_print();
		return -1;
	}
	return 1;
}





/*
struct {
	KeyShareEntry server_share;
} KeyShareServerHello;
*/
int tls13_key_share_server_hello_ext_to_bytes(const X509_KEY *key, uint8_t **out, size_t *outlen)
{
	uint16_t ext_type = TLS_extension_key_share;
	size_t ext_datalen = 0;

	if (tls13_key_share_entry_to_bytes(key, NULL, &ext_datalen) != 1) {
		error_print();
		return -1;
	}
	tls_uint16_to_bytes(ext_type, out, outlen);
	tls_uint16_to_bytes((uint16_t)ext_datalen, out, outlen);
	tls13_key_share_entry_to_bytes(key, out, outlen);
	return 1;
}

int tls13_key_share_server_hello_from_bytes(int *group, const uint8_t **key_exchange, size_t *key_exchange_len,
	const uint8_t *ext_data, size_t ext_datalen)
{
	if (tls13_key_share_entry_from_bytes(group, key_exchange, key_exchange_len,
			&ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_key_share_server_hello_print(FILE *fp, int fmt, int ind,
	const uint8_t *data, size_t datalen)
{
	uint16_t group;
	const uint8_t *key_exchange;
	size_t key_exchange_len;

	format_print(fp, fmt, ind, "server_share\n");
	ind += 4;
	if (tls_uint16_from_bytes(&group, &data, &datalen) != 1
		|| tls_uint16array_from_bytes(&key_exchange, &key_exchange_len, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "group: %s (%04x)\n", tls_named_curve_name(group), group);
	format_bytes(fp, fmt, ind, "key_exchange", key_exchange, key_exchange_len);
	if (datalen) {
		error_print();
		return -1;
	}
	return 1;
}

/*
struct {
	NamedGroup selected_group;
} KeyShareHelloRetryRequest;
*/
int tls13_key_share_hello_retry_request_ext_to_bytes(int selected_group, uint8_t **out, size_t *outlen)
{
	uint16_t ext_type = TLS_extension_key_share;

	uint8_t ext_data[2];
	uint8_t *p = ext_data;
	size_t len = 0;

	tls_uint16_to_bytes((uint16_t)selected_group, &p, &len);
	tls_ext_to_bytes(ext_type, ext_data, sizeof(ext_data), out, outlen);

	return 1;
}

int tls13_key_share_hello_retry_request_from_bytes(int *selected_group, const uint8_t *ext_data, size_t ext_datalen)
{
	uint16_t group;

	if (tls_uint16_from_bytes(&group, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	if (!tls_named_curve_name(group)) {
		error_print();
		return -1;
	}
	*selected_group = group;
	return 1;
}

int tls13_key_share_hello_retry_request_print(FILE *fp, int fmt, int ind,
	const uint8_t *ext_data, size_t ext_datalen)
{
	uint16_t selected_group;

	if (tls_uint16_from_bytes(&selected_group, &ext_data, &ext_datalen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "selected_group: %s (%04x)\n",
		tls_named_curve_name(selected_group), selected_group);
	if (ext_datalen) {
		error_print();
		return -1;
	}
	return 1;
}



/*
certificate_authorities

  opaque DistinguishedName<1..2^16-1>;

  struct {
	DistinguishedName authorities<3..2^16-1>;
  } CertificateAuthoritiesExtension;
*/

int tls13_certificate_authorities_ext_to_bytes(const uint8_t *ca_names, size_t ca_names_len,
	uint8_t **out, size_t *outlen)
{
	int ext_type = TLS_extension_certificate_authorities;
	size_t ext_datalen;
	size_t authorities_len;
	const uint8_t *name;
	size_t namelen;
	const uint8_t *p;
	size_t len;

	p = ca_names;
	len = ca_names_len;
	authorities_len = 0;
	while (len) {
		if (x509_name_from_der(&name, &namelen, &p, &len) != 1) {
			error_print();
			return -1;
		}
		tls_uint16array_to_bytes(name, namelen, NULL, &authorities_len);
	}
	if (authorities_len < 3 || authorities_len > (1 << 16) - 1) {
		error_print();
		return -1;
	}
	ext_datalen = tls_uint16_size() + authorities_len;

	tls_uint16_to_bytes(ext_type, out, outlen);
	tls_uint16_to_bytes((uint16_t)ext_datalen, out, outlen);
	tls_uint16_to_bytes((uint16_t)authorities_len, out, outlen);
	while (ca_names_len) {
		x509_name_from_der(&name, &namelen, &ca_names, &ca_names_len);
		tls_uint16array_to_bytes(name, namelen, out, outlen);
	}
	return 1;
}

int tls13_certificate_authorities_from_bytes(const uint8_t **ca_names, size_t *ca_names_len,
	const uint8_t *ext_data, size_t ext_datalen)
{
	if (tls_uint16array_from_bytes(ca_names, ca_names_len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	if (*ca_names == NULL) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_enable_certificate_authorities(TLS_CONNECT *conn)
{
	if (!conn) {
		error_print();
		return -1;
	}
	if (!conn->ctx->cacertslen) {
		error_print();
		return -1;
	}
	conn->certificate_authorities = 1;
	return 1;
}

int tls13_certificate_authorities_print(FILE *fp, int fmt, int ind,
	const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *authorities;
	size_t authorities_len;

	if (tls_uint16array_from_bytes(&authorities, &authorities_len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	while (authorities_len) {
		const uint8_t *dn;
		size_t dn_len;

		if (tls_uint16array_from_bytes(&dn, &dn_len, &authorities, &authorities_len) != 1) {
			error_print();
			return -1;
		}

		x509_name_print(fp, fmt, ind, "DistinguishedName", dn, dn_len);
	}
	return 1;
}


/*
48. oid_filters

struct {
	OIDFilter filters<0..2^16-1>;
} OIDFilterExtension;

struct {
	opaque certificate_extension_oid<1..2^8-1>;
	opaque certificate_extension_values<0..2^16-1>;
} OIDFilter;
*/

int tls13_oid_filters_ext_to_bytes(const uint8_t *filters, size_t filters_len, uint8_t **out, size_t *outlen)
{
	uint16_t ext_type = TLS_extension_oid_filters;
	size_t ext_datalen;

	if (!outlen) {
		error_print();
		return -1;
	}

	ext_datalen = tls_uint16_size() + filters_len;
	tls_uint16_to_bytes(ext_type, out, outlen);
	tls_uint16_to_bytes(ext_datalen, out, outlen);
	tls_uint16array_to_bytes(filters, filters_len, out, outlen);

	return 1;
}

int tls13_oid_filters_from_bytes(const uint8_t **filters, size_t *filters_len,
	const uint8_t *ext_data, size_t ext_datalen)
{
	if (tls_uint16array_from_bytes(filters, filters_len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_oid_filters_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen)
{
	return 1;
}










/*
struct {
	opaque certificate_request_context<0..2^8-1>;
	Extension extensions<2..2^16-1>;
} CertificateRequest;

certificate_request_context 用于 Post-handshake Authentication，否则应该长度为0

*/

int tls13_client_hello_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen)
{
	uint16_t protocol;
	const uint8_t *random;
	const uint8_t *session_id;
	const uint8_t *cipher_suites;
	const uint8_t *comp_meths;
	const uint8_t *exts;
	size_t session_id_len, cipher_suites_len, comp_meths_len, extslen;
	size_t i;

	format_print(fp, fmt, ind, "ClientHello\n");
	ind += 4;

	if (tls_uint16_from_bytes(&protocol, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "legacy_version: %s (%04x)\n",
		tls_protocol_name(protocol), protocol);

	if (tls_array_from_bytes(&random, 32, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "random", random ,32);

	if (tls_uint8array_from_bytes(&session_id, &session_id_len, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "legacy_session_id", session_id, session_id_len);

	format_print(fp, fmt, ind, "cipher_suites\n");
	if (tls_uint16array_from_bytes(&cipher_suites, &cipher_suites_len, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	while (cipher_suites_len) {
		uint16_t cipher;
		if (tls_uint16_from_bytes(&cipher, &cipher_suites, &cipher_suites_len) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind+4, "%s (%04x)\n", tls_cipher_suite_name(cipher), cipher);
	}

	format_print(fp, fmt, ind, "legacy_compression_methods\n");
	if (tls_uint8array_from_bytes(&comp_meths, &comp_meths_len, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; i < comp_meths_len; i++) {
		format_print(fp, fmt, ind + 4, "%s (%d)\n",
			tls_compression_method_name(comp_meths[i]), comp_meths[i]);
	}

	format_print(fp, fmt, ind, "extensions\n");
	ind += 4;
	if (tls_uint16array_from_bytes(&exts, &extslen, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	while (extslen) {
		uint16_t ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;

		// tls_ext_from_bytes can not parse unknown ext
		if (tls_uint16_from_bytes(&ext_type, &exts, &extslen) != 1
			|| tls_uint16array_from_bytes(&ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind, "%s (%d)\n", tls_extension_name(ext_type), ext_type);

		switch (ext_type) {
		case TLS_extension_supported_versions:
			tls13_client_supported_versions_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_signature_algorithms:
			tls_signature_algorithms_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_signature_algorithms_cert:
			tls_signature_algorithms_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_server_name:
			tls_server_name_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_status_request:
			tls_client_status_request_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_signed_certificate_timestamp:
			format_bytes(fp, fmt, ind + 4, "data", ext_data, ext_datalen); // should be empty
			break;
		case TLS_extension_supported_groups:
			tls_supported_groups_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_key_share:
			tls13_key_share_client_hello_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_psk_key_exchange_modes:
			tls13_psk_key_exchange_modes_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_pre_shared_key:
			tls13_client_pre_shared_key_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_early_data:
			tls13_early_data_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_cookie:
			tls13_cookie_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_post_handshake_auth:
			format_bytes(fp, fmt, ind + 4, "data", ext_data, ext_datalen); // should be empty
			break;
		case TLS_extension_max_fragment_length:
		case TLS_extension_use_srtp:
		case TLS_extension_heartbeat:
		case TLS_extension_application_layer_protocol_negotiation:
		case TLS_extension_server_certificate_type:
		case TLS_extension_client_certificate_type:
		case TLS_extension_padding:
		case TLS_extension_record_size_limit:
			format_bytes(fp, fmt, ind + 4, "data", ext_data, ext_datalen);
			break;
		default:
			format_bytes(fp, fmt, ind + 4, "data", ext_data, ext_datalen);
			error_print();
			//return -1;
		}
	}
	if (dlen) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_server_hello_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen)
{
	uint16_t protocol;
	const uint8_t *random;
	const uint8_t *session_id;
	uint16_t cipher_suite;
	uint8_t comp_meth;
	const uint8_t *exts;
	size_t session_id_len, extslen;

	format_print(fp, fmt, ind, "ServerHello\n");
	ind += 4;

	if (tls_uint16_from_bytes(&protocol, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "legacy_version: %s (%04x)\n",
		tls_protocol_name(protocol), protocol);

	if (tls_array_from_bytes(&random, 32, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "random", random, 32);

	if (tls_uint8array_from_bytes(&session_id, &session_id_len, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "legacy_session_id", session_id, session_id_len);

	if (tls_uint16_from_bytes(&cipher_suite, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "cipher_suite: %s (%04x)\n",
		tls_cipher_suite_name(cipher_suite), cipher_suite);

	if (tls_uint8_from_bytes(&comp_meth, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "legacy_compression_method: %s (%d)\n",
		tls_compression_method_name(comp_meth), comp_meth);

	format_print(fp, fmt, ind, "extensions\n");
	ind += 4;
	if (tls_uint16array_from_bytes(&exts, &extslen, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	while (extslen) {
		uint16_t ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;

		if (tls_uint16_from_bytes(&ext_type, &exts, &extslen) != 1
			|| tls_uint16array_from_bytes(&ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind, "%s (%d)\n", tls_extension_name(ext_type), ext_type);
		switch (ext_type) {
		case TLS_extension_supported_versions:
			tls13_server_supported_versions_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_key_share:
			tls13_key_share_server_hello_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_pre_shared_key:
			tls13_server_pre_shared_key_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_cookie:
			tls13_cookie_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		default:
			format_bytes(fp, fmt, ind + 4, "raw_data", ext_data, ext_datalen);
			error_print();
			return -1;
		}
	}
	if (dlen) {
		error_print();
		return -1;
	}
	return 1;
}



int tls13_record_set_handshake_hello_retry_request(uint8_t *record, size_t *recordlen,
	int legacy_version, const uint8_t random[32],
	const uint8_t *legacy_session_id_echo, size_t legacy_session_id_echo_len,
	int cipher_suite, int legacy_compress_meth,
	const uint8_t *exts, size_t extslen)
{
	int type = TLS_handshake_hello_retry_request;
	uint8_t *p;
	size_t len;

	if (!tls_protocol_name(legacy_version)) {
		error_print();
		return -1;
	}
	if (legacy_session_id_echo_len > 32) {
		error_print();
		return -1;
	}
	if (!tls_cipher_suite_name(cipher_suite)) {
		error_print();
		return -1;
	}
	if (legacy_compress_meth > 255) {
		error_print();
		return -1;
	}

	p = tls_handshake_data(tls_record_data(record));
	len = 0;

	tls_uint16_to_bytes((uint16_t)legacy_version, &p, &len);
	tls_array_to_bytes(random, 32, &p, &len);
	tls_uint8array_to_bytes(legacy_session_id_echo, legacy_session_id_echo_len, &p, &len);
	tls_uint16_to_bytes((uint16_t)cipher_suite, &p, &len);
	tls_uint8_to_bytes((uint8_t)legacy_compress_meth, &p, &len);
	tls_uint16array_to_bytes(exts, extslen, &p, &len);

	if (tls_record_set_handshake(record, recordlen, type, NULL, len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_record_get_handshake_hello_retry_request(uint8_t *record,
	int *legacy_version, const uint8_t **random,
	const uint8_t **legacy_session_id_echo, size_t *legacy_session_id_echo_len,
	int *cipher_suite, int *legacy_compress_meth,
	const uint8_t **exts, size_t *extslen)
{
	int type;
	const uint8_t *cp;
	size_t len;
	uint16_t version;
	uint16_t cipher;
	uint8_t comp_meth;

	if (tls_record_get_handshake(record, &type, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_hello_retry_request) {
		error_print();
		return -1;
	}
	if (tls_uint16_from_bytes(&version, &cp, &len) != 1
		|| tls_array_from_bytes(random, 32, &cp, &len) != 1
		|| tls_uint8array_from_bytes(legacy_session_id_echo, legacy_session_id_echo_len, &cp, &len) != 1
		|| tls_uint16_from_bytes(&cipher, &cp, &len) != 1
		|| tls_uint8_from_bytes(&comp_meth, &cp, &len) != 1
		|| tls_uint16array_from_bytes(exts, extslen, &cp, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	// if legacy_version != tls12, send protocol_version alert
	if (!tls_protocol_name(version)) {
		error_print();
		return -1;
	}
	if (version != TLS_protocol_tls12) {
		error_print();
	}
	*legacy_version = version;

	if (*legacy_session_id_echo_len > 32) {
		error_print();
		return -1;
	}

	if (!tls_cipher_suite_name(cipher)) {
		error_print();
		return -1;
	}
	*cipher_suite = cipher;

	// if legacy_compress_meth != 0, send illegal_parameter alert
	if (comp_meth != 0) {
		error_print();
	}
	*legacy_compress_meth = comp_meth;

	if (*extslen < 6) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_hello_retry_request_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen)
{
	uint16_t protocol;
	const uint8_t *random;
	const uint8_t *session_id;
	uint16_t cipher_suite;
	uint8_t comp_meth;
	const uint8_t *exts;
	size_t session_id_len, extslen;

	format_print(fp, fmt, ind, "HelloRetryRequest\n");
	ind += 4;

	if (tls_uint16_from_bytes(&protocol, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "legacy_version: %s (%04x)\n",
		tls_protocol_name(protocol), protocol);

	if (tls_array_from_bytes(&random, 32, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "random", random, 32);

	if (tls_uint8array_from_bytes(&session_id, &session_id_len, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "legacy_session_id", session_id, session_id_len);

	if (tls_uint16_from_bytes(&cipher_suite, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "cipher_suite: %s (%04x)\n",
		tls_cipher_suite_name(cipher_suite), cipher_suite);

	if (tls_uint8_from_bytes(&comp_meth, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "legacy_compression_method: %s (%d)\n",
		tls_compression_method_name(comp_meth), comp_meth);

	format_print(fp, fmt, ind, "extensions\n");
	ind += 4;
	if (tls_uint16array_from_bytes(&exts, &extslen, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	while (extslen) {
		uint16_t ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;

		if (tls_uint16_from_bytes(&ext_type, &exts, &extslen) != 1
			|| tls_uint16array_from_bytes(&ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind, "%s (%d)\n", tls_extension_name(ext_type), ext_type);
		switch (ext_type) {
		case TLS_extension_supported_versions:
			tls13_server_supported_versions_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_key_share:
			tls13_key_share_hello_retry_request_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_pre_shared_key:
			//tls13_pre_shared_key_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_cookie:
			tls13_cookie_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		default:
			format_bytes(fp, fmt, ind + 4, "raw_data", ext_data, ext_datalen);
			return -1;
		}
	}
	if (dlen) {
		error_print();
		return -1;
	}

	return 1;
}





int tls13_encrypted_extensions_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen)
{
	const uint8_t *exts;
	size_t extslen;

	format_print(fp, fmt, ind, "EncryptedExtensions\n");
	ind += 4;
	format_print(fp, fmt, ind, "extensions\n");
	ind += 4;

	if (tls_uint16array_from_bytes(&exts, &extslen, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	if (!extslen) {
		format_print(fp, fmt, ind, "(null)\n");
	}
	while (extslen) {
		uint16_t ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;

		if (tls_uint16_from_bytes(&ext_type, &exts, &extslen) != 1
			|| tls_uint16array_from_bytes(&ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind, "%s (%d)\n", tls_extension_name(ext_type), ext_type);

		switch (ext_type) {
		case TLS_extension_supported_groups:
			tls_supported_groups_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_early_data:
			tls13_early_data_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_client_certificate_type:
		case TLS_extension_server_certificate_type:
		case TLS_extension_server_name:
		case TLS_extension_max_fragment_length:
		case TLS_extension_use_srtp:
		case TLS_extension_heartbeat:
		case TLS_extension_application_layer_protocol_negotiation:
		case TLS_extension_record_size_limit:
			format_bytes(fp, fmt, ind + 4, "data", ext_data, ext_datalen);
			break;
		default:
			format_bytes(fp, fmt, ind + 4, "data", ext_data, ext_datalen);
			error_print();
		}
	}
	if (dlen) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_certificate_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen)
{
	const uint8_t *req_context;
	size_t req_context_len;
	const uint8_t *cert_list;
	size_t cert_list_len;

	format_print(fp, fmt, ind, "Certificate\n");
	ind += 4;

	if (tls_uint8array_from_bytes(&req_context, &req_context_len, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "certificate_request_context", req_context, req_context_len);

	format_print(fp, fmt, ind, "certificate_list\n");
	ind += 4;
	if (tls_uint24array_from_bytes(&cert_list, &cert_list_len, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	while (cert_list_len) {
		const uint8_t *cert_data;
		size_t cert_data_len;
		const uint8_t *exts;
		size_t extslen;

		format_print(fp, fmt, ind, "CertificateEntry\n");
		if (tls_uint24array_from_bytes(&cert_data, &cert_data_len, &cert_list, &cert_list_len) != 1
			|| tls_uint16array_from_bytes(&exts, &extslen, &cert_list, &cert_list_len) != 1) {
			error_print();
			return -1;
		}
		if (!cert_data_len) {
			error_print();
			return -1;
		}
		x509_cert_print(fp, fmt, ind + 4, "Certificate", cert_data, cert_data_len);
		x509_cert_to_pem(cert_data, cert_data_len, fp);

		if (extslen)
			format_print(fp, fmt, ind + 4, "extensions\n");
		else	format_print(fp, fmt, ind + 4, "extensions: (null)\n");

		while (extslen) {
			uint16_t ext_type;
			const uint8_t *ext_data;
			size_t ext_datalen;

			if (tls_uint16_from_bytes(&ext_type, &exts, &extslen) != 1
				|| tls_uint16array_from_bytes(&ext_data, &ext_datalen, &exts, &extslen) != 1) {
				error_print();
				return -1;
			}
			format_print(fp, fmt, ind, "%s (%d)\n", tls_extension_name(ext_type), ext_type);
			ind += 4;

			switch (ext_type) {
			case TLS_extension_status_request:
				tls_server_status_request_print(fp, fmt, ind + 4, ext_data, ext_datalen);
				break;
			case TLS_extension_signed_certificate_timestamp:
				tls_signed_certificate_timestamp_print(fp, fmt, ind + 4, ext_data, ext_datalen);
				break;
			case TLS_extension_server_certificate_type:
			case TLS_extension_client_certificate_type:
				format_bytes(fp, fmt, ind, "data", ext_data, ext_datalen);
				break;
			default:
				format_bytes(fp, fmt, ind, "data", ext_data, ext_datalen);
				error_print();
				//return -1;
			}
		}
	}
	if (dlen) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_certificate_request_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen)
{
	const uint8_t *req_context;
	size_t req_context_len;
	const uint8_t *exts;
	size_t extslen;

	format_print(fp, fmt, ind, "CertificateRequest\n");
	ind += 4;

	if (tls_uint8array_from_bytes(&req_context, &req_context_len, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "certificate_request_context", req_context, req_context_len);

	format_print(fp, fmt, ind, "extensions\n");
	ind += 4;
	if (tls_uint16array_from_bytes(&exts, &extslen, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	while (extslen) {
		uint16_t ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;

		if (tls_uint16_from_bytes(&ext_type, &exts, &extslen) != 1
			|| tls_uint16array_from_bytes(&ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			return -1;
		}
		switch (ext_type) {
		case TLS_extension_signature_algorithms:
			tls_signature_algorithms_print(fp, fmt, ind, ext_data, ext_datalen);
			break;
		case TLS_extension_certificate_authorities:
			tls13_certificate_authorities_print(fp, fmt, ind, ext_data, ext_datalen);
			break;
		case TLS_extension_status_request:
			//tls13_status_request_print(fp, fmt, ind, ext_data, ext_datalen);
			break;
		case TLS_extension_signature_algorithms_cert:
			tls_signature_algorithms_print(fp, fmt, ind, ext_data, ext_datalen);
			break;
		case TLS_extension_client_certificate_type:
			//tls13_client_certificate_type_print(fp, fmt, ind, ext_data, ext_datalen);
			break;
		default:
			error_print();
			return -1;
		}
	}
	if (dlen) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_certificate_verify_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen)
{
	uint16_t sig_alg;
	const uint8_t *sig;
	size_t siglen;

	format_print(fp, fmt, ind, "CertificateVerify\n");
	ind += 4;

	if (tls_uint16_from_bytes(&sig_alg, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "algorithm: %s (%04x)\n", tls_signature_scheme_name(sig_alg), sig_alg);
	if (tls_uint16array_from_bytes(&sig, &siglen, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "signature", sig, siglen);
	if (tls_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_key_update_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen)
{
	uint8_t update_requested;

	if (tls_uint8_from_bytes(&update_requested, &d, &dlen) != 1
		|| tls_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	switch (update_requested) {
	case 0:
	case 1:
		break;
	default:
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "request_update: %d\n", update_requested);
	return 1;
}

int tls13_message_hash_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen)
{
	return 1;
}

int tls13_finished_print(FILE *fp, int fmt, int ind, const uint8_t *data, size_t datalen)
{
	format_print(fp, fmt, ind, "Finished\n");
	ind += 4;
	format_bytes(fp, fmt, ind, "verify_data", data, datalen);
	return 1;
}


int tls13_handshake_print(FILE *fp, int fmt, int ind, const uint8_t *handshake, size_t handshake_len)
{
	const uint8_t *p = handshake;
	size_t len = handshake_len;
	uint8_t type;
	const uint8_t *data;
	size_t datalen;

	if (tls_uint8_from_bytes(&type, &handshake, &handshake_len) != 1
		|| tls_uint24array_from_bytes(&data, &datalen, &handshake, &handshake_len) != 1
		|| tls_length_is_zero(handshake_len) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "Handshake\n");
	ind += 4;
	format_print(fp, fmt, ind, "Type: %s (%d)\n", tls_handshake_type_name(type), type);
	format_print(fp, fmt, ind, "Length: %zu\n", datalen);

	switch (type) {
	case TLS_handshake_client_hello:
		tls13_client_hello_print(fp, fmt, ind, data, datalen);
		break;
	case TLS_handshake_server_hello:
		tls13_server_hello_print(fp, fmt, ind, data, datalen);
		break;
	case TLS_handshake_hello_retry_request:
		tls13_hello_retry_request_print(fp, fmt, ind, data, datalen);
		break;
	case TLS_handshake_new_session_ticket:
		tls13_new_session_ticket_print(fp, fmt, ind, data, datalen);
		break;
	case TLS_handshake_end_of_early_data:
		tls13_end_of_early_data_print(fp, fmt, ind, data, datalen);
		break;
	case TLS_handshake_encrypted_extensions:
		tls13_encrypted_extensions_print(fp, fmt, ind, data, datalen);
		break;
	case TLS_handshake_certificate:
		tls13_certificate_print(fp, fmt, ind, data, datalen);
		break;
	case TLS_handshake_certificate_request:
		tls13_certificate_request_print(fp, fmt, ind, data, datalen);
		break;
	case TLS_handshake_certificate_verify:
		tls13_certificate_verify_print(fp, fmt, ind, data, datalen);
		break;
	case TLS_handshake_finished:
		tls13_finished_print(fp, fmt, ind, data, datalen);
		break;
	case TLS_handshake_key_update:
		tls13_key_update_print(fp, fmt, ind, data, datalen);
		break;
	case TLS_handshake_message_hash:
		tls13_message_hash_print(fp, fmt, ind, data, datalen);
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

int tls13_record_print(FILE *fp, int format, int indent, const uint8_t *record, size_t recordlen)
{
	const uint8_t *data;
	size_t datalen;
	int protocol;

	format |= TLS_cipher_sm4_gcm_sm3 << 8;

	if (!fp || !record || recordlen < 5) {
		error_print();
		return -1;
	}
	protocol = tls_record_protocol(record);
	format_print(fp, format, indent, "Record\n"); indent += 4;
	format_print(fp, format, indent, "ContentType: %s (%d)\n", tls_record_type_name(record[0]), record[0]);
	format_print(fp, format, indent, "Version: %s (%04x)\n", tls_protocol_name(protocol), protocol);
	format_print(fp, format, indent, "Length: %d\n", tls_record_data_length(record));

	data = tls_record_data(record);
	datalen = tls_record_data_length(record);

	if (recordlen < tls_record_length(record)) {
		error_print();
		return -1;
	}

	// 最高字节设置后强制打印记录原始数据
	if (format >> 24) {
		format_bytes(fp, format, indent, "Data", data, datalen);
		fprintf(fp, "\n");
		return 1;
	}

	switch (record[0]) {
	case TLS_record_handshake:
		tls13_handshake_print(fp, format, indent, data, datalen);
		break;

	case TLS_record_alert:
		if (tls_alert_print(fp, data, datalen, format, indent) != 1) {
			error_print();
			return -1;
		}
		break;
	case TLS_record_change_cipher_spec:
		if (tls_change_cipher_spec_print(fp, data, datalen, format, indent) != 1) {
			error_print();
			return -1;
		}
		break;
	case TLS_record_application_data:
		if (tls_application_data_print(fp, data, datalen, format, indent) != 1) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}

	recordlen -= tls_record_length(record);
	if (recordlen) {
		format_print(fp, 0, 0, "DataLeftInRecord: %zu\n", recordlen);
	}

	fprintf(fp, "\n");
	return 1;
}




int tls13_certificate_list_to_bytes(const uint8_t *certs, size_t certslen,
	uint8_t **out, size_t *outlen)
{
	uint8_t *p = NULL;
	size_t cert_list_len = 0;

	if (out && *out) {
		p = (*out) + tls_uint24_size();
	}
	while (certslen) {
		const uint8_t *cert;
		size_t certlen;
		const uint8_t *entry_exts = NULL;
		size_t entry_exts_len = 0;

		if (x509_cert_from_der(&cert, &certlen, &certs, &certslen) != 1) {
			error_print();
			return -1;
		}
		tls_uint24array_to_bytes(cert, certlen, &p, &cert_list_len);
		tls_uint16array_to_bytes(entry_exts, entry_exts_len, &p, &cert_list_len);

	}
	tls_uint24array_to_bytes(NULL, cert_list_len, out, outlen);
	return 1;
}

int tls13_process_certificate_list(const uint8_t *cert_list, size_t cert_list_len,
	uint8_t *certs, size_t *certs_len)
{
	*certs_len = 0;

	while (cert_list_len) {
		const uint8_t *cert_data;
		size_t cert_data_len;
		const uint8_t *exts;
		size_t exts_len;
		const uint8_t *cert;
		size_t cert_len;

		if (tls_uint24array_from_bytes(&cert_data, &cert_data_len, &cert_list, &cert_list_len) != 1
			|| tls_uint16array_from_bytes(&exts, &exts_len, &cert_list, &cert_list_len) != 1) {
			error_print();
			return -1;
		}
		if (x509_cert_from_der(&cert, &cert_len, &cert_data, &cert_data_len) != 1
			|| asn1_length_is_zero(cert_data_len) != 1
			|| x509_cert_to_der(cert, cert_len, &certs, certs_len) != 1) {
			error_print();
			return -1;
		}

		while (exts_len) {
			int ext_type;
			const uint8_t *ext_data;
			size_t ext_data_len;

			if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_data_len, &exts, &exts_len) != 1) {
				error_print();
				return -1;
			}
			switch (ext_type) {
			case TLS_extension_status_request:
			case TLS_extension_signed_certificate_timestamp:
				error_print();
				return -1;
			default:
				error_print();
				return -1;
			}
		}
	}
	return 1;
}


// 1. client_hello
// 2. server_hello

/*
int tls13_record_set_handshake_hello_retry_request(uint8_t *record, size_t *recordlen,
	int protocol, const uint8_t random[32],
	const uint8_t *session_id, size_t session_id_len, int cipher_suite,
	const uint8_t *exts, size_t exts_len)
{
	uint8_t type = TLS_handshake_hello_retry_request;
	uint8_t *p;
	size_t len;

	if (!record || !recordlen || !random) {
		error_print();
		return -1;
	}
	if (session_id) {
		if (session_id_len == 0
			|| session_id_len < TLS_MIN_SESSION_ID_SIZE
			|| session_id_len > TLS_MAX_SESSION_ID_SIZE) {
			error_print();
			return -1;
		}
	}
	if (!tls_protocol_name(protocol)) {
		error_print();
		return -1;
	}
	if (!tls_cipher_suite_name(cipher_suite)) {
		error_print();
		return -1;
	}

	p = tls_handshake_data(tls_record_data(record));
	len = 0;

	tls_uint16_to_bytes((uint16_t)protocol, &p, &len);
	tls_array_to_bytes(random, 32, &p, &len);
	tls_uint8array_to_bytes(session_id, session_id_len, &p, &len);
	tls_uint16_to_bytes((uint16_t)cipher_suite, &p, &len);
	tls_uint8_to_bytes((uint8_t)TLS_compression_null, &p, &len);
	if (exts) {
		if (protocol < TLS_protocol_tls12) {
			error_print();
			return -1;
		}
		tls_uint16array_to_bytes(exts, exts_len, &p, &len);
	}
	if (tls_record_set_handshake(record, recordlen, type, NULL, len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}
*/

/*
NewSessionTicket

      struct {
          uint32 ticket_lifetime;
          uint32 ticket_age_add;
          opaque ticket_nonce<0..255>;
          opaque ticket<1..2^16-1>;
          Extension extensions<0..2^16-2>;
      } NewSessionTicket;
*/





// 8. encrypted_extensions
int tls13_record_set_handshake_encrypted_extensions(uint8_t *record, size_t *recordlen,
	const uint8_t *exts, size_t extslen)
{
	int type = TLS_handshake_encrypted_extensions;
	uint8_t *p = record + 5 + 4;
	size_t len = 0;

	tls_uint16array_to_bytes(exts, extslen, &p, &len);
	tls_record_set_handshake(record, recordlen, type, NULL, len);
	return 1;
}

int tls13_record_get_handshake_encrypted_extensions(const uint8_t *record,
	const uint8_t **exts, size_t *extslen)
{
	int type;
	const uint8_t *cp;
	size_t len;

	if (tls_record_get_handshake(record, &type, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_encrypted_extensions) {
		error_print();
		return 0;
	}
	if (tls_uint16array_from_bytes(exts, extslen, &cp, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}


// 11. certificate

/*
Certificate {
    opaque certificate_request_context<0..2^8-1>;
    CertificateEntry certificate_list<0..2^24-1>;
}

CertificateEntry {
	opaque cert_data<1..2^24-1>;
	Extension extensions<0..2^16-1>;
}
*/

int tls13_certificate_entry_to_bytes(const uint8_t *cert, size_t certlen,
	const uint8_t *status_request_ocsp_response, size_t status_request_ocsp_response_len,
	const uint8_t *signed_certificate_timestamp, size_t signed_certificate_timestamp_len,
	uint8_t **out, size_t *outlen)
{
	size_t extslen = 0;

	if (status_request_ocsp_response && status_request_ocsp_response_len) {
		tls_server_status_request_ext_to_bytes(status_request_ocsp_response, status_request_ocsp_response_len, NULL, &extslen);
	}
	if (signed_certificate_timestamp && signed_certificate_timestamp_len) {
		tls_signed_certificate_timestamp_ext_to_bytes(signed_certificate_timestamp, signed_certificate_timestamp_len, NULL, &extslen);
	}

	tls_uint24array_to_bytes(cert, certlen, out, outlen);
	tls_uint16_to_bytes(extslen, out, outlen);
	if (status_request_ocsp_response && status_request_ocsp_response_len) {
		tls_server_status_request_ext_to_bytes(status_request_ocsp_response, status_request_ocsp_response_len, out, outlen);
	}
	if (signed_certificate_timestamp && signed_certificate_timestamp_len) {
		tls_signed_certificate_timestamp_ext_to_bytes(signed_certificate_timestamp, signed_certificate_timestamp_len, out, outlen);
	}
	return 1;
}

int tls13_certificate_entry_from_bytes(const uint8_t **cert, size_t *certlen,
	const uint8_t **status_request_ocsp_response, size_t *status_request_ocsp_response_len,
	const uint8_t **signed_certificate_timestamp, size_t *signed_certificate_timestamp_len,
	const uint8_t **in, size_t *inlen)
{
	const uint8_t *exts;
	size_t extslen;

	if (!cert || !certlen
		|| !status_request_ocsp_response || !status_request_ocsp_response_len
		|| !signed_certificate_timestamp || !signed_certificate_timestamp_len
		|| !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (tls_uint24array_from_bytes(cert, certlen, in, inlen) != 1
		|| tls_uint16array_from_bytes(&exts, &extslen, in, inlen) != 1) {
		error_print();
		return -1;
	}
	while (extslen) {
		int ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;

		if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			return -1;
		}

		switch (ext_type) {
		case TLS_extension_status_request:
			*status_request_ocsp_response = ext_data;
			*status_request_ocsp_response_len = ext_datalen;
			break;
		case TLS_extension_signed_certificate_timestamp:
			*signed_certificate_timestamp = ext_data;
			*signed_certificate_timestamp_len = ext_datalen;
			break;
		default:
			error_print();
			return -1;
		}
	}
	return 1;
}

/*
struct {
	opaque certificate_request_context<0..2^8-1>;
	CertificateEntry certificate_list<0..2^24-1>;
} Certificate;

if has no proper certificate chain
the client should send the Certificate with empty certificate_list content
*/
int tls13_record_set_handshake_certificate(uint8_t *record, size_t *recordlen,
	const uint8_t *request_context, size_t request_context_len,
	const uint8_t *certs, size_t certslen,
	const uint8_t *entity_status_request_ocsp_response, size_t entity_status_request_ocsp_response_len,
	const uint8_t *entity_signed_certificate_timestamp, size_t entity_signed_certificate_timestamp_len)
{
	int type = TLS_handshake_certificate;
	uint8_t *data;
	size_t datalen = 0;
	uint8_t *cert_list;
	size_t cert_list_len = 0;
	const uint8_t *cert;
	size_t certlen;
	size_t len;

	if (!record || !recordlen) {
		error_print();
		return -1;
	}

	data = tls_handshake_data(tls_record_data(record));

	// certificate_request_context<0..2^8-1>
	tls_uint8array_to_bytes(request_context, request_context_len, &data, &datalen);

	// certificate_list<0..2^24-1>
	cert_list = data;
	tls_uint24_to_bytes(0, &data, &len);

	// client might send null certificate_list
	if (certs && certslen) {
		// first (entity) cert entry
		if (x509_cert_from_der(&cert, &certlen, &certs, &certslen) != 1) {
			error_print();
			return -1;
		}
		if (tls13_certificate_entry_to_bytes(cert, certlen,
			entity_status_request_ocsp_response, entity_status_request_ocsp_response_len,
			entity_signed_certificate_timestamp, entity_signed_certificate_timestamp_len,
			&data, &cert_list_len) != 1) {
			error_print();
			return -1;
		}
		// ca certs entries
		while (certslen) {
			if (x509_cert_from_der(&cert, &certlen, &certs, &certslen) != 1) {
				error_print();
				return -1;
			}
			if (tls13_certificate_entry_to_bytes(cert, certlen, NULL, 0, NULL, 0, &data, &cert_list_len) != 1) {
				error_print();
				return -1;
			}
		}
	}
	tls_uint24array_to_bytes(NULL, cert_list_len, &cert_list, &datalen);
	if (tls_record_set_handshake(record, recordlen, type, NULL, datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

/*
int _tls13_record_get_handshake_certificate(const uint8_t *record,
	const uint8_t **request_context, size_t *request_context_len,
	const uint8_t **cert_list, size_t *cert_list_len)
{
	int type;
	const uint8_t *p;
	size_t len;

	if (tls_record_get_handshake(record, &type, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_certificate) {
		error_print();
		return -1;
	}
	if (tls_uint8array_from_bytes(request_context, request_context_len, &p, &len) != 1
		|| tls_uint24array_from_bytes(cert_list, cert_list_len, &p, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}
*/


// even if status_request, signed_certificate_timestamp not requested
// server/client can still return certificate with these two extensions
int tls13_record_get_handshake_certificate(const uint8_t *record,
	const uint8_t **request_context, size_t *request_context_len,
	uint8_t *cert_chain, size_t *cert_chain_len, size_t cert_chain_maxlen,
	const uint8_t **entity_status_request_ocsp_response, size_t *entity_status_request_ocsp_response_len,
	const uint8_t **entity_signed_certificate_timestamp, size_t *entity_signed_certificate_timestamp_len)
{
	int type;
	const uint8_t *p;
	size_t len;
	const uint8_t *cert_list;
	size_t cert_list_len;
	const uint8_t *cert;
	size_t certlen;


	if (tls_record_get_handshake(record, &type, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_certificate) {
		error_print();
		return -1;
	}
	if (tls_uint8array_from_bytes(request_context, request_context_len, &p, &len) != 1
		|| tls_uint24array_from_bytes(&cert_list, &cert_list_len, &p, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	if (cert_list_len > cert_chain_maxlen) {
		error_print();
		return -1;
	}

	if (tls13_certificate_entry_from_bytes(&cert, &certlen,
		entity_status_request_ocsp_response, entity_status_request_ocsp_response_len,
		entity_signed_certificate_timestamp, entity_signed_certificate_timestamp_len,
		&cert_list, &cert_list_len) != 1) {
		error_print();
		return -1;
	}

	*cert_chain_len = 0;

	x509_cert_to_der(cert, certlen, &cert_chain, cert_chain_len);

	while (cert_list_len) {
		const uint8_t *status_request_ocsp_response;
		size_t status_request_ocsp_response_len;
		const uint8_t *signed_certificate_timestamp;
		size_t signed_certificate_timestamp_len;

		if (tls13_certificate_entry_from_bytes(&cert, &certlen,
			&status_request_ocsp_response, &status_request_ocsp_response_len,
			&signed_certificate_timestamp, &signed_certificate_timestamp_len,
			&cert_list, &cert_list_len) != 1) {
			error_print();
			return -1;
		}
			// 这里的解析可能是有问题的				


		x509_cert_to_der(cert, certlen, &cert_chain, cert_chain_len);
	}

	return 1;
}




// 13. certificate_request
/*
struct {
	opaque certificate_request_context<0..2^8-1>;
	Extension extensions<2..2^16-1>;
} CertificateRequest;

extensiosns:
	Extension signature_algorithms MUST be specified
*/
int tls13_record_set_handshake_certificate_request(uint8_t *record, size_t *recordlen,
	const uint8_t *request_context, size_t request_context_len,
	const uint8_t *exts, size_t extslen)
{
	int type = TLS_handshake_certificate_request;
	uint8_t *data;
	size_t datalen = 0;

	if (!record || !recordlen) {
		error_print();
		return -1;
	}
	data = tls_handshake_data(tls_record_data(record));
	tls_uint8array_to_bytes(request_context, request_context_len, &data, &datalen);
	tls_uint16array_to_bytes(exts, extslen, &data, &datalen);
	tls_record_set_handshake(record, recordlen, type, NULL, datalen);
	return 1;
}

int tls13_record_set_handshake_certificate_request_default(uint8_t *record, size_t *recordlen)
{
	int sig_algs[] = { TLS_sig_sm2sig_sm3 };
	uint8_t exts[256];
	uint8_t *p = exts;
	size_t extslen = 0;

	tls_signature_algorithms_ext_to_bytes(sig_algs, sizeof(sig_algs)/sizeof(int), &p, &extslen);
	tls13_record_set_handshake_certificate_request(record, recordlen, NULL, 0, exts, extslen);
	return 1;
}

int tls13_record_get_handshake_certificate_request(const uint8_t *record,
	const uint8_t **requst_context, size_t *request_context_len,
	const uint8_t **exts, size_t *exts_len)
{
	int type;
	const uint8_t *p;
	size_t len;

	if (tls_record_get_handshake(record, &type, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_certificate_request) {
		error_print();
		return -1;
	}
	if (tls_uint8array_from_bytes(requst_context, request_context_len, &p, &len) != 1
		|| tls_uint16array_from_bytes(exts, exts_len, &p, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

/*
handshake #15

struct {
	SignatureScheme algorithm;
	opaque signature<0..2^16-1>;
} CertificateVerify;
*/
int tls13_record_set_handshake_certificate_verify(uint8_t *record, size_t *recordlen,
	int sig_alg, const uint8_t *sig, size_t siglen)
{
	int type = TLS_handshake_certificate_verify;
	uint8_t *p = record + 5 + 4; // 这里都应该改为tls_record_handshake_data			
	size_t len = 0;

	if (!tls_signature_scheme_name(sig_alg)) {
		error_print();
		return -1;
	}
	tls_uint16_to_bytes((uint16_t)sig_alg, &p, &len);
	tls_uint16array_to_bytes(sig, siglen, &p, &len);
	if (tls_record_set_handshake_header(record, recordlen, type, len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_record_get_handshake_certificate_verify(const uint8_t *record,
	int *sig_alg, const uint8_t **sig, size_t *siglen)
{
	int type;
	const uint8_t *cp;
	size_t len ;
	uint16_t alg;

	if (tls_record_get_handshake(record, &type, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_certificate_verify) {
		return 0;
	}
	if (tls_uint16_from_bytes(&alg, &cp, &len) != 1
		|| tls_uint16array_from_bytes(sig, siglen, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (!tls_signature_scheme_name(alg)) {
		error_print();
		return -1;
	}
	*sig_alg = alg;
	return 1;
}


// 20. finished


/*
finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)

struct {
          opaque verify_data[Hash.length];
} Finished;

verify_data = HMAC(finished_key, Hash(Handshake Context, Certificate*, CertificateVerify*))
Hash = SM3, SHA256 or SHA384
*/


int tls13_record_set_handshake_finished(uint8_t *record, size_t *recordlen,
	const uint8_t *verify_data, size_t verify_data_len)
{
	int type = TLS_handshake_finished;

	if (!verify_data || !verify_data_len) {
		error_print();
		return -1;
	}
	if (verify_data_len != 32) {
		error_print();
		return -1;
	}
	if (tls_record_set_handshake(record, recordlen, type, verify_data, verify_data_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_record_get_handshake_finished(const uint8_t *record,
	const uint8_t **verify_data, size_t *verify_data_len)
{
	int type;

	if (tls_record_get_handshake(record, &type, verify_data, verify_data_len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_finished) {
		return 0;
	}
	if (*verify_data_len == 0) {
		error_print();
		return -1;
	}
	return 1;
}

// 24. key_update
int tls13_record_set_handshake_key_update(uint8_t *record, size_t *recordlen,
	int request_update)
{
	int type = TLS_handshake_key_update;
	uint8_t data[1]; // 这个值不太好

	data[0] = request_update ? 1 : 0;
	if (tls_record_set_handshake(record, recordlen, type, data, sizeof(data)) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_record_get_handshake_key_update(uint8_t *record, int *request_update)
{
	int type;
	const uint8_t *cp;
	size_t len;

	if (tls_record_get_handshake(record, &type, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_key_update) {
		return 0;
	}

	if (len != 1) {
		error_print();
		return -1;
	}
	switch (cp[0]) {
	case 0:
		*request_update = 0;
		break;
	case 1:
		*request_update = 1;
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}



// 254. message_hash
int tls13_record_set_message_hash(uint8_t *record, size_t *recordlen)
{
	return -1;
}

int tls13_record_get_message_hash(uint8_t *record, size_t *recordlen)
{
	return -1;
}






int tls_handshake_digest_print(FILE *fp, int fmt, int ind, const char *label, const DIGEST_CTX *dgst_ctx)
{
	DIGEST_CTX tmp_ctx;
	uint8_t dgst[64];
	size_t dgstlen;

	tmp_ctx = *dgst_ctx;

	digest_finish(&tmp_ctx, dgst, &dgstlen);

	format_bytes(fp, fmt, ind, label, dgst, dgstlen);

	return 1;
}





/*
       Client                                           Server

Key  ^ ClientHello
Exch | + key_share*
     | + signature_algorithms*
     | + psk_key_exchange_modes*
     v + pre_shared_key*       -------->
                                                  ServerHello  ^ Key
                                                 + key_share*  | Exch
                                            + pre_shared_key*  v


	| ecdhe => handshake_secret			|
	| handshake_secret => master_secret		|
	| handshake_secret, client_hello, server_hello	|
	|	=> client_handshake_traffic_secret	|
	| => server_handshake_traffic_secret		|


                                        {EncryptedExtensions}  ^  Server
                                        {CertificateRequest*}  v  Params
                                                {Certificate}  ^
                                          {CertificateVerify}  | Auth
                                                   {Finished}  v

	+ master_secret, ClientHello .. server Finished
		=> server_application_traffic_secret_0

                               <--------  [Application Data*]

     ^ {Certificate*}
Auth | {CertificateVerify*}
     v {Finished}              -------->


	+ master_secret, ClientHello .. server Finished
		=> client_application_traffic_secret_0

       [Application Data]      <------->  [Application Data]




*/



int tls_key_exchange_modes_print(FILE *fp, int fmt, int ind, const char *label, int modes)
{
	int first = 1;

	format_print(fp, fmt, ind, "%s:", label);

	if (modes & TLS_KE_CERT_DHE) {
		fprintf(fp, " CERT_DHE");
		first = 0;
	}
	if (modes & TLS_KE_PSK_DHE) {
		if (first)
			fprintf(fp, " PSK_DHE");
		else	fprintf(fp, "|PSK_DHE");
		first = 0;
	}
	if (modes & TLS_KE_PSK) {
		if (first)
			fprintf(fp, " PSK");
		else	fprintf(fp, "|PSK");
	}
	fprintf(fp, "\n");
	return 1;
}


/*

             0
             |
             v
[1]  PSK ->  HKDF-Extract = Early Secret
             |
[2]          +-----> Derive-Secret(., "ext binder" | "res binder", "")
             |                     = binder_key
             |
[3]          +-----> Derive-Secret(., "c e traffic", ClientHello)
             |                     = client_early_traffic_secret
             |
[4]          +-----> Derive-Secret(., "e exp master", ClientHello)
             |                     = early_exporter_master_secret
             v
[5]    Derive-Secret(., "derived", "")
             |
             v
[6]  (EC)DHE -> HKDF-Extract = Handshake Secret
             |
[7]          +-----> Derive-Secret(., "c hs traffic",
             |                     ClientHello...ServerHello)
             |                     = client_handshake_traffic_secret
             |
[8]          +-----> Derive-Secret(., "s hs traffic",
             |                     ClientHello...ServerHello)
             |                     = server_handshake_traffic_secret
             v
[9]    Derive-Secret(., "derived", "")
             |
             v
[10]   0 -> HKDF-Extract = Master Secret
             |
[11]         +-----> Derive-Secret(., "c ap traffic",
             |                     ClientHello...server Finished)
             |                     = client_application_traffic_secret_0
             |
[12]         +-----> Derive-Secret(., "s ap traffic",
             |                     ClientHello...server Finished)
             |                     = server_application_traffic_secret_0
             |
[13]         +-----> Derive-Secret(., "exp master",
             |                     ClientHello...server Finished)
             |                     = exporter_master_secret
             |
[14]         +-----> Derive-Secret(., "res master",
                                   ClientHello...client Finished)
                                   = resumption_master_secret

*/


// 这个函数实际上是生成握手过程的密钥
int tls13_generate_handshake_keys(TLS_CONNECT *conn)
{
	uint8_t zeros[32] = {0};
	uint8_t early_secret[32];
	uint8_t handshake_secret[32];
	uint8_t pre_master_secret[32] = {0};
	size_t pre_master_secret_len;
	uint8_t client_write_key[16] = {0};
	uint8_t server_write_key[16] = {0};
	DIGEST_CTX null_dgst_ctx;

	printf("generate handshake secrets\n");


	/*
	generate handshake keys
		uint8_t client_write_key[32]
		uint8_t server_write_key[32]
		uint8_t client_write_iv[12]
		uint8_t server_write_iv[12]
	*/



	// 计算ECDHE
	if (conn->key_exchange_modes != TLS_KE_PSK) {
		if (conn->key_exchange_idx >= conn->key_exchanges_cnt) {
			error_print();
			return -1;
		}
		if (x509_key_exchange(&conn->key_exchanges[conn->key_exchange_idx],
			conn->peer_key_exchange, conn->peer_key_exchange_len,
			pre_master_secret, &pre_master_secret_len) != 1) {
			error_print();
			return -1;
		}
	}

	digest_init(&null_dgst_ctx, conn->digest);


	/* [1]  */ tls13_hkdf_extract(conn->digest, zeros, conn->psk, early_secret);
	/* [5]  */ tls13_derive_secret(early_secret, "derived", &null_dgst_ctx, handshake_secret);
	/* [6]  */ tls13_hkdf_extract(conn->digest, handshake_secret, pre_master_secret, handshake_secret);
	/* [7]  */ tls13_derive_secret(handshake_secret, "c hs traffic", &conn->dgst_ctx, conn->client_handshake_traffic_secret);
	/* [8]  */ tls13_derive_secret(handshake_secret, "s hs traffic", &conn->dgst_ctx, conn->server_handshake_traffic_secret);

	/* [9]  */ tls13_derive_secret(handshake_secret, "derived", &null_dgst_ctx, conn->master_secret);
	/* [10] */ tls13_hkdf_extract(conn->digest, conn->master_secret, zeros, conn->master_secret);

	//[sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
	//[sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)
	//[sender] in {server, client}
	tls13_hkdf_expand_label(conn->digest, conn->server_handshake_traffic_secret, "key", NULL, 0, 16, server_write_key);
	block_cipher_set_encrypt_key(&conn->server_write_key, conn->cipher, server_write_key);
	tls13_hkdf_expand_label(conn->digest, conn->server_handshake_traffic_secret, "iv", NULL, 0, 12, conn->server_write_iv);
	tls_seq_num_reset(conn->server_seq_num);

	format_bytes(stderr, 0, 0, "server_handshake_traffic_secret", conn->server_handshake_traffic_secret, 48);
	format_bytes(stderr, 0, 0, "client_handshake_traffic_secret", conn->client_handshake_traffic_secret, 48);

	if (!conn->early_data) {
		format_print(stderr, 0, 0, "update client_write_key, client_write_iv\n");

		tls13_hkdf_expand_label(conn->digest, conn->client_handshake_traffic_secret, "key", NULL, 0, 16, client_write_key);
		block_cipher_set_encrypt_key(&conn->client_write_key, conn->cipher, client_write_key);
		tls13_hkdf_expand_label(conn->digest, conn->client_handshake_traffic_secret, "iv", NULL, 0, 12, conn->client_write_iv);
		tls_seq_num_reset(conn->client_seq_num);
	}

	format_bytes(stderr, 0, 4, "server_write_key", server_write_key, 16);
	format_bytes(stderr, 0, 4, "server_write_iv", conn->server_write_iv, 12);

	format_bytes(stderr, 0, 4, "client_write_key", client_write_key, 16);
	format_bytes(stderr, 0, 4, "client_write_iv", conn->client_write_iv, 12);

	return 1;
}

int tls13_init(TLS_CONNECT *conn, TLS_CTX *ctx)
{
	size_t i;


	if (!ctx->supported_versions_cnt) {
		error_print();
		return -1;
	}

	if (!ctx->cipher_suites_cnt) {
		error_print();
		return -1;
	}


	memset(conn, 0, sizeof(*conn));

	conn->ctx = ctx;

	conn->is_client = ctx->is_client;

	conn->protocol = ctx->protocol;



	conn->new_session_ticket = ctx->new_session_ticket;


	/*
	extensions depends on key_exchange_modes


	switch (key_exchange_mode)
	case CERT_DHE:
		* supported_groups		ctx->supported_groups_cnt != 0
		* signature_algorithms		ctx->signature_algorithms_cnt != 0
		* key_share			generated in ClientHello, so always ok
		* [signature_algorithms_cert]
		* [certificate_authorities]

	case PSK_DHE:
		* supported_groups
		* psk_key_exchange_modes	ctx->psk_key_exchange_modes has psk_dhe_ke
		* pre_shared_key		call tls13_add_pre_shared_key, tls13_add_pre_shared_key_from_session_file after tls13_init
		* key_share
		* [early_data]
		* [signature_algorithms]
		* [signature_algorithms_cert]

	case PSK:
		* psk_key_exchange_modes	ctx->psk_key_exchange_modes has psk_ke
		* pre_shared_key
		* [early_data]
		* [supported_groups]
		* [signature_algorithms]
		* [signature_algorithms_cert]
	*/


	fprintf(stderr, "tls13_init\n");

	// key_exchange_modes
	conn->key_exchange_modes = ctx->psk_key_exchange_modes;
	if (ctx->supported_groups_cnt && ctx->signature_algorithms_cnt) {
		conn->key_exchange_modes |= TLS_KE_CERT_DHE;
	}
	if (!ctx->supported_groups_cnt) {
		conn->key_exchange_modes &= ~(TLS_KE_CERT_DHE|TLS_KE_PSK_DHE);
	}


	tls_key_exchange_modes_print(stderr, 0, 0, "server key_exchange_modes", conn->key_exchange_modes);


	if (!conn->key_exchange_modes) {
		error_print();
		return -1;
	}

	// TLS_KE_PSK_DHE|TLS_KE_PSK depends on pre_shared_key
	// but pre_shared_key is set by tls13_add_pre_shared_key, tls13_add_pre_shared_key_from_session_file
	// after tls13_init

	// key_share
	if (conn->key_exchange_modes & (TLS_KE_CERT_DHE|TLS_KE_PSK_DHE)) {
		conn->key_share = 1;
	}

	conn->signed_certificate_timestamp = ctx->signed_certificate_timestamp;

	// early_data
	conn->early_data = ctx->early_data;
	conn->max_early_data_size = ctx->max_early_data_size;

	return 1;
}


/*
ClientHello中的很多扩展是和证书有关的
如果客户端在ClientHello中已经明确不支持证书认证（没有提供group + sig_alg的组合）
那么就不应该在ClientHello中包含这些扩展
*/

int tls13_send_client_hello(TLS_CONNECT *conn)
{
	int ret;

	if (!conn->recordlen) {
		const uint8_t *legacy_session_id = NULL;
		size_t legacy_session_id_len = 0;
		uint8_t exts[TLS_MAX_EXTENSIONS_SIZE];
		uint8_t *pexts = exts;
		size_t extslen = 0;

		tls_trace("send ClientHello\n");

		// record_version
		tls_record_set_protocol(conn->record, TLS_protocol_tls1);

		// client_random
		if (tls13_random_generate(conn->client_random) != 1) {
			error_print();
			return -1;
		}

		// legacy_session_id
		conn->session_id_len = 0;


		// exts in CH (RFC 8446 page 37), only oid_filter not in CH
		//  * supported_versions
		//  * signature_algorithms
		//  * signature_algorithms_cert
		//  * certificate_authorities
		//  * server_name
		//  * status_request
		//  * signed_certificate_timestamp
		//  * supported_groups
		//  * key_share
		//  * psk_key_exchange_modes
		//  * pre_shared_key
		//  * early_data (only in ClientHello1)
		//  * cookie (only in ClientHello2)
		//  * post_handshake_auth: client support post handshake auth
		//  * max_fragment_length
		//  * use_srtp
		//  * heartbeat
		//  * application_layer_protocol_negotiation
		//  * server_certificate_type: if client accept raw/x509
		//  * client_certificate_type: if client sned raw/x509
		//  * padding


		// supported_versions
		if (tls13_client_supported_versions_ext_to_bytes(conn->ctx->supported_versions,
			conn->ctx->supported_versions_cnt, &pexts, &extslen) != 1) {
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

		// signature_algorithms_cert
		if (conn->signature_algorithms_cert) {
			if (tls13_signature_algorithms_cert_ext_to_bytes(conn->ctx->signature_algorithms,
				conn->ctx->signature_algorithms_cnt, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// certificate_authorities
		if (conn->certificate_authorities) {
			if (tls13_certificate_authorities_ext_to_bytes(
				conn->ctx->ca_names, conn->ctx->ca_names_len, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// key_share
		if (conn->key_share) {
			size_t i;

			// empty ClientHello.key_share is allowed
			for (i = 0; i < conn->ctx->key_exchanges_cnt && i < conn->ctx->supported_groups_cnt; i++) {
				int curve_oid = tls_named_curve_oid(conn->ctx->supported_groups[i]);
				if (x509_key_generate(&conn->key_exchanges[i],
					OID_ec_public_key, &curve_oid, sizeof(curve_oid)) != 1) {
					error_print();
					tls13_send_alert(conn, TLS_alert_internal_error);
					return -1;
				}
			}
			conn->key_exchanges_cnt = i;
			if (tls13_key_share_client_hello_ext_to_bytes(conn->key_exchanges,
				conn->key_exchanges_cnt, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// server_name
		if (conn->server_name) {
			if (tls_server_name_ext_to_bytes(
				conn->host_name, conn->host_name_len, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// psk_key_exchange_modes
		if (conn->key_exchange_modes & (TLS_KE_PSK_DHE|TLS_KE_PSK)) {
			if (tls13_psk_key_exchange_modes_ext_to_bytes(
				conn->key_exchange_modes, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// status_request (hint only)
		if (conn->status_request) {
			if (tls_client_status_request_ext_to_bytes(TLS_certificate_status_type_ocsp,
				conn->status_request_responder_id_list, conn->status_request_responder_id_list_len,
				conn->status_request_exts, conn->status_request_exts_len,
				&pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
			conn->status_request = 0; // to track CertificateRequest.status_request
		}

		// signed_certificate_timestamp (hint only)
		if (conn->signed_certificate_timestamp) {
			if (tls_ext_to_bytes(TLS_extension_signed_certificate_timestamp, NULL, 0,
				&pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
			conn->signed_certificate_timestamp = 0; // to track CertificateRequest.signed_certificate_timestamp
		}

		// early_data
		if (conn->early_data) {
			if (tls_ext_to_bytes(TLS_extension_early_data, NULL, 0,
				&pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// post_handshake_auth
		if (conn->post_handshake_auth) {
			if (tls_ext_to_bytes(TLS_extension_post_handshake_auth, NULL, 0,
				&pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		fprintf(stderr, ">>>>> conn->pre_shared_key = %d\n", conn->pre_shared_key);


		// pre_shared_key (must be the last extension)
		if (conn->pre_shared_key) {
			uint8_t *ptruncated_exts = pexts;
			size_t truncated_extslen = extslen;
			uint8_t binders[256];
			uint8_t *pbinders = binders;
			size_t binderslen = 0;


			fprintf(stderr, "add pre_shared_key\n");

			if (!conn->psk_identities_len
				|| !conn->psk_keys_len
				|| !conn->psk_cipher_suites_cnt ) {
				error_print();
				return -1;
			}

			// output pre_shared_key ext with empty binders
			if (tls13_psk_binders_generate_empty(
				conn->psk_cipher_suites, conn->psk_cipher_suites_cnt,
				binders, &binderslen) != 1) {
				error_print();
				return -1;
			}
			if (tls13_client_pre_shared_key_ext_to_bytes(
				conn->psk_identities, conn->psk_identities_len,
				binders, binderslen, &ptruncated_exts, &truncated_extslen) != 1) {
				error_print();
				return -1;
			}

			// truncate(ClientHello)
			if (tls_record_set_handshake_client_hello(conn->record, &conn->recordlen,
				TLS_protocol_tls12, conn->client_random,
				legacy_session_id, legacy_session_id_len,
				conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt,
				exts, truncated_extslen) != 1) {
				error_print();
				return -1;
			}
			//tls13_record_print(stderr, 0, 0, conn->record, conn->recordlen);

			// generate binders and output final pre_shared_key ext
			if (tls13_psk_binders_generate(
				conn->psk_cipher_suites, conn->psk_cipher_suites_cnt,
				conn->psk_keys, conn->psk_keys_len,
				conn->record + 5, conn->recordlen - 5,
				binders, &binderslen) != 1) {
				error_print();
				return -1;
			}
			if (tls13_client_pre_shared_key_ext_to_bytes(
				conn->psk_identities, conn->psk_identities_len,
				binders, binderslen, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		if (tls_record_set_handshake_client_hello(conn->record, &conn->recordlen,
			TLS_protocol_tls12, conn->client_random,
			legacy_session_id, legacy_session_id_len,
			conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt,
			exts, extslen) != 1) {
			error_print();
			return -1;
		}
		tls13_record_print(stderr, 0, 0, conn->record, conn->recordlen);

		// early_data encryption keys depends on the full client_hello
		if (conn->early_data) {
			if (tls13_generate_early_data_keys(conn) != 1) {
				error_print();
				return -1;
			}
		}

		// backup client_hello
		memcpy(conn->plain_record, conn->record, conn->recordlen);
		conn->plain_recordlen = conn->recordlen;
	}

	if (conn->client_certificate_verify) {
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);
	}

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
recv HelloRetryRequest:
	* set conn->protocol
	* set conn->cipher_suite, conn->cipher, conn->digest
	* set conn->key_exchange_group
	* set conn->dgst_ctx <= ClientHello, HelloRetryRequest, ClientHello2

recv ServerHello after HelloRetryRequest:
	* check ServerHello.protocol == conn->protocol
	* check ServerHello.cipher_suite == conn->cipher_suite
	* check ServerHello.key_share.group == conn->key_exchange_group
	* conn->dgst_ctx <= ServerHello

recv ServerHello without HelloRetryRequest:
	* set conn->protocol
	* set conn->cipher_suite, conn->cipher, conn->digest
	* set conn->key_exchange_group
	* set conn->dgst_ctx <= ClientHello
*/

int tls13_recv_hello_retry_request(TLS_CONNECT *conn)
{
	int ret;

	// handshake
	int handshake_type;
	const uint8_t *handshake_data;
	size_t handshake_datalen;

	// HelloRetryRequest
	int legacy_version;
	const uint8_t *random;
	const uint8_t *legacy_session_id_echo;
	size_t legacy_session_id_echo_len;
	int cipher_suite;
	int legacy_compress_meth;
	const uint8_t *exts;
	size_t extslen;

	// extensions
	const uint8_t *supported_versions = NULL;
	size_t supported_versions_len = 0;
	const uint8_t *key_share = NULL;
	size_t key_share_len = 0;
	const uint8_t *cookie = NULL;
	size_t cookie_len = 0;

	int selected_version;
	int key_exchange_group;

	tls_trace("recv HelloRetryRequest*\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}

	if (tls_record_protocol(conn->record) != TLS_protocol_tls12) {
		error_print();
		tls13_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	// the record might be Alert?
	if ((ret = tls_record_get_handshake(conn->record,
		&handshake_type, &handshake_data, &handshake_datalen)) < 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		return -1;
	}
	if (handshake_type != TLS_handshake_hello_retry_request) {
		tls_trace("    no HelloRetryRequest\n");
		return 0;
	}

	tls13_record_print(stderr, 0, 0, conn->record, conn->recordlen);

	if ((ret = tls13_record_get_handshake_hello_retry_request(conn->record,
		&legacy_version, &random,
		&legacy_session_id_echo, &legacy_session_id_echo_len,
		&cipher_suite, &legacy_compress_meth, &exts, &extslen)) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_decode_error);
		return -1;
	}
	conn->hello_retry_request = 1;


	// HelloRetryRequest disable early_data
	conn->early_data = 0;


	// legacy_version
	if (legacy_version != TLS_protocol_tls12) {
		error_print();
		tls13_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	// random
	memcpy(conn->server_random, random, 32);

	// legacy_session_id_echo
	if (legacy_session_id_echo_len != conn->session_id_len
		|| memcmp(legacy_session_id_echo, conn->session_id, conn->session_id_len) != 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}

	// cipher_suite
	if (tls_type_is_in_list(cipher_suite, conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}
	if (tls13_cipher_suite_get(cipher_suite, &conn->cipher, &conn->digest) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}
	conn->cipher_suite = cipher_suite;

	// legacy_compression_method
	if (legacy_compress_meth != 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_illegal_parameter);
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

		// exts in HRR
		//  * supported_versions
		//  * key_share
		//  * cookie

		switch (ext_type) {
		case TLS_extension_supported_versions:
		case TLS_extension_key_share:
		case TLS_extension_cookie:
			if (!ext_data) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			break;
		}

		switch (ext_type) {
		case TLS_extension_supported_versions:
			if (supported_versions) {
				error_print();
				return -1;
			}
			supported_versions = ext_data;
			supported_versions_len = ext_datalen;
			break;

		case TLS_extension_key_share:
			if (!conn->key_share) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			if (key_share) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			key_share = ext_data;
			key_share_len = ext_datalen;
			break;

		case TLS_extension_cookie:
			if (cookie) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			cookie = ext_data;
			cookie_len = ext_datalen;
			conn->cookie = 1;
			break;

		default:
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
	}

	// supported_versions
	if (!supported_versions) {
		error_print();
		tls13_send_alert(conn, TLS_alert_missing_extension);
		return -1;
	}
	if (tls13_server_supported_versions_from_bytes(&selected_version,
		supported_versions, supported_versions_len) != 1) {
		tls13_send_alert(conn, TLS_alert_decode_error);
		error_print();
		return -1;
	}
	if (tls_type_is_in_list(selected_version,
		conn->ctx->supported_versions, conn->ctx->supported_versions_cnt) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}
	if (selected_version != TLS_protocol_tls13) {
		error_print();
		tls13_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}
	conn->protocol = selected_version;

	// key_share
	if (!key_share) {
		error_print();
		tls13_send_alert(conn, TLS_alert_missing_extension);
		return -1;
	}
	if (tls13_key_share_hello_retry_request_from_bytes(&key_exchange_group,
		key_share, key_share_len) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_decode_error);
		return -1;
	}
	if (tls_type_is_in_list(key_exchange_group,
		conn->ctx->supported_groups, conn->ctx->supported_groups_cnt) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}
	// HelloRetryRequest must choose a group not in ClientHello.key_share
	while (conn->key_exchanges_cnt--) {
		if (key_exchange_group == tls_named_curve_from_oid(
			conn->key_exchanges[conn->key_exchanges_cnt].algor_param)) {
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
		}
	}
	conn->key_exchange_group = key_exchange_group;

	// cookie
	if (cookie) {
		const uint8_t *cookie_data;
		size_t cookie_datalen;

		if (tls13_cookie_from_bytes(&cookie_data, &cookie_datalen,
			cookie, cookie_len) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}
		memcpy(conn->cookie_buf, cookie_data, cookie_datalen);
		conn->cookie_len = cookie_datalen;
	}

	// ClientHello1
	uint8_t message_hash[4 + 32];
	size_t dgstlen;
	message_hash[0] = TLS_handshake_message_hash;
	message_hash[1] = 0;
	message_hash[2] = 0;
	message_hash[3] = 32;

	// 我猜如果用了HRR，那么客户端实际上并没有保存ClientHello的数据，而是用ClientHello的哈希值来计算后续的

	if (digest_init(&conn->dgst_ctx, conn->digest) != 1
		|| digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1
		|| digest_finish(&conn->dgst_ctx, message_hash + 4, &dgstlen) != 1) {
		error_print();
		return -1;
	}

	// ClientHello, HelloRetryRequest
	if (digest_init(&conn->dgst_ctx, conn->digest) != 1
		|| digest_update(&conn->dgst_ctx, message_hash, sizeof(message_hash)) != 1
		|| digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}

	if (conn->client_certs_len) {
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);
	}

	return 1;
}

int tls13_client_hello_again_psk_update(TLS_CONNECT *conn)
{
	const uint8_t *psk_identities;
	const uint8_t *psk_keys;
	uint8_t tmp_identities_buf[sizeof(conn->psk_identities)];
	uint8_t *tmp_identities = tmp_identities_buf;
	size_t tmp_identities_len = 0;
	uint8_t tmp_keys_buf[sizeof(conn->psk_keys)];
	uint8_t *tmp_keys = tmp_keys_buf;
	size_t tmp_keys_len = 0;
	size_t tmp_cipher_suites_cnt = 0;
	size_t i;

	if (!conn) {
		error_print();
		return -1;
	}
	psk_identities = conn->psk_identities;
	psk_keys = conn->psk_keys;

	for (i = 0; i < conn->psk_cipher_suites_cnt; i++) {
		const uint8_t *identity;
		size_t identity_len;
		uint32_t obfuscated_ticket_age;
		const uint8_t *key;
		size_t key_len;

		if (tls13_psk_identity_from_bytes(&identity, &identity_len, &obfuscated_ticket_age, &psk_identities, &conn->psk_identities_len) != 1
			|| tls_uint8array_from_bytes(&key, &key_len, &psk_keys, &conn->psk_keys_len) != 1) {
			gmssl_secure_clear(tmp_keys_buf, sizeof(tmp_keys_buf));
			error_print();
			return -1;
		}
		if (conn->psk_cipher_suites[i] == conn->cipher_suite) {
			tls13_psk_identity_to_bytes(identity, identity_len, obfuscated_ticket_age, &tmp_identities, &tmp_identities_len);
			tls_uint16array_to_bytes(key, key_len, &tmp_keys, &tmp_keys_len);
			tmp_cipher_suites_cnt++;
		}
	}
	if (conn->psk_identities_len || conn->psk_keys_len) {
		gmssl_secure_clear(tmp_keys_buf, sizeof(tmp_keys_buf));
		error_print();
		return -1;
	}

	memcpy(conn->psk_identities, tmp_identities_buf, tmp_identities_len);
	conn->psk_identities_len = tmp_identities_len;
	memcpy(conn->psk_keys, tmp_keys_buf, tmp_keys_len);
	conn->psk_keys_len = tmp_keys_len;
	for (i = 0; i < tmp_cipher_suites_cnt; i++) {
		conn->psk_cipher_suites[i] = conn->cipher_suite;
	}
	conn->psk_cipher_suites_cnt = tmp_cipher_suites_cnt;

	gmssl_secure_clear(tmp_keys_buf, sizeof(tmp_keys_buf));
	return 1;
}

int tls13_send_client_hello_again(TLS_CONNECT *conn)
{
	int ret;
	tls_trace("send ClientHello again\n");

	if (!conn->recordlen) {
		const uint8_t *legacy_session_id = NULL;
		size_t legacy_session_id_len = 0;
		uint8_t exts[TLS_MAX_EXTENSIONS_SIZE];
		uint8_t *pexts = exts;
		size_t extslen = 0;
		int supported_versions = TLS_protocol_tls13;
		int curve_oid;

		// record_version
		tls_record_set_protocol(conn->record, TLS_protocol_tls1);

		// client_random
		if (tls13_random_generate(conn->client_random) != 1) {
			error_print();
			return -1;
		}

		// Extensions

		// keep ClientHello extensions except
		//	* key_share - generate a new key_exchange based on conn->key_exchange_group
		//	* pre_shared_key - remove PSKs not compatible with conn->cipher_suite
		//	* early_data - disable early_data
		//	* cookie - echo cookie if exist

		// supported_versions
		if (tls13_client_supported_versions_ext_to_bytes(conn->ctx->supported_versions,
			conn->ctx->supported_versions_cnt, &pexts, &extslen) != 1) {
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

		// signature_algorithms_cert
		if (conn->signature_algorithms_cert) {
			if (tls13_signature_algorithms_cert_ext_to_bytes(conn->ctx->signature_algorithms,
				conn->ctx->signature_algorithms_cnt, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// server_name
		if (conn->server_name) {
			if (tls_server_name_ext_to_bytes(conn->host_name, conn->host_name_len, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// key_share (re-generated)
		if ((curve_oid = tls_named_curve_oid(conn->key_exchange_group)) == OID_undef) {
			error_print();
			return -1;
		}
		if (x509_key_generate(&conn->key_exchanges[0],
			OID_ec_public_key, &curve_oid, sizeof(curve_oid)) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		conn->key_exchange_idx = 0;
		conn->key_exchanges_cnt = 1;
		if (tls13_key_share_client_hello_ext_to_bytes(conn->key_exchanges,
			conn->key_exchanges_cnt, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}

		// psk_key_exchange_modes
		if (conn->key_exchange_modes & (TLS_KE_PSK_DHE|TLS_KE_PSK)) {
			if (tls13_psk_key_exchange_modes_ext_to_bytes(conn->key_exchange_modes, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}
		// update key_exchange_modes (disable PSK-only)
		conn->key_exchange_modes &= ~TLS_KE_PSK;

		// status_request
		if (conn->status_request) {
			if (tls_client_status_request_ext_to_bytes(TLS_certificate_status_type_ocsp,
				conn->status_request_responder_id_list, conn->status_request_responder_id_list_len,
				conn->status_request_exts, conn->status_request_exts_len,
				&pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// signed_certificate_timestamp
		if (conn->ctx->signed_certificate_timestamp) {
			if (tls_ext_to_bytes(TLS_extension_signed_certificate_timestamp, NULL, 0, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// post_handshake_auth
		if (conn->post_handshake_auth) {
			if (tls_ext_to_bytes(TLS_extension_post_handshake_auth, NULL, 0,
				&pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// early_data must not in ClientHello2

		// cookie
		if (conn->cookie) {
			if (tls13_cookie_ext_to_bytes(conn->cookie_buf, conn->cookie_len, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// pre_shared_key
		if (conn->pre_shared_key) {
			if (!conn->psk_identities_len
				|| !conn->psk_keys_len
				|| !conn->psk_cipher_suites_cnt ) {
				error_print();
				return -1;
			}
			if (tls13_client_hello_again_psk_update(conn) != 1) {
				error_print();
				return -1;
			}
			if (!conn->psk_cipher_suites_cnt) {
				conn->pre_shared_key = 0;
			}
		}
		if (conn->pre_shared_key) {
			uint8_t *ptruncated_exts = pexts;
			size_t truncated_extslen = extslen;
			uint8_t binders[256];
			uint8_t *pbinders = binders;
			size_t binderslen = 0;

			// output pre_shared_key ext with empty binders
			if (tls13_psk_binders_generate_empty(
				conn->psk_cipher_suites, conn->psk_cipher_suites_cnt,
				binders, &binderslen) != 1) {
				error_print();
				return -1;
			}
			if (tls13_client_pre_shared_key_ext_to_bytes(
				conn->psk_identities, conn->psk_identities_len,
				binders, binderslen, &ptruncated_exts, &truncated_extslen) != 1) {
				error_print();
				return -1;
			}

			// truncate(ClientHello)
			if (tls_record_set_handshake_client_hello(conn->record, &conn->recordlen,
				TLS_protocol_tls12, conn->client_random,
				legacy_session_id, legacy_session_id_len,
				conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt,
				exts, truncated_extslen) != 1) {
				error_print();
				return -1;
			}
			//tls13_record_print(stderr, 0, 0, conn->record, conn->recordlen);

			// generate binders and output final pre_shared_key ext
			if (tls13_psk_binders_generate(
				conn->psk_cipher_suites, conn->psk_cipher_suites_cnt,
				conn->psk_keys, conn->psk_keys_len,
				conn->record + 5, conn->recordlen - 5,
				binders, &binderslen) != 1) {
				error_print();
				return -1;
			}
			if (tls13_client_pre_shared_key_ext_to_bytes(
				conn->psk_identities, conn->psk_identities_len,
				binders, binderslen, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		if (tls_record_set_handshake_client_hello(conn->record, &conn->recordlen,
			TLS_protocol_tls12, conn->client_random,
			legacy_session_id, legacy_session_id_len,
			conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt,
			exts, extslen) != 1) {
			error_print();
			return -1;
		}
		tls13_record_print(stderr, 0, 0, conn->record, conn->recordlen);

		// ClientHello2
		if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}
	}

	if (conn->client_certificate_verify) {
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);
	}

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
recv HelloRetryRequest:
	* set conn->protocol
	* set conn->cipher_suite, conn->cipher, conn->digest
	* set conn->key_exchange_group
	* set conn->dgst_ctx <= ClientHello, HelloRetryRequest, ClientHello2

recv ServerHello after HelloRetryRequest:
	* check ServerHello.protocol == conn->protocol
	* check ServerHello.cipher_suite == conn->cipher_suite
	* check ServerHello.key_share.group == conn->key_exchange_group
	* conn->dgst_ctx <= ServerHello

recv ServerHello without HelloRetryRequest:
	* set conn->protocol
	* set conn->cipher_suite, conn->cipher, conn->digest
	* set conn->key_exchange_group
	* set conn->dgst_ctx <= ClientHello
*/
int tls13_recv_server_hello(TLS_CONNECT *conn)
{
	int ret;

	// server_hello
	int legacy_version;
	const uint8_t *random;
	const uint8_t *legacy_session_id_echo;
	size_t legacy_session_id_echo_len;
	int cipher_suite;
	const uint8_t *exts;
	size_t extslen;

	const uint8_t *supported_versions = NULL;
	size_t supported_versions_len;
	const uint8_t *key_share = NULL;
	size_t key_share_len;
	const uint8_t *pre_shared_key = NULL;
	size_t pre_shared_key_len;

	int selected_version;
	int server_key_exchange_mode = 0;

	tls_trace("recv ServerHello\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	tls13_record_print(stderr, 0, 0, conn->record, conn->recordlen);

	if (tls_record_protocol(conn->record) != TLS_protocol_tls12) {
		error_print();
		tls13_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}
	if ((ret = tls_record_get_handshake_server_hello(conn->record,
		&legacy_version, &random,
		&legacy_session_id_echo, &legacy_session_id_echo_len,
		&cipher_suite, &exts, &extslen)) < 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	// legacy_version
	if (legacy_version != TLS_protocol_tls12) {
		error_print();
		tls13_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	// random
	if (conn->hello_retry_request) {
		if (memcmp(random, conn->server_random, 32) == 0) {
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
	}
	memcpy(conn->server_random, random, 32);

	// legacy_session_id_echo
	if (legacy_session_id_echo_len != conn->session_id_len
		|| memcmp(legacy_session_id_echo, conn->session_id, conn->session_id_len) != 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}

	// cipher_suite
	if (conn->hello_retry_request) {
		if (cipher_suite != conn->cipher_suite) {
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
	} else {
		if (tls_type_is_in_list(cipher_suite,
			conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
		conn->cipher_suite = cipher_suite;
		if (tls13_cipher_suite_get(cipher_suite, &conn->cipher, &conn->digest) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
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

		// exts in SH
		//  * supported_versions
		//  * key_share
		//  * pre_shared_key (not in HRR)
		//
		//
		//	ServerHello.key_share if only ClientHello.key_share
		//	ServerHello.pre_shared_key if only ClientHello.pre_shared_key
		//	if HelloRetryRequest, key_share must exist

		switch (ext_type) {
		case TLS_extension_supported_versions:
		case TLS_extension_key_share:
		case TLS_extension_pre_shared_key:
			if (!ext_data) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			break;
		}

		switch (ext_type) {
		case TLS_extension_supported_versions:
			if (supported_versions) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			supported_versions = ext_data;
			supported_versions_len = ext_datalen;
			break;

		case TLS_extension_key_share:
			// ServerHello.key_share if only ClientHello.key_share
			if (!conn->key_share) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			if (key_share) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			key_share = ext_data;
			key_share_len = ext_datalen;
			break;

		case TLS_extension_pre_shared_key:
			// ServerHello.pre_shared_key if only ClientHello.pre_shared_key
			if (!conn->pre_shared_key) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			if (pre_shared_key) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			pre_shared_key = ext_data;
			pre_shared_key_len = ext_datalen;
			break;

		default:
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
	}

	if (!supported_versions) {
		error_print();
		tls13_send_alert(conn, TLS_alert_missing_extension);
		return -1;
	}

	// if HelloRetryRequest, key_share must exist
	if (conn->hello_retry_request) {
		if (!key_share) {
			error_print();
			tls13_send_alert(conn, TLS_alert_missing_extension);
			return -1;
		}
	}

	// key_exchange_mode
	//  implicitly sent through ServerHello exts
	//
	//  * key_share + pre_shared_key	PSK_DHE
	//  * key_share				CERT_DHE
	//  * pre_shared_key			PSK
	//  * (none)				error
	//
	if (pre_shared_key) {
		if (key_share)
			server_key_exchange_mode = TLS_KE_PSK_DHE;
		else	server_key_exchange_mode = TLS_KE_PSK;
	} else {
		if (key_share) {
			server_key_exchange_mode = TLS_KE_CERT_DHE;
		} else {
			error_print();
			tls13_send_alert(conn, TLS_alert_missing_extension);
			return -1;
		}
	}


	// set key_exchange_mode
	conn->key_exchange_modes &= server_key_exchange_mode;

	if (!conn->key_exchange_modes) {
		error_print();
		tls13_send_alert(conn, TLS_alert_handshake_failure);
		return -1;
	}


	// supported_versions
	if (tls13_server_supported_versions_from_bytes(
		&selected_version, supported_versions, supported_versions_len) != 1) {
		tls13_send_alert(conn, TLS_alert_decode_error);
		error_print();
		return -1;
	}
	if (conn->hello_retry_request) {
		if (selected_version != conn->protocol) {
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
	} else {
		if (tls_type_is_in_list(selected_version,
			conn->ctx->supported_versions, conn->ctx->supported_versions_cnt) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
		if (selected_version != TLS_protocol_tls13) {
			error_print();
			tls13_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		conn->protocol = selected_version;
	}


	// key_share
	if (key_share) {
		int key_exchange_group;
		const uint8_t *key_exchange;
		size_t key_exchange_len;

		if (!conn->key_exchanges_cnt) {
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
		if (tls13_key_share_server_hello_from_bytes(&key_exchange_group,
			&key_exchange, &key_exchange_len, key_share, key_share_len) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}
		// compatible with/without HRR
		while (conn->key_exchange_idx < conn->key_exchanges_cnt) {
			if (conn->key_exchanges[conn->key_exchange_idx].algor_param ==
				tls_named_curve_oid(key_exchange_group)) {
				break;
			}
			conn->key_exchange_idx++;
		}
		if (conn->key_exchange_idx >= conn->key_exchanges_cnt) {
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
		if (key_exchange_len != 65) {
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
		conn->key_exchange_group = key_exchange_group;
		memcpy(conn->peer_key_exchange, key_exchange, key_exchange_len);
		conn->peer_key_exchange_len = 65;
	}

	// pre_shared_key
	if (pre_shared_key) {
		const uint8_t *psk_keys = conn->psk_keys;
		size_t psk_keys_len = conn->psk_keys_len;
		int selected_identity;
		const uint8_t *key = NULL;
		size_t keylen = 0;
		size_t i;

		if (tls13_server_pre_shared_key_from_bytes(&selected_identity,
			pre_shared_key, pre_shared_key_len) != 1) {
			error_print();
			return -1;
		}
		for (i = 0; i <= selected_identity; i++) {
			if (tls_uint8array_from_bytes(&key, &keylen, &psk_keys, &psk_keys_len) != 1) {
				error_print();
				return -1;
			}
		}
		if (!key) {
			error_print();
			return -1;
		}

		// TODO: change psk from buf to reference
		memcpy(conn->psk, key, keylen);
		conn->psk_len = keylen;
	}


	if (conn->hello_retry_request) {
		// dgst_ctx <= ServerHello
		if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls_handshake_digest_print(stderr, 0, 0, "ServerHello", &conn->dgst_ctx);
	} else {
		if (digest_init(&conn->dgst_ctx, conn->digest) != 1
			// dgst_ctx <= ClientHello
			|| digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1
			// dgst_ctx <= ServerHello
			|| digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		tls_handshake_digest_print(stderr, 0, 0, "ServerHello", &conn->dgst_ctx);
	}

	if (conn->client_certs_len) {
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);
	}

	if (tls13_generate_handshake_keys(conn) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int tls13_recv_encrypted_extensions(TLS_CONNECT *conn)
{
	int ret;
	const uint8_t *exts;
	size_t extslen;

	const uint8_t *supported_groups = NULL;
	size_t supported_groups_len;

	int server_name = 0;
	int early_data = 0;

	printf("recv {EncryptedExtensions}\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}

	if (tls13_record_decrypt(&conn->server_write_key, conn->server_write_iv,
		conn->server_seq_num, conn->record, conn->recordlen,
		conn->plain_record, &conn->plain_recordlen) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	tls_seq_num_incr(conn->server_seq_num);


	if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

	tls_handshake_digest_print(stderr, 0, 0, "EncryptedExtension", &conn->dgst_ctx);


	if ((ret = tls13_record_get_handshake_encrypted_extensions(conn->plain_record,
		&exts, &extslen)) < 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_unexpected_message);
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

		// Exts in EE (see RFC 8446 page 37)
		//  * supported_groups
		//  * server_name
		//  * early_data
		//  * application_layer_protocol_negotiation
		//  * use_srtp
		//  * client_certificate_type
		//  * server_certificate_type
		//  * max_fragment_length
		//  * heartbeat
		//  * record_size_limit (RFC 8449)


		switch (ext_type) {
		case TLS_extension_supported_groups:
			if (!ext_data) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			break;
		case TLS_extension_server_name:
		case TLS_extension_early_data:
			if (ext_data) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			break;
		}

		switch (ext_type) {
		case TLS_extension_supported_groups:
			if (!conn->ctx->supported_groups_cnt) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			if (supported_groups) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			break;

		case TLS_extension_server_name:
			if (!conn->server_name) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			if (server_name) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			server_name = 1;
			break;

		case TLS_extension_early_data:
			if (!conn->early_data) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			if (early_data) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			early_data = 1;
			break;

		case TLS_extension_application_layer_protocol_negotiation:
		case TLS_extension_use_srtp:
		case TLS_extension_client_certificate_type:
		case TLS_extension_server_certificate_type:
		case TLS_extension_max_fragment_length:
		case TLS_extension_heartbeat:
		case TLS_extension_record_size_limit:
			break;

		default:
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
	}

	// server_name
	// if or not server support SNI, do nothing

	// early_data
	conn->early_data = early_data; // server allow EarlyData messages


	return 1;
}

int tls_cert_match_signature_algorithms(const uint8_t *cert, size_t certlen,
	const int *signature_algorithms, size_t signature_algorithms_cnt,
	int *first_matched_sig_alg)
{
	X509_KEY subject_public_key;
	int group_oid;
	size_t i;

	if (!cert || !certlen || !signature_algorithms || !signature_algorithms_cnt) {
		error_print();
		return -1;
	}

	if (x509_cert_get_subject_public_key(cert, certlen, &subject_public_key) != 1) {
		error_print();
		return -1;
	}
	if (subject_public_key.algor != OID_ec_public_key) {
		error_print();
		return -1;
	}
	group_oid = subject_public_key.algor_param;

	for (i = 0; i < signature_algorithms_cnt; i++) {
		if (group_oid == tls_signature_scheme_group_oid(signature_algorithms[i])) {
			*first_matched_sig_alg = signature_algorithms[i];
			return 1;
		}
	}

	*first_matched_sig_alg = 0;
	return 0;
}

int tls_cert_chain_match_signature_algorithms_cert(
	const uint8_t *cert_chain, size_t cert_chain_len,
	const int *signature_algorithms_cert, size_t signature_algorithms_cert_cnt)
{
	const uint8_t *cert;
	size_t certlen;
	const uint8_t *next_cert;
	size_t next_certlen;
	X509_KEY subject_public_key;
	int alg_oid;
	int group_oid;
	int sig_alg;

	if (!cert_chain || !cert_chain_len
		|| !signature_algorithms_cert && signature_algorithms_cert_cnt) {
		error_print();
		return -1;
	}

	if (x509_cert_from_der(&cert, &certlen, &cert_chain, &cert_chain_len) != 1) {
		error_print();
		return -1;
	}

	while (cert_chain_len) {
		if (x509_cert_get_signature_algor(cert, certlen, &alg_oid) != 1) {
			error_print();
			return -1;
		}
		if (x509_cert_from_der(&next_cert, &next_certlen, &cert_chain, &cert_chain_len) != 1
			|| x509_cert_get_subject_public_key(next_cert, next_certlen, &subject_public_key) != 1) {
			error_print();
			return -1;
		}
		if (subject_public_key.algor != OID_ec_public_key) {
			error_print();
			return -1;
		}
		group_oid = subject_public_key.algor_param;
		if (!(sig_alg = tls_signature_scheme_from_algorithm_and_group_oid(alg_oid, group_oid))) {
			error_print();
			return -1;
		}
		if (!tls_type_is_in_list(sig_alg, signature_algorithms_cert, signature_algorithms_cert_cnt)) {
			return 0;
		}

		cert = next_cert;
		certlen = next_certlen;
	}

	// can not do full check on the last cert, the public key is in root CA cert
	if (x509_cert_get_signature_algor(cert, certlen, &alg_oid) != 1) {
		error_print();
		return -1;
	}
	// 这里需要CA证书才能验证最后一个证书的签名算法是否满足要求

	return 1;
}

int tls_cert_match_server_name(const uint8_t *cert, size_t certlen, const uint8_t *host_name, size_t host_name_len)
{
	int ret;
	const uint8_t *subject_dns_name;
	size_t subject_dns_name_len;

	if (!cert || !certlen || !host_name || !host_name_len) {
		error_print();
		return -1;
	}
	if ((ret = x509_cert_get_subject_alt_name_dns_name(cert, certlen,
		&subject_dns_name, &subject_dns_name_len)) < 0) {
		error_print();
		return -1;
	} else if (ret == 0) {
		return TLS_CERT_VERIFY_NO_SUBJECT_ALT_NAME;
	}
	if (subject_dns_name_len != host_name_len
		|| memcmp(subject_dns_name, host_name, host_name_len) != 0) {
		return 0;
	}
	return 1;
}

int tls_cert_chain_match_extensions(
	const uint8_t *cert_chain, size_t cert_chain_len,
	const int *signature_algorithms, size_t signature_algorithms_cnt,
	const int *signature_algorithms_cert, size_t signature_algorithms_cert_cnt, // optional
	const uint8_t *ca_names, size_t ca_names_len, // optional
	const uint8_t *oid_filters, size_t oid_filters_len, // optional
	const uint8_t *host_name, size_t host_name_len, // optional
	int *prefered_sig_alg)
{
	int ret;
	const uint8_t *cert;
	size_t certlen;
	int sig_alg;

	if (!cert_chain || !cert_chain_len
		|| !signature_algorithms || !signature_algorithms_cnt) {
		error_print();
		return -1;
	}

	if (prefered_sig_alg) {
		*prefered_sig_alg = 0;
	}

	if (x509_certs_get_cert_by_index(cert_chain, cert_chain_len, 0,
		&cert, &certlen) != 1) {
		error_print();
		return -1;
	}

	// signature_algorithms
	if ((ret = tls_cert_match_signature_algorithms(cert, certlen,
		signature_algorithms, signature_algorithms_cnt, &sig_alg)) < 0) {
		error_print();
		return -1;
	} else if (ret == 0) {
		return 0;
	}

	// server_name
	if (host_name && host_name_len) {
		if ((ret = tls_cert_match_server_name(cert, certlen,
			host_name, host_name_len)) < 0) {
			error_print();
			return -1;
		} else if (ret == 0) {
			return 0;
		}
	}

	// signature_algorithms_cert
	if (signature_algorithms_cert && signature_algorithms_cert_cnt) {
		if ((ret = tls_cert_chain_match_signature_algorithms_cert(cert_chain, cert_chain_len,
			signature_algorithms_cert, signature_algorithms_cert_cnt)) < 0) {
			error_print();
			return -1;
		} else if (ret == 0) {
			return 0;
		}
	}

	// certificate_authorities
	if (ca_names && ca_names_len) {
		if ((ret = tls_authorities_issued_certificate(
			ca_names, ca_names_len, cert, certlen)) < 0) {
			error_print();
			return -1;
		} else if (ret == 0) {
			return 0;
		}
	}

	// oid_filters
	if (oid_filters && oid_filters_len) {
	}

	if (prefered_sig_alg) {
		*prefered_sig_alg = sig_alg;
	}
	return 1;
}

int tls13_cert_chains_select(const uint8_t *cert_chains, size_t cert_chains_len,
	const int *signature_algorithms, size_t signature_algorithms_cnt,
	const int *signature_algorithms_cert, size_t signature_algorithms_cert_cnt, // optional
	const uint8_t *ca_names, size_t ca_names_len, // certificate_authorities optional
	const uint8_t *oid_filters, size_t oid_filters_len, // optional, only in CertificateRequest
	const uint8_t *host_name, size_t host_name_len, // optional, only in ClientHello
	const uint8_t **certs, size_t *certs_len, size_t *certs_idx, int *prefered_sig_alg) // optional
{
	size_t i;

	if (!cert_chains || !cert_chains_len
		|| !signature_algorithms || !signature_algorithms_cnt) {
		error_print();
		return -1;
	}

	for (i = 1; cert_chains_len; i++) {
		const uint8_t *cert_chain;
		size_t cert_chain_len;
		int sig_alg;
		int ret;

		if (tls_uint24array_from_bytes(&cert_chain, &cert_chain_len,
			&cert_chains, &cert_chains_len) != 1) {
			error_print();
			return -1;
		}

		if ((ret = tls_cert_chain_match_extensions(cert_chain, cert_chain_len,
			signature_algorithms, signature_algorithms_cnt,
			signature_algorithms_cert, signature_algorithms_cert_cnt,
			ca_names, ca_names_len,
			oid_filters, oid_filters_len,
			host_name, host_name_len,
			&sig_alg)) < 0) {
			error_print();
			return -1;
		} else if (ret == 0) {
			continue;
		}

		if (certs) *certs = cert_chain;
		if (certs_len) *certs_len = cert_chain_len;
		if (certs_idx) *certs_idx = i;
		if (prefered_sig_alg) *prefered_sig_alg = sig_alg;
		return 1;
	}

	if (certs) *certs = NULL;
	if (certs_len) *certs_len = 0;
	if (certs_idx) *certs_idx = 0;
	if (prefered_sig_alg) *prefered_sig_alg = 0;
	warning_print();
	return 0;
}


int tls13_recv_certificate_request(TLS_CONNECT *conn)
{
	int ret;
	int handshake_type;
	const uint8_t *handshake_data;
	size_t handshake_datalen;
	int client_cert;

	// certificate_request
	const uint8_t *request_context;
	size_t request_context_len;
	const uint8_t *exts;
	size_t extslen;

	// extensions
	const uint8_t *signature_algorithms = NULL;
	size_t signature_algorithms_len;
	const uint8_t *signature_algorithms_cert = NULL;
	size_t signature_algorithms_cert_len;
	const uint8_t *certificate_authorities = NULL;
	size_t certificate_authorities_len;
	const uint8_t *oid_filters = NULL;
	size_t oid_filters_len;
	int status_request = 0;
	int signed_certificate_timestamp = 0;

	int common_sig_algs[4];
	size_t common_sig_algs_cnt;
	int common_sig_algs_cert[4];
	size_t common_sig_algs_cert_cnt;
	const uint8_t *ca_names = NULL;
	size_t ca_names_len = 0;
	const uint8_t *filters = NULL;
	size_t filters_len = 0;

	tls_trace("recv {CertificateRequest*}\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}

	if (tls13_record_decrypt(&conn->server_write_key, conn->server_write_iv,
		conn->server_seq_num, conn->record, conn->recordlen,
		conn->plain_record, &conn->plain_recordlen) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	tls_seq_num_incr(conn->server_seq_num);

	if (tls_record_get_handshake(conn->plain_record,
		&handshake_type, &handshake_data, &handshake_datalen) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_decode_error);
		return -1;
	}
	if (handshake_type != TLS_handshake_certificate_request) {
		tls_trace("    no {CertificateRequest}\n");
		return 0;
	}

	if ((ret = tls13_record_get_handshake_certificate_request(conn->plain_record,
		&request_context, &request_context_len, &exts, &extslen)) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_decode_error);
		return -1;
	}

	if (request_context) {
		// request_context must be null in full/initial handshake
		// and must not be null in post authentication handshakes
		error_print();
		tls13_send_alert(conn, TLS_alert_illegal_parameter);
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

		// exts in CR (from RFC 8446 page 37)
		//  * signature_algorithms - the only ext must exist
		//  * signature_algorithms_cert
		//  * certificate_authorities
		//  * oid_filters (only in CR)
		//  * status_request
		//  * signed_certificate_timestamp

		switch (ext_type) {
		case TLS_extension_signature_algorithms:
		case TLS_extension_signature_algorithms_cert:
		case TLS_extension_certificate_authorities:
		case TLS_extension_oid_filters:
			if (!ext_data) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			break;
		case TLS_extension_status_request:
		case TLS_extension_signed_certificate_timestamp:
			if (ext_data) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			break;
		}

		switch (ext_type) {
		case TLS_extension_signature_algorithms:
			if (signature_algorithms) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			signature_algorithms = ext_data;
			signature_algorithms_len = ext_datalen;
			break;

		case TLS_extension_signature_algorithms_cert:
			if (signature_algorithms_cert) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			signature_algorithms_cert = ext_data;
			signature_algorithms_cert_len = ext_datalen;
			break;

		case TLS_extension_certificate_authorities:
			if (certificate_authorities) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			certificate_authorities = ext_data;
			certificate_authorities_len = ext_datalen;
			break;

		case TLS_extension_oid_filters:
			if (oid_filters) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			oid_filters = ext_data;
			oid_filters_len = ext_datalen;
			break;

		case TLS_extension_status_request:
			if (status_request) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			status_request = 1;
			break;

		case TLS_extension_signed_certificate_timestamp:
			if (signed_certificate_timestamp) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			signed_certificate_timestamp = 1;
			break;

		default:
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
	}

	if (!signature_algorithms) {
		error_print();
		tls13_send_alert(conn, TLS_alert_missing_extension);
		return -1;
	}

	// even if no client cert, check extensions
	if (conn->ctx->cert_chains_len) {
		client_cert = 1;
	}

	// signature_algorithms
	if ((ret = tls_process_signature_algorithms(
		signature_algorithms, signature_algorithms_len,
		conn->ctx->signature_algorithms, conn->ctx->signature_algorithms_cnt,
		common_sig_algs, &common_sig_algs_cnt,
		sizeof(common_sig_algs)/sizeof(common_sig_algs[0]))) < 0) {
		error_print();
		return -1;
	} else if (ret == 0) {
		client_cert = 0;
	}

	// signature_algorithms_cert
	if (signature_algorithms_cert) {
		if ((ret = tls_process_signature_algorithms(
			signature_algorithms_cert, signature_algorithms_cert_len,
			conn->ctx->signature_algorithms, conn->ctx->signature_algorithms_cnt,
			common_sig_algs_cert, &common_sig_algs_cert_cnt,
			sizeof(common_sig_algs_cert)/sizeof(common_sig_algs_cert[0]))) < 0) {
			error_print();
			return -1;
		} else if (ret == 0) {
			client_cert = 0;
		}
	}

	// certificate_authorities
	if (certificate_authorities) {
		if (tls13_certificate_authorities_from_bytes(
			&ca_names, &ca_names_len,
			certificate_authorities, certificate_authorities_len) != 1) {
			error_print();
			return -1;
		}
	}

	// oid_filters
	if (oid_filters) {
		if (tls13_oid_filters_from_bytes(
			&filters, &filters_len, oid_filters, oid_filters_len) != 1) {
			error_print();
			return -1;
		}
	}

	// status_request
	if (status_request) {
		conn->status_request = 1;
	}

	// signed_certificate_timestamp
	if (signed_certificate_timestamp) {
		conn->signed_certificate_timestamp = 1;
	}

	// select cert_chain
	//	* signature_algorithms
	//	* [signature_algorithms_cert]
	//	* [certificate_authorities]
	//	* [oid_filter]
	//
	if (client_cert) {
		if ((ret = tls13_cert_chains_select(conn->ctx->cert_chains, conn->ctx->cert_chains_len,
			common_sig_algs, common_sig_algs_cnt,
			common_sig_algs_cert, common_sig_algs_cert_cnt,
			ca_names, ca_names_len,
			filters, filters_len,
			NULL, 0,
			&conn->cert_chain, &conn->cert_chain_len, &conn->cert_chain_idx, &conn->sig_alg)) < 0) {
			error_print();
			return -1;
		}
		// when ret == 0, conn->cert_chain == NULL
	}

	if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
		error_print();
		return -1;
	}

	conn->certificate_request = 1;

	return ret;
}

int tls13_recv_server_certificate(TLS_CONNECT *conn)
{
	int ret;
	const uint8_t *request_context;
	size_t request_context_len;
	const uint8_t *leaf_status_request_ocsp_response;
	size_t leaf_status_request_ocsp_response_len;
	const uint8_t *leaf_signed_certificate_timestamp;
	size_t leaf_signed_certificate_timestamp_len;

	const int *signature_algorithms_cert = NULL;
	size_t signature_algorithms_cert_cnt = 0;
	const uint8_t *ca_names = NULL;
	size_t ca_names_len = 0;
	const uint8_t *host_name = NULL;
	size_t host_name_len = 0;

	int verify_result;

	tls_trace("recv server {Certificate}\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}

	// decrypt unless previous handshake is CertificateRequest
	if (!conn->plain_recordlen) {
		if (tls13_record_decrypt(&conn->server_write_key, conn->server_write_iv,
			conn->server_seq_num, conn->record, conn->recordlen,
			conn->plain_record, &conn->plain_recordlen) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_bad_record_mac);
			return -1;
		}
		tls_seq_num_incr(conn->server_seq_num);

	}

	if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);
	tls_handshake_digest_print(stderr, 0, 0, "ServerCertificate", &conn->dgst_ctx);

	if ((ret = tls13_record_get_handshake_certificate(conn->plain_record,
		&request_context, &request_context_len,
		conn->peer_cert_chain, &conn->peer_cert_chain_len, sizeof(conn->peer_cert_chain),
		&leaf_status_request_ocsp_response, &leaf_status_request_ocsp_response_len,
		&leaf_signed_certificate_timestamp, &leaf_signed_certificate_timestamp_len)) < 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_unexpected_message);
		return 0;
	}

	if (request_context) {
		error_print();
		tls13_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}
	if (!conn->peer_cert_chain_len) {
		error_print();
		tls13_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}

	// check server cert_chain match ClientHello.extensions
	if (conn->signature_algorithms_cert) {
		signature_algorithms_cert = conn->ctx->signature_algorithms;
		signature_algorithms_cert_cnt = conn->ctx->signature_algorithms_cnt;
	}
	if (conn->certificate_authorities) {
		ca_names = conn->ctx->ca_names;
		ca_names_len = conn->ctx->ca_names_len;
	}
	if (conn->server_name) {
		host_name = conn->host_name;
		host_name_len = conn->host_name_len;
	}
	if (tls_cert_chain_match_extensions(conn->peer_cert_chain, conn->peer_cert_chain_len,
		conn->ctx->signature_algorithms, conn->ctx->signature_algorithms_cnt,
		signature_algorithms_cert, signature_algorithms_cert_cnt,
		ca_names, ca_names_len, // certificate_authorities
		NULL, 0, // oid_filters
		host_name, host_name_len,
		NULL) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}

	// verify server cert_chain
	if (x509_certs_verify(
		conn->peer_cert_chain, conn->peer_cert_chain_len, X509_cert_chain_server,
		conn->ctx->cacerts, conn->ctx->cacertslen,
		conn->ctx->verify_depth, &verify_result) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}
	// status_request
	if (leaf_status_request_ocsp_response) {
		if (ocsp_response_verify(
			leaf_status_request_ocsp_response,
			leaf_status_request_ocsp_response_len,
			conn->ctx->cacerts, conn->ctx->cacertslen) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_certificate_revoked);
			return -1;
		}
	}
	// signed_certificate_timestamp
	if (leaf_signed_certificate_timestamp) {
		if (tls13_signed_certificate_timestamp_verify(
			leaf_signed_certificate_timestamp,
			leaf_signed_certificate_timestamp_len) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_bad_certificate);
			return -1;
		}
	}

	return 1;
}

int tls13_recv_server_certificate_verify(TLS_CONNECT *conn)
{
	int ret;
	int sig_alg;
	const uint8_t *sig;
	size_t siglen;
	const uint8_t *cert;
	size_t certlen;
	X509_KEY public_key;

	tls_trace("recv server {CertificateVerify}\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}

	if (tls13_record_decrypt(&conn->server_write_key, conn->server_write_iv,
		conn->server_seq_num, conn->record, conn->recordlen,
		conn->plain_record, &conn->plain_recordlen) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	tls_seq_num_incr(conn->server_seq_num);
	tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

	if ((ret = tls13_record_get_handshake_certificate_verify(conn->plain_record,
		&sig_alg, &sig, &siglen)) < 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (tls_type_is_in_list(sig_alg, conn->ctx->signature_algorithms,
		conn->ctx->signature_algorithms_cnt) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}
	if (!sig) {
		error_print();
		tls13_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}

	if (x509_certs_get_cert_by_index(conn->peer_cert_chain, conn->peer_cert_chain_len, 0, &cert, &certlen) != 1
		|| x509_cert_get_subject_public_key(cert, certlen, &public_key) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	// verify signature
	if (tls13_verify_certificate_verify(TLS_server_mode, sig_alg, &public_key,
		&conn->dgst_ctx, sig, siglen) != 1) {
		error_print();
		return -1;
	}

	if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
		error_print();
		return -1;
	}

	conn->recordlen = 0;
	conn->plain_recordlen = 0;

	return 1;
}

int tls13_recv_client_certificate_verify(TLS_CONNECT *conn)
{
	int ret;
	int sig_alg;
	const uint8_t *sig;
	size_t siglen;
	const uint8_t *cert;
	size_t certlen;
	X509_KEY public_key;

	tls_trace("recv client {CertificateVerify}\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}

	if (tls13_record_decrypt(&conn->client_write_key, conn->client_write_iv,
		conn->client_seq_num, conn->record, conn->recordlen,
		conn->plain_record, &conn->plain_recordlen) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	tls_seq_num_incr(conn->client_seq_num);
	tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

	if ((ret = tls13_record_get_handshake_certificate_verify(conn->plain_record,
		&sig_alg, &sig, &siglen)) < 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (tls_type_is_in_list(sig_alg, conn->ctx->signature_algorithms,
		conn->ctx->signature_algorithms_cnt) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}
	if (!sig) {
		error_print();
		tls13_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}

	if (x509_certs_get_cert_by_index(conn->peer_cert_chain, conn->peer_cert_chain_len, 0, &cert, &certlen) != 1
		|| x509_cert_get_subject_public_key(cert, certlen, &public_key) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	// verify signature
	if (tls13_verify_certificate_verify(TLS_server_mode, sig_alg, &public_key,
		&conn->dgst_ctx, sig, siglen) != 1) {
		error_print();
		return -1;
	}

	if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
		error_print();
		return -1;
	}

	return 1;
}


// ServerFinished消息之前有可能是什么消息？				

int tls13_recv_server_finished(TLS_CONNECT *conn)
{
	int ret;
	const uint8_t *server_verify_data;
	size_t server_verify_data_len;
	uint8_t verify_data[64];
	size_t verify_data_len;

	uint8_t server_write_key[16];

	// compute verify_data before digest_update
	if (tls13_compute_verify_data(conn->server_handshake_traffic_secret,
		&conn->dgst_ctx, verify_data, &verify_data_len) != 1) {
		error_print();
		return -1;
	}

	tls_trace("recv server {Finished}\n");

	if (!conn->plain_recordlen) {

		if ((ret = tls_recv_record(conn)) != 1) {
			if (ret != TLS_ERROR_RECV_AGAIN) {
				error_print();
			}
			return ret;
		}

		if (tls13_record_decrypt(&conn->server_write_key, conn->server_write_iv,
			conn->server_seq_num, conn->record, conn->recordlen,
			conn->plain_record, &conn->plain_recordlen) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_bad_record_mac);
			return -1;
		}
		tls_seq_num_incr(conn->server_seq_num);
	}
	tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

	if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	tls_handshake_digest_print(stderr, 0, 0, "ServerFinished", &conn->dgst_ctx);


	if ((ret = tls13_record_get_handshake_finished(conn->plain_record,
		&server_verify_data, &server_verify_data_len)) < 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	if (server_verify_data_len != verify_data_len
		|| memcmp(server_verify_data, verify_data, verify_data_len) != 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}

	// generate client_application_traffic_secret
	/* [11] */ tls13_derive_secret(conn->master_secret, "c ap traffic", &conn->dgst_ctx, conn->client_application_traffic_secret);
	// generate server_application_traffic_secret
	/* [12] */ tls13_derive_secret(conn->master_secret, "s ap traffic", &conn->dgst_ctx, conn->server_application_traffic_secret);

	// update server_write_key, server_write_iv, reset server_seq_num
	tls13_hkdf_expand_label(conn->digest, conn->server_application_traffic_secret, "key", NULL, 0, 16, server_write_key);
	block_cipher_set_encrypt_key(&conn->server_write_key, conn->cipher, server_write_key);
	tls13_hkdf_expand_label(conn->digest, conn->server_application_traffic_secret, "iv", NULL, 0, 12, conn->server_write_iv);
	tls_seq_num_reset(conn->server_seq_num);

	format_print(stderr, 0, 0, "update server secrets\n");
	format_bytes(stderr, 0, 4, "server_application_traffic_secret", conn->server_application_traffic_secret, 48);
	format_bytes(stderr, 0, 4, "server_write_key", server_write_key, 16);
	format_bytes(stderr, 0, 4, "server_write_iv", conn->server_write_iv, 12);
	format_bytes(stderr, 0, 4, "server_seq_num", conn->server_seq_num, 8);

	format_print(stderr, 0, 0, "\n");


	return 1;
}

int tls13_send_client_certificate(TLS_CONNECT *conn)
{
	int ret;

	tls_trace("send {Certificate}\n");

	if (conn->recordlen == 0) {
		const uint8_t *request_context = NULL;
		size_t request_context_len = 0;
		const uint8_t *entity_status_request_ocsp_response = NULL;
		size_t entity_status_request_ocsp_response_len = 0;
		const uint8_t *entity_signed_certificate_timestamp = NULL;
		size_t entity_signed_certificate_timestamp_len = 0;
		size_t padding_len;

		// status_request
		if (conn->status_request) {
			entity_status_request_ocsp_response = conn->status_request_ocsp_response;
			entity_status_request_ocsp_response_len = conn->status_request_ocsp_response_len;
		}

		// signed_certificate_timestamp
		if (conn->signed_certificate_timestamp) {
			entity_signed_certificate_timestamp = conn->signed_certificate_timestamp_list;
			entity_signed_certificate_timestamp_len = conn->signed_certificate_timestamp_list_len;
		}

		if (tls13_record_set_handshake_certificate(conn->plain_record, &conn->plain_recordlen,
			request_context, request_context_len,
			conn->cert_chain, conn->cert_chain_len,
			entity_status_request_ocsp_response, entity_status_request_ocsp_response_len,
			entity_signed_certificate_timestamp, entity_signed_certificate_timestamp_len) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

		if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
			error_print();
			return -1;
		}

		tls13_padding_len_rand(&padding_len);
		if (tls13_record_encrypt(&conn->client_write_key, conn->client_write_iv,
			conn->client_seq_num, conn->plain_record, conn->plain_recordlen, padding_len,
			conn->record, &conn->recordlen) != 1) {
			error_print();
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

int tls13_send_client_certificate_verify(TLS_CONNECT *conn)
{
	int ret;

	tls_trace("send {CertificateVerify*}\n");

	if (!conn->recordlen) {
		X509_KEY *sign_key = &conn->ctx->x509_keys[conn->cert_chain_idx - 1];
		uint8_t sig[256];
		size_t siglen;
		size_t padding_len;

		if (tls13_sign_certificate_verify(TLS_client_mode, conn->sig_alg,
			sign_key, &conn->dgst_ctx, sig, &siglen) != 1) {
			error_print();
			return -1;
		}

		if (tls13_record_set_handshake_certificate_verify(
			conn->plain_record, &conn->plain_recordlen,
			conn->sig_alg, sig, siglen) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

		if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
			error_print();
			return -1;
		}

		tls13_padding_len_rand(&padding_len);
		if (tls13_record_encrypt(&conn->client_write_key, conn->client_write_iv,
			conn->client_seq_num, conn->plain_record, conn->plain_recordlen, padding_len,
			conn->record, &conn->recordlen) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_internal_error);
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

int tls13_send_client_finished(TLS_CONNECT *conn)
{
	int ret;
	uint8_t client_write_key[16];

	tls_trace("send client {Finished}\n");

	if (!conn->recordlen) {
		uint8_t verify_data[64];
		size_t verify_data_len;
		size_t padding_len;


		tls_handshake_digest_print(stderr, 0, 0, "before ClientFinished", &conn->dgst_ctx);

		tls13_compute_verify_data(conn->client_handshake_traffic_secret, &conn->dgst_ctx,
			verify_data, &verify_data_len);

		memset(&conn->dgst_ctx, 0, sizeof(conn->dgst_ctx));


		if (tls_record_set_handshake_finished(conn->plain_record, &conn->plain_recordlen,
			verify_data, verify_data_len) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);


		format_bytes(stderr, 0, 0, "client_seq_num", conn->client_seq_num, 8);

		tls13_padding_len_rand(&padding_len);
		if (tls13_record_encrypt(&conn->client_write_key, conn->client_write_iv,
			conn->client_seq_num, conn->plain_record, conn->plain_recordlen, padding_len,
			conn->record, &conn->recordlen) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_internal_error);
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

	//update client_write_key, client_write_iv, reset client_seq_num
	tls13_hkdf_expand_label(conn->digest, conn->client_application_traffic_secret, "key", NULL, 0, 16, client_write_key);
	tls13_hkdf_expand_label(conn->digest, conn->client_application_traffic_secret, "iv", NULL, 0, 12, conn->client_write_iv);
	block_cipher_set_encrypt_key(&conn->client_write_key, conn->cipher, client_write_key);
	tls_seq_num_reset(conn->client_seq_num);

	format_print(stderr, 0, 0, "update client secrets\n");
	format_bytes(stderr, 0, 4, "client_application_traffic_secret", conn->client_application_traffic_secret, 48);
	format_bytes(stderr, 0, 4, "client_write_key", client_write_key, 16);
	format_bytes(stderr, 0, 4, "client_write_iv", conn->client_write_iv, 12);
	format_print(stderr, 0, 0, "\n");


	return 1;
}


int tls13_recv_client_hello(TLS_CONNECT *conn)
{
	int ret;
	uint8_t *record = conn->record;
	size_t recordlen;

	int client_verify = 0;

	int protocol;

	// client_hello
	int legacy_version;
	const uint8_t *random;
	const uint8_t *legacy_session_id;
	size_t legacy_session_id_len;
	const uint8_t *cipher_suites;
	size_t cipher_suites_len;
	const uint8_t *legacy_comp_methods;
	size_t legacy_comp_methods_len;
	const uint8_t *exts;
	size_t extslen;

	// extensions
	const uint8_t *supported_versions = NULL;
	size_t supported_versions_len;
	const uint8_t *supported_groups = NULL;
	size_t supported_groups_len;
	const uint8_t *signature_algorithms = NULL;
	size_t signature_algorithms_len;
	const uint8_t *signature_algorithms_cert = NULL;
	size_t signature_algorithms_cert_len;
	const uint8_t *certificate_authorities = NULL;
	size_t certificate_authorities_len;
	const uint8_t *key_share = NULL;
	size_t key_share_len;
	const uint8_t *server_name = NULL;
	size_t server_name_len;
	const uint8_t *psk_key_exchange_modes = NULL;
	size_t psk_key_exchange_modes_len;
	const uint8_t *pre_shared_key = NULL;
	size_t pre_shared_key_len;
	const uint8_t *status_request = NULL;
	size_t status_request_len;
	int signed_certificate_timestamp = 0;
	int early_data = 0;

	int common_versions[4];
	size_t common_versions_cnt = 0;
	int common_groups[4];
	size_t common_groups_cnt = 0;
	int common_sig_algs[4];
	size_t common_sig_algs_cnt = 0;
	int common_sig_algs_cert[4];
	size_t common_sig_algs_cert_cnt = 0;

	const uint8_t *host_name = NULL;
	size_t host_name_len;

	int common_key_exchange_modes = 0;

	const uint8_t *ca_names = NULL;
	size_t ca_names_len = 0;


	// 这个判断应该改为一个函数
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
	tls13_record_print(stderr, 0, 0, conn->record, conn->recordlen);

	if (tls_record_protocol(record) != TLS_protocol_tls1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}
	if ((ret = tls_record_get_handshake_client_hello(conn->record,
		&legacy_version, &random, &legacy_session_id, &legacy_session_id_len,
		&cipher_suites, &cipher_suites_len, &exts, &extslen)) < 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	// legacy_version
	if (legacy_version != TLS_protocol_tls12) {
		error_print();
		tls13_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	// random
	memcpy(conn->client_random, random, 32);

	// legacy_session_id
	if (legacy_session_id_len) {
		// tls13 server ignore legacy_session_id
		warning_print();
	}

	// cipher_suites
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

	tls13_cipher_suite_get(conn->cipher_suite, &conn->cipher, &conn->digest);

	// digest_update(client_hello) until conn->hello_retry_request


	while (extslen) {
		int ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;

		if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}

		// exts in CH (RFC 8446 page 37), only oid_filter not in CH
		//  * supported_versions
		//  * signature_algorithms
		//  * signature_algorithms_cert
		//  * certificate_authorities
		//  * server_name
		//  * status_request
		//  * signed_certificate_timestamp
		//  * supported_groups
		//  * key_share
		//  * psk_key_exchange_modes
		//  * pre_shared_key
		//  * early_data (only in ClientHello1)
		//  * max_fragment_length
		//  * use_srtp
		//  * heartbeat
		//  * application_layer_protocol_negotiation
		//  * server_certificate_type: if client accept raw/x509
		//  * client_certificate_type: if client sned raw/x509
		//  * padding
		//  * post_handshake_auth: client support post handshake auth
		//  * cookie (only in ClientHello2)


		switch (ext_type) {
		case TLS_extension_supported_versions:
		case TLS_extension_supported_groups:
		case TLS_extension_signature_algorithms:
		case TLS_extension_signature_algorithms_cert:
		case TLS_extension_certificate_authorities:
		case TLS_extension_key_share:
		case TLS_extension_server_name:
		case TLS_extension_psk_key_exchange_modes:
		case TLS_extension_pre_shared_key:
		case TLS_extension_status_request:
			if (!ext_data) {
				error_print();
				return -1;
			}
			break;
		case TLS_extension_signed_certificate_timestamp:
		case TLS_extension_early_data:
			if (ext_data) {
				error_print();
				return -1;
			}
			break;
		}

		switch (ext_type) {
		case TLS_extension_supported_versions:
			if (supported_versions) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			supported_versions = ext_data;
			supported_versions_len = ext_datalen;
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

		case TLS_extension_signature_algorithms_cert:
			if (signature_algorithms_cert) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			signature_algorithms_cert = ext_data;
			signature_algorithms_cert_len = ext_datalen;
			break;

		case TLS_extension_certificate_authorities:
			if (certificate_authorities) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			certificate_authorities = ext_data;
			certificate_authorities_len = ext_datalen;
			break;

		case TLS_extension_key_share:
			if (key_share) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			key_share = ext_data;
			key_share_len = ext_datalen;
			break;

		case TLS_extension_server_name:
			if (server_name) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			server_name = ext_data;
			server_name_len = ext_datalen;
			break;

		case TLS_extension_psk_key_exchange_modes:
			if (psk_key_exchange_modes) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			psk_key_exchange_modes = ext_data;
			psk_key_exchange_modes_len = ext_datalen;
			break;

		case TLS_extension_pre_shared_key:
			if (pre_shared_key) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			pre_shared_key = ext_data;
			pre_shared_key_len = ext_datalen;
			break;

		case TLS_extension_status_request:
			if (status_request) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			status_request = ext_data;
			status_request_len = ext_datalen;
			break;

		case TLS_extension_signed_certificate_timestamp:
			if (signed_certificate_timestamp) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			signed_certificate_timestamp = 1;
			break;

		case TLS_extension_early_data:
			if (early_data) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			early_data = 1;
			break;

		case TLS_extension_max_fragment_length:
		case TLS_extension_use_srtp:
		case TLS_extension_heartbeat:
		case TLS_extension_application_layer_protocol_negotiation:
		case TLS_extension_server_certificate_type:
		case TLS_extension_client_certificate_type:
		case TLS_extension_padding:
		case TLS_extension_post_handshake_auth:
			break;

		case TLS_extension_cookie:
			error_print();
		default:
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
	}

	// from RFC 8446 section 9.2
	//   * supported_versions required for CH, SH, HRR
	//   * if no pre_shared_key, signature_algorithms + supported_groups must exist
	//   * supported_groups + key_share must exist together
	//   * empty key_share is permitted
	//
	if (!supported_versions) {
		error_print();
		tls13_send_alert(conn, TLS_alert_missing_extension);
		return -1;
	}
	if (!pre_shared_key) {
		if (!(signature_algorithms && supported_groups)) {
			error_print();
			tls13_send_alert(conn, TLS_alert_missing_extension);
			return -1;
		}
	}
	if ((supported_groups && !key_share)
		|| (!supported_groups && key_share)) {
		error_print();
		tls13_send_alert(conn, TLS_alert_missing_extension);
		return -1;
	}
	if ((psk_key_exchange_modes && !pre_shared_key)
		|| (!psk_key_exchange_modes && pre_shared_key)) {
		error_print();
		tls13_send_alert(conn, TLS_alert_missing_extension);
		return -1;
	}

	// supported_versions
	if ((ret = tls13_process_client_supported_versions(
		supported_versions, supported_versions_len,
		conn->ctx->supported_versions, conn->ctx->supported_versions_cnt,
		common_versions, &common_versions_cnt,
		sizeof(common_versions)/sizeof(common_versions[0]))) < 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}
	if (common_versions[0] != TLS_protocol_tls13) {
		error_print();
		tls13_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}
	conn->protocol = common_versions[0];


	// psk_key_exchange_modes
	if (psk_key_exchange_modes) {
		if (tls13_psk_key_exchange_modes_from_bytes(&common_key_exchange_modes,
			psk_key_exchange_modes, psk_key_exchange_modes_len) != 1) {
			error_print();
			return -1;
		}
	}
	// client key_exchange_modes
	if (supported_groups && signature_algorithms) {
		common_key_exchange_modes |= TLS_KE_CERT_DHE;
	}

	// common key_exchange_modes
	common_key_exchange_modes &= conn->key_exchange_modes;
	if (!common_key_exchange_modes) {
		error_print();
		tls13_send_alert(conn, TLS_alert_handshake_failure);
		return -1;
	}

	// signature_algorithms
	if (signature_algorithms) {
		if ((ret = tls_process_signature_algorithms(
			signature_algorithms, signature_algorithms_len,
			conn->ctx->signature_algorithms, conn->ctx->signature_algorithms_cnt,
			common_sig_algs, &common_sig_algs_cnt,
			sizeof(common_sig_algs)/sizeof(common_sig_algs[0]))) < 0) {
			error_print();
			tls13_send_alert(conn, TLS_alert_decode_error);
			return -1;
		} else if (ret == 0) {
			common_key_exchange_modes &= ~TLS_KE_CERT_DHE;
		}
	}

	// signature_algorithms_cert
	if (signature_algorithms_cert) {
		if ((ret = tls_process_signature_algorithms(
			signature_algorithms_cert, signature_algorithms_cert_len,
			conn->ctx->signature_algorithms, conn->ctx->signature_algorithms_cnt,
			common_sig_algs_cert, &common_sig_algs_cert_cnt,
			sizeof(common_sig_algs_cert)/sizeof(common_sig_algs_cert[0]))) < 0) {
			error_print();
			tls13_send_alert(conn, TLS_alert_decode_error);
			return -1;
		} else if (ret == 0) {
			common_key_exchange_modes &= ~TLS_KE_CERT_DHE;
		}
	}

	// certificate_authorities
	if (certificate_authorities) {
		if (tls13_certificate_authorities_from_bytes(&ca_names, &ca_names_len,
			certificate_authorities, certificate_authorities_len) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
	}

	// server_name
	if (server_name) {
		if (tls_server_name_from_bytes(&host_name, &host_name_len,
			server_name, server_name_len) != 1) {
			error_print();
			return -1;
		}
		conn->server_name = 1;
	}

	// select server cert_chain
	//	* signature_algorithms
	//	* [signature_algorithms_cert]
	//	* [certificate_authorities]
	//	* [server_name.host_name]
	//
	if (common_key_exchange_modes & TLS_KE_CERT_DHE) {
		if ((ret = tls13_cert_chains_select(
			conn->ctx->cert_chains, conn->ctx->cert_chains_len,
			common_sig_algs, common_sig_algs_cnt,
			common_sig_algs_cert, common_sig_algs_cert_cnt,
			ca_names, ca_names_len,
			NULL, 0, // oid_filters
			host_name, host_name_len,
			&conn->cert_chain, &conn->cert_chain_len, &conn->cert_chain_idx, &conn->sig_alg)) < 0) {
			error_print();
			tls13_send_alert(conn, TLS_alert_decode_error);
			return -1;
		} else if (ret == 0) {
			error_print();
			common_key_exchange_modes &= ~TLS_KE_CERT_DHE;
		}
	}

	// status_request
	if (status_request) {
		int status_type;
		const uint8_t *responder_id_list;
		size_t responder_id_list_len;
		const uint8_t *request_exts;
		size_t request_exts_len;

		if (tls_client_status_request_from_bytes(&status_type,
			&responder_id_list, &responder_id_list_len,
			&request_exts, &request_exts_len,
			status_request, status_request_len) != 1) {
			error_print();
			return -1;
		}
		if (status_type != TLS_certificate_status_type_ocsp) {
			error_print();
			return -1;
		}
		if (conn->cert_chain) {
			const uint8_t *cp = conn->ctx->status_request_ocsp_responses;
			size_t len = conn->ctx->status_request_ocsp_responses_len;
			size_t i;

			// get ocsp_response
			for (i = 0; i < conn->cert_chain_idx; i++) {
				if (tls_uint24array_from_bytes(
					&conn->status_request_ocsp_response,
					&conn->status_request_ocsp_response_len,
					&cp, &len) != 1) {
					error_print();
					return -1;
				}
			}
			// check if ocsp_response match the status_request
			if (conn->status_request_ocsp_response) {
				if ((ret = tls_ocsp_response_match_status_request(
					conn->status_request_ocsp_response,
					conn->status_request_ocsp_response_len,
					responder_id_list, responder_id_list_len,
					request_exts, request_exts_len)) < 0) {
					error_print();
					return -1;
				} else if (ret == 0) {
					conn->status_request_ocsp_response = NULL;
					conn->status_request_ocsp_response_len = 0;
				}
			}
		}
		// send CertificateRequest.status_request
		conn->status_request = 1;
	}

	// signed_certificate_timestamp
	if (signed_certificate_timestamp) {
		if (conn->cert_chain) {
			const uint8_t *sct_lists = conn->ctx->signed_certificate_timestamp_lists;
			size_t sct_lists_len = conn->ctx->signed_certificate_timestamp_lists_len;
			size_t i;

			for (i = 0; i < conn->cert_chain_idx; i++) {
				if (tls_uint16array_from_bytes(
					&conn->signed_certificate_timestamp_list,
					&conn->signed_certificate_timestamp_list_len,
					&sct_lists, &sct_lists_len) != 1) {
					error_print();
					return -1;
				}
			}
		}
		// send CertificateRequest.signed_certificate_timestamp
		conn->signed_certificate_timestamp = 1;
	}

	// supported_groups
	if (supported_groups) {
		if ((ret = tls_process_supported_groups(
			supported_groups, supported_groups_len,
			conn->ctx->supported_groups, conn->ctx->supported_groups_cnt,
			common_groups, &common_groups_cnt,
			sizeof(common_groups)/sizeof(common_groups[0]))) < 0) {
			error_print();
			tls13_send_alert(conn, TLS_alert_decode_error);
			return -1;
		} else if (ret == 0) {
			common_key_exchange_modes &= ~(TLS_KE_CERT_DHE|TLS_KE_PSK_DHE);
		}
	}

	// key_share
	if (key_share) {
		int group = 0;
		const uint8_t *key_exchange = NULL;
		size_t key_exchange_len = 0;

		if (common_groups_cnt) {
			if ((ret = tls13_process_key_share_client_hello(
				key_share, key_share_len, common_groups, common_groups_cnt,
				&group, &key_exchange, &key_exchange_len)) < 0) {
				error_print();
				tls13_send_alert(conn, TLS_alert_decode_error);
				return -1;
			} else if (ret == 0) {
				// send HelloRetryRequest if modes == CERT_DHE|PSK_DHE
				conn->key_exchange_group = common_groups[0];
			} else {
				conn->key_exchange_group = group;
				memcpy(conn->peer_key_exchange, key_exchange, key_exchange_len);
				conn->peer_key_exchange_len = key_exchange_len;
			}
		}
	}

	// pre_shared_key
	if (pre_shared_key) {
		if (common_key_exchange_modes & (TLS_KE_PSK_DHE|TLS_KE_PSK)) {
			if (conn->psk_identities_len) {
				if ((ret = tls13_process_client_pre_shared_key_external(conn,
					pre_shared_key, pre_shared_key_len)) < 0) {
					error_print();
					return -1;
				} else if (ret == 0) {
					common_key_exchange_modes &= ~(TLS_KE_PSK_DHE|TLS_KE_PSK);
				}
			} else if (conn->ctx->session_ticket_key) {
				if ((ret = tls13_process_client_pre_shared_key_from_ticket(conn,
					pre_shared_key, pre_shared_key_len)) < 0) {
					error_print();
					return -1;
				} else if (ret == 0) {
					common_key_exchange_modes &= ~(TLS_KE_PSK_DHE|TLS_KE_PSK);
				}
			} else {
				// caller should set session_ticket_key or psk_keys
				error_print();
				return -1;
			}

			//format_print(stderr, 0, 0, "selected_psk_identity: %d\n", conn->selected_psk_identity - 1);
			//format_bytes(stderr, 0, 0, "selected_psk", conn->psk, conn->psk_len);
		}
	}

	/*
	decide the final key exchange mode and  hello_retry_request

	PSK_DHE
		* selected_psk_identity
		* key_exchange_group
		* [key_exchanges_cnt]

	PSK
		* selected_psk_identity

	CERT_DHE
		* cert_chain
		* key_exchange_group
		* [key_exchanges_cnt]
	*/
	if (common_key_exchange_modes & TLS_KE_PSK_DHE) {
		if (conn->selected_psk_identity && conn->key_exchange_group) {
			conn->key_exchange_modes = TLS_KE_PSK_DHE;
			if (!conn->peer_key_exchange_len) {
				conn->hello_retry_request = 1;
			}
		}
	} else if (common_key_exchange_modes & TLS_KE_PSK) {
		if (conn->selected_psk_identity) {
			conn->key_exchange_modes = TLS_KE_PSK;
		}
	} else if (common_key_exchange_modes & TLS_KE_CERT_DHE) {
		if (conn->cert_chain && conn->key_exchange_group) {
			conn->key_exchange_modes = TLS_KE_CERT_DHE;
		}
		if (!conn->peer_key_exchange_len) {
			conn->hello_retry_request = 1;
		}
	} else {
		error_print();
		tls13_send_alert(conn, TLS_alert_handshake_failure);
		return -1;
	}

	tls_key_exchange_modes_print(stderr, 0, 0, "server key_exchange_mode", conn->key_exchange_modes);

	// hello_retry_request
	if (conn->hello_retry_request) {
		uint8_t message_hash[4 + 32];
		size_t dgstlen;

		// cache ClientHello1, need by recv_client_hello_again
		memcpy(conn->plain_record, conn->record, conn->recordlen);
		conn->plain_recordlen = conn->recordlen;


		// message_hash handshake
		message_hash[0] = TLS_handshake_message_hash;
		message_hash[1] = 0;
		message_hash[2] = 0;
		message_hash[3] = 32;

		if (digest_init(&conn->dgst_ctx, conn->digest) != 1
			|| digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1
			|| digest_finish(&conn->dgst_ctx, message_hash + 4, &dgstlen) != 1) {
			error_print();
			return -1;
		}
		if (digest_init(&conn->dgst_ctx, conn->digest) != 1
			|| digest_update(&conn->dgst_ctx, message_hash, sizeof(message_hash)) != 1) {
			error_print();
			return -1;
		}
	} else {
		if (digest_init(&conn->dgst_ctx, conn->digest) != 1
			|| digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		tls_handshake_digest_print(stderr, 0, 0, "ClientHello", &conn->dgst_ctx);
	}

	// early_data
	conn->early_data =
		(conn->early_data) &&
		(conn->key_exchange_modes & (TLS_KE_PSK_DHE | TLS_KE_PSK)) &&
		(early_data) &&
		(conn->hello_retry_request == 0);

	// generate early_data keys
	if (conn->early_data) {
		if (tls13_generate_early_data_keys(conn) != 1) {
			error_print();
			return -1;
		}
	}

	if (client_verify)
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);

	tls_clean_record(conn);

	return 1;
}

int tls13_send_hello_retry_request(TLS_CONNECT *conn)
{
	int ret;

	tls_trace("send HelloRetryRequest\n");

	if (conn->recordlen == 0) {
		const uint8_t *legacy_session_id_echo = NULL;
		size_t legacy_session_id_echo_len = 0;
		int legacy_compress_meth = 0;
		uint8_t exts[256];
		uint8_t *pexts = exts;
		size_t extslen = 0;
		int curve_oid;
		uint8_t cookie[256];
		size_t cookie_len;

		tls_record_set_protocol(conn->record, TLS_protocol_tls12);

		if (tls13_random_generate(conn->server_random) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

		if (conn->session_id_len) {
			legacy_session_id_echo = conn->session_id;
			legacy_session_id_echo_len = conn->session_id_len;
		}

		// exts in HRR
		//  * supported_versions
		//  * key_share
		//  * [cookie]

		// supported_versions
		if (tls13_server_supported_versions_ext_to_bytes(
			TLS_protocol_tls13, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}

		// key_share
		if (tls13_key_share_hello_retry_request_ext_to_bytes(
			conn->key_exchange_group, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}

		// cookie
		if (conn->cookie) {
			// TODO: cookie = {ClientHello}
			if (tls13_cookie_generate(&conn->ctx->cookie_key, NULL, 0,
				cookie, &cookie_len) != 1) {
				error_print();
				return -1;
			}
			if (tls13_cookie_ext_to_bytes(
				cookie, sizeof(cookie), &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		if (tls13_record_set_handshake_hello_retry_request(
			conn->record, &conn->recordlen,
			TLS_protocol_tls12, conn->server_random,
			legacy_session_id_echo, legacy_session_id_echo_len,
			conn->cipher_suite, legacy_compress_meth, exts, extslen) != 1) {
			error_print();
			return -1;
		}
		tls13_record_print(stderr, 0, 0, conn->record, conn->recordlen);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}

	if (conn->ctx->cacertslen) {
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);
	}

	tls_clean_record(conn);

	return 1;
}

int tls13_recv_client_hello_again(TLS_CONNECT *conn)
{
	int ret;
	uint8_t *record = conn->record;
	size_t recordlen;

	int client_verify = 0;

	int protocol;

	// ClientHello1
	int _legacy_version;
	const uint8_t *_random;
	const uint8_t *_legacy_session_id;
	size_t _legacy_session_id_len;
	const uint8_t *_cipher_suites;
	size_t _cipher_suites_len;
	const uint8_t *_legacy_comp_methods;
	size_t _legacy_comp_methods_len;
	const uint8_t *_exts;
	size_t _extslen;

	// ClientHello2
	int legacy_version;
	const uint8_t *random;
	const uint8_t *legacy_session_id;
	size_t legacy_session_id_len;
	const uint8_t *cipher_suites;
	size_t cipher_suites_len;
	const uint8_t *legacy_comp_methods;
	size_t legacy_comp_methods_len;
	const uint8_t *exts;
	size_t extslen;

	// Extensions
	const uint8_t *key_share = NULL;
	size_t key_share_len;
	const uint8_t *pre_shared_key = NULL;
	size_t pre_shared_key_len;
	const uint8_t *cookie = NULL;
	size_t cookie_len;

	const uint8_t *key_exchange;
	size_t key_exchange_len;


	tls_trace("recv ClientHello again\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	tls13_record_print(stderr, 0, 0, conn->record, conn->recordlen);

	if (tls_record_protocol(record) != TLS_protocol_tls1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}
	if ((ret = tls_record_get_handshake_client_hello(conn->record,
		&legacy_version, &random, &legacy_session_id, &legacy_session_id_len,
		&cipher_suites, &cipher_suites_len, &exts, &extslen)) < 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (legacy_version != TLS_protocol_tls12) {
		error_print();
		tls13_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}

	// ClientHello1
	if (tls_record_get_handshake_client_hello(conn->plain_record,
		&_legacy_version, &_random, &_legacy_session_id, &_legacy_session_id_len,
		&_cipher_suites, &_cipher_suites_len, &_exts, &_extslen) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_decode_error);
		return -1;
	}
	if (legacy_version != _legacy_version
		|| legacy_session_id_len != _legacy_session_id_len
		|| memcmp(legacy_session_id, _legacy_session_id, _legacy_session_id_len) != 0
		|| cipher_suites_len != _cipher_suites_len
		|| memcmp(cipher_suites, _cipher_suites, _cipher_suites_len) != 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}
	// client random, should not send the same random
	if (memcmp(random, conn->client_random, 32) == 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}

	// update client_server
	memcpy(conn->client_random, random, 32);

	while (extslen) {
		int ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;
		int _ext_type;
		const uint8_t *_ext_data;
		size_t _ext_datalen;

		if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}

		// ClientHello2 extensions
		//	* key_share - must exist, only one key_exchange based on conn->key_exchange_group
		//	* pre_shared_key - might be subset of ClientHello1.pre_shared_key
		//	* early_data - must not exist
		//	* cookie - should exsit if conn->cookie == 1

		// early_data must not in ClientHello2
		if (ext_type == TLS_extension_early_data) {
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}

		// cookie not in ClientHello1
		if (ext_type == TLS_extension_cookie) {
			if (!conn->cookie) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			if (!ext_data) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			cookie = ext_data;
			cookie_len = ext_datalen;
			continue;
		}

		// get ext in ClientHello1 (omit early_data)
		if (tls_ext_from_bytes(&_ext_type, &_ext_data, &_ext_datalen, &_exts, &_extslen) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}
		if (_ext_type == TLS_extension_early_data) {
			if (tls_ext_from_bytes(&_ext_type, &_ext_data, &_ext_datalen, &_exts, &_extslen) != 1) {
				error_print();
				tls13_send_alert(conn, TLS_alert_decode_error);
				return -1;
			}
		}
		if (ext_type != _ext_type) {
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}

		// check ext_data
		switch (ext_type) {
		case TLS_extension_key_share:
			if (!ext_data) {
				error_print();
				tls13_send_alert(conn, TLS_alert_decode_error);
				return -1;
			}
			key_share = ext_data;
			key_share_len = ext_datalen;
			break;

		case TLS_extension_pre_shared_key:
			{
			const uint8_t *psk_identities;
			size_t psk_identities_len;
			const uint8_t *binders;
			size_t binders_len;
			const uint8_t *_psk_identities;
			size_t _psk_identities_len;

			if (!ext_data) {
				error_print();
				tls13_send_alert(conn, TLS_alert_decode_error);
				return -1;
			}
			if (tls13_client_pre_shared_key_from_bytes(&psk_identities, &psk_identities_len,
				&binders, &binders_len, ext_data, ext_datalen) != 1) {
				error_print();
				tls13_send_alert(conn, TLS_alert_decode_error);
				return -1;
			}
			if (tls13_client_pre_shared_key_from_bytes(&_psk_identities, &_psk_identities_len,
				&binders, &binders_len, _ext_data, _ext_datalen) != 1) {
				error_print();
				return -1;
			}
			while (psk_identities_len) {
				const uint8_t *id;
				size_t idlen;
				uint32_t age;
				const uint8_t *_id;
				size_t _idlen;
				int match = 0;

				if (tls13_psk_identity_from_bytes(&id, &idlen, &age, &psk_identities, &psk_identities_len) != 1) {
					error_print();
					tls13_send_alert(conn, TLS_alert_decode_error);
					return -1;
				}
				while (_psk_identities_len) {
					if (tls13_psk_identity_from_bytes(&_id, &_idlen, &age, &_psk_identities, &_psk_identities_len) != 1) {
						error_print();
						return -1;
					}
					if (idlen == _idlen && memcmp(id, _id, _idlen) == 0) {
						match = 1;
						break;
					}
				}
				if (!match) {
					error_print();
					tls13_send_alert(conn, TLS_alert_illegal_parameter);
					return -1;
				}
			}
			pre_shared_key = ext_data;
			pre_shared_key_len = ext_datalen;
			}
			break;

		default:
			if (ext_datalen != _ext_datalen
				|| memcmp(ext_data, _ext_data, _ext_datalen) != 0) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
		}
	}

	// client must echo ClientHello1.cookie
	if (conn->cookie && !cookie) {
		error_print();
		tls13_send_alert(conn, TLS_alert_missing_extension);
		return -1;
	}

	// cookie
	if (cookie) {
		const uint8_t *cookie_data;
		size_t cookie_datalen;

		if (!conn->cookie) {
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
		if (tls13_cookie_from_bytes(&cookie_data, &cookie_datalen, cookie, cookie_len) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}
		if (tls13_cookie_verify(&conn->ctx->cookie_key, NULL, 0, cookie_data, cookie_datalen) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
	}

	// key_share
	if (tls13_process_key_share_client_hello_again(key_share, key_share_len,
		conn->key_exchange_group, &key_exchange, &key_exchange_len) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_decode_error);
		return -1;
	}
	if (key_exchange_len != 65) {
		error_print();
		return -1;
	}
	memcpy(conn->peer_key_exchange, key_exchange, key_exchange_len);
	conn->peer_key_exchange_len = key_exchange_len;

	// pre_shared_key
	if (pre_shared_key) {
		if (conn->key_exchange_modes & (TLS_KE_PSK_DHE|TLS_KE_PSK)) {
			size_t selected_psk_identity = conn->selected_psk_identity;
			conn->selected_psk_identity = 0;

			if (conn->psk_identities_len) {
				if (tls13_process_client_pre_shared_key_external(conn,
					pre_shared_key, pre_shared_key_len) != 1) {
					tls13_send_alert(conn, TLS_alert_illegal_parameter);
					error_print();
					return -1;
				}
			} else if (conn->ctx->session_ticket_key) {
				if (tls13_process_client_pre_shared_key_from_ticket(conn,
					pre_shared_key, pre_shared_key_len) != 1) {
					error_print();
					tls13_send_alert(conn, TLS_alert_illegal_parameter);
					return -1;
				}
			}
			if (conn->selected_psk_identity != selected_psk_identity) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
		}
	}

	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}

	if (client_verify)
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);

	tls_clean_record(conn);
	return 1;
}

int tls13_send_server_hello(TLS_CONNECT *conn)
{
	int ret;

	tls_trace("send ServerHello\n");

	if (conn->recordlen == 0) {
		uint8_t exts[256];
		uint8_t *pexts = exts;
		size_t extslen = 0;

		tls_record_set_protocol(conn->record, TLS_protocol_tls12);

		// server_random
		if (tls13_random_generate(conn->server_random) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

		// exts in SH
		//  * supported_versions
		//  * key_share
		//  * pre_shared_key

		// supported_versions
		if (tls13_server_supported_versions_ext_to_bytes(
			conn->protocol, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}

		// key_share
		if (conn->key_exchange_modes & (TLS_KE_CERT_DHE|TLS_KE_PSK_DHE)) {
			int curve_oid;

			if (!conn->key_exchange_group) {
				error_print();
				return -1;
			}
			if ((curve_oid = tls_named_curve_oid(conn->key_exchange_group)) == OID_undef) {
				error_print();
				return -1;
			}
			if (x509_key_generate(&conn->key_exchanges[0],
				OID_ec_public_key, &curve_oid, sizeof(curve_oid)) != 1) {
				error_print();
				return -1;
			}
			conn->key_exchange_idx = 0;
			conn->key_exchanges_cnt = 1;
			if (tls13_key_share_server_hello_ext_to_bytes(
				&conn->key_exchanges[0], &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// pre_shared_key
		if (conn->key_exchange_modes & (TLS_KE_PSK_DHE|TLS_KE_PSK)) {
			if (tls13_server_pre_shared_key_ext_to_bytes(
				conn->selected_psk_identity, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		if (tls_record_set_handshake_server_hello(conn->record, &conn->recordlen,
			TLS_protocol_tls12, conn->server_random, NULL, 0,
			conn->cipher_suite, exts, extslen) != 1) {
			error_print();
			return -1;
		}
		tls13_record_print(stderr, 0, 0, conn->record, conn->recordlen);

		if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		tls_handshake_digest_print(stderr, 0, 0, "ServerHello", &conn->dgst_ctx);

		if (tls13_generate_handshake_keys(conn) != 1) {
			error_print();
			return -1;
		}
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	if (conn->ctx->cacertslen) {
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);
	}

	tls_clean_record(conn);
	return 1;
}

int tls13_send_alert(TLS_CONNECT *conn, int alert)
{
	int ret;
	size_t padding_len;

	tls_trace("send {Alert}\n");

	tls_record_set_protocol(conn->plain_record, TLS_protocol_tls12);
	tls_record_set_alert(conn->plain_record, &conn->plain_recordlen, TLS_alert_level_fatal, alert);

	switch (conn->state) {
	case TLS_handshake_client_hello:
	case TLS_handshake_server_hello:
	case TLS_handshake_hello_retry_request:
		tls_socket_send(conn->sock, conn->plain_record, conn->plain_recordlen, 0);
		break;
	default:
		tls13_padding_len_rand(&padding_len);
		if (tls13_record_encrypt(&conn->server_write_key, conn->server_write_iv,
			conn->server_seq_num, conn->plain_record, conn->plain_recordlen, padding_len,
			conn->record, &conn->recordlen) != 1) {
			error_print();
			return -1;
		}
		tls_seq_num_incr(conn->server_seq_num);

		if ((ret = tls_send_record(conn)) != 1) {
			if (ret != TLS_ERROR_SEND_AGAIN) {
				error_print();
			}
			return ret;
		}
	}

	return 1;
}

int tls13_send_encrypted_extensions(TLS_CONNECT *conn)
{
	int ret;
	tls_trace("send {EncryptedExtensions}\n");

	if (conn->recordlen == 0) {
		uint8_t exts[256];
		uint8_t *pexts = exts;
		size_t extslen = 0;
		size_t padding_len;

		tls_record_set_protocol(conn->plain_record, TLS_protocol_tls12);

		// Exts in EE (see RFC 8446 page 37)
		//  * supported_groups
		//  * server_name
		//  * early_data
		//  * application_layer_protocol_negotiation
		//  * use_srtp
		//  * client_certificate_type
		//  * server_certificate_type
		//  * max_fragment_length
		//  * heartbeat
		//  * record_size_limit (RFC 8449)

		// supported_groups
		if (conn->key_exchange_modes & (TLS_KE_CERT_DHE|TLS_KE_PSK_DHE)) {
			if (tls_supported_groups_ext_to_bytes(conn->ctx->supported_groups,
				conn->ctx->supported_groups_cnt, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// server_name
		if (conn->server_name) {
			if (tls_ext_to_bytes(TLS_extension_server_name, NULL, 0, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// early_data
		//	ClientHello.early_data
		//	PSK_DHE or PSK
		//	no HelloRetryRequest
		if (conn->early_data) {
			if (tls_ext_to_bytes(TLS_extension_early_data, NULL, 0, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		if (tls13_record_set_handshake_encrypted_extensions(
			conn->plain_record, &conn->plain_recordlen,
			exts, extslen) != 1) {
			error_print();
			return -1;
		}
		tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);
		digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5);


		tls_handshake_digest_print(stderr, 0, 0, "EncryptedExtensions", &conn->dgst_ctx);


		tls13_padding_len_rand(&padding_len);

		format_bytes(stderr, 0, 0, "server_seq_num", conn->server_seq_num, 8);
		if (tls13_record_encrypt(&conn->server_write_key, conn->server_write_iv,
			conn->server_seq_num, conn->plain_record, conn->plain_recordlen, padding_len,
			conn->record, &conn->recordlen) != 1) {
			error_print();
			return -1;
		}
		tls_seq_num_incr(conn->server_seq_num);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}


	if (conn->ctx->cacertslen) {
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);
	}

	tls_clean_record(conn);
	return 1;
}


int tls13_send_certificate_request(TLS_CONNECT *conn)
{
	int ret;
	tls_trace("send {CertificateRequest*}\n");

	if (conn->recordlen == 0) {
		const uint8_t *request_context = NULL;
		size_t request_context_len = 0;
		uint8_t exts[256];
		uint8_t *pexts = exts;
		size_t extslen = 0;
		size_t padding_len;

		// exts in CR (from RFC 8446 page 37)
		//  * signature_algorithms
		//  * signature_algorithms_cert
		//  * certificate_authorities
		//  * oid_filters
		//  * status_request
		//  * signed_certificate_timestamp

		// signature_algorithms
		if (!conn->signature_algorithms_cnt) {
			error_print();
			return -1;
		}
		// subset of ClientHello.signature_algorithms
		if (tls_signature_algorithms_ext_to_bytes(
			conn->signature_algorithms, conn->signature_algorithms_cnt,
			&pexts, &extslen) != 1) {
			error_print();
			return -1;
		}

		// signature_algorithms_cert, only when ClientHello.signature_algorithms_cert
		if (conn->signature_algorithms_cert) {
			if (tls13_signature_algorithms_cert_ext_to_bytes(
				conn->signature_algorithms, conn->signature_algorithms_cnt, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// certificate_authorities
		if (conn->certificate_authorities) {
			if (tls13_certificate_authorities_ext_to_bytes(
				conn->ctx->ca_names, conn->ctx->ca_names_len, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// oid_filters
		if (conn->oid_filters) {
			if (tls13_oid_filters_ext_to_bytes(
				conn->ctx->oid_filters, conn->ctx->oid_filters_len, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// status_request
		if (conn->status_request) {
			if (tls_ext_to_bytes(TLS_extension_status_request, NULL, 0, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// signed_certificate_timestamp
		if (conn->signed_certificate_timestamp) {
			if (tls_ext_to_bytes(TLS_extension_signed_certificate_timestamp, NULL, 0, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		if (tls13_record_set_handshake_certificate_request(
			conn->plain_record, &conn->plain_recordlen,
			request_context, request_context_len, exts, extslen) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

		format_bytes(stderr, 0, 0, "server_seq_num", conn->server_seq_num, 8);
		tls13_padding_len_rand(&padding_len);
		if (tls13_record_encrypt(&conn->server_write_key, conn->server_write_iv,
			conn->server_seq_num, conn->plain_record, conn->plain_recordlen, padding_len,
			conn->record, &conn->recordlen) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
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

int tls13_send_server_certificate(TLS_CONNECT *conn)
{
	int ret;

	tls_trace("send server {Certificate}\n");

	if (conn->recordlen == 0) {
		const uint8_t *request_context = NULL;
		size_t request_context_len = 0;
		const uint8_t *entity_status_request_ocsp_response = NULL;
		size_t entity_status_request_ocsp_response_len = 0;
		const uint8_t *entity_signed_certificate_timestamp = NULL;
		size_t entity_signed_certificate_timestamp_len = 0;
		size_t padding_len;

		// status_request
		if (conn->status_request) {
			entity_status_request_ocsp_response = conn->status_request_ocsp_response;
			entity_status_request_ocsp_response_len = conn->status_request_ocsp_response_len;
		}
		// if ClientHello.status_request, CertificateRequest.status_request = 1

		// signed_certificate_timestamp
		if (conn->signed_certificate_timestamp) {
			entity_signed_certificate_timestamp = conn->signed_certificate_timestamp_list;
			entity_signed_certificate_timestamp_len = conn->signed_certificate_timestamp_list_len;
		}
		// if ClientHello.signed_certificate_timestamp, CertificateRequest.signed_certificate_timestamp = 1

		if (tls13_record_set_handshake_certificate(conn->plain_record, &conn->plain_recordlen,
			request_context, request_context_len,
			conn->cert_chain, conn->cert_chain_len,
			entity_status_request_ocsp_response, entity_status_request_ocsp_response_len,
			entity_signed_certificate_timestamp, entity_signed_certificate_timestamp_len) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

		if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		tls_handshake_digest_print(stderr, 0, 0, "ServerCertificate", &conn->dgst_ctx);

		tls13_padding_len_rand(&padding_len);
		if (tls13_record_encrypt(&conn->server_write_key, conn->server_write_iv,
			conn->server_seq_num, conn->plain_record, conn->plain_recordlen, padding_len,
			conn->record, &conn->recordlen) != 1) {
			error_print();
			return -1;
		}
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


int tls13_send_server_certificate_verify(TLS_CONNECT *conn)
{
	int ret;

	tls_trace("send server {CertificateVerify}\n");

	if (conn->recordlen == 0) {
		X509_KEY *sign_key = &conn->ctx->x509_keys[conn->cert_chain_idx - 1];
		uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
		size_t siglen;
		size_t padding_len;

		if (tls13_sign_certificate_verify(TLS_server_mode, conn->sig_alg,
			sign_key, &conn->dgst_ctx, sig, &siglen) != 1) {
			error_print();
			return -1;
		}

		if (tls13_record_set_handshake_certificate_verify(
			conn->plain_record, &conn->plain_recordlen,
			conn->sig_alg, sig, siglen) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

		if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
			error_print();
			return -1;
		}

		tls13_padding_len_rand(&padding_len);
		if (tls13_record_encrypt(&conn->server_write_key, conn->server_write_iv,
			conn->server_seq_num, conn->plain_record, conn->plain_recordlen, padding_len,
			conn->record, &conn->recordlen) != 1) {
			error_print();
			return -1;
		}
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

int tls13_send_server_finished(TLS_CONNECT *conn)
{
	int ret;
	size_t padding_len;

	tls_trace("send server {Finished}\n");


	if (conn->recordlen == 0) {
		uint8_t verify_data[64];
		size_t verify_data_len;
		uint8_t server_write_key[16];

		// compute server verify_data before digest_update()
		tls13_compute_verify_data(conn->server_handshake_traffic_secret,
			&conn->dgst_ctx, verify_data, &verify_data_len);

		if (tls13_record_set_handshake_finished(conn->plain_record, &conn->plain_recordlen,
			verify_data, verify_data_len) != 1) {
			error_print();
			return -1;
		}
		if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

		tls_handshake_digest_print(stderr, 0, 0, "ServerFinished", &conn->dgst_ctx);


		format_bytes(stderr, 0, 0, "server_seq_num", conn->server_seq_num, 8);
		tls13_padding_len_rand(&padding_len);
		if (tls13_record_encrypt(&conn->server_write_key, conn->server_write_iv,
			conn->server_seq_num, conn->plain_record, conn->plain_recordlen, padding_len,
			conn->record, &conn->recordlen) != 1) {
			error_print();
			return -1;
		}
		tls_seq_num_incr(conn->server_seq_num);

		// Generate client_application_traffic_secret
		/* 11 */ tls13_derive_secret(conn->master_secret, "c ap traffic", &conn->dgst_ctx, conn->client_application_traffic_secret);
		// generate server_application_traffic_secret
		/* 12 */ tls13_derive_secret(conn->master_secret, "s ap traffic", &conn->dgst_ctx, conn->server_application_traffic_secret);

		// update server_write_key, server_write_iv, reset server_seq_num
		tls13_hkdf_expand_label(conn->digest, conn->server_application_traffic_secret, "key", NULL, 0, 16, server_write_key);
		block_cipher_set_encrypt_key(&conn->server_write_key, conn->cipher, server_write_key);
		tls13_hkdf_expand_label(conn->digest, conn->server_application_traffic_secret, "iv", NULL, 0, 12, conn->server_write_iv);
		tls_seq_num_reset(conn->server_seq_num);

		format_print(stderr, 0, 0, "update server secrets\n");
		format_bytes(stderr, 0, 4, "server_application_traffic_secret", conn->server_application_traffic_secret, 48);
		format_bytes(stderr, 0, 4, "server_write_key", server_write_key, 16);
		format_bytes(stderr, 0, 4, "server_write_iv", conn->server_write_iv, 12);
		format_bytes(stderr, 0, 4, "server_seq_num", conn->server_seq_num, 8);
		format_print(stderr, 0, 0, "\n");
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	return 1;
}

int tls13_recv_client_certificate(TLS_CONNECT *conn)
{
	int ret;
	size_t padding_len;
	const uint8_t *request_context;
	size_t request_context_len;
	const uint8_t *status_request_ocsp_response = NULL;
	size_t status_request_ocsp_response_len;
	const uint8_t *signed_certificate_timestamp = NULL;
	size_t signed_certificate_timestamp_len;

	const int *signature_algorithms_cert = NULL;
	size_t signature_algorithms_cert_cnt = 0;
	const uint8_t *ca_names = NULL;
	size_t ca_names_len = 0;
	const uint8_t *oid_filters = NULL;
	size_t oid_filters_len = 0;

	int verify_result;

	tls_trace("recv {Certificate*}\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	tls13_record_print(stderr, 0, 0, conn->record, conn->recordlen);

	if (tls_record_protocol(conn->record) != TLS_protocol_tls12) {
		error_print();
		tls13_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	format_bytes(stderr, 0, 0, "client_seq_num", conn->client_seq_num, 8);
	if (tls13_record_decrypt(&conn->client_write_key, conn->client_write_iv,
		conn->client_seq_num, conn->record, conn->recordlen,
		conn->plain_record, &conn->plain_recordlen) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	tls_seq_num_incr(conn->client_seq_num);

	tls13_record_trace(stderr, conn->plain_record, conn->plain_recordlen, 0, 0);

	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}

	if ((ret = tls13_record_get_handshake_certificate(conn->plain_record,
		&request_context, &request_context_len,
		conn->peer_cert_chain, &conn->peer_cert_chain_len, sizeof(conn->peer_cert_chain),
		&status_request_ocsp_response, &status_request_ocsp_response_len,
		&signed_certificate_timestamp, &signed_certificate_timestamp_len)) < 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_unexpected_message);
		return 0;
	}
	if (request_context) {
		error_print();
		tls13_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}
	if (!conn->peer_cert_chain_len) {
		error_print();
		tls13_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}

	// client cert_chain match CertificateRequest extensions
	if (conn->signature_algorithms_cert) {
		signature_algorithms_cert = conn->ctx->signature_algorithms;
		signature_algorithms_cert_cnt = conn->ctx->signature_algorithms_cnt;
	}
	if (conn->certificate_authorities) {
		ca_names = conn->ctx->ca_names;
		ca_names_len = conn->ctx->ca_names_len;
	}
	if (conn->oid_filters) {
		oid_filters = conn->ctx->oid_filters;
		oid_filters_len = conn->ctx->oid_filters_len;
	}
	if (tls_cert_chain_match_extensions(conn->peer_cert_chain, conn->peer_cert_chain_len,
		conn->ctx->signature_algorithms, conn->ctx->signature_algorithms_cnt,
		signature_algorithms_cert, signature_algorithms_cert_cnt,
		ca_names, ca_names_len,
		oid_filters, oid_filters_len,
		NULL, 0, // server_name not in CertificateRequest
		NULL) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}

	// verify client cert_chain
	if (x509_certs_verify(conn->peer_cert_chain, conn->peer_cert_chain_len, X509_cert_chain_client,
		conn->ctx->cacerts, conn->ctx->cacertslen,
		conn->ctx->verify_depth, &verify_result) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}
	// status_request
	if (status_request_ocsp_response) {
		if (ocsp_response_verify(
			status_request_ocsp_response, status_request_ocsp_response_len,
			conn->ctx->cacerts, conn->ctx->cacertslen) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_certificate_revoked);
			return -1;
		}
	}
	// signed_certificate_timestamp
	if (signed_certificate_timestamp) {
		if (tls13_signed_certificate_timestamp_verify(
			signed_certificate_timestamp, signed_certificate_timestamp_len) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_bad_certificate);
			return -1;
		}
	}

	return 1;
}

int tls13_recv_client_finished(TLS_CONNECT *conn)
{
	int ret;

	// Finished
	uint8_t local_verify_data[64];
	size_t local_verify_data_len;
	const uint8_t *verify_data;
	size_t verify_data_len;

	uint8_t client_write_key[16];

	tls_trace("recv client {Finished}\n");
	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}

	if (tls_record_protocol(conn->record) != TLS_protocol_tls12) {
		error_print();
		tls13_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	format_bytes(stderr, 0, 0, "client_seq_num", conn->client_seq_num, 8);
	if (tls13_record_decrypt(&conn->client_write_key, conn->client_write_iv,
		conn->client_seq_num, conn->record, conn->recordlen,
		conn->plain_record, &conn->plain_recordlen) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	tls_seq_num_incr(conn->client_seq_num);

	tls13_record_trace(stderr, conn->plain_record, conn->plain_recordlen, 0, 0);


	if ((ret = tls13_record_get_handshake_finished(conn->plain_record,
		&verify_data, &verify_data_len)) < 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	tls_handshake_digest_print(stderr, 0, 0, "before ClientFinished", &conn->dgst_ctx);

	if (tls13_compute_verify_data(conn->client_handshake_traffic_secret,
		&conn->dgst_ctx, local_verify_data, &local_verify_data_len) != 1) {
		error_print();
		return -1;
	}
	memset(&conn->dgst_ctx, 0, sizeof(conn->dgst_ctx));

	if (local_verify_data_len != verify_data_len
		|| memcmp(local_verify_data, verify_data, verify_data_len) != 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_decrypt_error);
		return -1;
	}


	// update client_write_key, client_write_iv, reset client_seq_num
	tls13_hkdf_expand_label(conn->digest, conn->client_application_traffic_secret, "key", NULL, 0, 16, client_write_key);
	block_cipher_set_encrypt_key(&conn->client_write_key, conn->cipher, client_write_key);
	tls13_hkdf_expand_label(conn->digest, conn->client_application_traffic_secret, "iv", NULL, 0, 12, conn->client_write_iv);
	tls_seq_num_reset(conn->client_seq_num);

	format_print(stderr, 0, 0, "update client secrets\n");
	format_bytes(stderr, 0, 4, "client_write_key", client_write_key, 16);
	format_bytes(stderr, 0, 4, "client_write_iv", conn->client_write_iv, 12);
	format_print(stderr, 0, 0, "\n");

	return 1;
}

int tls13_send_early_data(TLS_CONNECT *conn)
{
	size_t sentlen;

	tls_trace("send EarlyData\n");

	if (!conn->early_data) {
		error_print();
		return -1;
	}
	if (!conn->early_data_len) {
		error_print();
		return -1;
	}

	while (conn->early_data_offset < conn->early_data_len) {
		int ret;
		if ((ret = tls13_send(conn, conn->early_data_buf + conn->early_data_offset,
			conn->early_data_len - conn->early_data_offset, &sentlen)) <= 0) {
			if (ret == TLS_ERROR_SEND_AGAIN) {
				return ret;
			}
		}
		conn->early_data_offset += sentlen;
	}

	return 1;
}

int tls13_update_client_application_keys(TLS_CONNECT *conn)
{
	uint8_t client_write_key[16];

	tls13_hkdf_expand_label(conn->digest, conn->client_application_traffic_secret, "traffic upd", NULL, 0, 48, conn->client_application_traffic_secret);
	tls13_hkdf_expand_label(conn->digest, conn->client_application_traffic_secret, "key", NULL, 0, 16, client_write_key);
	block_cipher_set_encrypt_key(&conn->client_write_key, conn->cipher, client_write_key);
	tls13_hkdf_expand_label(conn->digest, conn->client_application_traffic_secret, "iv", NULL, 0, 12, conn->client_write_iv);
	tls_seq_num_reset(conn->client_seq_num);

	format_print(stderr, 0, 0, "update client secrets\n");
	format_bytes(stderr, 0, 4, "client application_traffic_secret", conn->client_application_traffic_secret, 48);
	format_bytes(stderr, 0, 4, "client_write_key", client_write_key, 16);
	format_bytes(stderr, 0, 4, "client_write_iv", conn->client_write_iv, 12);
	format_print(stderr, 0, 0, "\n");

	return 1;
}

int tls13_update_server_application_keys(TLS_CONNECT *conn)
{
	uint8_t server_write_key[16];

	tls13_hkdf_expand_label(conn->digest, conn->server_application_traffic_secret, "traffic upd", NULL, 0, 48, conn->server_application_traffic_secret);
	tls13_hkdf_expand_label(conn->digest, conn->server_application_traffic_secret, "key", NULL, 0, 16, server_write_key);
	block_cipher_set_encrypt_key(&conn->server_write_key, conn->cipher, server_write_key);
	tls13_hkdf_expand_label(conn->digest, conn->server_application_traffic_secret, "iv", NULL, 0, 12, conn->server_write_iv);
	tls_seq_num_reset(conn->server_seq_num);

	format_print(stderr, 0, 0, "update server secrets\n");
	format_bytes(stderr, 0, 4, "server_application_traffic_secret", conn->server_application_traffic_secret, 48);
	format_bytes(stderr, 0, 4, "server_write_key", server_write_key, 16);
	format_bytes(stderr, 0, 4, "server_write_iv", conn->server_write_iv, 12);
	format_print(stderr, 0, 0, "\n");

	return 1;
}

// 参数request_update应该根据当前状态设置
int tls13_send_client_key_update(TLS_CONNECT *conn, int request_update)
{
	int ret;

	if (conn->recordlen == 0) {
		size_t padding_len = 0;

		tls_trace("send {KeyUpdate}\n");

		if (tls13_record_set_handshake_key_update(conn->plain_record, &conn->plain_recordlen,
			request_update) != 1) {
			error_print();
			return -1;
		}
		tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

		tls13_padding_len_rand(&padding_len);
		if (tls13_record_encrypt(&conn->client_write_key, conn->client_write_iv,
			conn->client_seq_num, conn->plain_record, conn->plain_recordlen, padding_len,
			conn->record, &conn->recordlen) != 1) {
			error_print();
			return -1;
		}

		tls13_update_client_application_keys(conn);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}
	return 1;
}

int tls13_send_server_key_update(TLS_CONNECT *conn, int request_update)
{
	int ret;

	if (conn->recordlen == 0) {
		size_t padding_len = 0;

		tls_trace("send {KeyUpdate}\n");

		if (tls13_record_set_handshake_key_update(conn->plain_record, &conn->plain_recordlen,
			request_update) != 1) {
			error_print();
			return -1;
		}
		tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

		tls13_padding_len_rand(&padding_len);
		if (tls13_record_encrypt(&conn->server_write_key, conn->server_write_iv,
			conn->server_seq_num, conn->plain_record, conn->plain_recordlen, padding_len,
			conn->record, &conn->recordlen) != 1) {
			error_print();
			return -1;
		}

		tls13_update_server_application_keys(conn);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}
	return 1;
}


/*
Post-Handshake-Auth

	客户端在 ClientHello 中发送post_handshake_auht说明支持PHA

	在握手完成并进行数据通信时，如果客户端请求一个特殊的地址 比如 GET /admin
	默认未认证的客户端不能访问此地址，因此服务器端如果发现客户端支持PHA，那么就会给客户端发送一个CertificateRequest

	客户端不需要立即响应，但是如果客户端响应
	则需要发出连续的 Certificate, CertificateVerify, Finished消息



这意味着如果客户端开始发送Certificate
	服务器就必须再次进入到握手的状态机中
	这意味着SSL再次进入到状态机中


是否意味着每次不论上层调用是read/write，SSL都是按照状态机来处理


*/





















int tls13_do_client_handshake(TLS_CONNECT *conn)
{
	int ret;
	int next_state;


	// 客户端的状态机可能还是有问题的

	switch (conn->state) {
	case TLS_state_hello_retry_request:
	case TLS_state_client_hello_again:
	case TLS_state_server_hello:
	case TLS_state_encrypted_extensions:
		if (conn->early_data && conn->early_data_offset < conn->early_data_len) {
			tls_trace("send EarlyData\n");
			if (tls13_send_early_data(conn) != 1) {
				error_print();
				return -1;
			}
		}
		break;
	}

	switch (conn->state) {
	case TLS_state_client_hello:
		ret = tls13_send_client_hello(conn);
		next_state = TLS_state_hello_retry_request;
		break;

	case TLS_state_hello_retry_request: // optional
		ret = tls13_recv_hello_retry_request(conn);
		if (conn->hello_retry_request)
			next_state = TLS_state_client_hello_again;
		else	next_state = TLS_state_server_hello;
		break;

	case TLS_state_client_hello_again:
		ret = tls13_send_client_hello_again(conn);
		next_state = TLS_state_server_hello;
		break;

	case TLS_state_server_hello:
		ret = tls13_recv_server_hello(conn);
		next_state = TLS_state_encrypted_extensions;
		break;

	case TLS_state_encrypted_extensions:
		ret = tls13_recv_encrypted_extensions(conn);
		next_state = TLS_state_certificate_request;
		break;

	case TLS_state_certificate_request: // optional
		ret = tls13_recv_certificate_request(conn);
		if (conn->key_exchange_modes == TLS_KE_CERT_DHE)
			next_state = TLS_state_server_certificate;
		else	next_state = TLS_state_server_finished;
		break;

	case TLS_state_server_certificate:
		ret = tls13_recv_server_certificate(conn);
		next_state = TLS_state_certificate_verify;
		break;

	case TLS_state_certificate_verify:
		ret = tls13_recv_server_certificate_verify(conn);
		next_state = TLS_state_server_finished;
		break;

	case TLS_state_server_finished:
		ret = tls13_recv_server_finished(conn);
		if (conn->early_data)
			next_state = TLS_state_end_of_early_data;
		else if (conn->client_certificate_verify)
			next_state = TLS_state_client_certificate;
		else	next_state = TLS_state_client_finished;
		break;

	case TLS_state_end_of_early_data:
		ret = tls13_send_end_of_early_data(conn);
		next_state = TLS_state_client_finished;
		break;

	case TLS_state_client_certificate:
		// if client has no (proper) certificate
		// client will send {Certificate} with empty certificate_list
		// but will not send {CertificateVerify}
		ret = tls13_send_client_certificate(conn);
		if (conn->cert_chain)
			next_state = TLS_state_client_certificate_verify;
		else	next_state = TLS_state_client_finished;
		break;

	case TLS_state_client_certificate_verify:
		ret = tls13_send_client_certificate_verify(conn);
		next_state = TLS_state_client_finished;
		break;

	case TLS_state_client_finished:
		ret = tls13_send_client_finished(conn);
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


int tls13_do_server_handshake(TLS_CONNECT *conn)
{
	int ret;
	int next_state;

	switch (conn->state) {
	case TLS_state_client_hello:
		ret = tls13_recv_client_hello(conn);
		if (conn->early_data)
			next_state = TLS_state_early_data;
		else if (conn->hello_retry_request)
			next_state = TLS_state_hello_retry_request;
		else	next_state = TLS_state_server_hello;
		break;

	case TLS_state_early_data:
		ret = tls13_recv_early_data(conn);
		next_state = TLS_state_server_hello;
		break;

	case TLS_state_hello_retry_request:
		ret = tls13_send_hello_retry_request(conn);
		next_state = TLS_state_client_hello_again;
		break;

	case TLS_state_client_hello_again:
		ret = tls13_recv_client_hello_again(conn);
		next_state = TLS_state_server_hello;
		break;

	case TLS_state_server_hello:
		ret = tls13_send_server_hello(conn);
		next_state = TLS_state_encrypted_extensions;
		break;

	case TLS_state_encrypted_extensions:
		ret = tls13_send_encrypted_extensions(conn);
		if (conn->certificate_request)
			next_state = TLS_state_certificate_request;
		else if (conn->key_exchange_modes == TLS_KE_CERT_DHE)
			next_state = TLS_state_server_certificate;
		else	next_state = TLS_state_server_finished;
		break;

	case TLS_state_certificate_request:
		ret = tls13_send_certificate_request(conn);
		if (conn->key_exchange_modes == TLS_KE_CERT_DHE)
			next_state = TLS_state_server_certificate;
		else	next_state = TLS_state_server_finished;
		break;

	case TLS_state_server_certificate:
		ret = tls13_send_server_certificate(conn);
		next_state = TLS_state_certificate_verify;
		break;
	case TLS_state_certificate_verify:
		ret = tls13_send_server_certificate_verify(conn);
		next_state = TLS_state_server_finished;
		break;

	case TLS_state_server_finished:
		ret = tls13_send_server_finished(conn);
		if (conn->early_data)
			next_state = TLS_state_end_of_early_data;
		else if (conn->certificate_request)
			next_state = TLS_state_client_certificate;
		else	next_state = TLS_state_client_finished;
		break;

	case TLS_state_end_of_early_data:
		ret = tls13_recv_end_of_early_data(conn);
		next_state = TLS_state_client_finished;
		break;

	case TLS_state_client_certificate:
		ret = tls13_recv_client_certificate(conn);
		next_state = TLS_state_client_certificate_verify;
		break;

	case TLS_state_client_certificate_verify:
		ret = tls13_recv_client_certificate_verify(conn);
		next_state = TLS_state_client_finished;
		break;

	case TLS_state_client_finished:
		ret = tls13_recv_client_finished(conn);
		if (conn->new_session_ticket)
			next_state = TLS_state_new_session_ticket;
		else	next_state = TLS_state_handshake_over;
		break;

	case TLS_state_new_session_ticket:
		if (conn->new_session_ticket) {
			ret = tls13_send_new_session_ticket(conn);
			next_state = TLS_state_new_session_ticket;
		} else {
			ret = 1;
			next_state = TLS_state_handshake_over;
		}
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

	tls_clean_record(conn);

	return 1;
}

int tls13_client_handshake(TLS_CONNECT *conn)
{
	int ret;

	while (conn->state != TLS_state_handshake_over) {

		ret = tls13_do_client_handshake(conn);

		if (ret != 1) {
			if (ret != TLS_ERROR_RECV_AGAIN && ret != TLS_ERROR_SEND_AGAIN) {
				error_print();
			}
			return ret;
		}


	}


	conn->state = 0;

	// TODO: cleanup conn?

	return 1;
}

int tls13_server_handshake(TLS_CONNECT *conn)
{
	int ret;

	while (conn->state != TLS_state_handshake_over) {

		ret = tls13_do_server_handshake(conn);

		if (ret != 1) {
			if (ret != TLS_ERROR_RECV_AGAIN && ret != TLS_ERROR_SEND_AGAIN) {
				error_print();
			}
			return ret;
		}
	}

	conn->state = 0;

	// TODO: cleanup conn?

	return 1;
}

int tls13_do_connect(TLS_CONNECT *conn)
{
	int ret;
	fd_set rfds;
	fd_set wfds;

	// 应该把protocol_version的初始化放在这里

	conn->state = TLS_state_client_hello;
	sm3_init(&conn->sm3_ctx);

	while (1) {

		ret = tls13_client_handshake(conn);
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

	fprintf(stderr, "tls13_do_connect: connected\n");

	return 1;
}

int tls13_do_accept(TLS_CONNECT *conn)
{
	int ret;
	fd_set rfds;
	fd_set wfds;

	conn->state = TLS_state_client_hello;

	sm3_init(&conn->sm3_ctx);

	fprintf(stderr, "tls13_do_accept\n");


	while (1) {

		ret = tls13_server_handshake(conn);

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

	fprintf(stderr, "tls13_do_accept: connected\n");

	return 1;
}

// 这个函数应该是属于key_share的，不要放在这个函数里面
int tls13_ctx_set_max_key_exchanges(TLS_CTX *ctx, size_t cnt)
{
	size_t key_exchanges_capacity
		= sizeof(((TLS_CONNECT *)0)->key_exchanges)/sizeof(((TLS_CONNECT *)0)->key_exchanges[0]);

	if (!ctx) {
		error_print();
		return -1;
	}
	if (cnt > key_exchanges_capacity) {
		cnt = key_exchanges_capacity;
	}
	ctx->key_exchanges_cnt = cnt;
	return 1;
}

int tls13_enable_post_handshake_auth(TLS_CONNECT *conn)
{
	if (!conn) {
		error_print();
		return -1;
	}
	conn->post_handshake_auth = 1;
	return 1;
}

