/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/gcm.h>
#include <gmssl/hmac.h>
#include <gmssl/hkdf.h>
#include <gmssl/mem.h>

static const int tls13_ciphers[] = { TLS_cipher_sm4_gcm_sm3 };
static size_t tls13_ciphers_count = sizeof(tls13_ciphers)/sizeof(int);

/*
int tls13_record_print(FILE *fp, const uint8_t *record,  size_t recordlen, int format, int indent)
{
	// 目前只支持TLCP的ECC公钥加密套件，因此不论用哪个套件解析都是一样的
	// 如果未来支持ECDHE套件，可以将函数改为宏，直接传入 (conn->cipher_suite << 8)
	format |= tls13_ciphers[0] << 8;
	return tls_record_print(fp, record, recordlen, format, indent);
}
*/

static int tls13_client_hello_exts[] = {
	TLS_extension_supported_versions,
	TLS_extension_padding,
};


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

// 这个函数是不对的，在我们的一些情况下，加密的时候并不会组成完整的数据
int tls13_record_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t iv[12],
	const uint8_t seq_num[8], const uint8_t *record, size_t recordlen, size_t padding_len,
	uint8_t *enced_record, size_t *enced_recordlen)
{
	// 被加密的是握手消息或者是应用层数据

	if (tls13_gcm_encrypt(key, iv,
		seq_num, record[0], record + 5, recordlen - 5, padding_len,
		enced_record + 5, enced_recordlen) != 1) {
		error_print();
		return -1;
	}

	enced_record[0] = TLS_record_application_data; // 显然这个不太对啊
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

int tls13_send(TLS_CONNECT *conn, const uint8_t *data, size_t datalen, size_t *sentlen)
{
	const BLOCK_CIPHER_KEY *key;
	const uint8_t *iv;
	uint8_t *seq_num;
	uint8_t *record = conn->record;
	size_t recordlen;
	size_t padding_len = 0; //FIXME: 在conn中设置是否加随机填充，及设置该值

	tls_trace("send {ApplicationData}\n");

	if (conn->is_client) {
		key = &conn->client_write_key;
		iv = conn->client_write_iv;
		seq_num = conn->client_seq_num;
	} else {
		key = &conn->server_write_key;
		iv = conn->server_write_iv;
		seq_num = conn->server_seq_num;
	}

	if (tls13_gcm_encrypt(key, iv,
		seq_num, TLS_record_application_data, data, datalen, padding_len,
		record + 5, &recordlen) != 1) {
		error_print();
		return -1;
	}

	record[0] = TLS_record_application_data;
	record[1] = TLS_protocol_tls12 >> 8;
	record[2] = TLS_protocol_tls12 & 0xff;
	record[3] = (uint8_t)(recordlen >> 8);
	record[4] = (uint8_t)(recordlen);
	recordlen += 5;

	tls_record_send(record, recordlen, conn->sock);
	tls_record_trace(stderr, record, tls_record_length(record), 0, 0);

	tls_seq_num_incr(seq_num);

	*sentlen = datalen;

	return 1;
}

/*
int tls13_recv(TLS_CONNECT *conn, uint8_t *data, size_t *datalen)
{
	int record_type;
	uint8_t *record = conn->record;
	size_t recordlen;
	const BLOCK_CIPHER_KEY *key;
	const uint8_t *iv;
	uint8_t *seq_num;


	tls_trace("recv {ApplicationData}\n");

	if (conn->is_client) {
		key = &conn->server_write_key;
		iv = conn->server_write_iv;
		seq_num = conn->server_seq_num;
	} else {
		key = &conn->client_write_key;
		iv = conn->client_write_iv;
		seq_num = conn->client_seq_num;
	}

	if (tls_record_recv(record, &recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	if (record[0] != TLS_record_application_data) {
		error_print();
		return -1;
	}

	if (tls13_gcm_decrypt(key, iv,
		seq_num, record + 5, recordlen - 5,
		&record_type, data, datalen) != 1) {
		error_print();
		return -1;
	}

	tls_record_trace(stderr, record, tls_record_length(record), 0, 0);
	tls_seq_num_incr(seq_num);

	if (record_type != TLS_record_application_data) {
		error_print();
		return -1;
	}
	return 1;
}
*/

int tls13_do_recv(TLS_CONNECT *conn)
{
	int ret;
	const BLOCK_CIPHER_KEY *key;
	const uint8_t *iv;
	uint8_t *seq_num;
	uint8_t *record = conn->record;
	size_t recordlen;
	int record_type;

	if (conn->is_client) {
		key = &conn->server_write_key;
		iv = conn->server_write_iv;
		seq_num = conn->server_seq_num;
	} else {
		key = &conn->client_write_key;
		iv = conn->client_write_iv;
		seq_num = conn->client_seq_num;
	}

	tls_trace("recv ApplicationData\n");
	if ((ret = tls_record_recv(record, &recordlen, conn->sock)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	tls_record_trace(stderr, record, recordlen, 0, 0);
	// TODO: 是否需要检查record_type?  record[0] != TLS_record_application_data		

	if (tls13_gcm_decrypt(key, iv,
		seq_num, record + 5, recordlen - 5,
		&record_type, conn->databuf, &conn->datalen) != 1) {
		error_print();
		return -1;
	}
	conn->data = conn->databuf;
	tls_seq_num_incr(seq_num);

	tls_record_set_data(record, conn->data, conn->datalen);
	tls_trace("decrypt ApplicationData\n");
	tls_record_trace(stderr, record, tls_record_length(record), 0, 0);


	if (record_type != TLS_record_application_data) {
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

int tls13_derive_secret(const uint8_t secret[32], const char *label, const DIGEST_CTX *dgst_ctx, uint8_t out[32])
{
	DIGEST_CTX ctx = *dgst_ctx;
	uint8_t dgst[64];
	size_t dgstlen;

	if (digest_finish(&ctx, dgst, &dgstlen) != 1
		|| tls13_hkdf_expand_label(dgst_ctx->digest, secret, label, dgst, 32, dgstlen, out) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static const uint8_t TLS13_client_context_str_and_zero[] = "TLS 1.3, client CertificateVerify";
static const uint8_t TLS13_server_context_str_and_zero[] = "TLS 1.3, server CertificateVerify";
static size_t TLS13_client_context_str_and_zero_size = sizeof(TLS13_client_context_str_and_zero);
static size_t TLS13_server_context_str_and_zero_size = sizeof(TLS13_server_context_str_and_zero);

int tls13_sign_certificate_verify(int tls_mode,
	const SM2_KEY *key, const char *signer_id, size_t signer_id_len,
	const DIGEST_CTX *tbs_dgst_ctx,
	uint8_t *sig, size_t *siglen)
{
	SM2_SIGN_CTX sign_ctx;
	uint8_t prefix[64];
	const uint8_t *context_str_and_zero;
	size_t context_str_and_zero_len;
	DIGEST_CTX dgst_ctx;
	uint8_t dgst[64];
	size_t dgstlen;

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

	dgst_ctx = *tbs_dgst_ctx;
	digest_finish(&dgst_ctx, dgst, &dgstlen);

	sm2_sign_init(&sign_ctx, key, signer_id, signer_id_len);
	sm2_sign_update(&sign_ctx, prefix, 64);
	sm2_sign_update(&sign_ctx, context_str_and_zero, context_str_and_zero_len);
	sm2_sign_update(&sign_ctx, dgst, dgstlen);
	sm2_sign_finish(&sign_ctx, sig, siglen);

	gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
	return 1;
}

int tls13_verify_certificate_verify(int tls_mode,
	const SM2_KEY *public_key, const char *signer_id, size_t signer_id_len,
	const DIGEST_CTX *tbs_dgst_ctx, const uint8_t *sig, size_t siglen)
{
	int ret;
	SM2_SIGN_CTX verify_ctx;
	uint8_t prefix[64];
	const uint8_t *context_str_and_zero;
	size_t context_str_and_zero_len;
	DIGEST_CTX dgst_ctx;
	uint8_t dgst[64];
	size_t dgstlen;

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

	dgst_ctx = *tbs_dgst_ctx;
	digest_finish(&dgst_ctx, dgst, &dgstlen);

	sm2_verify_init(&verify_ctx, public_key, signer_id, signer_id_len);
	sm2_verify_update(&verify_ctx, prefix, 64);
	sm2_verify_update(&verify_ctx, context_str_and_zero, context_str_and_zero_len);
	sm2_verify_update(&verify_ctx, dgst, dgstlen);

	if ((ret = sm2_verify_finish(&verify_ctx, sig, siglen)) < 0) {
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
Handshakes

*/

int tls13_client_hello_exts_set(uint8_t *exts, size_t *extslen, size_t maxlen,
	const SM2_POINT *client_ecdhe_public)
{
	int protocols[] = { TLS_protocol_tls13 };
	int supported_groups[] = { TLS_curve_sm2p256v1 };
	int sig_algs[] = { TLS_sig_sm2sig_sm3 };
	size_t protocols_cnt = sizeof(protocols)/sizeof(int);
	size_t supported_groups_cnt = sizeof(supported_groups)/sizeof(int);
	size_t sig_algs_cnt = sizeof(sig_algs)/sizeof(int);


	if (!exts || !extslen || !client_ecdhe_public) {
		error_print();
		return -1;
	}

	*extslen = 0;
	if (tls13_supported_versions_ext_to_bytes(TLS_client_mode, protocols, protocols_cnt, NULL, extslen) != 1
		|| tls_supported_groups_ext_to_bytes(supported_groups, supported_groups_cnt, NULL, extslen) != 1
		|| tls_signature_algorithms_ext_to_bytes(sig_algs, sig_algs_cnt, NULL, extslen) != 1
		|| tls13_client_key_share_ext_to_bytes(client_ecdhe_public, NULL, extslen) != 1) {
		error_print();
		return -1;
	}
	if (*extslen > maxlen) {
		error_print();
		return -1;
	}
	*extslen = 0;
	tls13_supported_versions_ext_to_bytes(TLS_client_mode, protocols, protocols_cnt, &exts, extslen);
	tls_supported_groups_ext_to_bytes(supported_groups, supported_groups_cnt, &exts, extslen);
	tls_signature_algorithms_ext_to_bytes(sig_algs, sig_algs_cnt, &exts, extslen);
	tls13_client_key_share_ext_to_bytes(client_ecdhe_public, &exts, extslen);
	return 1;
}

int tls13_process_client_hello_exts(const uint8_t *exts, size_t extslen,
	const SM2_KEY *server_ecdhe_key, SM2_POINT *client_ecdhe_public,
	uint8_t *server_exts, size_t *server_exts_len, size_t server_exts_maxlen)
{
	size_t len = 0;
	*server_exts_len = 0;

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
		/*
		// tls13_process_client_hello_exts 的接口需要处理，部分输出要输出到server_exts中			
		case TLS_extension_supported_groups: // 这个应该放在EE里面
			if (tls_process_client_supported_groups(ext_data, ext_datalen, NULL, &len) != 1
				|| len > server_exts_maxlen) {
				error_print();
				return -1;
			}
			tls_process_client_supported_groups(ext_data, ext_datalen, &server_exts, server_exts_len);
			break;
		case TLS_extension_signature_algorithms: // client单方面通知就可以了，服务器不需要响应
			if (tls_process_client_signature_algorithms(ext_data, ext_datalen, NULL, &len) != 1
				|| len > server_exts_maxlen) {
				error_print();
				return -1;
			}
			tls_process_client_signature_algorithms(ext_data, ext_datalen, &server_exts, server_exts_len);
			break;
		*/
		case TLS_extension_supported_versions:
			if (tls13_process_client_supported_versions(ext_data, ext_datalen, NULL, &len) != 1
				|| len > server_exts_maxlen) {
				error_print();
				return -1;
			}
			tls13_process_client_supported_versions(ext_data, ext_datalen, &server_exts, server_exts_len);
			break;
		case TLS_extension_key_share:
			if (tls13_process_client_key_share(ext_data, ext_datalen, server_ecdhe_key, client_ecdhe_public, &server_exts, server_exts_len) != 1
				|| len > server_exts_maxlen) {
				error_print();
				return -1;
			}
			break;

		default:
			; // server ignore unkonwn extensions
		}
	}

	return 1;
}

int tls_client_key_shares_from_bytes(SM2_POINT *sm2_point, const uint8_t **in, size_t *inlen)
{
	const uint8_t *key_shares;
	size_t key_shares_len;

	tls_uint16array_from_bytes(&key_shares, &key_shares_len, in, inlen);

	while (key_shares_len) {
		uint16_t group;
		const uint8_t *key_exch;
		size_t key_exch_len;

		tls_uint16_from_bytes(&group, &key_shares, &key_shares_len);
		tls_uint16array_from_bytes(&key_exch, &key_exch_len, &key_shares, &key_shares_len);

		if (key_exch_len != 65) {
			error_print();
			return -1;
		}

		switch (group) {
		case TLS_curve_sm2p256v1:
			sm2_point_from_octets(sm2_point, key_exch, key_exch_len);
			break;
		default:
			error_print();
			return -1;
		}
	}

	return 1;
}

// 这个函数不是太正确，应该也是一个process
int tls13_server_hello_extensions_get(const uint8_t *exts, size_t extslen, SM2_POINT *sm2_point)
{
	uint16_t version;
	while (extslen) {
		uint16_t ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;

		tls_uint16_from_bytes(&ext_type, &exts, &extslen);
		tls_uint16array_from_bytes(&ext_data, &ext_datalen, &exts, &extslen);

		switch (ext_type) {
		case TLS_extension_supported_versions:
			if (tls_uint16_from_bytes(&version, &ext_data, &ext_datalen) != 1
				|| ext_datalen > 0) {
				error_print();
				return -1;
			}
			if (version != TLS_protocol_tls13) {
				error_print();
				return -1;
			}
			break;
		case TLS_extension_key_share:
			if (tls13_process_server_key_share(ext_data, ext_datalen, sm2_point) != 1) {
				error_print();
				return -1;
			}
			break;
		//default:
			// FIXME: 还有几个扩展没有处理！
			//error_print();
			//return -1;
		}
	}
	return 1;
}


/*
struct {
	Extension extensions<0..2^16-1>;
} EncryptedExtensions;
*/
static int tls13_encrypted_exts[] = {
	TLS_extension_server_name,
	TLS_extension_max_fragment_length,
	TLS_extension_supported_groups,
	TLS_extension_use_srtp,
	TLS_extension_heartbeat,
	TLS_extension_application_layer_protocol_negotiation,
	TLS_extension_client_certificate_type,
	TLS_extension_server_certificate_type,
	TLS_extension_early_data,
};

int tls13_encrypted_extensions_print(FILE *fp, int fmt, int ind, const uint8_t *data, size_t datalen)
{
	const uint8_t *exts;
	size_t extslen;

	format_print(fp, fmt, ind, "EncryptedExtensions\n");
	ind += 4;

	if (tls_uint16array_from_bytes(&exts, &extslen, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	if (exts) {
		tls13_extensions_print(fp, fmt, ind, TLS_handshake_encrypted_extensions, exts, extslen);
	}
	if (tls_length_is_zero(datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_record_set_handshake_encrypted_extensions(uint8_t *record, size_t *recordlen)
{
	int type = TLS_handshake_encrypted_extensions;
	uint8_t *p = record + 5 + 4;
	size_t len = 0;
	uint8_t exts[128];
	size_t extslen = 0;
	uint8_t *pexts = exts;
	const int supported_groups[] = { TLS_curve_sm2p256v1 };

	tls_supported_groups_ext_to_bytes(supported_groups, sizeof(supported_groups)/sizeof(int), &pexts, &extslen);

	tls_uint16array_to_bytes(exts, extslen, &p, &len);
	tls_record_set_handshake(record, recordlen, type, NULL, len);

	return 1;
}

int tls13_record_get_handshake_encrypted_extensions(const uint8_t *record)
{
	int type;
	const uint8_t *p;
	size_t len;
	const uint8_t *exts_data;
	size_t exts_datalen;

	if (tls_record_get_handshake(record, &type, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (tls_uint16array_from_bytes(&exts_data, &exts_datalen, &p, &len) != 1) {
		error_print();
		return -1;
	}
	// 当前实现不需要在EncryptedExtensions提供扩展
	if (exts_datalen) {
		// FIXME: 实际上supported_groups是放在这里的，应该加以处理		
		//error_print();
		//return -1;
	}
	return 1;
}


/*
	ClientHello.Extensions.signature_algorithms 列出客户端支持的签名+哈希算法
	ServerHello.Extensions.supported_groups 决定了服务器的公钥类型，
		因此也决定了服务器的签名算法
	ServerHello.cipher_suite决定了哈希函数
*/

/*
struct {
	SignatureScheme algorithm;
	opaque signature<0..2^16-1>;
} CertificateVerify;

注意：TLS 1.2中只有RAW signature, 也就是没有经过uint16array封装的，这其实不太符合TLS的设计逻辑
*/
int tls13_record_set_handshake_certificate_verify(uint8_t *record, size_t *recordlen,
	int sign_algor, const uint8_t *sig, size_t siglen)
{
	int type = TLS_handshake_certificate_verify;
	uint8_t *p = record + 5 + 4;
	size_t len = 0;

	tls_uint16_to_bytes((uint16_t)sign_algor, &p, &len);
	tls_uint16array_to_bytes(sig, siglen, &p, &len);

	if (tls_record_set_handshake(record, recordlen, type, NULL, len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_record_get_handshake_certificate_verify(const uint8_t *record,
	int *sign_algor, const uint8_t **sig, size_t *siglen)
{
	int type;
	const uint8_t *p;
	size_t len ;
	uint16_t alg;

	if (tls_record_get_handshake(record, &type, &p, &len) != 1
		|| type != TLS_handshake_certificate_verify) {
		error_print();
		return -1;
	}

	tls_uint16_from_bytes(&alg, &p, &len);
	tls_uint16array_from_bytes(sig, siglen, &p, &len);
	*sign_algor = alg;

	return 1;
}


/*
struct {
	opaque certificate_request_context<0..2^8-1>;
	Extension extensions<2..2^16-1>;
} CertificateRequest;

certificate_request_context 用于 Post-handshake Authentication，否则应该长度为0

*/
static int tls13_certificate_request_exts[] = {
	TLS_extension_signature_algorithms, // 必须包含
	TLS_extension_status_request,
	TLS_extension_signed_certificate_timestamp,
	TLS_extension_certificate_authorities,
	TLS_extension_oid_filters,
	TLS_extension_signature_algorithms_cert,
};




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

static const int tls13_handshake_certificate_exts[] = {
	TLS_extension_status_request,
	TLS_extension_signed_certificate_timestamp,
};
/*
enum { X509(0), RawPublicKey(2), (255) } CertificateType;

struct {
	select (certificate_type) {
	case RawPublicKey: opaque ASN1_subjectPublicKeyInfo<1..2^24-1>; -- TLS 1.3可以只传公钥不传证书
	case X509: opaque cert_data<1..2^24-1>;
	};
        Extension extensions<0..2^16-1>;
} CertificateEntry;

struct {
	opaque certificate_request_context<0..2^8-1>; -- 用于客户端证书，服务器证书该域长度为0
	CertificateEntry certificate_list<0..2^24-1>;
} Certificate;

TLS 1.3 Certificate：

	* TLS 1.3 支持发送公钥，可以去掉嵌入式环境的证书传输开销
	* TLS 1.3 的证书链中增加了 certificate_request_context
	  用于客户端发送证书时标识context，服务器端的证书中该域的长度为0
	* 证书链中每个证书都有一个独立的扩展域，TLS 1.2 中的证书相关扩展移至此处

Extensions in client Certificate MUST from ClientHello
Extensions in server Certificate MUST from CertificateRequest
Entensions apply to entire chain SHOULD be in the first CertificateEntry

目前CertificateEntry中的扩展主要用于服务器证书的验证
客户端在ClientHello中可以包含status_request 和 signed_certificate_timestamp
让服务器提供 OCSP 的状态证明和时间戳信息
服务器则在证书消息的每个证书否面附带这两个扩展，提供相关信息

在 RFC 8446 (TLS 1.3) 中还没有涉及客户端证书的具体扩展
但是客户端在提供客户端证书时，应该响应服务器CertificateRequest消息中的扩展

目前GmSSLv3还不支持这两个证书扩展的生成，但是提供解析和显示

Valid extensions for server certificates:
	TLS_extension_status_request (5)
	TLS_extension_signed_certificate_timestamp (18)
*/

int tls13_certificate_print(FILE *fp, int fmt, int ind, const uint8_t *cert, size_t certlen)
{
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "Certificate\n");
	ind += 4;

	if (tls_uint8array_from_bytes(&p, &len, &cert, &certlen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "certificate_request_context", p, len);

	format_print(fp, fmt, ind, "certificate_list\n");
	ind += 4;
	if (tls_uint24array_from_bytes(&p, &len, &cert, &certlen) != 1) {
		error_print();
		return -1;
	}
	while (len) {
		const uint8_t *cert_data;
		size_t cert_data_len;
		const uint8_t *exts;
		size_t extslen;

		if (tls_uint24array_from_bytes(&cert_data, &cert_data_len, &p, &len) != 1
			|| tls_uint16array_from_bytes(&exts, &extslen, &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (!cert_data) {
			error_print();
			return -1;
		}

		format_print(fp, fmt, ind, "CertificateEntry\n");
		x509_cert_print(fp, fmt, ind + 4, "Certificate", cert_data, cert_data_len);
		x509_cert_to_pem(cert_data, cert_data_len, fp);
		tls13_extensions_print(fp, fmt, ind + 4, TLS_handshake_certificate, exts, extslen);
	}
	return 1;
}

int tls13_certificate_request_print(FILE *fp, int fmt, int ind, const uint8_t *certreq, size_t certreqlen)
{
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "CertificateRequest\n");
	ind += 4;

	if (tls_uint8array_from_bytes(&p, &len, &certreq, &certreqlen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "certificate_request_context", p, len);

	if (tls_uint16array_from_bytes(&p, &len, &certreq, &certreqlen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "extensions", p, len);

	if (tls_length_is_zero(certreqlen) != 1) {
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
	format_print(fp, fmt, ind, "algorithm: %s (0x%04x)\n", tls_signature_scheme_name(sig_alg), sig_alg);
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

int tls13_record_set_handshake_certificate(uint8_t *record, size_t *recordlen,
	const uint8_t *request_context, size_t request_context_len,
	const uint8_t *certs, size_t certslen)
{
	int type = TLS_handshake_certificate;
	uint8_t *data;
	size_t datalen;

	if (!record || !recordlen || !certs || !certslen) {
		error_print();
		return -1;
	}

	datalen = 0;
	tls_uint8array_to_bytes(request_context, request_context_len, NULL, &datalen);
	tls13_certificate_list_to_bytes(certs, certslen, NULL, &datalen);
	if (datalen > TLS_MAX_HANDSHAKE_DATA_SIZE) {
		error_print();
		return -1;
	}

	data = tls_handshake_data(tls_record_data(record));
	datalen = 0;
	tls_uint8array_to_bytes(request_context, request_context_len, &data, &datalen);
	tls13_certificate_list_to_bytes(certs, certslen, &data, &datalen);
	tls_record_set_handshake(record, recordlen, type, NULL, datalen);

	return 1;
}

int tls13_record_get_handshake_certificate(const uint8_t *record,
	const uint8_t **cert_request_context, size_t *cert_request_context_len,
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
	if (tls_uint8array_from_bytes(cert_request_context, cert_request_context_len, &p, &len) != 1
		|| tls_uint24array_from_bytes(cert_list, cert_list_len, &p, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	if (*cert_list == NULL) {
		error_print();
		return -1;
	}
	return 1;
}



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
	if (!record || !recordlen || !verify_data) {
		error_print();
		return -1;
	}
	tls_record_set_handshake(record, recordlen, type, verify_data, verify_data_len);
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
		error_print();
		return -1;
	}
	if (*verify_data_len != SM3_DIGEST_SIZE
		&& *verify_data_len != SHA384_DIGEST_SIZE) {
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



int tls13_cipher_suite_get(int cipher_suite, const DIGEST **digest, const BLOCK_CIPHER **cipher)
{
	switch (cipher_suite) {
	case TLS_cipher_sm4_gcm_sm3:
		*digest = DIGEST_sm3();
		*cipher = BLOCK_CIPHER_sm4();
		break;
	case TLS_cipher_aes_128_gcm_sha256:
		*digest = DIGEST_sha256();
		*cipher = BLOCK_CIPHER_aes128();
		break;
	default:
		error_print();
		return -1;
	}
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


TLS 1.3的区别：

 * 首先在最开始的握手阶段就协商好了密钥，因此握手之后传输的就是加密消息了
 * 因此在第二阶段，双方不再发送ServerKeyExchange和ClientKeyExchange
 * 服务器先发送CertificateRequest，再发送Certificate
 * 没有ChangeCipherSpec了
 * 在握手阶段就需要加密，并且Certificate也在其中，因此需要格外的大的密文数据缓冲

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



int tls13_do_connect(TLS_CONNECT *conn)
{
	int ret = -1;
	uint8_t *record = conn->record;
	uint8_t *enced_record = conn->enced_record;
	size_t recordlen;

	size_t enced_recordlen;


	int type;
	const uint8_t *data;
	size_t datalen;

	int protocol;
	uint8_t client_random[32];
	uint8_t server_random[32];
	int cipher_suite;
	const uint8_t *random;
	const uint8_t *session_id;
	size_t session_id_len;

	int protocols[] = { TLS_protocol_tls13 };
	int supported_groups[] = { TLS_curve_sm2p256v1 };
	int sign_algors[] = { TLS_sig_sm2sig_sm3 };

	uint8_t client_exts[TLS_MAX_EXTENSIONS_SIZE];
	size_t client_exts_len;
	const uint8_t *server_exts;
	size_t server_exts_len;

	uint8_t sig[TLS_MAX_SIGNATURE_SIZE];
	size_t siglen = sizeof(sig);
	uint8_t verify_data[32];
	size_t verify_data_len;

	int server_sign_algor;
	const uint8_t *server_sig;
	size_t server_siglen;
	const uint8_t *server_verify_data;
	size_t server_verify_data_len;

	SM2_KEY client_ecdhe;
	SM2_POINT server_ecdhe_public;
	SM2_KEY server_sign_key;

	const DIGEST *digest = DIGEST_sm3();
	DIGEST_CTX dgst_ctx; // secret generation过程中需要ClientHello等数据输入的
	DIGEST_CTX null_dgst_ctx; // secret generation过程中不需要握手数据的
	const BLOCK_CIPHER *cipher = NULL;
	size_t padding_len;

	uint8_t zeros[32] = {0};
	uint8_t psk[32] = {0};
	uint8_t early_secret[32];
	uint8_t handshake_secret[32];
	uint8_t master_secret[32];
	uint8_t client_handshake_traffic_secret[32];
	uint8_t server_handshake_traffic_secret[32];
	uint8_t client_application_traffic_secret[32];
	uint8_t server_application_traffic_secret[32];
	uint8_t client_write_key[16];
	uint8_t server_write_key[16];


	const uint8_t *request_context;
	size_t request_context_len;
	const uint8_t *cert_request_exts;
	size_t cert_request_extslen;
	const uint8_t *cert_list;
	size_t cert_list_len;
	const uint8_t *cert;
	size_t certlen;


	conn->is_client = 1;
	tls_record_set_protocol(enced_record, TLS_protocol_tls12);

	digest_init(&dgst_ctx, digest);
	null_dgst_ctx = dgst_ctx;


	// send ClientHello
	tls_trace("send ClientHello\n");
	tls_record_set_protocol(record, TLS_protocol_tls1);
	rand_bytes(client_random, 32); // TLS 1.3 Random 不再包含 UNIX Time
	sm2_key_generate(&client_ecdhe);
	tls13_client_hello_exts_set(client_exts, &client_exts_len, sizeof(client_exts), &(client_ecdhe.public_key));
	tls_record_set_handshake_client_hello(record, &recordlen,
		TLS_protocol_tls12, client_random, NULL, 0,
		tls13_ciphers, sizeof(tls13_ciphers)/sizeof(tls13_ciphers[0]),
		client_exts, client_exts_len);
	tls13_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}
	// 此时尚未确定digest算法，因此无法digest_update


	// recv ServerHello
	tls_trace("recv ServerHello\n");
	if (tls_record_recv(enced_record, &enced_recordlen, conn->sock) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	tls13_record_trace(stderr, enced_record, enced_recordlen, 0, 0);
	if (tls_record_get_handshake_server_hello(enced_record,
		&protocol, &random, &session_id, &session_id_len,
		&cipher_suite, &server_exts, &server_exts_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	if (protocol != TLS_protocol_tls12) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		goto end;
	}
	memcpy(server_random, random, 32);
	memcpy(conn->session_id, session_id, session_id_len);
	conn->session_id_len = session_id_len;
	if (tls_cipher_suite_in_list(cipher_suite,
		tls13_ciphers, sizeof(tls13_ciphers)/sizeof(tls13_ciphers[0])) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_handshake_failure);
		goto end;
	}
	conn->cipher_suite = cipher_suite;
	if (tls13_server_hello_extensions_get(server_exts, server_exts_len, &server_ecdhe_public) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_handshake_failure);
		goto end;
	}
	conn->protocol = TLS_protocol_tls13;

	tls13_cipher_suite_get(conn->cipher_suite, &digest, &cipher);
	digest_update(&dgst_ctx, record + 5, recordlen - 5);
	digest_update(&dgst_ctx, enced_record + 5, enced_recordlen - 5);


	printf("generate handshake secrets\n");
	/*
	generate handshake keys
		uint8_t client_write_key[32]
		uint8_t server_write_key[32]
		uint8_t client_write_iv[12]
		uint8_t server_write_iv[12]
	*/
	sm2_do_ecdh(&client_ecdhe, &server_ecdhe_public, &server_ecdhe_public);
	/* [1]  */ tls13_hkdf_extract(digest, zeros, psk, early_secret);
	/* [5]  */ tls13_derive_secret(early_secret, "derived", &null_dgst_ctx, handshake_secret);
	/* [6]  */ tls13_hkdf_extract(digest, handshake_secret, (uint8_t *)&server_ecdhe_public, handshake_secret);
	/* [7]  */ tls13_derive_secret(handshake_secret, "c hs traffic", &dgst_ctx, client_handshake_traffic_secret);
	/* [8]  */ tls13_derive_secret(handshake_secret, "s hs traffic", &dgst_ctx, server_handshake_traffic_secret);
	/* [9]  */ tls13_derive_secret(handshake_secret, "derived", &null_dgst_ctx, master_secret);
	/* [10] */ tls13_hkdf_extract(digest, master_secret, zeros, master_secret);
	//[sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
	//[sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)
	//[sender] in {server, client}
	tls13_hkdf_expand_label(digest, server_handshake_traffic_secret, "key", NULL, 0, 16, server_write_key);
	tls13_hkdf_expand_label(digest, server_handshake_traffic_secret, "iv", NULL, 0, 12, conn->server_write_iv);
	block_cipher_set_encrypt_key(&conn->server_write_key, cipher, server_write_key);
	memset(conn->server_seq_num, 0, 8);
	tls13_hkdf_expand_label(digest, client_handshake_traffic_secret, "key", NULL, 0, 16, client_write_key);
	tls13_hkdf_expand_label(digest, client_handshake_traffic_secret, "iv", NULL, 0, 12, conn->client_write_iv);
	block_cipher_set_encrypt_key(&conn->client_write_key, cipher, client_write_key);
	memset(conn->client_seq_num, 0, 8);
	/*
	format_bytes(stderr, 0, 4, "client_write_key", client_write_key, 16);
	format_bytes(stderr, 0, 4, "server_write_key", server_write_key, 16);
	format_bytes(stderr, 0, 4, "client_write_iv", conn->client_write_iv, 12);
	format_bytes(stderr, 0, 4, "server_write_iv", conn->server_write_iv, 12);
	format_print(stderr, 0, 0, "\n");
	*/

	// recv {EncryptedExtensions}
	printf("recv {EncryptedExtensions}\n");
	if (tls_record_recv(enced_record, &enced_recordlen, conn->sock) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_handshake_failure);
		goto end;
	}
	if (tls13_record_decrypt(&conn->server_write_key, conn->server_write_iv,
		conn->server_seq_num, enced_record, enced_recordlen,
		record, &recordlen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		goto end;
	}
	tls13_record_trace(stderr, record, recordlen, 0, 0);
	if (tls13_record_get_handshake_encrypted_extensions(record) != 1) {
		tls_send_alert(conn, TLS_alert_handshake_failure);
		error_print();
		goto end;
	}
	digest_update(&dgst_ctx, record + 5, recordlen - 5);
	tls_seq_num_incr(conn->server_seq_num);


	// recv {CertififcateRequest*} or {Certificate}
	if (tls_record_recv(enced_record, &enced_recordlen, conn->sock) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_handshake_failure);
		goto end;
	}
	if (tls13_record_decrypt(&conn->server_write_key, conn->server_write_iv,
		conn->server_seq_num, enced_record, enced_recordlen,
		record, &recordlen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		goto end;
	}
	if (tls_record_get_handshake(record, &type, &data, &datalen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_handshake_failure);
		goto end;
	}
	if (type == TLS_handshake_certificate_request) {
		tls_trace("recv {CertificateRequest*}\n");
		tls13_record_trace(stderr, record, recordlen, 0, 0);
		if (tls13_record_get_handshake_certificate_request(record,
			&request_context, &request_context_len,
			&cert_request_exts, &cert_request_extslen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_handshake_failure);
			goto end;
		}
		// 当前忽略 request_context 和 cert_request_exts
		// request_context 应该为空，当前实现中不支持Post-Handshake Auth
		digest_update(&dgst_ctx, record + 5, recordlen - 5);
		tls_seq_num_incr(conn->server_seq_num);


		// recv {Certificate}
		if (tls_record_recv(enced_record, &enced_recordlen, conn->sock) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_handshake_failure);
			goto end;
		}
		if (tls13_record_decrypt(&conn->server_write_key, conn->server_write_iv,
			conn->server_seq_num, enced_record, enced_recordlen,
			record, &recordlen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_record_mac);
			goto end;
		}
	} else {
		conn->client_certs_len = 0;
		// 清空客户端签名密钥
	}

	// recv {Certificate}
	tls_trace("recv {Certificate}\n");
	tls13_record_trace(stderr, record, recordlen, 0, 0);
	if (tls13_record_get_handshake_certificate(record,
		&request_context, &request_context_len,
		&cert_list, &cert_list_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	if (tls13_process_certificate_list(cert_list, cert_list_len, conn->server_certs, &conn->server_certs_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	if (x509_certs_get_cert_by_index(conn->server_certs, conn->server_certs_len, 0, &cert, &certlen) != 1
		|| x509_cert_get_subject_public_key(cert, certlen, &server_sign_key) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	digest_update(&dgst_ctx, record + 5, recordlen - 5);
	tls_seq_num_incr(conn->server_seq_num);

	// verify ServerCertificate
	int verify_result = 0; // TODO: maybe remove this arg from x509_certs_verify()
	if (x509_certs_verify(conn->server_certs, conn->server_certs_len, X509_cert_chain_server,
		conn->ca_certs, conn->ca_certs_len, X509_MAX_VERIFY_DEPTH, &verify_result) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		goto end;
	}

	// recv {CertificateVerify}
	tls_trace("recv {CertificateVerify}\n");
	if (tls_record_recv(enced_record, &enced_recordlen, conn->sock) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	if (tls13_record_decrypt(&conn->server_write_key, conn->server_write_iv,
		conn->server_seq_num, enced_record, enced_recordlen,
		record, &recordlen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		goto end;
	}
	tls13_record_trace(stderr, record, recordlen, 0, 0);
	if (tls13_record_get_handshake_certificate_verify(record,
		&server_sign_algor, &server_sig, &server_siglen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	if (server_sign_algor != TLS_sig_sm2sig_sm3) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	if (tls13_verify_certificate_verify(TLS_server_mode, &server_sign_key, TLS13_SM2_ID, TLS13_SM2_ID_LENGTH, &dgst_ctx, server_sig, server_siglen) != 1) {
		error_print();
		goto end;
	}
	digest_update(&dgst_ctx, record + 5, recordlen - 5);
	tls_seq_num_incr(conn->server_seq_num);


	// use Transcript-Hash(Handshake Context, Certificate*, CertificateVerify*)
	tls13_compute_verify_data(server_handshake_traffic_secret,
		&dgst_ctx, verify_data, &verify_data_len);


	// recv {Finished}
	tls_trace("recv {Finished}\n");
	if (tls_record_recv(enced_record, &enced_recordlen, conn->sock) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	if (tls13_record_decrypt(&conn->server_write_key, conn->server_write_iv,
		conn->server_seq_num, enced_record, enced_recordlen,
		record, &recordlen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		goto end;
	}
	tls13_record_trace(stderr, record, recordlen, 0, 0);
	if (tls13_record_get_handshake_finished(record,
		&server_verify_data, &server_verify_data_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	if (server_verify_data_len != verify_data_len
		|| memcmp(server_verify_data, verify_data, verify_data_len) != 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	digest_update(&dgst_ctx, record + 5, recordlen - 5);
	tls_seq_num_incr(conn->server_seq_num);


	// generate server_application_traffic_secret
	/* [12] */ tls13_derive_secret(master_secret, "s ap traffic", &dgst_ctx, server_application_traffic_secret);
	// generate client_application_traffic_secret
	/* [11] */ tls13_derive_secret(master_secret, "c ap traffic", &dgst_ctx, client_application_traffic_secret);


	if (conn->client_certs_len) {
		int client_sign_algor;
		uint8_t sig[TLS_MAX_SIGNATURE_SIZE];
		size_t siglen;

		// send client {Certificate*}
		tls_trace("send {Certificate*}\n");
		if (tls13_record_set_handshake_certificate(record, &recordlen,
			NULL, 0, // certificate_request_context
			conn->client_certs, conn->client_certs_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			goto end;
		}
		tls13_record_trace(stderr, record, recordlen, 0, 0);
		tls13_padding_len_rand(&padding_len);
		if (tls13_record_encrypt(&conn->client_write_key, conn->client_write_iv,
			conn->client_seq_num, record, recordlen, padding_len,
			enced_record, &enced_recordlen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			goto end;
		}
		if (tls_record_send(enced_record, enced_recordlen, conn->sock) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			goto end;
		}
		digest_update(&dgst_ctx, record + 5, recordlen - 5);
		tls_seq_num_incr(conn->client_seq_num);


		// send {CertificateVerify*}
		tls_trace("send {CertificateVerify*}\n");
		client_sign_algor = TLS_sig_sm2sig_sm3; // FIXME: 应该放在conn里面
		tls13_sign_certificate_verify(TLS_client_mode, &conn->sign_key, TLS13_SM2_ID, TLS13_SM2_ID_LENGTH, &dgst_ctx, sig, &siglen);
		if (tls13_record_set_handshake_certificate_verify(record, &recordlen,
			client_sign_algor, sig, siglen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			goto end;
		}
		tls13_record_trace(stderr, record, recordlen, 0, 0);
		tls13_padding_len_rand(&padding_len);
		if (tls13_record_encrypt(&conn->client_write_key, conn->client_write_iv,
			conn->client_seq_num, record, recordlen, padding_len,
			enced_record, &enced_recordlen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			goto end;
		}
		if (tls_record_send(enced_record, enced_recordlen, conn->sock) != 1) {
			error_print();
			goto end;
		}
		digest_update(&dgst_ctx, record + 5, recordlen - 5);
		tls_seq_num_incr(conn->client_seq_num);
	}

	// send Client {Finished}
	tls_trace("send {Finished}\n");
	tls13_compute_verify_data(client_handshake_traffic_secret, &dgst_ctx, verify_data, &verify_data_len);
	if (tls_record_set_handshake_finished(record, &recordlen, verify_data, verify_data_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	tls13_record_trace(stderr, record, recordlen, 0, 0);
	tls13_padding_len_rand(&padding_len);
	if (tls13_record_encrypt(&conn->client_write_key, conn->client_write_iv,
		conn->client_seq_num, record, recordlen, padding_len,
		enced_record, &enced_recordlen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	if (tls_record_send(enced_record, enced_recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}
	digest_update(&dgst_ctx, record + 5, recordlen - 5);
	tls_seq_num_incr(conn->client_seq_num);



	// update server_write_key, server_write_iv, reset server_seq_num
	tls13_hkdf_expand_label(digest, server_application_traffic_secret, "key", NULL, 0, 16, server_write_key);
	block_cipher_set_encrypt_key(&conn->server_write_key, cipher, server_write_key);
	tls13_hkdf_expand_label(digest, server_application_traffic_secret, "iv", NULL, 0, 12, conn->server_write_iv);
	memset(conn->server_seq_num, 0, 8);
	/*
	format_print(stderr, 0, 0, "update server secrets\n");
	format_bytes(stderr, 0, 4, "server_write_key", server_write_key, 16);
	format_bytes(stderr, 0, 4, "server_write_iv", conn->server_write_iv, 12);
	format_print(stderr, 0, 0, "\n");
	*/

	//update client_write_key, client_write_iv, reset client_seq_num
	tls13_hkdf_expand_label(digest, client_application_traffic_secret, "key", NULL, 0, 16, client_write_key);
	tls13_hkdf_expand_label(digest, client_application_traffic_secret, "iv", NULL, 0, 12, conn->client_write_iv);
	block_cipher_set_encrypt_key(&conn->client_write_key, cipher, client_write_key);
	memset(conn->client_seq_num, 0, 8);

	/*
	format_print(stderr, 0, 0, "update client secrets\n");
	format_bytes(stderr, 0, 4, "client_write_key", client_write_key, 16);
	format_bytes(stderr, 0, 4, "client_write_iv", conn->client_write_iv, 12);
	format_print(stderr, 0, 0, "\n");
	*/
	fprintf(stderr, "Connection established\n");
	ret = 1;

end:
	gmssl_secure_clear(&client_ecdhe, sizeof(client_ecdhe));
	gmssl_secure_clear(&server_sign_key, sizeof(server_sign_key));
	gmssl_secure_clear(psk, sizeof(psk));
	gmssl_secure_clear(early_secret, sizeof(early_secret));
	gmssl_secure_clear(handshake_secret, sizeof(handshake_secret));
	gmssl_secure_clear(master_secret, sizeof(master_secret));
	gmssl_secure_clear(client_handshake_traffic_secret, sizeof(client_handshake_traffic_secret));
	gmssl_secure_clear(server_handshake_traffic_secret, sizeof(server_handshake_traffic_secret));
	gmssl_secure_clear(client_application_traffic_secret, sizeof(client_application_traffic_secret));
	gmssl_secure_clear(server_application_traffic_secret, sizeof(server_application_traffic_secret));
	gmssl_secure_clear(client_write_key, sizeof(client_write_key));
	gmssl_secure_clear(server_write_key, sizeof(server_write_key));
	return ret;
}

int tls13_do_accept(TLS_CONNECT *conn)
{
	int ret = -1;
	uint8_t *record = conn->record;
	size_t recordlen;
	uint8_t enced_record[25600];
	size_t enced_recordlen = sizeof(enced_record);

	int server_ciphers[] = { TLS_cipher_sm4_gcm_sm3 };


	int protocol;
	const uint8_t *random;
	const uint8_t *session_id;
	size_t session_id_len;
	const uint8_t *client_exts;
	size_t client_exts_len;

	uint8_t client_random[32];
	uint8_t server_random[32];
	const uint8_t *client_ciphers;
	size_t client_ciphers_len;
	uint8_t server_exts[TLS_MAX_EXTENSIONS_SIZE];
	size_t server_exts_len;

	SM2_KEY server_ecdhe;
	SM2_POINT client_ecdhe_public;
	SM2_KEY client_sign_key;
	const BLOCK_CIPHER *cipher;
	const DIGEST *digest;
	DIGEST_CTX dgst_ctx;
	DIGEST_CTX null_dgst_ctx;
	size_t padding_len;


	uint8_t sig[TLS_MAX_SIGNATURE_SIZE];
	size_t siglen = sizeof(sig);

	uint8_t verify_data[32];
	size_t verify_data_len;

	const uint8_t *client_verify_data;
	size_t client_verify_data_len;

	uint8_t client_write_key[16];
	uint8_t server_write_key[16];

	uint8_t zeros[32] = {0};
	uint8_t psk[32] = {0};
	uint8_t early_secret[32];
	uint8_t handshake_secret[32];
	uint8_t client_handshake_traffic_secret[32];
	uint8_t server_handshake_traffic_secret[32];
	uint8_t client_application_traffic_secret[32];
	uint8_t server_application_traffic_secret[32];
	uint8_t master_secret[32];

	const uint8_t *request_context;
	size_t request_context_len;
	const uint8_t *cert_list;
	size_t cert_list_len;
	const uint8_t *cert;
	size_t certlen;


	int client_verify = 0;
	if (conn->ca_certs_len)
		client_verify = 1;


	// 1. Recv ClientHello
	tls_trace("recv ClientHello\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	tls13_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_get_handshake_client_hello(record,
		&protocol, &random,
		&session_id, &session_id_len, // 不支持SessionID，不做任何处理
		&client_ciphers, &client_ciphers_len,
		&client_exts, &client_exts_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	if (protocol != TLS_protocol_tls12) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		goto end;
	}
	memcpy(client_random, random, 32);
	if (tls_cipher_suites_select(client_ciphers, client_ciphers_len,
		server_ciphers, sizeof(server_ciphers)/sizeof(int),
		&conn->cipher_suite) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_insufficient_security);
		goto end;
	}
	if (!client_exts) {
		error_print();
		goto end;
	}
	tls13_cipher_suite_get(conn->cipher_suite, &digest, &cipher); // 这个函数是否应该放到tls_里面？
	digest_init(&dgst_ctx, digest);
	null_dgst_ctx = dgst_ctx; // 在密钥导出函数中可能输入的消息为空，因此需要一个空的dgst_ctx，这里不对了，应该在tls13_derive_secret里面直接支持NULL！
	digest_update(&dgst_ctx, record + 5, recordlen - 5);


	// 2. Send ServerHello
	tls_trace("send ServerHello\n");
	rand_bytes(server_random, 32);
	sm2_key_generate(&server_ecdhe);
	if (tls13_process_client_hello_exts(client_exts, client_exts_len,
		&server_ecdhe, &client_ecdhe_public,
		server_exts, &server_exts_len, sizeof(server_exts)) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	tls_record_set_protocol(record, TLS_protocol_tls12);
	if (tls_record_set_handshake_server_hello(record, &recordlen,
		TLS_protocol_tls12, server_random,
		NULL, 0, // openssl的兼容模式在ClientHello中发送SessionID并检查在ServerHello是否返回，用`-no_middlebox`可关闭兼容模式
		conn->cipher_suite, server_exts, server_exts_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	tls13_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}
	digest_update(&dgst_ctx, record + 5, recordlen - 5);


	sm2_do_ecdh(&server_ecdhe, &client_ecdhe_public, &client_ecdhe_public);
	/* 1  */ tls13_hkdf_extract(digest, zeros, psk, early_secret);
	/* 5  */ tls13_derive_secret(early_secret, "derived", &null_dgst_ctx, handshake_secret);
	/* 6  */ tls13_hkdf_extract(digest, handshake_secret, (uint8_t *)&client_ecdhe_public, handshake_secret);
	/* 7  */ tls13_derive_secret(handshake_secret, "c hs traffic", &dgst_ctx, client_handshake_traffic_secret);
	/* 8  */ tls13_derive_secret(handshake_secret, "s hs traffic", &dgst_ctx, server_handshake_traffic_secret);
	/* 9  */ tls13_derive_secret(handshake_secret, "derived", &null_dgst_ctx, master_secret);
	/* 10 */ tls13_hkdf_extract(digest, master_secret, zeros, master_secret);
	// generate server_write_key, server_write_iv, reset server_seq_num
	tls13_hkdf_expand_label(digest, server_handshake_traffic_secret, "key", NULL, 0, 16, server_write_key);
	block_cipher_set_encrypt_key(&conn->server_write_key, cipher, server_write_key);
	tls13_hkdf_expand_label(digest, server_handshake_traffic_secret, "iv", NULL, 0, 12, conn->server_write_iv);
	memset(conn->server_seq_num, 0, 8);
	// generate client_write_key, client_write_iv, reset client_seq_num
	tls13_hkdf_expand_label(digest, client_handshake_traffic_secret, "key", NULL, 0, 16, client_write_key);
	block_cipher_set_encrypt_key(&conn->client_write_key, cipher, client_write_key);
	tls13_hkdf_expand_label(digest, client_handshake_traffic_secret, "iv", NULL, 0, 12, conn->client_write_iv);
	memset(conn->client_seq_num, 0, 8);
	/*
	format_print(stderr, 0, 0, "generate handshake secrets\n");
	format_bytes(stderr, 0, 4, "server_write_key", server_write_key, 16);
	format_bytes(stderr, 0, 4, "server_write_iv", conn->server_write_iv, 12);
	format_bytes(stderr, 0, 4, "client_write_key", client_write_key, 16);
	format_bytes(stderr, 0, 4, "client_write_iv", conn->client_write_iv, 12);
	format_print(stderr, 0, 0, "\n");
	*/

	// 3. Send {EncryptedExtensions}
	tls_trace("send {EncryptedExtensions}\n");
	tls_record_set_protocol(record, TLS_protocol_tls12);
	tls13_record_set_handshake_encrypted_extensions(record, &recordlen);
	tls13_record_trace(stderr, record, recordlen, 0, 0);
	tls13_padding_len_rand(&padding_len);
	if (tls13_record_encrypt(&conn->server_write_key, conn->server_write_iv,
		conn->server_seq_num, record, recordlen, padding_len,
		enced_record, &enced_recordlen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	// FIXME: tls13_record_encrypt需要支持握手消息
	// tls_record_data(enced_record)[0] = TLS_handshake_encrypted_extensions;
	if (tls_record_send(enced_record, enced_recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}
	digest_update(&dgst_ctx, record + 5, recordlen - 5);
	tls_seq_num_incr(conn->server_seq_num);


	// send {CertificateRequest*}
	if (client_verify) {
		tls_trace("send {CertificateRequest*}\n");

		// TODO: 设置certificate_request中的extensions!
		if (tls13_record_set_handshake_certificate_request_default(record, &recordlen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			goto end;
		}
		tls13_record_trace(stderr, record, recordlen, 0, 0);
		tls13_padding_len_rand(&padding_len);
		if (tls13_record_encrypt(&conn->server_write_key, conn->server_write_iv,
			conn->server_seq_num, record, recordlen, padding_len,
			enced_record, &enced_recordlen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			goto end;
		}
		if (tls_record_send(enced_record, enced_recordlen, conn->sock) != 1) {
			error_print();
			goto end;
		}
		digest_update(&dgst_ctx, record + 5, recordlen - 5);
		tls_seq_num_incr(conn->server_seq_num);
	}

	// send Server {Certificate}
	tls_trace("send {Certificate}\n");
	if (tls13_record_set_handshake_certificate(record, &recordlen, NULL, 0, conn->server_certs, conn->server_certs_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	tls13_record_trace(stderr, record, recordlen, 0, 0);
	tls13_padding_len_rand(&padding_len);
	if (tls13_record_encrypt(&conn->server_write_key, conn->server_write_iv,
		conn->server_seq_num, record, recordlen, padding_len,
		enced_record, &enced_recordlen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	if (tls_record_send(enced_record, enced_recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}
	digest_update(&dgst_ctx, record + 5, recordlen - 5);
	tls_seq_num_incr(conn->server_seq_num);


	// send Server {CertificateVerify}
	tls_trace("send {CertificateVerify}\n");
	tls13_sign_certificate_verify(TLS_server_mode, &conn->sign_key, TLS13_SM2_ID, TLS13_SM2_ID_LENGTH, &dgst_ctx, sig, &siglen);
	if (tls13_record_set_handshake_certificate_verify(record, &recordlen,
		TLS_sig_sm2sig_sm3, sig, siglen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	tls13_record_trace(stderr, record, recordlen, 0, 0);
	tls13_padding_len_rand(&padding_len);
	if (tls13_record_encrypt(&conn->server_write_key, conn->server_write_iv,
		conn->server_seq_num, record, recordlen, padding_len,
		enced_record, &enced_recordlen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	if (tls_record_send(enced_record, enced_recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}
	digest_update(&dgst_ctx, record + 5, recordlen - 5);
	tls_seq_num_incr(conn->server_seq_num);


	// Send Server {Finished}
	tls_trace("send {Finished}\n");

	// compute server verify_data before digest_update()
	tls13_compute_verify_data(server_handshake_traffic_secret,
		&dgst_ctx, verify_data, &verify_data_len);
	if (tls13_record_set_handshake_finished(record, &recordlen, verify_data, verify_data_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	tls13_record_trace(stderr, record, recordlen, 0, 0);
	tls13_padding_len_rand(&padding_len);
	if (tls13_record_encrypt(&conn->server_write_key, conn->server_write_iv,
		conn->server_seq_num, record, recordlen, padding_len,
		enced_record, &enced_recordlen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	if (tls_record_send(enced_record, enced_recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}
	digest_update(&dgst_ctx, record + 5, recordlen - 5);
	tls_seq_num_incr(conn->server_seq_num);

	// generate server_application_traffic_secret
	/* 12 */ tls13_derive_secret(master_secret, "s ap traffic", &dgst_ctx, server_application_traffic_secret);
	// Generate client_application_traffic_secret
	/* 11 */ tls13_derive_secret(master_secret, "c ap traffic", &dgst_ctx, client_application_traffic_secret);
	// 因为后面还要解密握手消息，因此client application key, iv 等到握手结束之后再更新

	// Recv Client {Certificate*}
	if (client_verify) {
		tls_trace("recv {Certificate*}\n");
		if (tls_record_recv(enced_record, &enced_recordlen, conn->sock) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_unexpected_message);
			goto end;
		}
		if (tls13_record_decrypt(&conn->client_write_key, conn->client_write_iv,
			conn->client_seq_num, enced_record, enced_recordlen,
			record, &recordlen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_record_mac);
			goto end;
		}
		tls13_record_trace(stderr, record, recordlen, 0, 0);

		if (tls13_record_get_handshake_certificate(record,
			&request_context, &request_context_len,
			&cert_list, &cert_list_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_unexpected_message);
			goto end;
		}
		if (tls13_process_certificate_list(cert_list, cert_list_len, conn->client_certs, &conn->client_certs_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_unexpected_message);
			goto end;
		}
		if (x509_certs_get_cert_by_index(conn->client_certs, conn->client_certs_len, 0, &cert, &certlen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_unexpected_message);
			goto end;
		}
		if (x509_cert_get_subject_public_key(cert, certlen, &client_sign_key) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_unexpected_message);
			goto end;
		}
		digest_update(&dgst_ctx, record + 5, recordlen - 5);
		tls_seq_num_incr(conn->client_seq_num);

		// verify client Certificate
		int verify_result;
		if (x509_certs_verify(conn->client_certs, conn->client_certs_len, X509_cert_chain_client,
			conn->ca_certs, conn->ca_certs_len, X509_MAX_VERIFY_DEPTH, &verify_result) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_certificate);
			goto end;
		}
	}

	// Recv client {CertificateVerify*}
	if (client_verify) {
		int client_sign_algor;
		const uint8_t *client_sig;
		size_t client_siglen;

		tls_trace("recv Client {CertificateVerify*}\n");
		if (tls_record_recv(enced_record, &enced_recordlen, conn->sock) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_unexpected_message);
			goto end;
		}
		if (tls13_record_decrypt(&conn->client_write_key, conn->client_write_iv,
			conn->client_seq_num, enced_record, enced_recordlen, record, &recordlen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_record_mac);
			goto end;
		}
		tls13_record_trace(stderr, record, recordlen, 0, 0);

		if (tls13_record_get_handshake_certificate_verify(record, &client_sign_algor, &client_sig, &client_siglen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_unexpected_message);
			goto end;
		}
		if (tls13_verify_certificate_verify(TLS_client_mode, &client_sign_key, TLS13_SM2_ID, TLS13_SM2_ID_LENGTH, &dgst_ctx, client_sig, client_siglen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_decrypt_error);
			goto end;
		}
		digest_update(&dgst_ctx, record + 5, recordlen - 5);
		tls_seq_num_incr(conn->client_seq_num);
	}

	// 12. Recv Client {Finished}

	tls_trace("recv {Finished}\n");
	if (tls_record_recv(enced_record, &enced_recordlen, conn->sock) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	if (tls13_record_decrypt(&conn->client_write_key, conn->client_write_iv,
		conn->client_seq_num, enced_record, enced_recordlen,
		record, &recordlen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		goto end;
	}
	tls13_record_trace(stderr, record, recordlen, 0, 0);
	if (tls13_record_get_handshake_finished(record, &client_verify_data, &client_verify_data_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	if (tls13_compute_verify_data(client_handshake_traffic_secret, &dgst_ctx, verify_data, &verify_data_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	if (client_verify_data_len != verify_data_len
		|| memcmp(client_verify_data, verify_data, verify_data_len) != 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		goto end;
	}
	digest_update(&dgst_ctx, record + 5, recordlen - 5);
	tls_seq_num_incr(conn->client_seq_num);


	// 注意：OpenSSL兼容模式在此处会收发ChangeCipherSpec报文


	// update server_write_key, server_write_iv, reset server_seq_num
	tls13_hkdf_expand_label(digest, server_application_traffic_secret, "key", NULL, 0, 16, server_write_key);
	tls13_hkdf_expand_label(digest, server_application_traffic_secret, "iv", NULL, 0, 12, conn->server_write_iv);
	block_cipher_set_encrypt_key(&conn->server_write_key, cipher, server_write_key);
	memset(conn->server_seq_num, 0, 8);
	/*
	format_print(stderr, 0, 0, "update server secrets\n");
	format_bytes(stderr, 0, 4, "server_write_key", server_write_key, 16);
	format_bytes(stderr, 0, 4, "server_write_iv", conn->server_write_iv, 12);
	format_print(stderr, 0, 0, "\n");
	*/

	// update client_write_key, client_write_iv
	// reset client_seq_num
	tls13_hkdf_expand_label(digest, client_application_traffic_secret, "key", NULL, 0, 16, client_write_key);
	tls13_hkdf_expand_label(digest, client_application_traffic_secret, "iv", NULL, 0, 12, conn->client_write_iv);
	block_cipher_set_encrypt_key(&conn->client_write_key, cipher, client_write_key);
	memset(conn->client_seq_num, 0, 8);
	/*
	format_print(stderr, 0, 0, "update client secrets\n");
	format_bytes(stderr, 0, 4, "client_write_key", client_write_key, 16);
	format_bytes(stderr, 0, 4, "client_write_iv", conn->client_write_iv, 12);
	format_print(stderr, 0, 0, "\n");
	*/

	fprintf(stderr, "Connection Established!\n\n");
	ret = 1;
end:
	gmssl_secure_clear(&server_ecdhe, sizeof(server_ecdhe));
	gmssl_secure_clear(&client_sign_key, sizeof(client_sign_key));
	gmssl_secure_clear(psk, sizeof(psk));
	gmssl_secure_clear(early_secret, sizeof(early_secret));
	gmssl_secure_clear(handshake_secret, sizeof(handshake_secret));
	gmssl_secure_clear(master_secret, sizeof(master_secret));
	gmssl_secure_clear(client_handshake_traffic_secret, sizeof(client_handshake_traffic_secret));
	gmssl_secure_clear(server_handshake_traffic_secret, sizeof(server_handshake_traffic_secret));
	gmssl_secure_clear(client_application_traffic_secret, sizeof(client_application_traffic_secret));
	gmssl_secure_clear(server_application_traffic_secret, sizeof(server_application_traffic_secret));
	gmssl_secure_clear(client_write_key, sizeof(client_write_key));
	gmssl_secure_clear(server_write_key, sizeof(server_write_key));
	return ret;
}
