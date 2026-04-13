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

// 对于optional的选项，指针为空或者长度为0，均视为未提供参数
// 对于非optional的选项，如果为空，那么就不用判断了，不要把这种逻辑判断留给函数来处理
// 函数的逻辑尽可能的简单

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

int tls13_send(TLS_CONNECT *conn, const uint8_t *data, size_t datalen, size_t *sentlen)
{
	const BLOCK_CIPHER_KEY *key;
	const uint8_t *iv;
	uint8_t *seq_num;
	uint8_t *record = conn->record;
	size_t recordlen;
	size_t padding_len = 0; //FIXME: add random padding to conn			

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

	format_bytes(stderr, 0, 0, "send seq_num", seq_num, 8);

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
	//tls_record_trace(stderr, record, tls_record_length(record), 0, 0);

	tls_seq_num_incr(seq_num);

	*sentlen = datalen;

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
	if (tls13_send(conn, conn->early_data_buf, conn->early_data_len, &sentlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}


/*
这里有两个问题
	* 这个函数需要处理handshake.NewSessionTicket, alert等消息，这些消息不是ApplicationData
	* 在握手完成后，客户端需要同时处理发送和接收，而不是等待用户发送


还有一个问题就是缓冲区的使用，最好每次解密就放到plain_record中，不再使用conn->data

*/

int tls13_do_recv(TLS_CONNECT *conn)
{
	int ret;
	const BLOCK_CIPHER_KEY *key;
	const uint8_t *iv;
	uint8_t *seq_num;
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

	tls_trace("recv {ApplicationData}\n");
	if ((ret = tls_record_recv(conn->record, &conn->recordlen, conn->sock)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	tls13_record_print(stderr, 0, 0, conn->record, conn->recordlen);

	if (tls_record_type(conn->record) != TLS_record_application_data) {
		error_print();
		return -1;
	}


	if (tls13_gcm_decrypt(key, iv,
		seq_num, conn->record + 5, conn->recordlen - 5,
		&record_type, conn->databuf, &conn->datalen) != 1) {
		error_print();
		return -1;
	}
	tls_seq_num_incr(seq_num);



	conn->data = conn->databuf;
	tls_record_set_data(conn->record, conn->data, conn->datalen);


	if (record_type == TLS_record_handshake) {
		error_print();
		fprintf(stderr, "recv handshake\n");
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
Extension Cookie
struct {
	opaque cookie<1..2^16-1>;
} Cookie;
*/


int tls13_cookie_ext_to_bytes(const uint8_t *cookie, size_t cookielen, uint8_t **out, size_t *outlen)
{
	uint16_t ext_type = TLS_extension_cookie;
	size_t ext_datalen;

	if (!cookie || !cookielen || cookielen > 65535) {
		error_print();
		return -1;
	}
	ext_datalen = 2 + cookielen;
	if (ext_datalen > 65535) {
		error_print();
		return -1;
	}
	tls_uint16_to_bytes(ext_type, out, outlen);
	tls_uint16_to_bytes((uint16_t)ext_datalen, out, outlen);
	tls_uint16array_to_bytes(cookie, cookielen, out, outlen);
	return 1;
}

int tls13_cookie_from_bytes(const uint8_t **cookie, size_t *cookielen, const uint8_t *ext_data, size_t ext_datalen)
{
	if (tls_uint16array_from_bytes(cookie, cookielen, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	if (!(*cookie) || !(*cookielen)) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_cookie_print(FILE *fp, int fmt, int ind, const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *cookie;
	size_t cookielen;

	if (tls_uint16array_from_bytes(&cookie, &cookielen, &ext_data, &ext_datalen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "cookie", cookie, cookielen);
	if (ext_datalen) {
		error_print();
		return -1;
	}
	return 1;
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
NewSessionTicket的扩展也需要存储起来，用于判断是否0-RTT
	1. early_data 标识，这是必须的
	2. max_early_data_size 如果early_data == 1, 不一定包含这个扩展
*/
int tls13_session_to_bytes(int protocol_version, int cipher_suite,
	const uint8_t *pre_shared_key, size_t pre_shared_key_len,
	uint32_t ticket_issue_time, uint32_t ticket_lifetime, uint32_t ticket_age_add,
	const uint8_t *ticket, size_t ticketlen, uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	tls_uint16_to_bytes((uint16_t)protocol_version, NULL, &len);
	tls_uint16_to_bytes((uint16_t)cipher_suite, NULL, &len);
	tls_uint8array_to_bytes(pre_shared_key, pre_shared_key_len, NULL, &len);
	tls_uint32_to_bytes(ticket_issue_time, NULL, &len);
	tls_uint32_to_bytes(ticket_lifetime, NULL, &len);
	tls_uint32_to_bytes(ticket_age_add, NULL, &len);
	tls_uint16array_to_bytes(ticket, ticketlen, NULL, &len);

	tls_uint16_to_bytes(len, out, outlen);

	tls_uint16_to_bytes((uint16_t)protocol_version, out, outlen);
	tls_uint16_to_bytes((uint16_t)cipher_suite, out, outlen);
	tls_uint8array_to_bytes(pre_shared_key, pre_shared_key_len, out, outlen);
	tls_uint32_to_bytes(ticket_issue_time, out, outlen);
	tls_uint32_to_bytes(ticket_lifetime, out, outlen);
	tls_uint32_to_bytes(ticket_age_add, out, outlen);
	tls_uint16array_to_bytes(ticket, ticketlen, out, outlen);

	return 1;
}

/*
int tls13_session_from_file(uint8_t *session, size_t *sessionlen, size_t session_maxlen,
	int *protocol_version, int *cipher_suite,
	const uint8_t **pre_shared_key, size_t *pre_shared_key_len,
	uint32_t *ticket_issue_time, uint32_t *ticket_lifetime, uint32_t *ticket_age_add,
	const uint8_t **ticket, size_t *ticketlen,
	const char *file)
{
	const uint8_t *cpsession = session;

	FILE *fp;

	if (!(fp = fopen(file, "rb"))) {
		error_print();
		return -1;
	}
	// load session ticket
	if (tls_uint16array_from_file(session, sessionlen, session_maxlen, fp) != 1) {
		error_print();
		fclose(fp);
		return -1;
	}
	fclose(fp);

	if (tls13_session_from_bytes(protocol_version, cipher_suite,
		pre_shared_key, pre_shared_key_len,
		ticket_issue_time, ticket_lifetime, ticket_age_add,
		ticket, ticketlen, cpsession, sessionlen) != 1
		|| tls_length_is_zero(sessionlen) != 1) {
		error_print();
		return -1;
	}
	if (pre_shared_key_len != 32) {
		error_print();
		return -1;
	}

	return 1;
}
*/

int tls13_session_from_bytes(int *protocol_version, int *cipher_suite,
	const uint8_t **pre_shared_key, size_t *pre_shared_key_len,
	uint32_t *ticket_issue_time, uint32_t *ticket_lifetime, uint32_t *ticket_age_add,
	const uint8_t **ticket, size_t *ticketlen,
	const uint8_t **in, size_t *inlen)
{
	const uint8_t *cp;
	size_t len;
	uint16_t version;
	uint16_t cipher;

	if (tls_uint16array_from_bytes(&cp, &len, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (tls_uint16_from_bytes(&version, &cp, &len) != 1
		|| tls_uint16_from_bytes(&cipher, &cp, &len) != 1
		|| tls_uint8array_from_bytes(pre_shared_key, pre_shared_key_len, &cp, &len) != 1
		|| tls_uint32_from_bytes(ticket_issue_time, &cp, &len) != 1
		|| tls_uint32_from_bytes(ticket_lifetime, &cp, &len) != 1
		|| tls_uint32_from_bytes(ticket_age_add, &cp, &len) != 1
		|| tls_uint16array_from_bytes(ticket, ticketlen, &cp, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	if (!tls_protocol_name(version)) {
		error_print();
		return -1;
	}
	*protocol_version = version;
	if (!tls_cipher_suite_name(cipher)) {
		error_print();
		return -1;
	}
	*cipher_suite = cipher;
	if (*pre_shared_key_len != 32) {
		error_print();
		return -1;
	}
	if (*ticket_lifetime > 60 * 60 * 24 * 7) {
		error_print();
		return -1;
	}
	if (!ticketlen) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_session_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen)
{
	const uint8_t *cp;
	size_t len;
	uint16_t protocol_version;
	uint16_t cipher_suite;
	const uint8_t *pre_shared_key;
	size_t pre_shared_key_len;
	uint32_t ticket_issue_time;
	uint32_t ticket_lifetime;
	uint32_t ticket_age_add;
	const uint8_t *ticket;
	size_t ticketlen;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	if (tls_uint16array_from_bytes(&cp, &len, &a, &alen) != 1) {
		error_print();
		return -1;
	}
	if (tls_uint16_from_bytes(&protocol_version, &cp, &len) != 1
		|| tls_uint16_from_bytes(&cipher_suite, &cp, &len) != 1
		|| tls_uint8array_from_bytes(&pre_shared_key, &pre_shared_key_len, &cp, &len) != 1
		|| tls_uint32_from_bytes(&ticket_issue_time, &cp, &len) != 1
		|| tls_uint32_from_bytes(&ticket_lifetime, &cp, &len) != 1
		|| tls_uint32_from_bytes(&ticket_age_add, &cp, &len) != 1
		|| tls_uint16array_from_bytes(&ticket, &ticketlen, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "protocol_version: %s (%04x)\n", tls_protocol_name(protocol_version), protocol_version);
	format_print(fp, fmt, ind, "cipher_suite: %s (%04x)\n", tls_cipher_suite_name(cipher_suite), cipher_suite);
	format_bytes(fp, fmt, ind, "pre_shared_key", pre_shared_key, pre_shared_key_len);
	format_print(fp, fmt, ind, "ticket_issue_time: %"PRIu32"\n", ticket_issue_time);
	format_print(fp, fmt, ind, "ticket_lifetime: %"PRIu32"\n", ticket_lifetime);
	format_print(fp, fmt, ind, "ticket_age_add: %"PRIu32"\n", ticket_age_add);
	format_bytes(fp, fmt, ind, "ticket", ticket, ticketlen);
	if (tls_length_is_zero(alen) != 1 || tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

/*
到底提取了什么内容
	* protocol 这个必须是TLS 1.3
	* pre_shared_key 应该赋值给conn->psk
	* ticket 这个需要提供给pre_shared_key 中的identity，但是现在最好让上面提供一个buffer
	* obfuscated_ticket_age 这个是计算出拉来的
	* binder 我们就干不了了，因为如果要载入多个session的时候，肯定要最后才能做

*/



/*
      struct {} Empty;

      struct {
          select (Handshake.msg_type) {
              case new_session_ticket:   uint32 max_early_data_size;
              case client_hello:         Empty;
              case encrypted_extensions: Empty;
          };
      } EarlyDataIndication;

*/

int tls13_early_data_ext_to_bytes(size_t max_early_data_size, uint8_t **out, size_t *outlen)
{
	uint8_t ext_data[4];
	uint8_t *p = ext_data;
	size_t ext_datalen = 0;
	tls_uint32_to_bytes(max_early_data_size, &p, &ext_datalen);
	if (tls_ext_to_bytes(TLS_extension_early_data, ext_data, ext_datalen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_early_data_from_bytes(size_t *max_early_data_size, const uint8_t *ext_data, size_t ext_datalen)
{
	uint32_t max_size;
	if (tls_uint32_from_bytes(&max_size, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	*max_early_data_size = max_size;
	return 1;
}

int tls13_early_data_print(FILE *fp, int fmt, int ind, const uint8_t *ext_data, size_t ext_datalen)
{
	uint32_t max_early_data_size;

	if (!ext_data || !ext_datalen) {
		format_print(fp, fmt, ind, "(null)\n");
	} else {
		if (tls_uint32_from_bytes(&max_early_data_size, &ext_data, &ext_datalen) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind, "max_early_data_size: %"PRIu32"\n", max_early_data_size);
		if (ext_datalen) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int tls13_empty_early_data_ext_to_bytes(uint8_t **out, size_t *outlen)
{
	if (tls_ext_to_bytes(TLS_extension_early_data, NULL, 0, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_empty_early_data_print(FILE *fp, int fmt, int ind, const uint8_t *ext_data, size_t ext_datalen)
{
	if (ext_data || ext_datalen) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "(null)\n");
	return 1;
}





/*
enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;

struct {
	PskKeyExchangeMode ke_modes<1..255>;
} PskKeyExchangeModes;
*/

int tls13_ctx_set_psk_key_exchange_modes(TLS_CTX *ctx, int psk_ke, int psk_dhe_ke)
{
	ctx->key_exchange_modes &= ~TLS_KE_PSK;
	ctx->key_exchange_modes &= ~TLS_KE_PSK_DHE;

	if (psk_ke)
		ctx->key_exchange_modes |= TLS_KE_PSK;

	if (psk_dhe_ke)
		ctx->key_exchange_modes |= TLS_KE_PSK_DHE;

	return 1;
}

const char *tls13_psk_key_exchange_mode_name(int mode)
{
	switch (mode) {
	case TLS_psk_ke: return "psk_ke";
	case TLS_psk_dhe_ke: return "psk_dhe_ke";
	}
	return NULL;
}

int tls13_psk_key_exchange_modes_ext_to_bytes(int modes, uint8_t **out, size_t *outlen)
{
	int type = TLS_extension_psk_key_exchange_modes;
	uint8_t ke_modes[2] = { TLS_psk_dhe_ke, TLS_psk_ke };
	uint8_t ext_data[3];
	uint8_t *p = ext_data;
	size_t ext_datalen = 0;

	if ((modes & TLS_KE_PSK_DHE) && (modes & TLS_KE_PSK)) {
		tls_uint8array_to_bytes(ke_modes, 2, &p, &ext_datalen);
	} else if (modes & TLS_KE_PSK_DHE) {
		tls_uint8array_to_bytes(ke_modes, 1, &p, &ext_datalen);
	} else if (modes & TLS_KE_PSK) {
		tls_uint8array_to_bytes(ke_modes + 1, 1, &p, &ext_datalen);
	}

	if (tls_ext_to_bytes(type, ext_data, ext_datalen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_psk_key_exchange_modes_from_bytes(int *modes, const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *ke_modes;
	size_t ke_modes_len;

	if (tls_uint8array_from_bytes(&ke_modes, &ke_modes_len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}

	while (ke_modes_len) {
		uint8_t mode;
		if (tls_uint8_from_bytes(&mode, &ke_modes, &ke_modes_len) != 1) {
			error_print();
			return -1;
		}
		switch (mode) {
		case TLS_psk_ke:
			*modes |= TLS_KE_PSK;
			break;
		case TLS_psk_dhe_ke:
			*modes |= TLS_KE_PSK_DHE;
			break;
		default:
			error_print();
			return -1;
		}
	}

	return 1;
}

int tls13_psk_key_exchange_modes_print(FILE *fp, int fmt, int ind, const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *ke_modes;
	size_t ke_modes_len;

	format_print(fp, fmt, ind, "ke_modes\n");
	ind += 4;
	if (tls_uint8array_from_bytes(&ke_modes, &ke_modes_len, &ext_data, &ext_datalen) != 1) {
		error_print();
		return -1;
	}
	if (!ke_modes_len) {
		format_print(fp, fmt, ind, "(null)\n");
	}
	while (ke_modes_len) {
		uint8_t mode;
		tls_uint8_from_bytes(&mode, &ke_modes, &ke_modes_len);
		format_print(fp, fmt, ind, "%s (%d)\n", tls13_psk_key_exchange_mode_name(mode), mode);
	}
	if (ext_datalen) {
		error_print();
		return -1;
	}
	return 1;
}

/*
struct {
	opaque identity<1..2^16-1>;
	uint32 obfuscated_ticket_age;
} PskIdentity;
*/
int tls13_psk_identity_to_bytes(const uint8_t *ticket, size_t ticketlen, uint32_t obfuscated_ticket_age,
	uint8_t **out, size_t *outlen)
{
	if (!ticket || !ticketlen || ticketlen > 65535) {
		error_print();
		return -1;
	}

	tls_uint16array_to_bytes(ticket, ticketlen, out, outlen);
	tls_uint32_to_bytes(obfuscated_ticket_age, out, outlen);
	return 1;
}

int tls13_psk_identity_from_bytes(const uint8_t **ticket, size_t *ticketlen, uint32_t *obfuscated_ticket_age,
	const uint8_t **in, size_t *inlen)
{
	if (tls_uint16array_from_bytes(ticket, ticketlen, in, inlen) != 1
		|| tls_uint32_from_bytes(obfuscated_ticket_age, in, inlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_search_psk(
	const uint8_t *psk_identities, size_t psk_identities_len,
	const uint8_t *psk_keys, size_t psk_keys_len,
	const uint8_t *psk_identity, size_t psk_identity_len,
	const uint8_t **psk_key, size_t *psk_key_len, int *psk_key_idx)
{
	size_t i;

	if (!psk_identities || !psk_identities_len || !psk_keys || !psk_keys_len) {
		error_print();
		return -1;
	}
	if (!psk_identity || !psk_identity_len
		|| !psk_key || !psk_key_len) {
		error_print();
		return -1;
	}
	for (i = 0; psk_identities_len; i++) {
		const uint8_t *id;
		size_t idlen;
		uint32_t ticket_age;
		const uint8_t *key;
		size_t keylen;

		if (tls13_psk_identity_from_bytes(&id, &idlen, &ticket_age, &psk_identities, &psk_identities_len) != 1
			|| tls_uint8array_from_bytes(&key, &keylen, &psk_keys, &psk_keys_len) != 1) {
			error_print();
			return -1;
		}
		if (idlen == psk_identity_len
			&& memcmp(id, psk_identity, psk_identity_len) == 0) {
			*psk_key = key;
			*psk_key_len = keylen;
			*psk_key_idx = i;
			return 1;
		}
	}
	return 0;
}


/*
int tls_cipher_suites_support_digest(const int *cipher_suites, size_t cipher_suites_cnt,
	const DIGEST *digest)
{
	const BLOCK_CIPHER *_cipher;
	const DIGEST *_digest;
	size_t i;

	for (i = 0; i < cipher_suites_cnt; i++) {
		if (tls13_cipher_suite_get(cipher_suites[i], &_cipher, &_digest) != 1) {
			error_print();
			return -1;
		}
		if (digest == _digest) {
			return 1;
		}
	}
	return 0;
}
*/

int tls13_add_pre_shared_key(TLS_CONNECT *conn,
	const uint8_t *psk_identity, size_t psk_identity_len,
	const uint8_t *psk_key, size_t psk_key_len,
	int psk_cipher_suite, uint32_t obfuscated_ticket_age)
{
	const BLOCK_CIPHER *cipher;
	const DIGEST *digest;
	uint8_t *psk_identities;
	size_t psk_identities_len;
	uint8_t *psk_keys;
	size_t psk_keys_len;

	if (!conn || !psk_identity || !psk_identity_len || !psk_key || !psk_key_len) {
		error_print();
		return -1;
	}
	if (tls_type_is_in_list(psk_cipher_suite,
		conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt) != 1) {
		error_print();
		return -1;
	}
	if (tls13_cipher_suite_get(psk_cipher_suite, &cipher, &digest) != 1) {
		error_print();
		return -1;
	}
	if (psk_key_len != digest->digest_size) {
		error_print();
		return -1;
	}

	// add psk_identity
	psk_identities_len = conn->psk_identities_len;
	if (tls13_psk_identity_to_bytes(psk_identity, psk_identity_len, obfuscated_ticket_age,
		NULL, &psk_identities_len) != 1) {
		error_print();
		return -1;
	}
	if (psk_identities_len > sizeof(conn->psk_identities)) {
		error_print();
		return -1;
	}
	psk_identities = conn->psk_identities + conn->psk_identities_len;
	tls13_psk_identity_to_bytes(psk_identity, psk_identity_len, obfuscated_ticket_age,
		&psk_identities, &conn->psk_identities_len);


	// add psk_key
	psk_keys_len = conn->psk_keys_len;
	tls_uint8array_to_bytes(psk_key, psk_key_len, NULL, &psk_keys_len);
	if (psk_keys_len > sizeof(conn->psk_keys)) {
		error_print();
		return -1;
	}
	psk_keys = conn->psk_keys + conn->psk_keys_len;
	tls_uint8array_to_bytes(psk_key, psk_key_len, &psk_keys, &conn->psk_keys_len);

	// add psk_cipher_suite
	if (conn->psk_cipher_suites_cnt >= sizeof(conn->psk_cipher_suites)/sizeof(conn->psk_cipher_suites[0])) {
		error_print();
		return -1;
	}
	conn->psk_cipher_suites[conn->psk_cipher_suites_cnt++] = psk_cipher_suite;

	return 1;
}

int tls13_add_pre_shared_key_from_file(TLS_CONNECT *conn, const char *file)
{
	FILE *fp;
	uint8_t buf[512];
	const uint8_t *cp = buf;
	size_t len;

	int protocol_version;
	int cipher_suite;
	const uint8_t *pre_shared_key;
	size_t pre_shared_key_len;
	uint32_t ticket_issue_time;
	uint32_t ticket_lifetime;
	uint32_t ticket_age_add;
	const uint8_t *ticket;
	size_t ticketlen;

	uint32_t obfuscated_ticket_age;

	if (!(fp = fopen(file, "rb"))) {
		error_print();
		return -1;
	}
	if (tls_uint16array_from_file(buf, &len, sizeof(buf), fp) != 1) {
		error_print();
		fclose(fp);
		return -1;
	}
	fclose(fp);

	if (tls13_session_from_bytes(&protocol_version, &cipher_suite,
		&pre_shared_key, &pre_shared_key_len,
		&ticket_issue_time, &ticket_lifetime, &ticket_age_add,
		&ticket, &ticketlen, &cp, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	if (pre_shared_key_len != 32) {
		error_print();
		return -1;
	}
	// 计算出age

	if (tls13_add_pre_shared_key(conn, ticket, ticketlen,
		pre_shared_key, pre_shared_key_len, cipher_suite, obfuscated_ticket_age) != 1) {
		error_print();
		return -1;
	}

	return 1;
}


/*
      struct {
          PskIdentity identities<7..2^16-1>;
          PskBinderEntry binders<33..2^16-1>;
      } OfferedPsks;
*/



int tls13_client_pre_shared_key_ext_to_bytes(const uint8_t *identities, size_t identitieslen,
	const uint8_t *binders, size_t binderslen, uint8_t **out, size_t *outlen)
{
	int ext_type = TLS_extension_pre_shared_key;
	uint8_t *ext_data = *out + 4;
	size_t ext_datalen = 0;

	tls_uint16array_to_bytes(identities, identitieslen, &ext_data, &ext_datalen);
	tls_uint16array_to_bytes(binders, binderslen, &ext_data, &ext_datalen);
	tls_ext_to_bytes(ext_type, NULL, ext_datalen, out, outlen); // tls_ext_to_bytes 逻辑不一定对啊			

	return 1;
}

int tls13_client_pre_shared_key_from_bytes(const uint8_t **identities, size_t *identitieslen,
	const uint8_t **binders, size_t *binderslen, const uint8_t *ext_data, size_t ext_datalen)
{
	if (tls_uint16array_from_bytes(identities, identitieslen, &ext_data, &ext_datalen) != 1
		|| tls_uint16array_from_bytes(binders, binderslen, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}


int tls13_process_client_pre_shared_key_external(TLS_CONNECT *conn,
	const uint8_t *ext_data, size_t ext_datalen)
{
	int ret;
	const uint8_t *identities;
	size_t identitieslen;
	const uint8_t *binders;
	size_t binderslen;
	const uint8_t *truncated_binders;
	size_t truncated_binderslen;
	size_t i;

	if (!conn || !ext_data || !ext_datalen) {
		error_print();
		return -1;
	}
	if (!conn->psk_cipher_suites_cnt || !conn->psk_identities_len || !conn->psk_keys_len) {
		error_print();
		return -1;
	}

	// parse pre_shared_key extension
	if (tls_uint16array_from_bytes(&identities, &identitieslen, &ext_data, &ext_datalen) != 1
		|| tls_uint16array_from_bytes(&binders, &binderslen, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}

	// truncate client_hello => plain_record
	memcpy(conn->plain_record, conn->record, conn->recordlen);
	conn->plain_recordlen = conn->recordlen;
	truncated_binders = conn->plain_record + (binders - conn->record);
	truncated_binderslen = binderslen;
	while (truncated_binderslen) {
		const uint8_t *truncated_binder;
		size_t truncated_binderlen;
		if (tls_uint8array_from_bytes(&truncated_binder, &truncated_binderlen,
			&truncated_binders, &truncated_binderslen) != 1) {
			error_print();
			return -1;
		}
		memset((uint8_t *)truncated_binder, 0, truncated_binderlen);
	}

	// search psk
	for (i = 0; identitieslen; i++) {
		const uint8_t *identity;
		size_t identitylen;
		uint32_t obfuscated_ticket_age;
		const uint8_t *binder;
		size_t binderlen;
		const uint8_t *matched_psk;
		size_t matched_psk_len;
		int matched_psk_idx;

		int cipher_suite;

		DIGEST_CTX dgst_ctx;

		// get psk_identity, psk_key, age and binder, age is useless whne psk is external
		if (tls13_psk_identity_from_bytes(&identity, &identitylen, &obfuscated_ticket_age,
			&identities, &identitieslen) != 1
			|| tls_uint8array_from_bytes(&binder, &binderlen,
			&binders, &binderslen) != 1) {
			error_print();
			return -1;
		}

		// search psk by psk_identity
		if ((ret = tls13_search_psk(
			conn->psk_identities, conn->psk_identities_len,
			conn->psk_keys, conn->psk_keys_len,
			identity, identitylen,
			&matched_psk, &matched_psk_len, &matched_psk_idx)) < 0) {
			error_print();
			return -1;
		} else if (ret == 0) {
			continue;
		}

		conn->cipher_suite = conn->psk_cipher_suites[matched_psk_idx];

		if (tls13_cipher_suite_get(conn->cipher_suite, &conn->cipher, &conn->digest) != 1) {
			error_print();
			return -1;
		}

		// verify binder
		if (digest_init(&dgst_ctx, conn->digest) != 1
			|| digest_update(&dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		if ((ret = tls13_verify_psk_binder(conn->digest, matched_psk, matched_psk_len,
			&dgst_ctx, binder, binderlen)) < 0) {
			error_print();
			return -1;
		} else if (ret == 0) {
			continue;
		}

		// set psk
		memcpy(conn->psk, matched_psk, matched_psk_len);
		conn->psk_len = matched_psk_len;
		conn->selected_psk_identity = (int)i + 1;
		break;
	}

	if (!conn->selected_psk_identity) {
		return 0;
	}
	return 1;
}






int tls13_process_client_pre_shared_key_from_ticket(TLS_CONNECT *conn,
	const uint8_t *ext_data, size_t ext_datalen)
{
	int ret;
	const uint8_t *identities;
	size_t identitieslen;
	const uint8_t *binders;
	size_t binderslen;
	const uint8_t *truncated_binders;
	size_t truncated_binderslen;
	size_t i;

	if (!conn || !ext_data || !ext_datalen) {
		error_print();
		return -1;
	}
	if (!conn->ctx->session_ticket_key) {
		error_print();
		return -1;
	}
	if (!conn->digest) {
		error_print();
		return -1;
	}
	if (conn->selected_psk_identity) {
		error_print();
		return -1;
	}

	// parse pre_shared_key extension
	if (tls_uint16array_from_bytes(&identities, &identitieslen, &ext_data, &ext_datalen) != 1
		|| tls_uint16array_from_bytes(&binders, &binderslen, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}

	// truncate client_hello
	memcpy(conn->plain_record, conn->record, conn->recordlen);
	conn->plain_recordlen = conn->recordlen;
	truncated_binders = conn->plain_record + (binders - conn->record);
	truncated_binderslen = binderslen;
	while (truncated_binderslen) {
		const uint8_t *truncated_binder;
		size_t truncated_binderlen;
		if (tls_uint8array_from_bytes(&truncated_binder, &truncated_binderlen,
			&truncated_binders, &truncated_binderslen) != 1) {
			error_print();
			return -1;
		}
		memset((uint8_t *)truncated_binder, 0, truncated_binderlen);
	}

	// search psk
	for (i = 0; identitieslen; i++) {
		const uint8_t *ticket;
		size_t ticketlen;
		uint32_t obfuscated_ticket_age;
		const uint8_t *binder;
		size_t binderlen;

		// ticket content
		uint8_t pre_shared_key[32];
		int protocol_version;
		int cipher_suite;
		uint32_t ticket_issue_time;
		uint32_t ticket_lifetime;
		DIGEST_CTX dgst_ctx;

		// get psk_identity, psk_key, age and binder
		if (tls13_psk_identity_from_bytes(&ticket, &ticketlen, &obfuscated_ticket_age,
			&identities, &identitieslen) != 1
			|| tls_uint8array_from_bytes(&binder, &binderlen,
			&binders, &binderslen) != 1) {
			error_print();
			return -1;
		}

		// decrypt ticket
		if (tls13_decrypt_ticket(conn->ctx->session_ticket_key, ticket, ticketlen,
			pre_shared_key, &protocol_version, &cipher_suite,
			&ticket_issue_time, &ticket_lifetime) != 1) {
			continue;
		}

		// check protocol_version and cipher_suite
		if (protocol_version != conn->protocol
			|| cipher_suite != conn->cipher_suite) {
			continue;
		}

		// check time
		uint32_t current_time = time(NULL);
		if (ticket_issue_time > current_time) {
			error_print();
			continue;
		}
		if (current_time - ticket_issue_time > ticket_lifetime) {
			error_print();
			continue;
		}

		// verify binder
		if (digest_init(&dgst_ctx, conn->digest) != 1
			|| digest_update(&dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		if ((ret = tls13_verify_psk_binder(conn->digest,
			pre_shared_key, sizeof(pre_shared_key),
			&dgst_ctx, binder, binderlen)) != 1) {
			error_print();
			return -1;
		} else if (ret == 0) {
			continue;
		}

		// set psk
		memcpy(conn->psk, pre_shared_key, sizeof(pre_shared_key));
		conn->psk_len = sizeof(pre_shared_key);
		conn->selected_psk_identity = (int)i + 1;
		break;
	}

	if (!conn->selected_psk_identity) {
		return 0;
	}
	return 1;
}





























int tls13_client_pre_shared_key_print(FILE *fp, int fmt, int ind, const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *identities;
	size_t identitieslen;
	const uint8_t *binders;
	size_t binderslen;

	format_print(fp, fmt, ind, "pre_shared_key\n");
	ind += 4;

	if (tls_uint16array_from_bytes(&identities, &identitieslen, &ext_data, &ext_datalen) != 1
		|| tls_uint16array_from_bytes(&binders, &binderslen, &ext_data, &ext_datalen) != 1) {
		error_print();
		return -1;
	}

	format_print(fp, fmt, ind, "identities\n");
	if (!identitieslen) {
		format_print(fp, fmt, ind + 4, "(null)\n");
	}
	while (identitieslen) {
		int indent = ind + 4;
		const uint8_t *ticket;
		size_t ticketlen;
		uint32_t obfuscated_ticket_age;

		if (tls13_psk_identity_from_bytes(&ticket, &ticketlen, &obfuscated_ticket_age, &identities, &identitieslen) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, indent, "PskIdentity\n");
		indent += 4;
		format_bytes(fp, fmt, indent, "identity", ticket, ticketlen);
		format_print(fp, fmt, indent, "obfuscated_ticket_age: %"PRIu32"\n", obfuscated_ticket_age);
	}

	format_print(fp, fmt, ind, "binders\n");
	if (!binderslen) {
		format_print(fp, fmt, ind + 4, "(null)\n");
	}
	while (binderslen) {
		int indent = ind + 4;
		const uint8_t *binder;
		size_t binderlen;

		if (tls_uint8array_from_bytes(&binder, &binderlen, &binders, &binderslen) != 1) {
			error_print();
			return -1;
		}
		format_bytes(fp, fmt, indent, "PskBinderEntry", binder, binderlen);
	}


	return 1;
}


int tls13_server_pre_shared_key_ext_to_bytes(int selected_identity, uint8_t **out, size_t *outlen)
{
	int ext_type = TLS_extension_pre_shared_key;
	uint8_t ext_data[2];
	uint8_t *p = ext_data;
	size_t ext_datalen = 0;

	if (selected_identity <= 0 || selected_identity > 65535) {
		error_print();
		return -1;
	}
	tls_uint16_to_bytes((uint16_t)(selected_identity - 1), &p, &ext_datalen);
	tls_ext_to_bytes(ext_type, ext_data, sizeof(ext_data), out, outlen);
	return 1;
}

int tls13_server_pre_shared_key_from_bytes(int *selected_identity, const uint8_t *ext_data, size_t ext_datalen)
{
	uint16_t identity;
	if (tls_uint16_from_bytes(&identity, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	*selected_identity = identity;
	return 1;
}

int tls13_server_pre_shared_key_print(FILE *fp, int fmt, int ind, const uint8_t *ext_data, size_t ext_datalen)
{
	uint16_t identity;
	if (tls_uint16_from_bytes(&identity, &ext_data, &ext_datalen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "seleceted_identity: %d\n", identity);
	if (ext_datalen) {
		error_print();
		return -1;
	}
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
		case TLS_extension_supported_groups:
			tls_supported_groups_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_key_share:
			tls13_key_share_client_hello_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_signature_algorithms:
			tls_signature_algorithms_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_cookie:
			tls13_cookie_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_early_data:
			tls13_early_data_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_pre_shared_key:
			tls13_client_pre_shared_key_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		case TLS_extension_psk_key_exchange_modes:
			tls13_psk_key_exchange_modes_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;

		case TLS_extension_server_name:
		case TLS_extension_application_layer_protocol_negotiation:
		case TLS_extension_padding:
		case TLS_extension_record_size_limit:
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
			return -1;
		}
	}
	if (dlen) {
		error_print();
		return -1;
	}
	return 1;
}

/*
struct {
    ProtocolVersion server_version;      // 服务器选择的版本
    CipherSuite cipher_suite;             // 服务器选择的密码套件
    Extension extensions<2..2^16-1>;      // 扩展列表
} HelloRetryRequest;
*/

int tls13_set_handshake_hello_retry_request(uint8_t *record, size_t *recordlen,
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



/*
struct {
    select (Handshake.msg_type) {
        case new_session_ticket:   uint32 max_early_data_size;
        case client_hello:          empty;
        case encrypted_extensions:  empty;
    };
} EarlyDataIndication;
*/

int tls13_new_session_ticket_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen)
{
	uint32_t ticket_lifetime;
	uint32_t ticket_age_add;
	const uint8_t *ticket_nonce;
	size_t ticket_nonce_len;
	const uint8_t *ticket;
	size_t ticket_len;
	const uint8_t *exts;
	size_t extslen;

	// early_data extension
	uint32_t max_early_data_size;


	format_print(fp, fmt, ind, "NewSessionTicket\n");
	ind += 4;

	if (tls_uint32_from_bytes(&ticket_lifetime, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "ticket_lifetime: %"PRIu32" seconds\n", ticket_lifetime);

	if (tls_uint32_from_bytes(&ticket_age_add, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "ticket_age_add: %"PRIu32"\n", ticket_age_add);

	if (tls_uint8array_from_bytes(&ticket_nonce, &ticket_nonce_len, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "ticket_nonce", ticket_nonce, ticket_nonce_len);

	if (tls_uint16array_from_bytes(&ticket, &ticket_len, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "ticket", ticket, ticket_len);

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
		case TLS_extension_early_data:
			tls13_early_data_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		default:
			format_print(fp, fmt, ind, "%s (%d)\n", tls_extension_name(ext_type), ext_type);
			format_bytes(fp, fmt, ind + 4, "raw_data", ext_data, ext_datalen);
			error_print();
		}
	}
	if (dlen) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_end_of_early_data_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen)
{
	format_print(fp, fmt, ind, "EndOfEarlyData\n");
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
		default:
			format_bytes(fp, fmt, ind, "raw_data", ext_data, ext_datalen);
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
			case TLS_extension_signed_certificate_timestamp:
			case TLS_extension_server_certificate_type:
			case TLS_extension_client_certificate_type:
				break;
			default:
				error_print();
				return -1;
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
			tls13_signature_algorithms_cert_print(fp, fmt, ind, ext_data, ext_datalen);
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




// 对于客户端来说，只要多存储一个server_session_ticket就可以了


int tls13_ticket_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *resumption_master_secret;
	uint16_t protocol_version;
	uint16_t cipher_suite;
	uint32_t ticket_issue_time;
	uint32_t ticket_lifetime;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	if (tls_array_from_bytes(&resumption_master_secret, 48, &d, &dlen) != 1
		|| tls_uint16_from_bytes(&protocol_version, &d, &dlen) != 1
		|| tls_uint16_from_bytes(&cipher_suite, &d, &dlen) != 1
		|| tls_uint32_from_bytes(&ticket_issue_time, &d, &dlen) != 1
		|| tls_uint32_from_bytes(&ticket_lifetime, &d, &dlen) != 1
		|| tls_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "resumption_master_secret", resumption_master_secret, 48);
	format_print(fp, fmt, ind, "protocol_version: %s (%04x)\n", tls_protocol_name(protocol_version), protocol_version);
	format_print(fp, fmt, ind, "cipher_suite: %s (%04x)\n", tls_cipher_suite_name(cipher_suite), cipher_suite);
	format_print(fp, fmt, ind, "ticket_issue_time: %"PRIu32"\n", ticket_issue_time);
	format_print(fp, fmt, ind, "ticket_lifetime: %"PRIu32"\n", ticket_lifetime);
	return 1;
}


/*
OpenSSL的s_server自动的生成一个ticket加密密钥
因此s_server的ticket有效期只能保证在一次启动的时间内
重启之后密钥就丢失了
*/

int tls13_encrypt_ticket(const SM4_KEY *key, const uint8_t pre_shared_key[32],
	int protocol_version, int cipher_suite, uint32_t ticket_issue_time,  uint32_t ticket_lifetime,
	uint8_t *out, size_t *outlen)
{
	uint8_t ticket[32 + 2 + 2 + 4 + 4];
	uint8_t *p = ticket;
	size_t ticketlen = 0;

	uint8_t *iv = out;
	size_t ivlen = 12;
	const uint8_t *aad = NULL;
	size_t aadlen = 0;
	uint8_t *tag;
	size_t taglen = 16;

	if (!key || !pre_shared_key || !out || !outlen) {
		error_print();
		return -1;
	}


	out += ivlen;
	tag = out + sizeof(ticket);

	tls_array_to_bytes(pre_shared_key, 32, &p, &ticketlen);
	tls_uint16_to_bytes(protocol_version, &p, &ticketlen);
	tls_uint16_to_bytes(cipher_suite, &p, &ticketlen);
	tls_uint32_to_bytes(ticket_issue_time, &p, &ticketlen);
	tls_uint32_to_bytes(ticket_lifetime, &p, &ticketlen);

	if (ticketlen != sizeof(ticket)) {
		error_print();
		return -1;
	}

	if (rand_bytes(iv, ivlen) != 1) {
		error_print();
		return -1;
	}
	if (sm4_gcm_encrypt(key, iv, ivlen, aad, aadlen, ticket, ticketlen, out, taglen, tag) != 1) {
		error_print();
		return -1;
	}

	*outlen = ivlen + sizeof(ticket) + taglen;
	return 1;
}

int tls13_decrypt_ticket(const SM4_KEY *key, const uint8_t *in, size_t inlen,
	uint8_t pre_shared_key[32], int *protocol_version, int *cipher_suite,
	uint32_t *ticket_issue_time, uint32_t *ticket_lifetime)
{
	const uint8_t *iv;
	size_t ivlen = 12;
	const uint8_t *aad = NULL;
	size_t aadlen = 0;
	const uint8_t *tag;
	size_t taglen = 16;

	uint8_t ticket[32 + 2 + 2 + 4 + 4];
	const uint8_t *cp = ticket;
	const uint8_t *psk;
	uint16_t version;
	uint16_t cipher;

	if (inlen != ivlen + sizeof(ticket) + taglen) {
		error_print();
		return -1;
	}
	iv = in;

	in += ivlen;
	inlen -= ivlen;

	tag = in + sizeof(ticket);
	inlen -= taglen;

	if (sm4_gcm_decrypt(key, iv, ivlen, aad, aadlen, in, sizeof(ticket), tag, taglen, ticket) != 1) {
		error_print();
		return -1;
	}
	if (tls_array_from_bytes(&psk, 32, &cp, &inlen) != 1
		|| tls_uint16_from_bytes(&version, &cp, &inlen) != 1
		|| tls_uint16_from_bytes(&cipher, &cp, &inlen) != 1
		|| tls_uint32_from_bytes(ticket_issue_time, &cp, &inlen) != 1
		|| tls_uint32_from_bytes(ticket_lifetime, &cp, &inlen) != 1
		|| tls_length_is_zero(inlen) != 1) {
		error_print();
		return -1;
	}
	memcpy(pre_shared_key, psk, 32);
	*protocol_version = version;
	*cipher_suite = cipher;
	return 1;
}

int tls13_record_set_handshake_new_session_ticket(uint8_t *record, size_t *recordlen,
	uint32_t ticket_lifetime, uint32_t ticket_age_add,
	const uint8_t *ticket_nonce, size_t ticket_nonce_len,
	const uint8_t *ticket, size_t ticketlen,
	const uint8_t *exts, size_t extslen)
{
	int type = TLS_handshake_new_session_ticket;
	uint8_t *p = record + 5 + 4;
	size_t len = 0;

	if (ticket_nonce_len > 255
		|| ticketlen > 65535
		|| extslen > 65534) {
		error_print();
		return -1;
	}
	tls_uint32_to_bytes(ticket_lifetime, &p, &len);
	tls_uint32_to_bytes(ticket_age_add, &p, &len);
	tls_uint8array_to_bytes(ticket_nonce, ticket_nonce_len, &p, &len);
	tls_uint16array_to_bytes(ticket, ticketlen, &p, &len);
	tls_uint16array_to_bytes(exts, extslen, &p, &len);
	tls_record_set_handshake(record, recordlen, type, NULL, len);
	return 1;
}

int tls13_record_get_handshake_new_session_ticket(uint8_t *record,
	uint32_t *ticket_lifetime, uint32_t *ticket_age_add,
	const uint8_t **ticket_nonce, size_t *ticket_nonce_len,
	const uint8_t **ticket, size_t *ticketlen,
	const uint8_t **exts, size_t *extslen)
{
	int type;
	const uint8_t *cp;
	size_t len;

	// new_session_ticket是optional的吗？			
	if (tls_record_get_handshake(record, &type, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_new_session_ticket) {
		error_print();
		return -1;
	}
	if (tls_uint32_from_bytes(ticket_lifetime, &cp, &len) != 1
		|| tls_uint32_from_bytes(ticket_age_add, &cp, &len) != 1
		|| tls_uint8array_from_bytes(ticket_nonce, ticket_nonce_len, &cp, &len) != 1
		|| tls_uint16array_from_bytes(ticket, ticketlen, &cp, &len) != 1
		|| tls_uint16array_from_bytes(exts, extslen, &cp, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	if (*ticket_lifetime > 60 * 60 * 24 * 7) {
		error_print();
		return -1;
	}
	if (!ticketlen) {
		error_print();
		return -1;
	}
	if (*extslen > 65534) {
		error_print();
		return -1;
	}
	return 1;
}


// 5. end_of_early_data
int tls13_record_set_handshake_end_of_early_data(uint8_t *record, size_t *recordlen)
{
	int type = TLS_handshake_end_of_early_data;
	tls_record_set_handshake(record, recordlen, type, NULL, 0);
	return 1;
}

int tls13_record_get_handshake_end_of_early_data(uint8_t *record)
{
	int type;
	const uint8_t *cp;
	size_t len;

	if (tls_record_get_handshake(record, &type, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_end_of_early_data) {
		error_print();
		return -1;
	}
	if (len) {
		error_print();
		return -1;
	}
	return 1;
}

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
	const uint8_t *cert_data;
	size_t cert_data_len;
	const uint8_t *exts;
	size_t extslen;

	if (!cert || !certlen
		|| !status_request_ocsp_response || !status_request_ocsp_response_len
		|| !signed_certificate_timestamp || !signed_certificate_timestamp_len
		|| !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (tls_uint24array_from_bytes(&cert_data, &cert_data_len, in, inlen) != 1
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

int tls13_record_get_handshake_key_update(uint8_t *record, size_t *recordlen,
	int *request_update)
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



/*
如果执行0-RTT（前提是CTX，CONN中准备了session)

那么ClientHello中必须包含
	pre_shared_key (从session中获得1个活着多个）
	early_data (empty)
	key_share 虽然是可选的，但是我们强制实现

客户端发送完ClientHello之后，就可以先发送一个ApplicationData，因此这个流程和默认的是不一样的

然后接收：
	ServerHello
		必须包含key_share
	EncryptedExtensions
		(必须包含early_data，否则和常规的是一样的）
		也就是说获得了EE才知道后续的状态
	Finished 采用0-RTT时状态变了


客户端如何决定是否用PSK模式？

	我们可以在TLS_CTX中设定psk模式，并且psk就存储在CTX中

客户端通过ClientHello.pre_shared_key 来请求启用PSK模式
服务器通过ServerHello.pre_shared_key 来响应，或者不包含pre_shared_key来拒绝，以回到完整握手
PSK模式的握手过程和Full握手是不同的


客户端通过ClientHello.early_data(empty)来请求启动0-RTT
服务器在EncryptedExtensions.early_data来响应
如果响应了early_data，那么握手过程在PSK模式上又增加了消息
*/

int tls13_verify_psk_binder(const DIGEST *digest,
	const uint8_t *pre_shared_key, size_t pre_shared_key_len,
	const DIGEST_CTX *truncated_client_hello_dgst_ctx,
	const uint8_t *binder, size_t binderlen)
{
	uint8_t secret[32] = {0};
	uint8_t *zeros = secret;
	uint8_t *early_secret = secret;
	uint8_t *binder_key = secret;
	uint8_t *local_binder = secret;
	DIGEST_CTX null_dgst_ctx;
	size_t local_binder_len;

	if (digest_init(&null_dgst_ctx, digest) != 1) {
		error_print();
		return -1;
	}

	// [1]
	tls13_hkdf_extract(digest, zeros, pre_shared_key, early_secret);
	// [2]
	tls13_derive_secret(early_secret, "res binder", &null_dgst_ctx, binder_key);

	tls13_compute_verify_data(binder_key, truncated_client_hello_dgst_ctx, local_binder, &local_binder_len);

	if (binderlen != local_binder_len || memcmp(local_binder, binder, binderlen) != 0) {
		return 0;
	}

	return 1;
}

int tls13_psk_generate_empty_binders(const int *psk_cipher_suites, size_t psk_cipher_suites_cnt,
	uint8_t *binders, size_t *binders_len)
{
	const uint8_t empty_binder[64] = {0};
	size_t i;

	if (!psk_cipher_suites || !psk_cipher_suites_cnt || !binders || !binders_len) {
		error_print();
		return -1;
	}

	*binders_len = 0;
	for (i = 0; i < psk_cipher_suites_cnt; i++) {
		const BLOCK_CIPHER *cipher;
		const DIGEST *digest;

		if (tls13_cipher_suite_get(psk_cipher_suites[i], &cipher, &digest) != 1) {
			error_print();
			return -1;
		}
		if (digest->digest_size > sizeof(empty_binder)) {
			error_print();
			return -1;
		}
		tls_uint8array_to_bytes(empty_binder, digest->digest_size, &binders, binders_len);
	}
	return 1;
}

int tls13_psk_generate_binders(
	const int *psk_cipher_suites, size_t psk_cipher_suites_cnt,
	const uint8_t *psk_keys, size_t psk_keys_len,
	const uint8_t *truncated_client_hello, size_t truncated_client_hello_len,
	uint8_t *binders, size_t *binders_len)
{
	const uint8_t zeros[32] = {0};
	DIGEST_CTX null_dgst_ctx;
	DIGEST_CTX dgst_ctx;
	uint8_t secret[32];
	uint8_t *early_secret = secret;
	uint8_t *binder_key = secret;
	uint8_t *binder = secret;
	size_t binderlen;
	size_t i;

	if (!psk_cipher_suites || !psk_cipher_suites_cnt
		|| !psk_keys || !psk_keys_len || !truncated_client_hello
		|| !truncated_client_hello_len || !binders || !binders_len) {
		error_print();
		return -1;
	}

	*binders_len = 0;

	for (i = 0; i < psk_cipher_suites_cnt; i++) {
		const BLOCK_CIPHER *cipher;
		const DIGEST *digest;
		const uint8_t *psk_key;
		size_t psk_key_len;

		if (tls13_cipher_suite_get(psk_cipher_suites[i], &cipher, &digest) != 1) {
			error_print();
			return -1;
		}

		if (digest->digest_size != sizeof(secret)) {
			error_print();
			return -1;
		}
		if (digest_init(&null_dgst_ctx, digest) != 1
			|| digest_init(&dgst_ctx, digest) != 1
			|| digest_update(&dgst_ctx, truncated_client_hello, truncated_client_hello_len) != 1) {
			error_print();
			return -1;
		}

		if (tls_uint8array_from_bytes(&psk_key, &psk_key_len, &psk_keys, &psk_keys_len) != 1) {
			error_print();
			return -1;
		}
		if (psk_key_len != digest->digest_size) {
			gmssl_secure_clear(early_secret, sizeof(early_secret));
			error_print();
			return -1;
		}

		// [1]
		tls13_hkdf_extract(digest, zeros, psk_key, early_secret);
		// [2]
		tls13_derive_secret(early_secret, "res binder", &null_dgst_ctx, binder_key);

		tls13_compute_verify_data(binder_key, &dgst_ctx, binder, &binderlen);

		tls_uint8array_to_bytes(binder, binderlen, &binders, binders_len);
	}

	gmssl_secure_clear(secret, sizeof(secret));
	return 1;
}

int tls13_psk_keys_get_first(const uint8_t *keys, size_t keyslen, const uint8_t **key, size_t *keylen)
{
	if (tls_uint8array_from_bytes(key, keylen, &keys, &keyslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_get_pre_shared_key_by_index(const uint8_t *psk_keys, size_t psk_keys_len, int index,
	const uint8_t **psk_key, size_t *psk_key_len)
{
	const uint8_t *key;
	size_t keylen;
	int i;

	for (i = 0; i <= index; i++) {
		if (tls_uint8array_from_bytes(&key, &keylen, &psk_keys, &psk_keys_len) != 1) {
			error_print();
			return -1;
		}
	}
	*psk_key = key;
	*psk_key_len = keylen;
	return 1;
}

int tls_key_exchange_modes_print(FILE *fp, int fmt, int ind, const char *label, int modes)
{
	format_print(fp, fmt, ind, "%s:", label);

	if (modes & TLS_KE_CERT_DHE) {
		fprintf(fp, " CERT_DHE");
	}
	if (modes & TLS_KE_PSK_DHE) {
		fprintf(fp, " PSK_DHE");
	}
	if (modes & TLS_KE_PSK) {
		fprintf(fp, " PSK");
	}
	fprintf(fp, "\n");
	return 1;
}


// 因为CTX中包含很多参数，这些参数有时候设置的并不是很一致，因此在使用之前需要做一些检查
int tls13_ctx_prepare(TLS_CTX *ctx)
{
	size_t i;

	// cipher_suites
	format_print(stderr, 0, 0, "ctx->cipher_suites\n");
	for (i = 0; i < ctx->cipher_suites_cnt; i++) {
		format_print(stderr, 0, 4,  "%s\n", tls_cipher_suite_name(ctx->cipher_suites[i]));
	}
	// supported_groups
	format_print(stderr, 0, 0, "ctx->supported_groups\n");
	for (i = 0; i < ctx->supported_groups_cnt; i++) {
		format_print(stderr, 0, 4, "%s\n", tls_named_curve_name(ctx->supported_groups[i]));
	}
	// signature_algorithms
	format_print(stderr, 0, 0, "ctx->signature_algorithms\n");
	for (i = 0; i < ctx->signature_algorithms_cnt; i++) {
		format_print(stderr, 0, 4, "%s\n", tls_signature_scheme_name(ctx->signature_algorithms[i]));
	}
	// psk_key_exchange_modes
	tls_key_exchange_modes_print(stderr, 0, 0, "psk_key_exchange_modes", ctx->key_exchange_modes);

	// group sm2p256v1 depends on TLS_SM4_GCM_SM3 or TLS_SM4_CCM_SM3
	if (ctx->supported_groups_cnt) {
		if (tls_type_is_in_list(TLS_curve_sm2p256v1, ctx->supported_groups, ctx->supported_groups_cnt)) {
			if (!tls_type_is_in_list(TLS_cipher_sm4_gcm_sm3, ctx->cipher_suites, ctx->cipher_suites_cnt)) {
				error_print();
				return -1;
			}
		}
	}

	if (ctx->supported_groups_cnt && ctx->signature_algorithms_cnt) {
		ctx->key_exchange_modes |= TLS_KE_CERT_DHE;
	}
	tls_key_exchange_modes_print(stderr, 0, 0, "key_exchange_modes", ctx->key_exchange_modes);
	if (!ctx->key_exchange_modes) {
		error_print();
		return -1;
	}

	return 1;
}






int tls13_handshake_prepare(TLS_CONNECT *conn)
{
	if (tls13_ctx_prepare(conn->ctx) != 1) {
		error_print();
		return -1;
	}

	return 1;
}


/*

这里面分为几个不同阶段的密钥


 * early_data
	client_early_traffic_secret
	因为early_data是一个单向的过程，因为只有客户端的密钥，没有服务器端的
	这个密钥完全是在客户端确定的
	客户端用的第一个PSK，就是early_data的密钥


 * handshake的密钥
	client_handshake_traffic_secret
	server_handshake_traffic_secret
	这个过程只用于握手阶段
	客户端必须在接收到ServerHello的时候，才能计算出
	因为在ServerHello中才有 服务器的DH, PSK等信息

	服务器呢？
	服务器是在发送ServerHello的阶段生成密钥

	因此客户端和服务器端都是在ServerHello阶段生成handshake密钥


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



int tls13_generate_early_data_keys(TLS_CONNECT *conn)
{
	uint8_t zeros[32] = {0};
	const uint8_t *first_psk;
	size_t first_psk_len;
	uint8_t early_secret[32];
	uint8_t client_early_traffic_secret[32];
	uint8_t client_write_key[16];

	if (tls13_cipher_suite_get(conn->psk_cipher_suites[0], &conn->cipher, &conn->digest) != 1) {
		error_print();
		return -1;
	}

	if (digest_init(&conn->dgst_ctx, conn->digest) != 1
		|| digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}

	// early_data always encrypted with the first psk
	if (tls13_psk_keys_get_first(conn->psk_keys, conn->psk_keys_len, &first_psk, &first_psk_len) != 1) {
		error_print();
		return -1;
	}

	// psk => client_early_traffic_secret
	tls13_hkdf_extract(conn->digest, zeros, first_psk, early_secret);
	tls13_derive_secret(early_secret, "c e traffic", &conn->dgst_ctx, client_early_traffic_secret);
	tls13_hkdf_expand_label(conn->digest, client_early_traffic_secret, "key", NULL, 0, 16, client_write_key);
	block_cipher_set_encrypt_key(&conn->client_write_key, conn->cipher, client_write_key);
	tls13_hkdf_expand_label(conn->digest, client_early_traffic_secret, "iv", NULL, 0, 12, conn->client_write_iv);
	tls_seq_num_reset(conn->client_seq_num);

	format_print(stderr, 0, 0, "client_write_key/iv <= client_early_traffic_secret\n");
	format_bytes(stderr, 0, 4, "client_early_traffic_secret", client_early_traffic_secret, 32);
	format_bytes(stderr, 0, 4, "client_write_key", client_write_key, 16);
	format_bytes(stderr, 0, 4, "client_write_iv", conn->client_write_iv, 12);

	return 1;
}









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

		// supported_versions
		if (tls13_client_supported_versions_ext_to_bytes(conn->ctx->supported_versions,
			conn->ctx->supported_versions_cnt, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}

		/*
		extensions depends on key_exchange_modes

		switch (key_exchange_mode)
		case CERT_DHE:
			* supported_groups
			* signature_algorithms
			* [key_share]
			* [signature_algorithms_cert]

		case PSK_DHE:
			* supported_groups
			* psk_key_exchange_modes
			* pre_shared_key
			* [key_share]
			* [early_data]
			* [signature_algorithms]
			* [signature_algorithms_cert]

		case PSK:
			* psk_key_exchange_modes
			* pre_shared_key
			* [early_data]
			* [supported_groups]
			* [signature_algorithms]
			* [signature_algorithms_cert]
		*/

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

		// key_share
		if (conn->key_exchange_modes & (TLS_KE_CERT_DHE|TLS_KE_PSK_DHE)) {
			size_t i;
			for (i = 0; i < conn->key_exchanges_cnt && i < conn->ctx->supported_groups_cnt; i++) {
				int curve_oid = tls_named_curve_oid(conn->ctx->supported_groups[i]);
				if (x509_key_generate(&conn->key_exchanges[i],
					OID_ec_public_key, &curve_oid, sizeof(curve_oid)) != 1) {
					error_print();
					tls_send_alert(conn, TLS_alert_internal_error);
					return -1;
				}
			}
			conn->key_exchanges_cnt = i;
			fprintf(stderr, "conn->key_exchanges_cnt = %zu\n", conn->key_exchanges_cnt);

			if (conn->key_exchanges_cnt) {
				if (tls13_key_share_client_hello_ext_to_bytes(conn->key_exchanges,
					conn->key_exchanges_cnt, &pexts, &extslen) != 1) {
					error_print();
					return -1;
				}
			}
		}

		// psk_key_exchange_modes
		if (conn->key_exchange_modes & (TLS_KE_PSK_DHE|TLS_KE_PSK)) {
			if (tls13_psk_key_exchange_modes_ext_to_bytes(conn->key_exchange_modes, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// server_name
		if (conn->server_name_len) {
			if (tls_server_name_ext_to_bytes(conn->server_name, conn->server_name_len, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// status_request
		if (conn->ctx->status_request) {
			if (tls_client_status_request_ext_to_bytes(TLS_certificate_status_type_ocsp,
				conn->ctx->status_request_responder_id_list, conn->ctx->status_request_responder_id_list_len,
				conn->ctx->status_request_exts, conn->ctx->status_request_exts_len,
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

		// early_data
		if (conn->key_exchange_modes & (TLS_KE_PSK_DHE|TLS_KE_PSK)) {
			if (conn->early_data) {
				if (tls13_empty_early_data_ext_to_bytes(&pexts, &extslen) != 1) {
					error_print();
					return -1;
				}
			}
		}

		// pre_shared_key (must be the last extension)
		if (conn->key_exchange_modes & (TLS_KE_PSK_DHE|TLS_KE_PSK)) {
			uint8_t *ptruncated_exts = pexts;
			size_t truncated_extslen = extslen;
			uint8_t binders[256];
			uint8_t *pbinders = binders;
			size_t binderslen = 0;

			if (!conn->psk_identities_len
				|| !conn->psk_keys_len
				|| !conn->psk_cipher_suites_cnt ) {
				error_print();
				return -1;
			}

			// output pre_shared_key ext with empty binders
			if (tls13_psk_generate_empty_binders(
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
			if (tls13_psk_generate_binders(
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

			/*
			const uint8_t *first_psk;
			size_t first_psk_len;
			uint8_t zeros[32] = {0};
			uint8_t early_secret[32];
			uint8_t client_early_traffic_secret[32];
			uint8_t client_write_key[16];

			conn->digest = conn->psk_digests[0];

			if (digest_init(&conn->dgst_ctx, conn->psk_digests[0]) != 1
				|| digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
				error_print();
				return -1;
			}

			// early_data always encrypted with the first psk
			if (tls13_psk_keys_get_first(conn->psk_keys, conn->psk_keys_len, &first_psk, &first_psk_len) != 1) {
				error_print();
				return -1;
			}

			// psk => client_early_traffic_secret
			tls13_hkdf_extract(conn->digest, zeros, first_psk, early_secret);
			tls13_derive_secret(early_secret, "c e traffic", &conn->dgst_ctx, client_early_traffic_secret);
			tls13_hkdf_expand_label(conn->digest, client_early_traffic_secret, "key", NULL, 0, 16, client_write_key);
			block_cipher_set_encrypt_key(&conn->client_write_key, conn->cipher, client_write_key);
			tls13_hkdf_expand_label(conn->digest, client_early_traffic_secret, "iv", NULL, 0, 12, conn->client_write_iv);
			tls_seq_num_reset(conn->client_seq_num);

			format_print(stderr, 0, 0, "client_write_key/iv <= client_early_traffic_secret\n");
			format_bytes(stderr, 0, 4, "client_early_traffic_secret", client_early_traffic_secret, 32);
			format_bytes(stderr, 0, 4, "client_write_key", client_write_key, 16);
			format_bytes(stderr, 0, 4, "client_write_iv", conn->client_write_iv, 12);
			*/

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

int tls13_recv_hello_retry_request(TLS_CONNECT *conn)
{
	int ret;

	// handshake
	int handshake_type;
	const uint8_t *handshake_data;
	size_t handshake_datalen;

	// server_hello
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
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	// is ServerHello ?
	if (tls_record_get_handshake(conn->record,
		&handshake_type, &handshake_data, &handshake_datalen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	}
	if (handshake_type == TLS_handshake_server_hello) {
		tls_trace("    no HelloRetryRequest\n");
		return 0;
	}

	// HelloRetryRequest
	tls13_record_print(stderr, 0, 0, conn->record, conn->recordlen);

	if ((ret = tls13_record_get_handshake_hello_retry_request(conn->record,
		&legacy_version, &random,
		&legacy_session_id_echo, &legacy_session_id_echo_len,
		&cipher_suite, &legacy_compress_meth, &exts, &extslen)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	conn->hello_retry_request = 1;

	// update key_exchange_modes
	conn->key_exchange_modes &= ~TLS_KE_PSK;

	if (!conn->key_exchange_modes) {
		error_print();
		tls_send_alert(conn, TLS_alert_handshake_failure);
		return -1;
	}


	// legacy_version
	if (legacy_version != TLS_protocol_tls12) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	// random
	memcpy(conn->server_random, random, 32);

	// legacy_session_id_echo
	if (legacy_session_id_echo_len != conn->session_id_len
		|| memcmp(legacy_session_id_echo, conn->session_id, conn->session_id_len) != 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}

	// cipher_suite
	if (tls_type_is_in_list(cipher_suite, conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}
	conn->cipher_suite = cipher_suite;
	if (tls13_cipher_suite_get(cipher_suite, &conn->cipher, &conn->digest) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}

	// legacy_compression_method
	if (legacy_compress_meth != 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}

	while (extslen) {
		int ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;

		if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}

		switch (ext_type) {
		case TLS_extension_supported_versions:
		case TLS_extension_key_share:
		case TLS_extension_cookie:
			if (!ext_data) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
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
			if (key_share) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			key_share = ext_data;
			key_share_len = ext_datalen;
			break;

		case TLS_extension_cookie:
			if (cookie) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			cookie = ext_data;
			cookie_len = ext_datalen;
			break;

		default:
			error_print();
			tls_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
	}

	// supported_versions
	if (!supported_versions) {
		error_print();
		tls_send_alert(conn, TLS_alert_missing_extension);
		return -1;
	}
	if (tls13_server_supported_versions_from_bytes(&selected_version,
		supported_versions, supported_versions_len) != 1) {
		tls_send_alert(conn, TLS_alert_decode_error);
		error_print();
		return -1;
	}
	if (tls_type_is_in_list(selected_version,
		conn->ctx->supported_versions, conn->ctx->supported_versions_cnt) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}
	if (selected_version != TLS_protocol_tls13) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}
	conn->protocol = selected_version;


	// key_share
	if (!key_share) {
		error_print();
		tls_send_alert(conn, TLS_alert_missing_extension);
		return -1;
	}
	if (tls13_key_share_hello_retry_request_from_bytes(&key_exchange_group,
		key_share, key_share_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	}
	if (tls_type_is_in_list(key_exchange_group,
		conn->ctx->supported_groups, conn->ctx->supported_groups_cnt) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}
	conn->key_exchange_group = key_exchange_group;

	// cookie
	if (cookie) {
		const uint8_t *cookie_data;
		size_t cookie_datalen;

		if (tls13_cookie_from_bytes(&cookie_data, &cookie_datalen,
			cookie, cookie_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
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

int tls13_send_client_hello_again(TLS_CONNECT *conn)
{
	int ret;

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
		if (rand_bytes(conn->client_random, 32) != 1) {
			error_print();
			return -1;
		}

		// supported_versions
		if (tls13_client_supported_versions_ext_to_bytes(conn->ctx->supported_versions,
			conn->ctx->supported_versions_cnt, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}

		// supported_groups
		if (tls_supported_groups_ext_to_bytes(conn->ctx->supported_groups,
			conn->ctx->supported_groups_cnt, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}

		// signature_algorithms
		if (conn->key_exchange_modes & TLS_KE_CERT_DHE) {
			if (tls_signature_algorithms_ext_to_bytes(conn->ctx->signature_algorithms,
				conn->ctx->signature_algorithms_cnt, &pexts, &extslen) != 1) {
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
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		conn->key_exchange_idx = 0;
		conn->key_exchanges_cnt = 1;

		if (tls13_key_share_client_hello_ext_to_bytes(conn->key_exchanges,
			conn->key_exchanges_cnt, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}

		// cookie
		if (conn->cookie_len) {
			if (tls13_cookie_ext_to_bytes(conn->cookie_buf, conn->cookie_len,
				&pexts, &extslen) != 1) {
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

		tls_trace("send ClientHello again\n");
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
	size_t supported_versions_len = 0;
	const uint8_t *supported_groups = NULL;
	size_t supported_groups_len = 0;
	const uint8_t *key_share = NULL;
	size_t key_share_len = 0;
	const uint8_t *pre_shared_key = NULL;
	size_t pre_shared_key_len = 0;

	int selected_version;

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
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}
	if ((ret = tls_record_get_handshake_server_hello(conn->record,
		&legacy_version, &random,
		&legacy_session_id_echo, &legacy_session_id_echo_len,
		&cipher_suite, &exts, &extslen)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	// legacy_version
	if (legacy_version != TLS_protocol_tls12) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	// random
	memcpy(conn->server_random, random, 32);

	// legacy_session_id_echo
	if (legacy_session_id_echo_len != conn->session_id_len
		|| memcmp(legacy_session_id_echo, conn->session_id, conn->session_id_len) != 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}

	// cipher_suite
	if (conn->hello_retry_request) {
		if (cipher_suite != conn->cipher_suite) {
			error_print();
			tls_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
	} else {
		if (tls_type_is_in_list(cipher_suite,
			conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
		conn->cipher_suite = cipher_suite;
		if (tls13_cipher_suite_get(cipher_suite, &conn->cipher, &conn->digest) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
	}

	while (extslen) {
		int ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;

		if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}

		switch (ext_type) {
		case TLS_extension_supported_versions:
		case TLS_extension_key_share:
		case TLS_extension_pre_shared_key:
			if (!ext_data) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			break;
		}

		switch (ext_type) {
		case TLS_extension_supported_versions:
			if (supported_versions) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			supported_versions = ext_data;
			supported_versions_len = ext_datalen;
			break;

		case TLS_extension_key_share:
			if (key_share) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			key_share = ext_data;
			key_share_len = ext_datalen;
			break;

		case TLS_extension_pre_shared_key:
			if (pre_shared_key) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			pre_shared_key = ext_data;
			pre_shared_key_len = ext_datalen;
			break;

		// extensions MUST NOT exist
		case TLS_extension_supported_groups:
		case TLS_extension_signature_algorithms:
		case TLS_extension_server_name:
			error_print();
			tls_send_alert(conn, TLS_alert_illegal_parameter);
			break;

		default:
			warning_print();
		}
	}

	// supported_versions
	if (!supported_versions) {
		error_print();
		tls_send_alert(conn, TLS_alert_missing_extension);
		return -1;
	}
	if (tls13_server_supported_versions_from_bytes(
		&selected_version, supported_versions, supported_versions_len) != 1) {
		tls_send_alert(conn, TLS_alert_decode_error);
		error_print();
		return -1;
	}
	if (conn->hello_retry_request) {
		if (selected_version != conn->protocol) {
			error_print();
			tls_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
	} else {
		if (tls_type_is_in_list(selected_version,
			conn->ctx->supported_versions, conn->ctx->supported_versions_cnt) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
		if (selected_version != TLS_protocol_tls13) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
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
			tls_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
		if (tls13_key_share_server_hello_from_bytes(&key_exchange_group,
			&key_exchange, &key_exchange_len, key_share, key_share_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}
		while (conn->key_exchange_idx < conn->key_exchanges_cnt) {
			if (conn->key_exchanges[conn->key_exchange_idx].algor_param ==
				tls_named_curve_oid(key_exchange_group)) {
				break;
			}
			conn->key_exchange_idx++;
		}
		if (conn->key_exchange_idx >= conn->key_exchanges_cnt) {
			error_print();
			tls_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
		if (key_exchange_len != 65) {
			error_print();
			tls_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
		conn->key_exchange_group = key_exchange_group;
		memcpy(conn->peer_key_exchange, key_exchange, key_exchange_len);
		conn->peer_key_exchange_len = 65;
	}

	// pre_shared_key
	if (pre_shared_key) {
		int selected_identity;
		const uint8_t *key;
		size_t keylen;

		if (!conn->psk_identities_len) {
			error_print();
			tls_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
		if (tls13_server_pre_shared_key_from_bytes(&selected_identity,
			pre_shared_key, pre_shared_key_len) != 1) {
			error_print();
			return -1;
		}
		if (tls13_get_pre_shared_key_by_index(conn->psk_keys, conn->psk_keys_len,
			selected_identity, &key, &keylen) != 1) {
			error_print();
			return -1;
		}

		memcpy(conn->psk, key, keylen);
		conn->psk_len = keylen;
	}

	/*
	key_exchange_modes

	PSK_DHE
		* pre_shared_key
		* key_share

	PSK
		* pre_shared_key

	CERT_DHE
		* key_share
	*/
	if (pre_shared_key && key_share) {
		conn->key_exchange_modes &= TLS_KE_PSK_DHE;
	} else if(pre_shared_key) {
		conn->key_exchange_modes &= TLS_KE_PSK;
	} else {
		conn->key_exchange_modes &= TLS_KE_CERT_DHE;
	}
	if (!conn->key_exchange_modes) {
		error_print();
		return -1;
	}

	if (!conn->hello_retry_request) {
		if (digest_init(&conn->dgst_ctx, conn->digest) != 1
			|| digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
			error_print();
			return -1;
		}
	}
	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}

	// 这里怎么没有更新服务器的seq_num

	if (conn->client_certs_len) {
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);
	}

	// 接受到ServerHello之后，双方已经可以确定握手阶段的密钥了
	// 但是服务器端的握手密钥可以初始化了，客户端的必须等到send_end_of_early_data完成的时候才能变更



	if (tls13_generate_handshake_keys(conn) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int tls13_send_end_of_early_data(TLS_CONNECT *conn)
{
	int ret;

	if (!conn->recordlen) {
		if (tls13_record_set_handshake_end_of_early_data(conn->plain_record, &conn->plain_recordlen) != 1) {
			error_print();
			return -1;
		}
		tls_trace("send EndOfEarlyData\n");

		format_bytes(stderr, 0, 4, "client_write_iv", conn->client_write_iv, 12);

		size_t padding_len;
		tls13_padding_len_rand(&padding_len);
		if (tls13_record_encrypt(&conn->client_write_key, conn->client_write_iv,
			conn->client_seq_num, conn->plain_record, conn->plain_recordlen, padding_len,
			conn->record, &conn->recordlen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
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


	uint8_t client_write_key[16];
	tls13_hkdf_expand_label(conn->digest, conn->client_handshake_traffic_secret, "key", NULL, 0, 16, client_write_key);
	block_cipher_set_encrypt_key(&conn->client_write_key, conn->cipher, client_write_key);
	tls13_hkdf_expand_label(conn->digest, conn->client_handshake_traffic_secret, "iv", NULL, 0, 12, conn->client_write_iv);
	tls_seq_num_reset(conn->client_seq_num);

	// client_early_traffic_secret 用来加密early_data, end_of_early_data
	format_print(stderr, 0, 0, "client_write_key/iv <= client_handshake_traffic_secret\n");
	format_bytes(stderr, 0, 4, "client_handshake_traffic_secret", conn->client_handshake_traffic_secret, 32);
	format_bytes(stderr, 0, 4, "client_write_key", client_write_key, 16);
	format_bytes(stderr, 0, 4, "client_write_iv", conn->client_write_iv, 12);

	tls_clean_record(conn);
	return 1;

}























int tls13_recv_encrypted_extensions(TLS_CONNECT *conn)
{
	int ret;
	const uint8_t *exts;
	size_t extslen;

	const uint8_t *supported_groups = NULL;
	size_t supported_groups_len;
	const uint8_t *alpn = NULL;
	size_t alpn_len;
	const uint8_t *max_fragment_length = NULL;
	size_t max_fragment_length_len;
	const uint8_t *record_size_limit = NULL;
	size_t record_size_limit_len;

	int server_name = 0;
	int early_data = 0;
	int padding = 0;

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
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

	if ((ret = tls13_record_get_handshake_encrypted_extensions(conn->plain_record,
		&exts, &extslen)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	while (extslen) {
		int ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;

		if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}

		switch (ext_type) {
		case TLS_extension_supported_groups:
		case TLS_extension_application_layer_protocol_negotiation:
		case TLS_extension_max_fragment_length:
		case TLS_extension_record_size_limit:
			if (!ext_data) {
				error_print();
				return -1;
			}
		}

		switch (ext_type) {
		case TLS_extension_supported_groups:
			if (supported_groups) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			break;

		case TLS_extension_server_name:
			if (server_name) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			if (ext_data) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			break;

		case TLS_extension_early_data:
			if (early_data) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			if (ext_data) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			early_data = 1;
			break;

		case TLS_extension_application_layer_protocol_negotiation:
			if (alpn) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			alpn = ext_data;
			alpn_len = ext_datalen;
			break;

		case TLS_extension_max_fragment_length:
			if (max_fragment_length) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			max_fragment_length = ext_data;
			max_fragment_length_len = ext_datalen;
			break;

		case TLS_extension_record_size_limit:
			if (record_size_limit) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			record_size_limit = ext_data;
			record_size_limit_len = ext_datalen;
			break;

		case TLS_extension_padding:
			if (padding) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			padding = 1;
			break;

		// extensions must not be included
		case TLS_extension_supported_versions:
		case TLS_extension_key_share:
		case TLS_extension_psk_key_exchange_modes:
		case TLS_extension_pre_shared_key:
		case TLS_extension_signature_algorithms:
		case TLS_extension_certificate_authorities:
		case TLS_extension_status_request:
		case TLS_extension_signed_certificate_timestamp:
			error_print();
			tls_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
	}

	// server_name
	if (server_name) {
		if (!conn->server_name_len) {
			error_print();
			tls_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
	}

	// early_data
	if (early_data) {
		if (!conn->early_data) {
			error_print();
			tls_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
	}

	if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
		error_print();
		return -1;
	}

	tls_seq_num_incr(conn->server_seq_num);

	return 1;
}

int tls_cert_chain_check_signature_algorithms_cert(const uint8_t *cert_chain, size_t cert_chain_len,
	const int *signature_algorithms_cert, size_t signature_algorithms_cert_cnt)
{
	int sig_algs_cert[16];
	int sig_alg;
	size_t i;

	if (!cert_chain || !cert_chain_len) {
		error_print();
		return -1;
	}
	if (!signature_algorithms_cert && signature_algorithms_cert_cnt) {
		error_print();
		return -1;
	}
	if (signature_algorithms_cert_cnt > sizeof(sig_algs_cert)/sizeof(sig_algs_cert[0])) {
		error_print();
		return -1;
	}

	for (i = 0; i < signature_algorithms_cert_cnt; i++) {
		if (!(sig_algs_cert[i] = tls_signature_scheme_algorithm_oid(signature_algorithms_cert[i]))) {
			error_print();
			return -1;
		}
	}
	while (cert_chain_len) {
		const uint8_t *cert;
		size_t certlen;
		int oid;

		if (x509_cert_from_der(&cert, &certlen, &cert_chain, &cert_chain_len) != 1
			|| x509_cert_get_signature_algor(cert, certlen, &oid) != 1) {
			error_print();
			return -1;
		}
		if (!tls_type_is_in_list(oid, sig_algs_cert, signature_algorithms_cert_cnt)) {
			return 0;
		}
	}

	return 1;
}


/*
关于证书的签名算法

	在 ClientHello/ServerHello 的握手中
	双方可以确定共享的signature_algorithms
	服务器可以根据签名算法选择出一个证书链，这个证书链决定
	服务器端可选的签名算法是共享算法中的一个子集（可能不唯一）
	服务器需要进一步确定具体选择哪个算法

	客户端在接收到服务器的证书链之后，实际上是不能确定算法的
	客户端应该在接收到服务器的验证之后再决定签名算法是什么


	因此这个函数返回证书，应该根据证书，确定支持的签名算法的子集


	因此

	* 服务器在接收到ClientHello之后就可以确定自己的签名算法了conn->sig_alg
	* 客户端在接收到ServerCertificate之后还不能确定签名算法
	* 客户端在接收到CertificateVerify之后，可以显式获得签名算法


	这个函数有两个使用场景

	* 服务器根据公共参数，从多个证书链中选择一个证书链，以及对应的签名算法

	* 客户端验证服务器的证书链是否满足ClientHello中提供的条件
	  在这种情况下，客户端不需要获得选择的结果

*/

int tls13_server_cert_chains_select(const uint8_t *cert_chains, size_t cert_chains_len,
	const int *signature_algorithms, size_t signature_algorithms_cnt,
	const int *signature_algorithms_cert, size_t signature_algorithms_cert_cnt, // optional
	const uint8_t *server_name, size_t server_name_len, // optional
	const uint8_t **certs, size_t *certs_len, int *certs_idx, int *prefered_sig_alg) // optional
{
	int ret;
	X509_KEY subject_public_key;
	const uint8_t *subject_dns_name;
	size_t subject_dns_name_len;
	int sig_algs[16];
	int sig_alg;
	size_t i;

	if (!cert_chains || !cert_chains_len || !signature_algorithms || !signature_algorithms_cnt
		|| !certs || !certs_len) {
		error_print();
		return -1;
	}

	// prepare signature_algorithms oid
	if (signature_algorithms_cnt > sizeof(sig_algs)/sizeof(sig_algs[0])) {
		error_print();
		return -1;
	}
	for (i = 0; i < signature_algorithms_cnt; i++) {
		if (!(sig_algs[i] = tls_signature_scheme_algorithm_oid(signature_algorithms[i]))) {
			error_print();
			return -1;
		}
	}

	for (i = 0; cert_chains_len; i++) {
		const uint8_t *cert_chain;
		size_t cert_chain_len;
		const uint8_t *cert;
		size_t certlen;

		if (tls_uint24array_from_bytes(&cert_chain, &cert_chain_len, &cert_chains, &cert_chains_len) != 1) {
			error_print();
			return -1;
		}
		if (x509_certs_get_cert_by_index(cert_chain, cert_chain_len, 0, &cert, &certlen) != 1
			|| x509_cert_get_subject_public_key(cert, certlen, &subject_public_key) != 1
			|| x509_key_get_sign_algor(&subject_public_key, &sig_alg) != 1
			|| x509_cert_get_subject_alt_name_dns_name(cert, certlen, &subject_dns_name, &subject_dns_name_len) < 0) {
			error_print();
			return -1;
		}

		// check first cert signature_algorithms
		if (!tls_type_is_in_list(sig_alg, sig_algs, signature_algorithms_cnt)) {
			continue;
		}

		// check first cert host_name (SNI)
		if (server_name && server_name_len && subject_dns_name) {
			if (subject_dns_name_len != server_name_len
				|| memcmp(subject_dns_name, server_name, server_name_len) != 0) {
				continue;
			}
		}

		// check cert_chain signature_algorithms_cert
		if (signature_algorithms_cert && signature_algorithms_cert_cnt) {
			if ((ret = tls_cert_chain_check_signature_algorithms_cert(cert_chain, cert_chain_len,
				signature_algorithms_cert, signature_algorithms_cert_cnt)) < 0) {
				error_print();
				return -1;
			} else if (ret == 0) {
				continue;
			}
		}

		if (certs) *certs = cert_chain;
		if (certs_len) *certs_len = cert_chain_len;
		if (certs_idx) *certs_idx = i;
		if (prefered_sig_alg) *prefered_sig_alg = sig_alg;

		return 1;
	}

	if (certs) *certs = NULL;
	if (certs_len) *certs_len = 0;
	if (certs_idx) *certs_idx = -1;
	if (prefered_sig_alg) *prefered_sig_alg = 0;

	return 0;
}

/*

	* 客户端根据服务器的要求，从自己的备选证书链中选择一个证书链，确定签名的密钥
	  客户端同时可以确定签名算法

	* 服务器端确定客户端的证书链和自己要求的是否一致


*/

int tls13_client_cert_chains_select(const uint8_t *cert_chains, size_t cert_chains_len,
	const int *signature_algorithms, size_t signature_algorithms_cnt,
	const int *signature_algorithms_cert, size_t signature_algorithms_cert_cnt, // optional
	const uint8_t *certificate_authorities, size_t certificate_authorities_len, // optional
	const uint8_t **certs, size_t *certs_len, int *certs_idx, int *prefered_sig_alg) // optional
{
	int ret;
	X509_KEY subject_public_key;
	int sig_algs[16];
	int sig_alg;
	size_t i;

	if (!cert_chains || !cert_chains_len || !signature_algorithms || !certs || !certs_len) {
		error_print();
		return -1;
	}

	if (!signature_algorithms_cnt) {
		if (certs) *certs = NULL;
		if (certs_len) *certs_len = 0;
		if (certs_idx) *certs_idx = -1;
		if (prefered_sig_alg) *prefered_sig_alg = 0;
		return 0;
	}
	if (signature_algorithms_cert && !signature_algorithms_cert_cnt) {
		if (certs) *certs = NULL;
		if (certs_len) *certs_len = 0;
		if (certs_idx) *certs_idx = -1;
		if (prefered_sig_alg) *prefered_sig_alg = 0;
		return 0;
	}

	// prepare signature_algorithms oid
	if (signature_algorithms_cnt > sizeof(sig_algs)/sizeof(sig_algs[0])) {
		error_print();
		return -1;
	}
	for (i = 0; i < signature_algorithms_cnt; i++) {
		if (!(sig_algs[i] = tls_signature_scheme_algorithm_oid(signature_algorithms[i]))) {
			error_print();
			return -1;
		}
	}

	for (i = 0; cert_chains_len; i++) {
		const uint8_t *cert_chain;
		size_t cert_chain_len;
		const uint8_t *cert;
		size_t certlen;

		if (tls_uint24array_from_bytes(&cert_chain, &cert_chain_len, &cert_chains, &cert_chains_len) != 1) {
			error_print();
			return -1;
		}

		// check first cert's public key match signature_algorithms
		if (x509_certs_get_cert_by_index(cert_chain, cert_chain_len, 0, &cert, &certlen) != 1
			|| x509_cert_get_subject_public_key(cert, certlen, &subject_public_key) != 1
			|| x509_key_get_sign_algor(&subject_public_key, &sig_alg) != 1) {
			error_print();
			return -1;
		}
		if (!tls_type_is_in_list(sig_alg, sig_algs, signature_algorithms_cnt)) {
			continue;
		}

		// check cert_chain match signature_algorithms_cert
		if (signature_algorithms_cert) {
			if ((ret = tls_cert_chain_check_signature_algorithms_cert(cert_chain, cert_chain_len,
				signature_algorithms_cert, signature_algorithms_cert_cnt)) < 0) {
				error_print();
				return -1;
			} else if (ret == 0) {
				continue;
			}
		}

		// check issuer of last cert in certificate_authorities
		if (certificate_authorities) {
			if (x509_certs_get_last(cert_chain, cert_chain_len, &cert, &certlen) != 1) {
				error_print();
				return -1;
			}
			if ((ret = tls_authorities_issued_certificate(certificate_authorities,
				certificate_authorities_len, cert, certlen)) < 0) {
				error_print();
				return -1;
			} else if (ret == 0) {
				continue;
			}
		}

		if (certs) *certs = cert_chain;
		if (certs_len) *certs_len = cert_chain_len;
		if (certs_idx) *certs_idx = i;
		if (prefered_sig_alg) *prefered_sig_alg = sig_alg;

		return 1;
	}

	if (certs) *certs = NULL;
	if (certs_len) *certs_len = 0;
	if (certs_idx) *certs_idx = -1;
	if (prefered_sig_alg) *prefered_sig_alg = 0;

	return 0;
}

int tls13_recv_certificate_request(TLS_CONNECT *conn)
{
	int ret;
	int handshake_type;
	const uint8_t *handshake_data;
	size_t handshake_datalen;

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

	int common_sig_algs[4];
	size_t common_sig_algs_cnt;
	int common_sig_algs_cert[4];
	size_t common_sig_algs_cert_cnt;

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
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}

	if (tls_record_get_handshake(conn->plain_record,
		&handshake_type, &handshake_data, &handshake_datalen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	}
	if (handshake_type == TLS_handshake_certificate) {
		tls_trace("    no {CertificateRequest}\n");
		return 0;
	}

	tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

	if ((ret = tls13_record_get_handshake_certificate_request(conn->plain_record,
		&request_context, &request_context_len, &exts, &extslen)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return 0;
	}


	if (request_context) {
		// request_context must be null in full/initial handshake
		// and must not be null in post authentication handshakes
		error_print();
		tls_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}

	while (extslen) {
		int ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;

		if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}

		switch (ext_type) {
		case TLS_extension_signature_algorithms:
		case TLS_extension_signature_algorithms_cert:
		case TLS_extension_certificate_authorities:
		case TLS_extension_oid_filters:
			if (!ext_data) {
				error_print();
				return -1;
			}
		}

		switch (ext_type) {
		case TLS_extension_signature_algorithms:
			if (signature_algorithms) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			signature_algorithms = ext_data;
			signature_algorithms_len = ext_datalen;
			break;

		case TLS_extension_signature_algorithms_cert:
			if (signature_algorithms_cert) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			signature_algorithms_cert = ext_data;
			signature_algorithms_cert_len = ext_datalen;
			break;

		case TLS_extension_certificate_authorities:
			if (certificate_authorities) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			certificate_authorities = ext_data;
			certificate_authorities_len = ext_datalen;
			break;

		case TLS_extension_oid_filters:
			if (oid_filters) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			oid_filters = ext_data;
			oid_filters_len = ext_datalen;
			break;

		default:
			error_print();
			return -1;
		}
	}

	ret = 1;

	// local cert_chain
	if (!conn->ctx->cert_chains_len) {
		ret = 0;
	}

	// signature_algorithms
	if (!signature_algorithms) {
		error_print();
		tls_send_alert(conn, TLS_alert_missing_extension);
		return -1;
	}
	if (tls_process_signature_algorithms(signature_algorithms, signature_algorithms_len,
		conn->ctx->signature_algorithms, conn->ctx->signature_algorithms_cnt,
		common_sig_algs, &common_sig_algs_cnt,
		sizeof(common_sig_algs)/sizeof(common_sig_algs[0])) < 0) {
		error_print();
		return -1;
	}
	if (!common_sig_algs_cnt) {
		ret = 0;
	}

	// signature_algorithms_cert
	if (signature_algorithms_cert) {
		if (tls_process_signature_algorithms(signature_algorithms_cert, signature_algorithms_cert_len,
			conn->ctx->signature_algorithms, conn->ctx->signature_algorithms_cnt,
			common_sig_algs_cert, &common_sig_algs_cert_cnt,
			sizeof(common_sig_algs_cert)/sizeof(common_sig_algs_cert[0])) < 0) {
			error_print();
			return -1;
		}
		if (!common_sig_algs_cert_cnt) {
			ret = 0;
		}
	}

	if (ret) {
		// 如果没有找到合适的证书应该怎么处理				
		if ((ret = tls13_client_cert_chains_select(conn->ctx->cert_chains, conn->ctx->cert_chains_len,
			common_sig_algs, common_sig_algs_cnt,
			common_sig_algs_cert, common_sig_algs_cert_cnt,
			certificate_authorities, certificate_authorities_len,
			&conn->cert_chain, &conn->cert_chain_len, &conn->cert_chain_idx, &conn->sig_alg)) < 0) {
			error_print();
			return -1;
		}
	}

	if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	tls_seq_num_incr(conn->server_seq_num);

	conn->certificate_request = 1;

	return ret;
}

int tls13_recv_server_certificate(TLS_CONNECT *conn)
{
	int ret;
	const uint8_t *request_context;
	size_t request_context_len;
	const uint8_t *entity_status_request_ocsp_response;
	size_t entity_status_request_ocsp_response_len;
	const uint8_t *entity_signed_certificate_timestamp;
	size_t entity_signed_certificate_timestamp_len;
	const uint8_t *cert;
	size_t certlen;
	/*
	const uint8_t *cp;
	size_t len = 0;
	int i;
	*/

	tls_trace("recv {Certificate}\n");

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
			tls_send_alert(conn, TLS_alert_bad_record_mac);
			return -1;
		}
	}
	tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

	if ((ret = tls13_record_get_handshake_certificate(conn->plain_record,
		&request_context, &request_context_len,
		conn->server_certs, &conn->server_certs_len, sizeof(conn->server_certs),
		&entity_status_request_ocsp_response, &entity_status_request_ocsp_response_len,
		&entity_signed_certificate_timestamp, &entity_signed_certificate_timestamp_len)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return 0;
	}
	if (request_context) {
		error_print();
		tls_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}
	if (!conn->server_certs_len) {
		error_print();
		tls_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}

	// check entity cert extensions
	if (entity_status_request_ocsp_response) {
		if (ocsp_response_verify(entity_status_request_ocsp_response, entity_status_request_ocsp_response_len,
			conn->ctx->cacerts, conn->ctx->cacertslen) != 1) {
			error_print();
			return -1;
		}
	}
	if (entity_signed_certificate_timestamp) {
		// TODO: check
	}

	// check extensions matching
	if (tls13_server_cert_chains_select(
		conn->server_certs, conn->server_certs_len,
		conn->ctx->signature_algorithms, conn->ctx->signature_algorithms_cnt,
		conn->ctx->signature_algorithms, conn->ctx->signature_algorithms_cnt,
		conn->server_name, conn->server_name_len,
		NULL, NULL, NULL, NULL) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}

	int verify_result;
	if (x509_certs_verify(conn->server_certs, conn->server_certs_len, X509_cert_chain_server,
		conn->ctx->cacerts, conn->ctx->cacertslen, conn->ctx->verify_depth, &verify_result) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}

	if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	tls_seq_num_incr(conn->server_seq_num);

	return 1;
}

int tls13_recv_certificate_verify(TLS_CONNECT *conn)
{
	int ret;
	int sig_alg;
	const uint8_t *sig;
	size_t siglen;
	const uint8_t *cert;
	size_t certlen;
	X509_KEY public_key;

	tls_trace("recv {CertificateVerify}\n");

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
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

	if ((ret = tls13_record_get_handshake_certificate_verify(conn->plain_record,
		&sig_alg, &sig, &siglen)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (tls_type_is_in_list(sig_alg, conn->ctx->signature_algorithms,
		conn->ctx->signature_algorithms_cnt) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}
	if (!sig) {
		error_print();
		tls_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}

	if (x509_certs_get_cert_by_index(conn->server_certs, conn->server_certs_len, 0, &cert, &certlen) != 1
		|| x509_cert_get_subject_public_key(cert, certlen, &public_key) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
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
	tls_seq_num_incr(conn->server_seq_num);

	return 1;
}

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

	tls_trace("recv {Finished}\n");
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
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);
	if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	tls_seq_num_incr(conn->server_seq_num);

	if ((ret = tls13_record_get_handshake_finished(conn->plain_record,
		&server_verify_data, &server_verify_data_len)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	if (server_verify_data_len != verify_data_len
		|| memcmp(server_verify_data, verify_data, verify_data_len) != 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
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
	format_print(stderr, 0, 0, "\n");

	tls_seq_num_reset(conn->server_seq_num);

	return 1;
}

int tls13_send_client_certificate(TLS_CONNECT *conn)
{
	int ret;

	tls_trace("send {Certificate*}\n");

	if (!conn->recordlen) {
		size_t padding_len;
		uint8_t *request_context = NULL;
		size_t request_context_len = 0;
		uint8_t *entity_status_request_ocsp_response = NULL;
		size_t entity_status_request_ocsp_response_len = 0;
		uint8_t *entity_signed_certificate_timestamp = NULL;
		size_t entity_signed_certificate_timestamp_len = 0;

		if (tls13_record_set_handshake_certificate(conn->plain_record, &conn->plain_recordlen,
			request_context, request_context_len,
			conn->client_certs, conn->client_certs_len,
			entity_status_request_ocsp_response, entity_status_request_ocsp_response_len,
			entity_signed_certificate_timestamp, entity_signed_certificate_timestamp_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

		if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
			error_print();
			return -1;
		}

		format_bytes(stderr, 0, 0, "client_seq_num", conn->client_seq_num, 8);

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

// 为什么要有一个单独的send_client_certificate_verify
int tls13_send_client_certificate_verify(TLS_CONNECT *conn)
{
	int ret;


	// 这里需要一个单独的处理，因此需要单独的
	if (conn->is_client && !conn->cert_chain) {
		tls_trace("omit {CertificateVerify*}\n");
		return 0;
	}

	tls_trace("send {CertificateVerify*}\n");

	if (!conn->recordlen) {
		X509_KEY *sign_key = &conn->ctx->x509_keys[conn->cert_chain_idx];
		int sig_alg = 0;
		uint8_t sig[256];
		size_t siglen;
		size_t padding_len;
		size_t i;

		// use the first matching sig_alg
		for (i = 0; i < conn->ctx->signature_algorithms_cnt; i++) {
			if (tls_signature_scheme_group_oid(conn->ctx->signature_algorithms[i]) == sign_key->algor_param) {
				sig_alg = conn->ctx->signature_algorithms[i];
				break;
			}
		}
		if (!sig_alg) {
			error_print();
			return -1;
		}

		if (tls13_sign_certificate_verify(TLS_client_mode, sig_alg,
			sign_key, &conn->dgst_ctx, sig, &siglen) != 1) {
			error_print();
			return -1;
		}

		if (tls13_record_set_handshake_certificate_verify(
			conn->plain_record, &conn->plain_recordlen,
			sig_alg, sig, siglen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
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

	tls_seq_num_incr(conn->client_seq_num);

	return 1;
}

int tls13_send_client_finished(TLS_CONNECT *conn)
{
	int ret;
	uint8_t client_write_key[16];

	tls_trace("send {Finished}\n");

	if (!conn->recordlen) {
		uint8_t verify_data[64];
		size_t verify_data_len;
		size_t padding_len;

		tls13_compute_verify_data(conn->client_handshake_traffic_secret, &conn->dgst_ctx,
			verify_data, &verify_data_len);

		if (tls_record_set_handshake_finished(conn->plain_record, &conn->plain_recordlen,
			verify_data, verify_data_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
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


// 我们一般不可能实现知道消息是NewSessionTicket
// 在解密ApplicationData才能确定
int tls13_recv_new_session_ticket(TLS_CONNECT *conn)
{
	int ret;
	int handshake_type;
	const uint8_t *handshake_data;
	size_t handshake_datalen;

	uint32_t ticket_lifetime;
	uint32_t ticket_age_add;
	const uint8_t *ticket_nonce;
	size_t ticket_nonce_len;
	const uint8_t *ticket;
	size_t ticketlen;
	const uint8_t *exts;
	size_t extslen;
	size_t max_early_data_size;
	const uint8_t *cp;
	size_t len;


	// 可以在这里判断是否已经收到并且解密了消息，略过前面的工作
	// 直接跳转到tls13_record_get_handshake_new_session_ticket

	tls_trace("recv {NewSessionTicket*}\n");

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
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);
	tls_seq_num_incr(conn->server_seq_num);

	if (tls_record_get_handshake(conn->plain_record,
		&handshake_type, &handshake_data, &handshake_datalen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	}
	if (handshake_type != TLS_handshake_new_session_ticket) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	// only cheching encoding
	if ((ret = tls13_record_get_handshake_new_session_ticket(conn->plain_record,
		&ticket_lifetime, &ticket_age_add, &ticket_nonce, &ticket_nonce_len,
		&ticket, &ticketlen, &exts, &extslen)) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	}

	if (!ticket_lifetime || ticket_lifetime > 60 * 60 * 24 * 7) {
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
		case TLS_extension_early_data:
			if (tls13_early_data_from_bytes(&max_early_data_size, ext_data, ext_datalen) != 1) {
				error_print();
				return -1;
			}
			break;
		default:
			error_print();
			return -1;
		}
	}

	uint8_t resumption_master_secret[48];
	size_t dgstlen = 32;
	uint8_t pre_shared_key[32];

	// generate resumption_master_secret
	/* [14] */ tls13_derive_secret(conn->master_secret, "res master", &conn->dgst_ctx, resumption_master_secret);

	// pre_shared_key = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)
	tls13_hkdf_expand_label(conn->digest, resumption_master_secret, "resumption",
		ticket_nonce, ticket_nonce_len, dgstlen, pre_shared_key);

	uint8_t session[512];
	uint8_t *p = session;
	size_t sessionlen = 0;

	uint32_t ticket_issue_time = time(NULL);

	if (tls13_session_to_bytes(conn->protocol, conn->cipher_suite, pre_shared_key, 32,
		ticket_issue_time, ticket_lifetime, ticket_age_add, ticket, ticketlen,
		&p, &sessionlen) != 1) {
		error_print();
		return -1;
	}
	tls13_session_print(stderr, 0, 0, "SESSION", session, sessionlen);

	if (conn->session_out) {
		FILE *fp;
		if (!(fp = fopen(conn->session_out, "wb"))) {
			error_print();
			return -1;
		}
		if (fwrite(session, 1, sessionlen, fp) != sessionlen) {
			error_print();
			fclose(fp);
			return -1;
		}
		fclose(fp);
	}

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
	int common_key_exchange_modes = 0;
	const uint8_t *host_name = NULL;
	size_t host_name_len;


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
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}
	if ((ret = tls_record_get_handshake_client_hello(conn->record,
		&legacy_version, &random, &legacy_session_id, &legacy_session_id_len,
		&cipher_suites, &cipher_suites_len, &exts, &extslen)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	// legacy_version
	if (legacy_version != TLS_protocol_tls12) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
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
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_handshake_failure);
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
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}
		switch (ext_type) {
		case TLS_extension_supported_versions:
		case TLS_extension_supported_groups:
		case TLS_extension_signature_algorithms:
		case TLS_extension_signature_algorithms_cert:
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
		case TLS_extension_early_data:
		case TLS_extension_signed_certificate_timestamp:
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
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			supported_versions = ext_data;
			supported_versions_len = ext_datalen;
			break;

		case TLS_extension_supported_groups:
			if (supported_groups) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			supported_groups = ext_data;
			supported_groups_len = ext_datalen;
			break;

		case TLS_extension_signature_algorithms:
			if (signature_algorithms) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			signature_algorithms = ext_data;
			signature_algorithms_len = ext_datalen;
			break;

		case TLS_extension_signature_algorithms_cert:
			if (signature_algorithms_cert) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			signature_algorithms_cert = ext_data;
			signature_algorithms_cert_len = ext_datalen;
			break;

		case TLS_extension_key_share:
			if (key_share) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			key_share = ext_data;
			key_share_len = ext_datalen;
			break;

		case TLS_extension_server_name:
			if (server_name) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			server_name = ext_data;
			server_name_len = ext_datalen;
			break;

		case TLS_extension_psk_key_exchange_modes:
			if (psk_key_exchange_modes) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			psk_key_exchange_modes = ext_data;
			psk_key_exchange_modes_len = ext_datalen;
			break;

		case TLS_extension_pre_shared_key:
			if (pre_shared_key) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			pre_shared_key = ext_data;
			pre_shared_key_len = ext_datalen;
			break;

		case TLS_extension_status_request:
			if (status_request) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			status_request = ext_data;
			status_request_len = ext_datalen;
			break;

		case TLS_extension_signed_certificate_timestamp:
			if (signed_certificate_timestamp) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			signed_certificate_timestamp = 1;
			break;

		case TLS_extension_early_data:
			if (early_data) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			early_data = 1;
			break;

		default:
			warning_print();
		}
	}

	// supported_versions
	if (!supported_versions) {
		error_print();
		tls_send_alert(conn, TLS_alert_missing_extension);
		return -1;
	}
	if ((ret = tls13_process_client_supported_versions(
		supported_versions, supported_versions_len,
		conn->ctx->supported_versions, conn->ctx->supported_versions_cnt,
		common_versions, &common_versions_cnt,
		sizeof(common_versions)/sizeof(common_versions[0]))) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}
	if (common_versions[0] != TLS_protocol_tls13) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
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
	if (supported_groups && signature_algorithms) {
		common_key_exchange_modes |= TLS_KE_CERT_DHE;
	}

	// the final common key_exchang_modes
	common_key_exchange_modes &= conn->key_exchange_modes;

	// no common modes
	if (!common_key_exchange_modes) {
		error_print();
		tls_send_alert(conn, TLS_alert_handshake_failure);
		return -1;
	}

	// supported_groups
	if (supported_groups) {
		if (common_key_exchange_modes & (TLS_KE_CERT_DHE|TLS_KE_PSK_DHE)) {
			if (tls_process_supported_groups(
				supported_groups, supported_groups_len,
				conn->ctx->supported_groups, conn->ctx->supported_groups_cnt,
				common_groups, &common_groups_cnt,
				sizeof(common_groups)/sizeof(common_groups[0])) < 0) {
				error_print();
				tls_send_alert(conn, TLS_alert_decode_error);
				return -1;
			}
			if (!common_groups_cnt) {
				common_key_exchange_modes &= ~(TLS_KE_CERT_DHE|TLS_KE_PSK_DHE);
			}
		}
	}

	// signature_algorithms
	if (signature_algorithms) {
		if (common_key_exchange_modes & TLS_KE_CERT_DHE) {
			if (tls_process_signature_algorithms(
				signature_algorithms, signature_algorithms_len,
				conn->ctx->signature_algorithms, conn->ctx->signature_algorithms_cnt,
				common_sig_algs, &common_sig_algs_cnt,
				sizeof(common_sig_algs)/sizeof(common_sig_algs[0])) < 0) {
				error_print();
				tls_send_alert(conn, TLS_alert_decode_error);
				return -1;
			}
			if (!common_sig_algs_cnt) {
				common_key_exchange_modes &= ~TLS_KE_CERT_DHE;
			}
		}
	}

	// signature_algorithms_cert
	if (signature_algorithms_cert) {
		if (common_key_exchange_modes & TLS_KE_CERT_DHE) {
			if (tls_process_signature_algorithms(
				signature_algorithms_cert, signature_algorithms_cert_len,
				conn->ctx->signature_algorithms, conn->ctx->signature_algorithms_cnt,
				common_sig_algs_cert, &common_sig_algs_cert_cnt,
				sizeof(common_sig_algs_cert)/sizeof(common_sig_algs_cert[0])) < 0) {
				error_print();
				tls_send_alert(conn, TLS_alert_decode_error);
				return -1;
			}
			if (!common_sig_algs_cert_cnt) {
				common_key_exchange_modes &= ~TLS_KE_CERT_DHE;
			}
		}
	}

	// key_share
	if (key_share) {
		if (common_key_exchange_modes & (TLS_KE_CERT_DHE|TLS_KE_PSK_DHE)) {
			int group = 0;
			const uint8_t *key_exchange = NULL;
			size_t key_exchange_len = 0;

			if ((ret = tls13_process_key_share_client_hello(
				key_share, key_share_len,
				common_groups, common_groups_cnt,
				&group, &key_exchange, &key_exchange_len)) < 0) {
				error_print();
				tls_send_alert(conn, TLS_alert_decode_error);
				return -1;
			} else if (ret == 0) {
				// backup ClientHello1 for HelloRetryRequest
				memcpy(conn->plain_record, conn->record, conn->recordlen);
				conn->plain_recordlen = conn->recordlen;
				conn->key_exchange_group = supported_groups[0];
			} else {
				// valid key_exchange found
				if (key_exchange_len != 65) {
					error_print();
					return -1;
				}
				conn->key_exchange_group = group;
				memcpy(conn->peer_key_exchange, key_exchange, key_exchange_len);
				conn->peer_key_exchange_len = key_exchange_len;
			}
		}
	}

	// server_name
	if (server_name) {
		if (tls_server_name_from_bytes(&host_name, &host_name_len, server_name, server_name_len) != 1) {
			error_print();
			return -1;
		}
	}

	// select server cert_chain
	//	* signature_algorithms
	//	* [signature_algorithms_cert]
	//	* [server_name.host_name]
	//	* [oid_filter]
	//
	if (common_key_exchange_modes & TLS_KE_CERT_DHE) {
		if (tls13_server_cert_chains_select(conn->ctx->cert_chains, conn->ctx->cert_chains_len,
			common_sig_algs, common_sig_algs_cnt,
			common_sig_algs_cert, common_sig_algs_cert_cnt,
			host_name, host_name_len,
			&conn->cert_chain, &conn->cert_chain_len, &conn->cert_chain_idx, &conn->sig_alg) < 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}
		if (!conn->cert_chain) {
			common_key_exchange_modes &= ~TLS_KE_CERT_DHE;
		}
	}

	// pre_shared_key
	if (pre_shared_key) {
		if (common_key_exchange_modes & (TLS_KE_PSK_DHE|TLS_KE_PSK)) {

			int psk_selected = 0;

			if (conn->psk_identities_len) {
				if ((psk_selected = tls13_process_client_pre_shared_key_external(conn,
					pre_shared_key, pre_shared_key_len)) < 0) {
					error_print();
					return -1;
				}
			} else if (conn->ctx->session_ticket_key) {
				if ((psk_selected = tls13_process_client_pre_shared_key_from_ticket(conn,
					pre_shared_key, pre_shared_key_len)) < 0) {
					error_print();
					return -1;
				}
			} else {
				// caller should set session_ticket_key or psk_keys
				error_print();
				return -1;
			}

			// update psk_key_exchange_modes
			if (!psk_selected) {
				common_key_exchange_modes &= ~(TLS_KE_PSK_DHE|TLS_KE_PSK);
				format_print(stderr, 0, 0, "no common pre_shared_key\n");
			} else {
				conn->pre_shared_key = 1;
				format_print(stderr, 0, 0, "selected_psk_identity: %d\n", conn->selected_psk_identity - 1);
				format_bytes(stderr, 0, 0, "selected_psk", conn->psk, conn->psk_len);
			}
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
			if (!conn->key_exchanges_cnt) {
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
		if (!conn->key_exchanges_cnt) {
			conn->hello_retry_request = 1;
		}
	} else {
		error_print();
		tls_send_alert(conn, TLS_alert_handshake_failure);
		return -1;
	}

	// hello_retry_request
	if (conn->hello_retry_request) {
		uint8_t message_hash[4 + 32];
		size_t dgstlen;

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
	}

	// early_data
	conn->early_data =
		(conn->early_data) &&
		(conn->key_exchange_modes & (TLS_KE_PSK_DHE | TLS_KE_PSK)) &&
		(early_data) &&
		(conn->hello_retry_request == 0);

	// generate early_data keys
	if (conn->early_data) {

		/*
		uint8_t zeros[32] = {0};
		uint8_t early_secret[32];
		uint8_t client_early_traffic_secret[32];
		uint8_t client_write_key[16];

		// [1]
		tls13_hkdf_extract(conn->digest, zeros, conn->psk, early_secret);
		// [2]
		tls13_derive_secret(early_secret, "c e traffic", &conn->dgst_ctx, client_early_traffic_secret);
		tls13_hkdf_expand_label(conn->digest, client_early_traffic_secret, "key", NULL, 0, 16, client_write_key);
		block_cipher_set_encrypt_key(&conn->client_write_key, conn->cipher, client_write_key);
		tls13_hkdf_expand_label(conn->digest, client_early_traffic_secret, "iv", NULL, 0, 12, conn->client_write_iv);
		tls_seq_num_reset(conn->client_seq_num);

		format_print(stderr, 0, 0, "client_write_key/iv <= client_early_traffic_secret\n");
		format_bytes(stderr, 0, 4, "client_early_traffic_secret", client_early_traffic_secret, 32);
		format_bytes(stderr, 0, 4, "client_write_key", client_write_key, 16);
		format_bytes(stderr, 0, 4, "client_write_iv", conn->client_write_iv, 12);
		*/

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


int tls13_generate_cookie(const SM4_KEY *cookie_key, const uint8_t *client_info, size_t client_info_len,
	uint8_t *cookie, size_t *cookie_len)
{
	rand_bytes(cookie, 32);
	*cookie_len = 32;
	return 1;
}

int tls12_verify_cookie(const SM4_KEY *cookie_key, const uint8_t *client_info, size_t client_info_len,
	const uint8_t *cookie, size_t cookie_len)
{
	return 1;
}

int tls13_send_hello_retry_request(TLS_CONNECT *conn)
{
	int ret;

	tls_trace("send HelloRetryRequest\n");

	if (conn->recordlen == 0) {
		uint8_t exts[256];
		uint8_t *p = exts;
		size_t extslen = 0;
		int curve_oid;
		uint8_t cookie[256];
		size_t cookie_len;

		tls_record_set_protocol(conn->record, TLS_protocol_tls12);

		if (rand_bytes(conn->server_random, 32) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

		if (tls13_server_supported_versions_ext_to_bytes(TLS_protocol_tls13, &p, &extslen) != 1
			|| tls13_key_share_hello_retry_request_ext_to_bytes(conn->key_exchange_group, &p, &extslen) != 1) {
			error_print();
			return -1;
		}
		if (conn->ctx->cookie) {
			if (tls13_generate_cookie(&conn->ctx->cookie_key, NULL, 0, cookie, &cookie_len) != 1) {
				error_print();
				return -1;
			}
			if (tls13_cookie_ext_to_bytes(cookie, sizeof(cookie), &p, &extslen) != 1) {
				error_print();
				return -1;
			}
		}
		if (tls13_record_set_handshake_hello_retry_request(conn->record, &conn->recordlen,
			TLS_protocol_tls12, conn->server_random, NULL, 0,
			conn->cipher_suite, exts, extslen) != 1) {
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


	return 1;
}

int tls13_recv_client_hello_again(TLS_CONNECT *conn)
{
	int ret;
	uint8_t *record = conn->record;
	size_t recordlen;

	int client_verify = 0;

	int protocol;

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
	const uint8_t *supported_versions = NULL;
	size_t supported_versions_len = 0;
	const uint8_t *supported_groups = NULL;
	size_t supported_groups_len = 0;
	const uint8_t *key_share = NULL;
	size_t key_share_len = 0;
	const uint8_t *key_exchange = NULL;
	size_t key_exchange_len = 0;
	const uint8_t *signature_algorithms = NULL;
	size_t signature_algorithms_len;

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
	const uint8_t *_supported_versions = NULL;
	size_t _supported_versions_len = 0;
	const uint8_t *_supported_groups = NULL;
	size_t _supported_groups_len = 0;
	const uint8_t *_signature_algorithms = NULL;
	size_t _signature_algorithms_len = 0;

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
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}
	if ((ret = tls_record_get_handshake_client_hello(conn->record,
		&legacy_version, &random, &legacy_session_id, &legacy_session_id_len,
		&cipher_suites, &cipher_suites_len, &exts, &extslen)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	// ClientHello1
	if (tls_record_get_handshake_client_hello(conn->plain_record,
		&_legacy_version, &_random, &_legacy_session_id, &_legacy_session_id_len,
		&_cipher_suites, &_cipher_suites_len, &_exts, &_extslen) != 1) {
		error_print();
		return -1;
	}

	if (legacy_version != _legacy_version
		|| legacy_session_id_len != _legacy_session_id_len
		|| memcmp(legacy_session_id, _legacy_session_id, _legacy_session_id_len) != 0
		|| cipher_suites_len != _cipher_suites_len
		|| memcmp(cipher_suites, _cipher_suites, _cipher_suites_len) != 0
		//|| legacy_comp_methods_len != _legacy_comp_methods_len
		//|| memcmp(legacy_comp_methods, _legacy_comp_methods, _legacy_comp_methods_len) != 0
		) {
		error_print();
		tls_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}

	// update random
	if (memcmp(random, _random, 32) == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}
	memcpy(conn->client_random, random, 32);

	// ClientHello1 extensions
	while (_extslen) {
		int _ext_type;
		const uint8_t *_ext_data;
		size_t _ext_datalen;

		if (tls_ext_from_bytes(&_ext_type, &_ext_data, &_ext_datalen, &_exts, &_extslen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}
		switch (_ext_type) {
		case TLS_extension_supported_versions:
			_supported_versions = _ext_data;
			_supported_versions_len = _ext_datalen;
			break;
		case TLS_extension_supported_groups:
			_supported_groups = _ext_data;
			_supported_groups_len = _ext_datalen;
			break;
		case TLS_extension_signature_algorithms:
			_signature_algorithms = _ext_data;
			_signature_algorithms_len = _ext_datalen;
			break;
		}
	}

	// process ClientHello2 extensions
	while (extslen) {
		int ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;

		if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}
		if (!ext_datalen) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}

		switch (ext_type) {
		case TLS_extension_supported_versions:
			if (supported_versions) {
				error_print();
				return -1;
			}
			if (ext_datalen != _supported_versions_len
				|| memcmp(ext_data, _supported_versions, _supported_versions_len) != 0) {
				error_print();
				return -1;
			}
			supported_versions = ext_data;
			supported_versions_len = ext_datalen;
			break;

		case TLS_extension_supported_groups:
			if (supported_groups
				|| ext_datalen != _supported_groups_len
				|| memcmp(ext_data, _supported_groups, _supported_groups_len) != 0) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			supported_groups = ext_data;
			supported_groups_len = ext_datalen;
			break;

		case TLS_extension_signature_algorithms:
			if (signature_algorithms
				|| ext_datalen != _signature_algorithms_len
				|| memcmp(ext_data, _signature_algorithms, _signature_algorithms_len) != 0) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			signature_algorithms = ext_data;
			signature_algorithms_len = ext_datalen;
			break;

		case TLS_extension_key_share:
			if (key_share) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			key_share = ext_data;
			key_share_len = ext_datalen;
			break;

		// ClientHello2 should not have early_data
		case TLS_extension_early_data:
			error_print();
			tls_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
	}
	if (!supported_versions || !supported_groups || !key_share || !signature_algorithms) {
		error_print();
		tls_send_alert(conn, TLS_alert_missing_extension);
		return -1;
	}

	if (tls13_process_key_share_client_hello_again(key_share, key_share_len,
		conn->key_exchange_group, &key_exchange, &key_exchange_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	}
	if (key_exchange_len != 65) {
		error_print();
		return -1;
	}
	memcpy(conn->peer_key_exchange, key_exchange, key_exchange_len);
	conn->peer_key_exchange_len = key_exchange_len;

	digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5);

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
		uint8_t *p = exts;
		size_t extslen = 0;

		tls_record_set_protocol(conn->record, TLS_protocol_tls12);

		// server_random
		if (tls13_random_generate(conn->server_random) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

		// supported_versions
		if (tls13_server_supported_versions_ext_to_bytes(conn->protocol, &p, &extslen) != 1) {
			error_print();
			return -1;
		}

		// pre_shared_key
		if (conn->pre_shared_key) {
			if (tls13_server_pre_shared_key_ext_to_bytes(conn->selected_psk_identity, &p, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// key_share
		if (conn->key_exchange_modes != TLS_KE_PSK) {
			int curve_oid;

			if (!conn->key_exchange_group) {
				error_print();
				return -1;
			}

			if ((curve_oid = tls_named_curve_oid(conn->key_exchange_group)) == OID_undef) {
				error_print();
				return -1;
			}
			if (x509_key_generate(&conn->key_exchanges[0], OID_ec_public_key, &curve_oid, sizeof(curve_oid)) != 1) {
				error_print();
				return -1;
			}
			conn->key_exchange_idx = 0;
			conn->key_exchanges_cnt = 1;

			if (tls13_key_share_server_hello_ext_to_bytes(&conn->key_exchanges[0], &p, &extslen) != 1) {
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

int tls13_send_encrypted_extensions(TLS_CONNECT *conn)
{
	int ret;
	tls_trace("send {EncryptedExtensions}\n");

	if (conn->recordlen == 0) {
		uint8_t exts[256];
		uint8_t *p = exts;
		size_t extslen = 0;
		size_t padding_len;

		tls_record_set_protocol(conn->plain_record, TLS_protocol_tls12);

		// supported_groups

		if (conn->key_exchange_modes & (TLS_KE_CERT_DHE|TLS_KE_PSK_DHE)) {
			if (tls_supported_groups_ext_to_bytes(conn->ctx->supported_groups,
				conn->ctx->supported_groups_cnt, &p, &extslen) != 1) {
				error_print();
				return -1;
			}
		}
		if (conn->early_data) {
			if (tls13_empty_early_data_ext_to_bytes(&p, &extslen) != 1) {
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

		tls13_padding_len_rand(&padding_len);

		format_bytes(stderr, 0, 0, "server_seq_num", conn->server_seq_num, 8);
		if (tls13_record_encrypt(&conn->server_write_key, conn->server_write_iv,
			conn->server_seq_num, conn->plain_record, conn->plain_recordlen, padding_len,
			conn->record, &conn->recordlen) != 1) {
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

	tls_seq_num_incr(conn->server_seq_num);

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

	const uint8_t *request_context = NULL;
	size_t request_context_len = 0;

	if (conn->recordlen == 0) {
		uint8_t ca_names[256];
		size_t ca_names_len;
		uint8_t exts[256];
		uint8_t *p = exts;
		size_t extslen = 0;
		size_t padding_len;

		if (tls_authorities_from_certs(ca_names, &ca_names_len, sizeof(ca_names),
			conn->ctx->cacerts, conn->ctx->cacertslen) != 1) {
			error_print();
			return -1;
		}
		if (tls_signature_algorithms_ext_to_bytes(
			conn->signature_algorithms, conn->signature_algorithms_cnt, &p, &extslen) != 1
			|| tls13_signature_algorithms_cert_ext_to_bytes(
			conn->signature_algorithms, conn->signature_algorithms_cnt, &p, &extslen) != 1
			|| tls13_certificate_authorities_ext_to_bytes(
			ca_names, ca_names_len, &p, &extslen) != 1) {
			error_print();
			return -1;
		}

		if (tls13_record_set_handshake_certificate_request(
			conn->plain_record, &conn->plain_recordlen,
			request_context, request_context_len, exts, extslen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
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
			tls_send_alert(conn, TLS_alert_internal_error);
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

/*
struct {
    CertificateStatusType status_type;
    select (status_type) {
        case ocsp:
            OCSPResponse response;
    };
} CertificateStatus;

OCSPResponse ::= SEQUENCE {
    responseStatus         OCSPResponseStatus,
    responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL
}

OCSPResponseStatus ::= ENUMERATED {
    successful            (0),  -- 响应有效
    malformedRequest      (1),  -- 请求格式错误
    internalError         (2),  -- 服务器内部错误
    tryLater              (3),  -- 稍后重试
    -- 状态码 4 未使用
    sigRequired           (5),  -- 必须签名
    unauthorized          (6)   -- 未授权
}

ResponseBytes ::= SEQUENCE {
    responseType          OBJECT IDENTIFIER,
    response              OCTET STRING
}

-- 当 responseType 为 id-pkix-ocsp-basic 时，response 包含 BasicOCSPResponse
BasicOCSPResponse ::= SEQUENCE {
    tbsResponseData      ResponseData,
    signatureAlgorithm   AlgorithmIdentifier,
    signature            BIT STRING,
    certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
}
*/

int tls13_send_server_certificate(TLS_CONNECT *conn)
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

		// entity CertificateEntry extensions
		if (conn->status_request) {
			entity_status_request_ocsp_response = conn->ctx->status_request_ocsp_response;
			entity_status_request_ocsp_response_len = conn->ctx->status_request_ocsp_response_len;
		}

		if (conn->signed_certificate_timestamp) {
			entity_signed_certificate_timestamp = conn->ctx->signed_certificate_timestamp_list;
			entity_signed_certificate_timestamp_len = conn->ctx->signed_certificate_timestamp_list_len;
		}

		if (tls13_record_set_handshake_certificate(conn->plain_record, &conn->plain_recordlen,
			request_context, request_context_len,
			conn->server_certs, conn->server_certs_len,
			entity_status_request_ocsp_response, entity_status_request_ocsp_response_len,
			entity_signed_certificate_timestamp, entity_signed_certificate_timestamp_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

		if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
			error_print();
			return -1;
		}

		format_bytes(stderr, 0, 0, "server_seq_num", conn->server_seq_num, 8);

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

	tls_trace("send {CertificateVerify}\n");

	if (conn->recordlen == 0) {
		X509_KEY *sign_key = &conn->ctx->x509_keys[conn->cert_chain_idx];
		int sig_alg = 0;
		uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
		size_t siglen;
		size_t padding_len;
		size_t i;


		for (i = 0; i < conn->ctx->signature_algorithms_cnt; i++) {
			if (tls_signature_scheme_group_oid(conn->ctx->signature_algorithms[i]) == sign_key->algor_param) {
				sig_alg = conn->ctx->signature_algorithms[i];
				break;
			}
		}
		if (!sig_alg) {
			error_print();
			return -1;
		}

		if (tls13_sign_certificate_verify(TLS_server_mode, sig_alg,
			sign_key, &conn->dgst_ctx, sig, &siglen) != 1) {
			error_print();
			return -1;
		}

		if (tls13_record_set_handshake_certificate_verify(
			conn->plain_record, &conn->plain_recordlen,
			sig_alg, sig, siglen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);


		if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
			error_print();
			return -1;
		}

		format_bytes(stderr, 0, 0, "server_seq_num", conn->server_seq_num, 8);

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

	tls_trace("send {Finished}\n");


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
	const uint8_t *status_request_ocsp_response;
	size_t status_request_ocsp_response_len;
	const uint8_t *signed_certificate_timestamp;
	size_t signed_certificate_timestamp_len;

	/*
	uint8_t *p;
	const uint8_t *cp;
	size_t len = 0;
	*/

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
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	format_bytes(stderr, 0, 0, "client_seq_num", conn->client_seq_num, 8);
	if (tls13_record_decrypt(&conn->client_write_key, conn->client_write_iv,
		conn->client_seq_num, conn->record, conn->recordlen,
		conn->plain_record, &conn->plain_recordlen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	tls13_record_trace(stderr, conn->plain_record, conn->plain_recordlen, 0, 0);



	if ((ret = tls13_record_get_handshake_certificate(conn->plain_record,
		&request_context, &request_context_len,
		conn->client_certs, &conn->client_certs_len, sizeof(conn->client_certs),
		&status_request_ocsp_response, &status_request_ocsp_response_len,
		&signed_certificate_timestamp, &signed_certificate_timestamp_len)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return 0;
	}
	if (request_context) {
		error_print();
		tls_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}
	if (!conn->client_certs_len) {
		error_print();
		tls_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}

	// verify cert_chain
	int i;
	if (tls13_client_cert_chains_select(conn->client_certs, conn->client_certs_len,
		conn->ctx->signature_algorithms, conn->ctx->signature_algorithms_cnt,
		conn->ctx->signature_algorithms, conn->ctx->signature_algorithms_cnt,
		conn->ctx->cacerts, conn->ctx->cacertslen,
		NULL, NULL, NULL, NULL) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}
	int verify_result;
	if (x509_certs_verify(conn->client_certs, conn->client_certs_len, X509_cert_chain_client,
		conn->ctx->cacerts, conn->ctx->cacertslen,
		conn->ctx->verify_depth, &verify_result) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}

	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}

	tls_seq_num_incr(conn->client_seq_num);

	return 1;
}

/*
struct {
    SignatureScheme algorithm;
    opaque signature<0..2^16-1>;
} CertificateVerify;
*/


int tls13_recv_client_finished(TLS_CONNECT *conn)
{
	int ret;

	// Finished
	uint8_t local_verify_data[64];
	size_t local_verify_data_len;
	const uint8_t *verify_data;
	size_t verify_data_len;

	uint8_t client_write_key[16];

	tls_trace("recv {Finished}\n");
	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}

	if (tls_record_protocol(conn->record) != TLS_protocol_tls12) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	format_bytes(stderr, 0, 0, "client_seq_num", conn->client_seq_num, 8);
	if (tls13_record_decrypt(&conn->client_write_key, conn->client_write_iv,
		conn->client_seq_num, conn->record, conn->recordlen,
		conn->plain_record, &conn->plain_recordlen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	tls13_record_trace(stderr, conn->plain_record, conn->plain_recordlen, 0, 0);


	if ((ret = tls13_record_get_handshake_finished(conn->plain_record,
		&verify_data, &verify_data_len)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	if (tls13_compute_verify_data(conn->client_handshake_traffic_secret,
		&conn->dgst_ctx, local_verify_data, &local_verify_data_len) != 1) {
		error_print();
		return -1;
	}
	if (local_verify_data_len != verify_data_len
		|| memcmp(local_verify_data, verify_data, verify_data_len) != 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decrypt_error);
		return -1;
	}

	// 这个应该放在哪个位置？			
	if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	tls_seq_num_incr(conn->client_seq_num);


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


int tls13_recv_end_of_early_data(TLS_CONNECT *conn)
{
	int ret;
	tls_trace("recv {EndOfEarlyData}\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}


	format_bytes(stderr, 0, 4, "client_write_iv", conn->client_write_iv, 12);

	if (tls13_record_decrypt(&conn->client_write_key, conn->client_write_iv,
		conn->client_seq_num, conn->record, conn->recordlen,
		conn->plain_record, &conn->plain_recordlen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

	if ((ret = tls13_record_get_handshake_end_of_early_data(conn->plain_record)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	uint8_t client_write_key[16];
	tls13_hkdf_expand_label(conn->digest, conn->client_handshake_traffic_secret, "key", NULL, 0, 16, client_write_key);
	block_cipher_set_encrypt_key(&conn->client_write_key, conn->cipher, client_write_key);
	tls13_hkdf_expand_label(conn->digest, conn->client_handshake_traffic_secret, "iv", NULL, 0, 12, conn->client_write_iv);
	tls_seq_num_reset(conn->client_seq_num);

	format_print(stderr, 0, 0, "client_write_key/iv <= client_handshake_traffic_secret\n");
	format_bytes(stderr, 0, 4, "client_handshake_traffic_secret", conn->client_handshake_traffic_secret, 32);
	format_bytes(stderr, 0, 4, "client_write_key", client_write_key, 16);
	format_bytes(stderr, 0, 4, "client_write_iv", conn->client_write_iv, 12);

	return 1;
}





// 这个的总长度是48 + 2 + 8 == 58
typedef struct {
	uint8_t master_secret[48];
	uint16_t cipher_suite;
	uint64_t timestamp;
} TLS_SESSION_TICKET;


int tls13_send_new_session_ticket(TLS_CONNECT *conn)
{
	int ret;
	size_t padding_len;

	tls_trace("send {NewSessionTicket*}\n");

	if (conn->recordlen == 0) {
		// new_session_ticket
		uint32_t ticket_lifetime = 60 * 60 * 24 * 2; // = 2 days
		uint32_t ticket_age_add;
		uint8_t ticket_nonce[8];
		uint8_t ticket[12 + (32 + 2 + 2 + 4 + 4) + 16];
		size_t ticketlen;
		uint8_t exts[16];
		size_t extslen = 0;
		uint8_t *p = exts;
		// early_data
		uint32_t max_early_data_size = 256 * 1024; // 256 KB
		uint32_t ticket_issue_time = time(NULL);

		if (rand_bytes((uint8_t *)&ticket_age_add, sizeof(ticket_age_add)) != 1) {
			error_print();
			return -1;
		}
		if (rand_bytes(ticket_nonce, sizeof(ticket_nonce)) != 1) {
			error_print();
			return -1;
		}

		uint8_t resumption_master_secret[48];
		size_t dgstlen = 32;
		uint8_t pre_shared_key[32];

		// generate resumption_master_secret
		/* [14] */ tls13_derive_secret(conn->master_secret, "res master", &conn->dgst_ctx, resumption_master_secret);

		// pre_shared_key = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)
		tls13_hkdf_expand_label(conn->digest, resumption_master_secret, "resumption",
			ticket_nonce, sizeof(ticket_nonce), dgstlen, pre_shared_key);

		format_bytes(stderr, 0, 0, ">>>> pre_shared_key", pre_shared_key, sizeof(pre_shared_key));

		if (tls13_encrypt_ticket(conn->ctx->session_ticket_key,
			pre_shared_key, conn->protocol, conn->cipher_suite,
			ticket_issue_time, ticket_lifetime, ticket, &ticketlen) != 1) {
			error_print();
			return -1;
		}
		if (ticketlen != sizeof(ticket)) {
			error_print();
			return -1;
		}

		if (tls13_early_data_ext_to_bytes(max_early_data_size, &p, &extslen) != 1) {
			error_print();
			return -1;
		}

		if (tls13_record_set_handshake_new_session_ticket(
			conn->plain_record, &conn->plain_recordlen,
			ticket_lifetime, ticket_age_add,
			ticket_nonce, sizeof(ticket_nonce),
			ticket, ticketlen,
			exts, extslen) != 1) {
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
		tls_seq_num_incr(conn->server_seq_num);

		conn->new_session_ticket--;
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	return 1;
}
















int tls13_do_client_handshake(TLS_CONNECT *conn)
{
	int ret;
	int next_state;


	switch (conn->state) {
	case TLS_state_hello_retry_request:
	case TLS_state_client_hello_again:
	case TLS_state_server_hello:
	case TLS_state_encrypted_extensions:
		if (conn->early_data && conn->early_data_len) {
			tls_trace("send EarlyData\n");
			if (tls13_send_early_data(conn) != 1) {
				error_print();
				return -1;
			}
			conn->early_data_len = 0;
		}
		break;
	}


	switch (conn->state) {
	case TLS_state_client_hello:
		ret = tls13_send_client_hello(conn);
		/*
		if (conn->early_data)
			next_state = TLS_state_early_data;
		else	next_state = TLS_state_hello_retry_request;
		*/
		next_state = TLS_state_hello_retry_request;
		break;

	/*
	case TLS_state_early_data:
		ret = tls13_send_early_data(conn);
		next_state = TLS_state_hello_retry_request;
		break;
	*/

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
		if (conn->key_exchange_modes)
			next_state = TLS_state_server_finished;
		else	next_state = TLS_state_certificate_request;
		break;

	case TLS_state_certificate_request: // optional
		ret = tls13_recv_certificate_request(conn);
		next_state = TLS_state_server_certificate;
		break;

	case TLS_state_server_certificate:
		ret = tls13_recv_server_certificate(conn);
		next_state = TLS_state_certificate_verify;
		break;

	case TLS_state_certificate_verify:
		ret = tls13_recv_certificate_verify(conn);
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
		ret = tls13_send_client_certificate(conn);
		next_state = TLS_state_client_certificate_verify;
		break;

	case TLS_state_client_certificate_verify:
		ret = tls13_send_client_certificate_verify(conn);
		next_state = TLS_state_client_finished;
		break;

	case TLS_state_client_finished:
		ret = tls13_send_client_finished(conn);
		next_state = TLS_state_handshake_over;
		//next_state = TLS_state_new_session_ticket;
		break;

	/*
	case TLS_state_new_session_ticket:
		ret = tls13_recv_new_session_ticket(conn);
		next_state = TLS_state_handshake_over;
		break;
	*/

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
		if (conn->key_exchange_modes)
			next_state = TLS_state_server_finished;
		else if (conn->certificate_request)
			next_state = TLS_state_certificate_request;
		else	next_state = TLS_state_server_certificate;
		break;

	case TLS_state_certificate_request:
		ret = tls13_send_certificate_request(conn);
		next_state = TLS_state_server_certificate;
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
		ret = tls13_recv_certificate_verify(conn);
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


	if (tls13_handshake_prepare(conn) != 1) {
		error_print();
		return -1;
	}

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


	if (tls13_handshake_prepare(conn) != 1) {
		error_print();
		return -1;
	}

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

int tls13_set_early_data(TLS_CONNECT *conn, const uint8_t *data, size_t datalen)
{
	size_t len;

	if (!conn) {
		error_print();
		return -1;
	}
	if (!conn->is_client) {
		error_print();
		return -1;
	}
	if (!data || !datalen || datalen > sizeof(conn->early_data_buf)) {
		error_print();
		return -1;
	}
	memcpy(conn->early_data_buf, data, datalen);
	conn->early_data_len = datalen;
	conn->early_data = 1;
	return 1;
}

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

// 服务器通过max_early_data_size是否能够隐式的启用呢？
// 我觉得是可以隐式启用的？TLS_CTX可以不管这个功能
// 如果CTX将max_early_data_size设置为0，那么根本不会发送new_session_ticket
// 是否发送new_session_ticket
int tls13_ctx_set_max_early_data_size(TLS_CTX *ctx, size_t max_early_data_size)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	// 是否有必要在CTX中做过多的状态触发？
	ctx->max_early_data_size = max_early_data_size;
	return 1;
}

int tls13_set_max_early_data_size(TLS_CONNECT *conn, size_t max_early_data_size)
{
	if (!conn) {
		error_print();
		return -1;
	}
	if (max_early_data_size > sizeof(conn->early_data)) {
		error_print();
		return -1;
	}
	conn->max_early_data_size = max_early_data_size;
	conn->early_data = max_early_data_size ? 1 : 0;
	return 1;
}























int tls13_enable_pre_shared_key(TLS_CONNECT *conn, int enable)
{
	if (!conn) {
		error_print();
		return -1;
	}
	//error_print();
	//conn->pre_shared_key_enabled = enable ? 1 : 0;
	return 1;
}

int tls13_enable_early_data(TLS_CONNECT *conn, int enable)
{
	if (!conn) {
		error_print();
		return -1;
	}
	conn->early_data = enable ? 1 : 0;
	return 1;
}

/*
SNI Extension

      struct {
          NameType name_type;
          select (name_type) {
              case host_name: HostName;
          } name;
      } ServerName;

      enum {
          host_name(0), (255)
      } NameType;

      opaque HostName<1..2^16-1>;

      struct {
          ServerName server_name_list<1..2^16-1>
      } ServerNameList;


struct {
	NameType name_type = host_name(0);
	HostName name<1..2^16-1>;
} ServerName;


// 这里比较麻烦的是，这里提供的是多个服务器名字
// 但是实际上我们还是只支持一个名字，实际上我们只解析第一个名字，后面的都忽略掉
struct {
	ServerName server_name_list<1..2^16-1>
} ServerNameList;

*/




int tls_server_name_ext_to_bytes(const uint8_t *host_name, size_t host_name_len, uint8_t **out, size_t *outlen)
{
	int type = TLS_extension_server_name;
	uint8_t *ext_data = NULL;
	size_t ext_datalen = 0;
	uint8_t *server_name_list = NULL;
	size_t server_name_list_len = 0;

	if (out && *out) {
		ext_data = *out + 4; // sizeof(ext_header) == 4
		server_name_list = ext_data + 2; // sizeof(host_name_list_len) == 2
	}

	// output one host_name to server_name_list
	tls_uint8_to_bytes(TLS_name_type_host_name, &server_name_list, &server_name_list_len);
	tls_uint16array_to_bytes(host_name, host_name_len, &server_name_list, &server_name_list_len);
	// output ext data
	tls_uint16array_to_bytes(NULL, server_name_list_len, &ext_data, &ext_datalen);
	// output ext header
	tls_ext_to_bytes(type, NULL, ext_datalen, out, outlen);

	return 1;
}

int tls_server_name_from_bytes(const uint8_t **host_name, size_t *host_name_len,
	const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *server_name_list;
	size_t server_name_list_len;

	if (!host_name || !host_name_len) {
		error_print();
		return -1;
	}
	if (tls_uint16array_from_bytes(&server_name_list, &server_name_list_len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	if (!server_name_list) {
		error_print();
		return -1;
	}
	while (server_name_list_len) {
		uint8_t name_type;
		const uint8_t *name;
		size_t namelen;

		if (tls_uint8_from_bytes(&name_type, &server_name_list, &server_name_list_len) != 1
			|| tls_uint16array_from_bytes(&name, &namelen, &server_name_list, &server_name_list_len) != 1) {
			error_print();
			return -1;
		}
		if (name_type != TLS_name_type_host_name) {
			error_print();
			return -1;
		}
		if (!name) {
			error_print();
			return -1;
		}
		// only return the first hostname
		if (*host_name == NULL) {
			*host_name = name;
			*host_name_len = namelen;
		}
	}
	return 1;
}

int tls_server_name_print(FILE *fp, int fmt, int ind, const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *server_name_list;
	size_t server_name_list_len;
	uint8_t name_type;
	const uint8_t *host_name;
	size_t host_name_len;

	if (tls_uint16array_from_bytes(&server_name_list, &server_name_list_len, &ext_data, &ext_datalen) != 1) {
		error_print();
		return -1;
	}
	while (server_name_list_len) {
		if (tls_uint8_from_bytes(&name_type, &server_name_list, &server_name_list_len) != 1
			|| tls_uint16array_from_bytes(&host_name, &host_name_len, &server_name_list, &server_name_list_len) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind, "name_type: %s (%d)\n", name_type == 0 ? "host_name" : "(unknown)", name_type);
		format_bytes(fp, fmt, ind, "host_name", host_name, host_name_len); // TODO: print string
	}
	if (ext_datalen) {
		error_print();
		return -1;
	}
	return 1;
}

