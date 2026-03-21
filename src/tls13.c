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

static const int tls13_ciphers[] = { TLS_cipher_sm4_gcm_sm3 };
static size_t tls13_ciphers_count = sizeof(tls13_ciphers)/sizeof(int);

static int tls13_client_hello_exts[] = {
	TLS_extension_supported_versions,
	TLS_extension_padding,
};

#define TLS_state_hello_retry_request 111111
#define TLS_state_client_hello_again 12222

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
	// TODO: do we need to check record_type?  record[0] != TLS_record_application_data		


	format_bytes(stderr, 0, 0, "recv seq_num", seq_num, 8);

	if (tls13_gcm_decrypt(key, iv,
		seq_num, record + 5, recordlen - 5,
		&record_type, conn->databuf, &conn->datalen) != 1) {
		error_print();
		return -1;
	}
	conn->data = conn->databuf;
	tls_seq_num_incr(seq_num);

	tls_record_set_data(record, conn->data, conn->datalen);
	//tls_trace("decrypt ApplicationData\n");
	//tls_record_trace(stderr, record, tls_record_length(record), 0, 0);


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

// 这个函数需要改为支持X509_KEY的版本			
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

//同上			
int tls13_verify_certificate_verify(int tls_mode,
	const X509_KEY *public_key, const char *signer_id, size_t signer_id_len,
	const DIGEST_CTX *tbs_dgst_ctx, const uint8_t *sig, size_t siglen)
{
	int ret;
	SM2_VERIFY_CTX verify_ctx;
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

	// FIXME: use x509_verify_init/update/finish			
	if (public_key->algor != OID_ec_public_key
		|| public_key->algor_param != OID_sm2) {
		error_print();
		return -1;
	}
	sm2_verify_init(&verify_ctx, &public_key->u.sm2_key, signer_id, signer_id_len);
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




























// extensions

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
		format_print(fp, fmt, ind, "(empty)\n");
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





/*
Extension: pre_shared_key


      struct {
          opaque identity<1..2^16-1>;
          uint32 obfuscated_ticket_age;
      } PskIdentity;


	每个psk_identity包含一个identity字符串（可能是一个哈希值或者随机值）
	还有一个uint32_t 的时间

	在每个pre_shared_key 扩展中，首先包含一组PskIdentity

	然后包含一组binder，每个binder是一个


      opaque PskBinderEntry<32..255>;



      struct {
          PskIdentity identities<7..2^16-1>;
          PskBinderEntry binders<33..2^16-1>;
      } OfferedPsks;


      struct {
          select (Handshake.msg_type) {
              case client_hello: OfferedPsks;
              case server_hello: uint16 selected_identity;
          };
      } PreSharedKeyExtension;



	客户端在pre_shared_key扩展中提供一组预设的密钥，让服务器从中选择
		这个密钥可能来自于系统外部预设的
		或者来自于之前的NewSessionTicket

	每个密钥除了密钥的ID之外，还包含一个密钥的MAC，客户端通过这个MAC证明自己拥有密钥ID对应的密钥

		这个mac命名为binder

		binder = HMAC(binder_key, transcript_hash)

		因为这个binder是在ClientHello（也就是第一个消息中发送的）
		因此在计算ClientHello的哈希的时候显然存在一个死锁
		因此我们需要先准备好ClientHello（其中binder字段添全0，长度由HMAC算法决定）
		然后调用binder_key生成binder


		binder_key = HKDF-Expand-Label(early_secret, "res binder", "", Hash.length)

		这里的early_secret是什么？		



	客户端在完成Full Handshake之后可以缓冲？

	我们可以缓冲在CTX中，按域名 / SNI / ALPN”等维度索引

)


*/



int tls13_server_pre_shared_key_ext_to_bytes(int selected_identity, uint8_t **out, size_t *outlen)
{
	if (selected_identity > 65535) {
		error_print();
		return -1;
	}
	tls_uint16_to_bytes((uint16_t)selected_identity, out, outlen);
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

		case TLS_extension_psk_key_exchange_modes:
		case TLS_extension_pre_shared_key:
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
			//tls13_pre_shared_key_print(fp, fmt, ind, ext_data, ext_datalen);
			break;
		case TLS_extension_cookie:
			tls13_cookie_print(fp, fmt, ind, ext_data, ext_datalen);
			break;
		default:
			format_bytes(fp, fmt, ind, "raw_data", ext_data, ext_datalen);
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


typedef struct {
	uint8_t resumption_master_secret[48];
	uint16_t protocol_version;
	uint16_t cipher_suite;
	uint32_t ticket_issue_time;
	uint32_t ticket_lifetime;
	// TODO: SNI, ALPN, client_certificate (dgst or subject), ticket_age_add, max_early_data_size
} TLS_TICKET;


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


int tls13_encrypt_ticket(const SM4_KEY *key, const uint8_t resumption_master_secret[48],
	int protocol_version, int cipher_suite, uint32_t ticket_issue_time,  uint32_t ticket_lifetime,
	uint8_t *out, size_t *outlen)
{
	uint8_t ticket[60];
	uint8_t *p = ticket;
	size_t ticketlen = 0;

	uint8_t *iv = out;
	size_t ivlen = 12;
	const uint8_t *aad = NULL;
	size_t aadlen = 0;
	uint8_t *tag;
	size_t taglen = 16;

	out += ivlen;
	tag = out + sizeof(ticket);

	tls_array_to_bytes(resumption_master_secret, 48, &p, &ticketlen);
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
	uint8_t resumption_master_secret[48], int *protocol_version, int *cipher_suite,
	uint32_t *ticket_issue_time, uint32_t *ticket_lifetime)
{
	const uint8_t *iv;
	size_t ivlen = 12;
	const uint8_t *aad = NULL;
	size_t aadlen = 0;
	const uint8_t *tag;
	size_t taglen = 16;

	uint8_t ticket[60];
	const uint8_t *cp = ticket;
	const uint8_t *master_secret;
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


	if (tls_array_from_bytes(&master_secret, 48, &cp, &inlen) != 1
		|| tls_uint16_from_bytes(&version, &cp, &inlen) != 1
		|| tls_uint16_from_bytes(&cipher, &cp, &inlen) != 1
		|| tls_uint32_from_bytes(ticket_issue_time, &cp, &inlen) != 1
		|| tls_uint32_from_bytes(ticket_lifetime, &cp, &inlen) != 1
		|| tls_length_is_zero(inlen) != 1) {
		error_print();
		return -1;
	}
	memcpy(resumption_master_secret, master_secret, 48);
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

int tls13_record_get_handshake_end_of_early_data(uint8_t *record, size_t *recordlen)
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

// 这里有一个问题，就是TLS 1.3的Certificate是由CertificateEntry构成的，
// 每一个Entry都有可选的扩展，都有哪些可选的扩展呢？
/*

	客户端在ClientHello扩展中对服务器的证书提出要求

	status_request				证书的OCSP响应
		这个扩展在ClientHello和ServerCertificate中的格式是不一样的
		暂时先不要支持了
		服务器可以忽略这个请求
		这个信息是需要经常更新的
		服务器可以每天（根据OCSP的配置）去OCSP服务器获取，并且在初始化的时候提供给ctx


	signed_certificate_timestamp		证书透明，证明证书已被提交到公共日志系统
		可能出现在客户端或者服务器端
		这个扩展本身可以嵌入在证书中，也可以从TLS扩展提供
		实际上没必要现在就实现

	certificate_authorities			接收的CA
		应该出现在CertificateRequest和ClientHello中
		我们需要支持从一组证书中获取这个信息
		这个已经支持了

	oid_filters
		仅仅出现在CertificateRequest中

	这些扩展处理起来是比较复杂的


	这里的主要问题是，每个证书都带有一组。


	每个CertificateEntry都包含一个extensions，extensions的结构是uint16array
	因此我们可以提供一个exts_list

Certificate {
    opaque certificate_request_context<0..2^8-1>;
    CertificateEntry certificate_list<0..2^24-1>;  // 证书链，第一个是终端证书
}

CertificateEntry {
    select (certificate_type) {
        case X509: opaque cert_data<1..2^24-1>;    // DER编码的X.509证书
    };
    Extension extensions<0..2^16-1>;               // 这个证书的扩展列表
}


*/
// 这个函数还应该提供扩展
int tls13_record_set_handshake_certificate(uint8_t *record, size_t *recordlen,
	const uint8_t *request_context, size_t request_context_len,
	const uint8_t *certs, size_t certslen,
	const uint8_t *exts_list, size_t exts_list_len)
{
	int type = TLS_handshake_certificate;
	uint8_t *data;
	size_t datalen;

	if (!record || !recordlen || !certs || !certslen) {
		error_print();
		return -1;
	}

	// 这个就比较复杂了，需要先计算所有的长度
	// 然后最后再输出

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

int tls13_send_client_hello(TLS_CONNECT *conn)
{
	int ret;

	if (!conn->recordlen) {
		const uint8_t *legacy_session_id = NULL;
		size_t legacy_session_id_len = 0;
		uint8_t exts[TLS_MAX_EXTENSIONS_SIZE];
		uint8_t *p = exts;
		size_t extslen = 0;
		size_t i;

		tls_trace("send ClientHello\n");

		// record_version
		tls_record_set_protocol(conn->record, TLS_protocol_tls1);

		if (rand_bytes(conn->client_random, 32) != 1) {
			error_print();
			return -1;
		}

		// legacy_session_id
		conn->session_id_len = 0;

		// key_share
		if (!conn->key_exchanges_cnt || conn->key_exchanges_cnt >
			sizeof(conn->key_exchanges)/sizeof(conn->key_exchanges[0])) {
			error_print();
			return -1;
		}
		for (i = 0; i < conn->ctx->supported_groups_cnt && i < conn->key_exchanges_cnt; i++) {
			int curve_oid = tls_named_curve_oid(conn->ctx->supported_groups[i]);
			if (x509_key_generate(&conn->key_exchanges[i],
				OID_ec_public_key, &curve_oid, sizeof(curve_oid)) != 1) {
				error_print();
				tls_send_alert(conn, TLS_alert_internal_error);
				return -1;
			}
		}

		// extensions
		if (tls13_client_supported_versions_ext_to_bytes(conn->ctx->supported_versions,
			conn->ctx->supported_versions_cnt, &p, &extslen) != 1
			|| tls_supported_groups_ext_to_bytes(conn->ctx->supported_groups,
			conn->ctx->supported_groups_cnt, &p, &extslen) != 1
			|| tls13_key_share_client_hello_ext_to_bytes(conn->key_exchanges,
			conn->key_exchanges_cnt, &p, &extslen) != 1
			|| tls_signature_algorithms_ext_to_bytes(conn->ctx->signature_algorithms,
			conn->ctx->signature_algorithms_cnt, &p, &extslen) != 1) {
			error_print();
			return -1;
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

	// backup ClientHello record for handshake message digest
	memcpy(conn->plain_record, conn->record, conn->recordlen);
	conn->plain_recordlen = conn->recordlen;

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
	int selected_version = -1;
	int key_share_group = -1;
	const uint8_t *cookie = NULL;
	size_t cookielen = 0;

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
	if (tls_type_is_in_list(cipher_suite, conn->cipher_suites, conn->cipher_suites_cnt) != 1) {
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
			// 这里都没有判断扩展是否重复			
			if (tls13_server_supported_versions_from_bytes(&selected_version,
				ext_data, ext_datalen) != 1) {
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
			break;

		case TLS_extension_key_share:
			if (tls13_key_share_hello_retry_request_from_bytes(&key_share_group,
				ext_data, ext_datalen) != 1) {
				error_print();
				tls_send_alert(conn, TLS_alert_decode_error);
				return -1;
			}
			if (tls_type_is_in_list(key_share_group, conn->ctx->supported_groups, conn->ctx->supported_groups_cnt) != 1) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			conn->key_exchange_group = key_share_group;
			break;

		case TLS_extension_cookie:
			if (tls13_cookie_from_bytes(&cookie, &cookielen, ext_data, ext_datalen) != 1) {
				error_print();
				tls_send_alert(conn, TLS_alert_decode_error);
				return -1;
			}
			memcpy(conn->cookie, cookie, cookielen);
			conn->cookielen = cookielen;
			break;

		// extensions MUST NOT be included
		case TLS_extension_supported_groups:
		case TLS_extension_signature_algorithms:
		case TLS_extension_server_name:
			error_print();
			tls_send_alert(conn, TLS_alert_illegal_parameter);
			break;

		// extensions can be ignored
		case TLS_extension_pre_shared_key:
		default:
			warning_print();
		}
	}

	if (selected_version < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_missing_extension);
		return -1;
	}
	if (key_share_group < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}

	// ClientHello1
	uint8_t message_hash[4 + 32];
	size_t dgstlen;
	message_hash[0] = TLS_handshake_message_hash;
	message_hash[1] = 0;
	message_hash[2] = 0;
	message_hash[3] = 32;

	digest_init(&conn->dgst_ctx, conn->digest);
	digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5);
	digest_finish(&conn->dgst_ctx, message_hash + 4, &dgstlen);

	// ClientHello, HelloRetryRequest
	digest_init(&conn->dgst_ctx, conn->digest);
	digest_update(&conn->dgst_ctx, message_hash, sizeof(message_hash));
	digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5);

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
		uint8_t *p = exts;
		size_t extslen = 0;
		int supported_versions = TLS_protocol_tls13;
		int curve_oid;

		// record_version
		tls_record_set_protocol(conn->record, TLS_protocol_tls1);

		// re-generate client_random
		if (rand_bytes(conn->client_random, 32) != 1) {
			error_print();
			return -1;
		}

		// re-generate key_share
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

		// extensions
		if (tls13_client_supported_versions_ext_to_bytes(conn->ctx->supported_versions,
			conn->ctx->supported_versions_cnt, &p, &extslen) != 1
			|| tls_supported_groups_ext_to_bytes(
			conn->ctx->supported_groups, conn->ctx->supported_groups_cnt, &p, &extslen) != 1
			|| tls13_key_share_client_hello_ext_to_bytes(
			conn->key_exchanges, conn->key_exchanges_cnt, &p, &extslen) != 1
			|| tls_signature_algorithms_ext_to_bytes(
			conn->ctx->signature_algorithms, conn->ctx->signature_algorithms_cnt, &p, &extslen) != 1) {
			error_print();
			return -1;
		}
		if (conn->cookielen) {
			if (tls13_cookie_ext_to_bytes(conn->cookie, conn->cookielen, &p, &extslen) != 1) {
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
		digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5);
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

	// supported_versions
	int selected_version = 0;
	// supported_groups
	int group = 0;
	const uint8_t *key_exchange = NULL;
	size_t key_exchange_len = 0;

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
			if (selected_version) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			if (tls13_server_supported_versions_from_bytes(
				&selected_version, ext_data, ext_datalen) != 1) {
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
			break;

		case TLS_extension_key_share:
			if (group) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			if (tls13_key_share_server_hello_from_bytes(
				&group, &key_exchange, &key_exchange_len, ext_data, ext_datalen) != 1) {
				error_print();
				tls_send_alert(conn, TLS_alert_decode_error);
				return -1;
			}
			while (conn->key_exchange_idx < conn->key_exchanges_cnt) {
				if (conn->key_exchanges[conn->key_exchange_idx].algor_param ==
					tls_named_curve_oid(group)) {
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
			conn->key_exchange_group = group;
			memcpy(conn->peer_key_exchange, key_exchange, key_exchange_len);
			conn->peer_key_exchange_len = 65;
			break;

		// extensions MUST NOT exist
		case TLS_extension_supported_groups:
		case TLS_extension_signature_algorithms:
		case TLS_extension_server_name:
			error_print();
			tls_send_alert(conn, TLS_alert_illegal_parameter);
			break;

		// extensions can be ignored
		case TLS_extension_pre_shared_key:
		default:
			warning_print();
		}
	}

	// ClientHello must contain supported_versions and key_share
	if (!selected_version || !group) {
		error_print();
		tls_send_alert(conn, TLS_alert_missing_extension);
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

int tls13_generate_keys(TLS_CONNECT *conn)
{
	uint8_t zeros[32] = {0};
	uint8_t psk[32] = {0};
	uint8_t early_secret[32];
	uint8_t handshake_secret[32];
	uint8_t pre_master_secret[32];
	size_t pre_master_secret_len;
	uint8_t client_write_key[16];
	uint8_t server_write_key[16];
	DIGEST_CTX null_dgst_ctx;

	printf("generate handshake secrets\n");

	/*
	generate handshake keys
		uint8_t client_write_key[32]
		uint8_t server_write_key[32]
		uint8_t client_write_iv[12]
		uint8_t server_write_iv[12]
	*/

	if (x509_key_exchange(&conn->key_exchanges[conn->key_exchange_idx],
		conn->peer_key_exchange, conn->peer_key_exchange_len,
		pre_master_secret, &pre_master_secret_len) != 1) {
		error_print();
		return -1;
	}

	digest_init(&null_dgst_ctx, conn->digest);


	{
		DIGEST_CTX tmp_dgst_ctx = conn->dgst_ctx;
		uint8_t dgst[32] = {0};
		size_t dgstlen;

		digest_finish(&tmp_dgst_ctx, dgst, &dgstlen);
		format_bytes(stderr, 0, 0, "dgst_ctx", dgst, dgstlen);
	}



	/* [1]  */ tls13_hkdf_extract(conn->digest, zeros, psk, early_secret);
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


	tls13_hkdf_expand_label(conn->digest, conn->client_handshake_traffic_secret, "key", NULL, 0, 16, client_write_key);
	block_cipher_set_encrypt_key(&conn->client_write_key, conn->cipher, client_write_key);
	tls13_hkdf_expand_label(conn->digest, conn->client_handshake_traffic_secret, "iv", NULL, 0, 12, conn->client_write_iv);
	tls_seq_num_reset(conn->client_seq_num);

	format_bytes(stderr, 0, 4, "client_write_key", client_write_key, 16);
	format_bytes(stderr, 0, 4, "server_write_key", server_write_key, 16);
	format_bytes(stderr, 0, 4, "client_write_iv", conn->client_write_iv, 12);
	format_bytes(stderr, 0, 4, "server_write_iv", conn->server_write_iv, 12);
	format_print(stderr, 0, 0, "\n");

	return 1;
}

int tls13_recv_encrypted_extensions(TLS_CONNECT *conn)
{
	int ret;
	const uint8_t *exts;
	size_t extslen;
	int supported_groups[1];
	size_t supported_groups_cnt = 0;

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
			if (supported_groups_cnt) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			// check ServerHello.exts.key_share.group in supported_groups
			if (tls_process_supported_groups(ext_data, ext_datalen,
				&conn->key_exchange_group, 1,
				supported_groups, &supported_groups_cnt, 1) != 1) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			break;

		case TLS_extension_early_data:
			if (ext_datalen) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			conn->early_data = 1;
			break;

		// extensions must not be included
		case TLS_extension_supported_versions:
		case TLS_extension_key_share:
		case TLS_extension_psk_key_exchange_modes:
			error_print();
			tls_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		case TLS_extension_server_name:
		case TLS_extension_application_layer_protocol_negotiation:
		case TLS_extension_record_size_limit:
		case TLS_extension_client_certificate_type:
		case TLS_extension_server_certificate_type:
		case TLS_extension_use_srtp:
		case TLS_extension_padding:
		case TLS_extension_signed_certificate_timestamp:
		case TLS_extension_status_request:
		default:
			// ignore
			warning_print();
		}
	}

	if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
		error_print();
		return -1;
	}

	tls_seq_num_incr(conn->server_seq_num);

	return 1;
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

	const uint8_t *certs;
	size_t certslen;
	const uint8_t *cert;
	size_t certlen;
	X509_KEY client_sign_key;
	int sig_alg_oid;
	int sig_algs[4];
	size_t sig_algs_cnt = 0;
	int common_sig_alg;
	size_t common_sig_alg_cnt;


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

	conn->certificate_request = 1;

	// request_context must be null in full/initial handshake
	// and must not be null in post authentication handshakes
	if (request_context) {
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

	if (!conn->client_certs_len) {
		error_print();
		tls_send_alert(conn, TLS_alert_certificate_unobtainable);
		return -1;
	}
	certs = conn->client_certs;
	certslen = conn->client_certs_len;

	// TODO: select client's certificate based on the extensions
	// currently the client's certificate has been set.
	// we need to check if the certificate match the extensions

	// signature_algorithms
	if (!signature_algorithms) {
		error_print();
		tls_send_alert(conn, TLS_alert_missing_extension);
		return -1;
	}
	if (x509_certs_get_cert_by_index(certs, certslen, 0, &cert, &certlen) != 1
		|| x509_cert_get_subject_public_key(cert, certlen, &client_sign_key) != 1) {
		error_print();
		return -1;
	}
	if (x509_key_get_sign_algor(&client_sign_key, &sig_alg_oid) != 1) {
		error_print();
		return -1;
	}
	switch (sig_alg_oid) {
	case OID_sm2sign_with_sm3:
		sig_algs[0] = TLS_sig_sm2sig_sm3;
		sig_algs_cnt = 1;
		break;
	case OID_ecdsa_with_sha256:
		sig_algs[0] = TLS_sig_ecdsa_secp256r1_sha256;
		//sig_algs[1] = TLS_sig_ecdsa_secp256r1_sha384;
		sig_algs_cnt = 1;
		break;
	default:
		error_print();
		return -1;
	}
	if (tls_process_signature_algorithms(signature_algorithms, signature_algorithms_len,
		sig_algs, sig_algs_cnt, &common_sig_alg, &common_sig_alg_cnt, 1) != 1) {
		error_print();
		return -1;
	}

	// signature_algorithms_cert, certificate_authorities, oid_filters
	while (certslen) {
		if (x509_cert_from_der(&cert, &certlen, &certs, &certslen) != 1) {
			error_print();
			return -1;
		}
		if (signature_algorithms_cert) {
			int sig_alg_cert_oid;
			int sig_alg_cert;

			if (x509_cert_get_signature_algor(cert, certlen, &sig_alg_cert_oid) != 1) {
				error_print();
				tls_send_alert(conn, TLS_alert_internal_error);
				return -1;
			}
			sig_alg_cert = tls_signature_scheme_from_oid(sig_alg_cert_oid);
			if (tls_process_signature_algorithms(
				signature_algorithms_cert, signature_algorithms_cert_len,
				&sig_alg_cert, 1, &common_sig_alg, &common_sig_alg_cnt, 1) != 1) {
				error_print();
				tls_send_alert(conn, TLS_alert_certificate_unobtainable);
				return -1;
			}
		}
		if (certificate_authorities) {
			if (tls_authorities_issued_certificate(certificate_authorities,
				certificate_authorities_len, cert, certlen) != 1) {
				error_print();
				tls_send_alert(conn, TLS_alert_certificate_unobtainable);
				return -1;
			}
		}
		if (oid_filters) {
			// TODO
		}
	}

	if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	tls_seq_num_incr(conn->server_seq_num);

	return 1;
}

int tls13_recv_server_certificate(TLS_CONNECT *conn)
{
	int ret;
	const uint8_t *request_context;
	size_t request_context_len;
	const uint8_t *cert_list;
	size_t cert_list_len;
	const uint8_t *cert;
	size_t certlen;
	X509_KEY server_sign_key;

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
		&cert_list, &cert_list_len)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return 0;
	}

	// TLS 1.3中证书列表是由CertificateListEntry构成的
	// 其中包含一个证书和若干的扩展
	/*
		CertificateListEntry中没有必选的扩展
		可选的扩展包括：status_request, signed_certificate_timestamp
		不能存在的扩展：certificate_authorities，server_name
	*/

	if (tls13_process_certificate_list(cert_list, cert_list_len,
		conn->server_certs, &conn->server_certs_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}


	if (x509_certs_get_cert_by_index(conn->server_certs, conn->server_certs_len, 0, &cert, &certlen) != 1
		|| x509_cert_get_subject_public_key(cert, certlen, &server_sign_key) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}


	// 要判断服务器的证书的公钥类型和客户端匹配了


	if (server_sign_key.algor != OID_ec_public_key
		|| server_sign_key.algor_param != OID_sm2) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5);
	tls_seq_num_incr(conn->server_seq_num);

	// verify ServerCertificate
	int verify_result = 0; // TODO: maybe remove this arg from x509_certs_verify()
	if (x509_certs_verify(conn->server_certs, conn->server_certs_len, X509_cert_chain_server,
		conn->ca_certs, conn->ca_certs_len, X509_MAX_VERIFY_DEPTH, &verify_result) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}

	return 1;
}

int tls13_recv_certificate_verify(TLS_CONNECT *conn)
{
	int ret;
	int sig_alg;
	const uint8_t *sig;
	size_t siglen;
	X509_KEY server_key;
	const uint8_t *cert;
	size_t certlen;

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

	// sig_alg in ClientHello.signature_algorithms
	if (tls_type_is_in_list(sig_alg, conn->ctx->signature_algorithms, conn->ctx->signature_algorithms_cnt) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}

	// sig_alg match server's certificate
	if (x509_certs_get_cert_by_index(conn->server_certs, conn->server_certs_len, 0, &cert, &certlen) != 1
		|| x509_cert_get_subject_public_key(cert, certlen, &server_key) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	switch (server_key.algor_param) {
	case OID_sm2:
		if (sig_alg != TLS_sig_sm2sig_sm3) {
			error_print();
			return -1;
		}
		break;
	case OID_secp256r1:
		if (sig_alg != TLS_sig_ecdsa_secp256r1_sha256) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}

	// verify signature
	if (tls13_verify_certificate_verify(TLS_server_mode,
		&server_key, TLS13_SM2_ID, TLS13_SM2_ID_LENGTH,
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
	format_bytes(stderr, 0, 4, "server_write_key", server_write_key, 16);
	format_bytes(stderr, 0, 4, "server_write_iv", conn->server_write_iv, 12);
	format_print(stderr, 0, 0, "\n");


	tls_seq_num_reset(conn->server_seq_num);


	return 1;
}

int tls13_send_client_certificate(TLS_CONNECT *conn)
{
	int ret;
	int client_sign_algor;
	uint8_t sig[TLS_MAX_SIGNATURE_SIZE];
	size_t siglen;

	size_t padding_len;

	tls_trace("send {Certificate*}\n");

	const uint8_t *request_context = NULL;
	size_t request_context_len = 0;
	const uint8_t *exts;
	size_t extslen = 0;

	if (tls13_record_set_handshake_certificate(conn->plain_record, &conn->plain_recordlen,
		request_context, request_context_len,
		conn->client_certs, conn->client_certs_len,
		exts, extslen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}
	tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);
	tls13_padding_len_rand(&padding_len);

	format_bytes(stderr, 0, 0, "client_seq_num", conn->client_seq_num, 8);
	if (tls13_record_encrypt(&conn->client_write_key, conn->client_write_iv,
		conn->client_seq_num, conn->plain_record, conn->plain_recordlen, padding_len,
		conn->record, &conn->recordlen) != 1) {
		error_print();
		return -1;
	}

	if (tls_record_send(conn->record, conn->recordlen, conn->sock) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}
	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5);
	tls_seq_num_incr(conn->client_seq_num);

	return 1;
}

int tls13_send_certificate_verify(TLS_CONNECT *conn)
{
	int ret;
	int sig_alg;
	uint8_t sig[256];
	size_t siglen;
	size_t padding_len;

	tls_trace("send {CertificateVerify*}\n");

	switch (conn->sign_key.algor_param) {
	case OID_sm2:
		sig_alg = TLS_sig_sm2sig_sm3;
		break;
	case OID_secp256r1:
		sig_alg = TLS_sig_ecdsa_secp256r1_sha256;
		break;
	default:
		error_print();
		return -1;
	}

	tls13_sign_certificate_verify(TLS_client_mode,
		&conn->sign_key.u.sm2_key, TLS13_SM2_ID, TLS13_SM2_ID_LENGTH,
		&conn->dgst_ctx, sig, &siglen);

	if (tls13_record_set_handshake_certificate_verify(
		conn->plain_record, &conn->plain_recordlen,
		sig_alg, sig, siglen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}
	tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

	digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5);

	format_bytes(stderr, 0, 0, "client_seq_num", conn->client_seq_num, 8);
	tls13_padding_len_rand(&padding_len);
	if (tls13_record_encrypt(&conn->client_write_key, conn->client_write_iv,
		conn->client_seq_num, conn->plain_record, conn->plain_recordlen, padding_len,
		conn->record, &conn->recordlen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
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
	uint8_t verify_data[64];
	size_t verify_data_len;
	size_t padding_len;

	uint8_t client_write_key[16];

	tls_trace("send {Finished}\n");

	tls13_compute_verify_data(conn->client_handshake_traffic_secret, &conn->dgst_ctx,
		verify_data, &verify_data_len);

	if (tls_record_set_handshake_finished(conn->plain_record, &conn->plain_recordlen,
		verify_data, verify_data_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}
	tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);
	digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5);

	format_bytes(stderr, 0, 0, "client_seq_num", conn->client_seq_num, 8);
	tls13_padding_len_rand(&padding_len);
	if (tls13_record_encrypt(&conn->client_write_key, conn->client_write_iv,
		conn->client_seq_num, conn->plain_record, conn->plain_recordlen, padding_len,
		conn->record, &conn->recordlen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	tls_seq_num_incr(conn->client_seq_num);


	//update client_write_key, client_write_iv, reset client_seq_num
	tls13_hkdf_expand_label(conn->digest, conn->client_application_traffic_secret, "key", NULL, 0, 16, client_write_key);
	tls13_hkdf_expand_label(conn->digest, conn->client_application_traffic_secret, "iv", NULL, 0, 12, conn->client_write_iv);
	block_cipher_set_encrypt_key(&conn->client_write_key, conn->cipher, client_write_key);
	tls_seq_num_reset(conn->client_seq_num);

	format_print(stderr, 0, 0, "update client secrets\n");
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
	// supported_versions ext
	int supported_versions[4];
	size_t supported_versions_cnt = 0;
	// supported_groups ext
	int supported_groups[4];
	size_t supported_groups_cnt = 0;
	// key_share ext
	const uint8_t *key_share = NULL;
	size_t key_share_len = 0;
	int group = 0;
	const uint8_t *key_exchange = NULL;
	size_t key_exchange_len = 0;


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
		conn->cipher_suites, conn->cipher_suites_cnt,
		&conn->cipher_suite)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_handshake_failure);
		return -1;
	}
	format_print(stderr, 0, 0, "cipher_suite: %s\n", tls_cipher_suite_name(conn->cipher_suite));
	tls13_cipher_suite_get(conn->cipher_suite, &conn->cipher, &conn->digest);

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
			// following extensions should not be empty
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}

		switch (ext_type) {
		case TLS_extension_supported_versions:
			if (supported_versions_cnt) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			if ((ret = tls13_process_client_supported_versions(ext_data, ext_datalen,
				conn->ctx->supported_versions, conn->ctx->supported_versions_cnt,
				supported_versions, &supported_versions_cnt,
				sizeof(supported_versions)/sizeof(supported_versions[0]))) < 0) {
				error_print();
				tls_send_alert(conn, TLS_alert_decode_error);
				return -1;
			} else if (ret == 0) {
				error_print();
				tls_send_alert(conn, TLS_alert_protocol_version);
				return -1;
			}
			// TODO: supported TLS1.2 and TLCP
			if (supported_versions[0] != TLS_protocol_tls13) {
				error_print();
				tls_send_alert(conn, TLS_alert_protocol_version);
				return -1;
			}
			conn->protocol = supported_versions[0];
			break;

		case TLS_extension_supported_groups:
			if (supported_groups_cnt) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			if ((ret = tls_process_supported_groups(ext_data, ext_datalen,
				conn->ctx->supported_groups, conn->ctx->supported_groups_cnt,
				supported_groups, &supported_groups_cnt,
				sizeof(supported_groups)/sizeof(supported_groups[0]))) < 0) {
				error_print();
				tls_send_alert(conn, TLS_alert_decode_error);
				return -1;
			} else if (ret == 0) {
				error_print();
				tls_send_alert(conn, TLS_alert_handshake_failure);
				return -1;
			}
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

		case TLS_extension_signature_algorithms:
			if (conn->signature_algorithms_cnt) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			if ((ret = tls_process_signature_algorithms(ext_data, ext_datalen,
				conn->ctx->signature_algorithms, conn->ctx->signature_algorithms_cnt,
				conn->signature_algorithms, &conn->signature_algorithms_cnt,
				sizeof(conn->signature_algorithms)/sizeof(conn->signature_algorithms[0]))) < 0) {
				error_print();
				tls_send_alert(conn, TLS_alert_decode_error);
				return -1;
			} else if (ret == 0) {
				error_print();
				tls_send_alert(conn, TLS_alert_handshake_failure);
				return -1;
			}
			break;

		default:
			warning_print();
		}
	}

	// supported_versions
	if (!supported_versions_cnt) {
		error_print();
		tls_send_alert(conn, TLS_alert_missing_extension);
		return -1;
	}

	// supported_groups
	if (!supported_groups_cnt) {
		error_print();
		tls_send_alert(conn, TLS_alert_missing_extension);
		return -1;
	}

	// key_share
	if (!key_share) {
		error_print();
		tls_send_alert(conn, TLS_alert_missing_extension);
		return -1;
	}
	if ((ret = tls13_process_key_share_client_hello(key_share, key_share_len,
		supported_groups, supported_groups_cnt,
		&group, &key_exchange, &key_exchange_len)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		// backup ClientHello1
		memcpy(conn->plain_record, conn->record, conn->recordlen);
		conn->plain_recordlen = conn->recordlen;
		conn->key_exchange_group = supported_groups[0];
		conn->hello_retry_request = 1;
	} else {
		if (key_exchange_len != 65) {
			error_print();
			return -1;
		}
		conn->key_exchange_group = group;
		memcpy(conn->peer_key_exchange, key_exchange, key_exchange_len);
		conn->peer_key_exchange_len = key_exchange_len;
	}

	// signature_algorithms
	if (!conn->signature_algorithms_cnt) {
		error_print();
		tls_send_alert(conn, TLS_alert_missing_extension);
		return -1;
	}
	// 如果服务器支持多个证书链，那么应该根据签名算法以及SNI去选择证书链
	// 但是目前我们只有一个服务器证书链，因此应该判断服务器的签名算法是否和这个签名算法匹配
	// 最好在设置CTX证书的时候，把证书的DN和签名算法先提取出来
	// 实际上证书中的公钥类型没有办法完全确定签名算法，比如ecdsa-p256-sha256 和 ecdsa-p256-sha384，公钥类型一样但是签名不同


	if (conn->hello_retry_request) {
		uint8_t message_hash[4 + 32];
		size_t dgstlen;

		message_hash[0] = TLS_handshake_message_hash;
		message_hash[1] = 0;
		message_hash[2] = 0;
		message_hash[3] = 32;

		digest_init(&conn->dgst_ctx, conn->digest);
		digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5);
		digest_finish(&conn->dgst_ctx, message_hash + 4, &dgstlen);

		digest_init(&conn->dgst_ctx, conn->digest);
		digest_update(&conn->dgst_ctx, message_hash, sizeof(message_hash));
	} else {
		digest_init(&conn->dgst_ctx, conn->digest);
		digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5);
	}

	if (client_verify)
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);

	tls_clean_record(conn);

	return 1;
}




/*
如果客户端提供的supported_groups满足服务器的条件，也就是有common_gruops
但是客户端发送的key_share里面并没有
这时候服务器要发送HRR消息了
因此recv_client_hello要决定下一个状态变化的状态，也就是说我们要有一个conn的状态来记录这个


在初始化的时候，客户端提供的supported_groups : secp256r1, sm2
但是key_share中只提供secp256r1

服务器的supported_groups 中只有sm2

*/

int tls13_send_hello_retry_request(TLS_CONNECT *conn)
{
	int ret;

	tls_trace("send HelloRetryRequest\n");

	if (conn->recordlen == 0) {
		uint8_t exts[256];
		uint8_t *p = exts;
		size_t extslen = 0;
		int curve_oid;
		uint8_t cookie[] = "Cookie from server";


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
		// cookie for testing
		if (tls13_cookie_ext_to_bytes(cookie, sizeof(cookie), &p, &extslen) != 1) {
			error_print();
			return -1;
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

	digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5);

	if (conn->ca_certs_len) {
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
		int curve_oid;

		tls_record_set_protocol(conn->record, TLS_protocol_tls12);
		if (rand_bytes(conn->server_random, 32) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

		// key_share
		if ((curve_oid = tls_named_curve_oid(conn->key_exchange_group)) == OID_undef) {
			error_print();
			return -1;
		}
		if (x509_key_generate(&conn->key_exchanges[0], OID_ec_public_key, &curve_oid, sizeof(curve_oid)) != 1) {
			error_print();
			return -1;
		}

		if (tls13_server_supported_versions_ext_to_bytes(conn->protocol, &p, &extslen) != 1
			|| tls13_key_share_server_hello_ext_to_bytes(&conn->key_exchanges[0], &p, &extslen) != 1) {
			error_print();
			return -1;
		}
		if (tls_record_set_handshake_server_hello(conn->record, &conn->recordlen,
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

	digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5);

	if (conn->ca_certs_len) {
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
		if (tls_supported_groups_ext_to_bytes(conn->ctx->supported_groups,
			conn->ctx->supported_groups_cnt, &p, &extslen) != 1) {
			error_print();
			return -1;
		}
		// empty early_data
		// 需要根据系统的配置决定是否支持0-RTT
		if (tls_ext_to_bytes(TLS_extension_early_data, NULL, 0, &p, &extslen) != 1) {
			error_print();
			return -1;
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

	if (conn->ca_certs_len) {
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
		uint8_t exts_list[256];
		size_t exts_list_len = 0;
		uint8_t exts[128];
		uint8_t *p = exts;
		size_t extslen = 0;
		size_t padding_len;

		// CertificateEntry.extensions
		if (conn->ctx->certificate_status_len) {
			if (tls_ext_to_bytes(TLS_extension_status_request,
				conn->ctx->certificate_status, conn->ctx->certificate_status_len,
				&p, &extslen) != 1) {
				error_print();
				return -1;
			}
		}
		if (conn->ctx->signed_certificate_timestamp_len) {
			if (tls_ext_to_bytes(TLS_extension_signed_certificate_timestamp,
				conn->ctx->signed_certificate_timestamp, conn->ctx->signed_certificate_timestamp_len,
				&p, &extslen) != 1) {
				error_print();
				return -1;
			}
		}
		p = exts_list;
		tls_uint16array_to_bytes(exts, extslen, &p, &exts_list_len);

		if (tls13_record_set_handshake_certificate(conn->plain_record, &conn->plain_recordlen,
			request_context, request_context_len,
			conn->server_certs, conn->server_certs_len,
			exts_list, exts_list_len) != 1) {
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
		uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
		size_t siglen;
		size_t padding_len;

		tls13_sign_certificate_verify(TLS_server_mode,
			&conn->sign_key.u.sm2_key, TLS13_SM2_ID, TLS13_SM2_ID_LENGTH,
			&conn->dgst_ctx, sig, &siglen);

		// 服务器的签名算法实际上是由签名密钥决定的，目前签名密钥（曲线）决定了签名算法
		// 一个签名算法目前不支持可选的哈希函数，因此这个就决定了

		// 这段代码要挪到server_hello后者之后
		switch (conn->sign_key.algor_param) {
		case OID_sm2:
			conn->sig_alg = TLS_sig_sm2sig_sm3;
			break;
		case OID_secp256r1:
			conn->sig_alg = TLS_sig_ecdsa_secp256r1_sha256;
			break;
		default:
			error_print();
			return -1;
		}


		if (tls13_record_set_handshake_certificate_verify(
			conn->plain_record, &conn->plain_recordlen,
			conn->sig_alg, sig, siglen) != 1) {
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

	const uint8_t *request_context;
	size_t request_context_len;
	const uint8_t *cert_list;
	size_t cert_list_len;

	if ((ret = tls13_record_get_handshake_certificate(conn->plain_record,
		&request_context, &request_context_len,
		&cert_list, &cert_list_len)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return 0;
	}

	// 这里要处理什么？			
	if (tls13_process_certificate_list(cert_list, cert_list_len,
		conn->server_certs, &conn->server_certs_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	/*
	if (x509_certs_get_cert_by_index(conn->server_certs, conn->server_certs_len, 0, &cert, &certlen) != 1
		|| x509_cert_get_subject_public_key(cert, certlen, &server_sign_key) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}


		if (x509_cert_get_subject_public_key(cert, certlen, &client_sign_key) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_certificate);
			goto end;
		}
		if (client_sign_key.algor != OID_ec_public_key
			|| client_sign_key.algor_param != OID_sm2) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_certificate);
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
	*/

	return 1;
}


/*
struct {
    SignatureScheme algorithm;
    opaque signature<0..2^16-1>;
} CertificateVerify;
*/
int tls13_recv_client_certificate_verify(TLS_CONNECT *conn)
{
	int ret;

	// CertificateVerify
	int sig_alg;
	const uint8_t *sig;
	size_t siglen;

	tls_trace("recv Client {CertificateVerify*}\n");

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

	/*
	if (sig_alg != conn->client_sig_alg) {
		error_print();
		tls_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}

	*/
	X509_KEY client_sign_key;			

	if (tls13_verify_certificate_verify(TLS_client_mode,
		&client_sign_key, TLS13_SM2_ID, TLS13_SM2_ID_LENGTH,
		&conn->dgst_ctx,sig, siglen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}
	digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5);
	tls_seq_num_incr(conn->client_seq_num);

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
		uint8_t ticket[12 + 60 + 16];
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
		if (tls13_encrypt_ticket(&conn->ctx->server_session_ticket_key,
			conn->master_secret, conn->protocol, conn->cipher_suite,
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

int tls13_save_session_ticket(TLS_CONNECT *conn, const uint8_t *new_session_ticket, size_t new_session_ticket_len)
{
	tls13_ticket_print(stderr, 0, 0, "save SessionTicket", new_session_ticket, new_session_ticket_len);

	return 1;
}

int tls13_recv_new_session_ticket(TLS_CONNECT *conn)
{
	int ret;
	int handshake_type;
	const uint8_t *handshake_data;
	size_t handshake_datalen;

	uint32_t ticket_lifetime;
	uint32_t ticket_age_add;
	const uint8_t *ticket_nonce;
	const uint8_t *ticket;
	const uint8_t *exts;
	size_t ticket_nonce_len, ticketlen, extslen;
	size_t max_early_data_size;
	const uint8_t *cp;
	size_t len;

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

	// save ticket
	if (tls13_save_session_ticket(conn, handshake_data, handshake_datalen) != 1) {
		error_print();
		return -1;
	}

	return 1;
}



/*
	send_client_hello
	*recv_hello_retry_request
	if (recv_hello_retry_request)
		send_client_hello2
	recv_server_hello
	recv_encrypted_extensions
	*recv_certificate_request
	recv_server_certificate
	recv_certificate_verify
	recv_server_finished
	if (recv_certificate_request)
		send_client_certificate
		send_certificate_verify
	send_client_finished
*/


int tls13_do_client_handshake(TLS_CONNECT *conn)
{
	int ret;
	int next_state;

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
		next_state = TLS_state_generate_keys;
		break;

	case TLS_state_generate_keys:
		ret = tls13_generate_keys(conn);
		next_state = TLS_state_encrypted_extensions;
		break;

	case TLS_state_encrypted_extensions:
		ret = tls13_recv_encrypted_extensions(conn);
		next_state = TLS_state_certificate_request;
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
		if (conn->client_certificate_verify)
			next_state = TLS_state_client_certificate;
		else	next_state = TLS_state_client_finished;
		break;

	case TLS_state_client_certificate:
		ret = tls13_send_client_certificate(conn);
		next_state = TLS_state_client_certificate_verify;
		break;

	case TLS_state_client_certificate_verify:
		ret = tls13_send_certificate_verify(conn);
		next_state = TLS_state_client_finished;
		break;

	case TLS_state_client_finished:
		ret = tls13_send_client_finished(conn);
		next_state = TLS_state_handshake_over;
		next_state = TLS_state_new_session_ticket;
		break;

	case TLS_state_new_session_ticket:
		ret = tls13_recv_new_session_ticket(conn);
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
		if (conn->hello_retry_request)
			next_state = TLS_state_hello_retry_request;
		else	next_state = TLS_state_server_hello;
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
		next_state = TLS_state_generate_keys;
		break;

	case TLS_state_generate_keys:
		ret = tls13_generate_keys(conn);
		next_state = TLS_state_encrypted_extensions;

	case TLS_state_encrypted_extensions:
		ret = tls13_send_encrypted_extensions(conn);
		if (conn->certificate_request)
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
		if (conn->certificate_request)
			next_state = TLS_state_client_certificate;
		else	next_state = TLS_state_client_finished;
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
		ret = tls13_send_new_session_ticket(conn);
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

