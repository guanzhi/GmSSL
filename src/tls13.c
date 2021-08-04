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
#include <gmssl/digest.h>
#include <gmssl/gcm.h>
#include <gmssl/hmac.h>
#include <gmssl/hkdf.h>
#include "mem.h"



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
	uint8_t *mbuf = malloc(inlen + 256); // FIXME: update gcm_encrypt API		
	size_t mlen, clen;

	// nonce = (zeros|seq_num) xor (iv)
	nonce[0] = nonce[1] = nonce[2] = 0;
	memcpy(nonce + 3, seq_num, 8);
	gmssl_memxor(nonce, nonce, iv, 12);

	// TLSInnerPlaintext
	memcpy(mbuf, in, inlen);
	mbuf[inlen] = record_type;
	memset(mbuf + inlen + 1, 0, padding_len);
	mlen = inlen + 1 + padding_len;
	clen = mlen + GHASH_SIZE;

	// aad = TLSCiphertext header
	aad[0] = TLS_record_application_data;
	aad[1] = TLS_version_tls12_major;
	aad[2] = TLS_version_tls12_minor;
	aad[3] = clen >> 8;
	aad[4] = clen;

	gmac = out + mlen;
	if (gcm_encrypt(key, nonce, sizeof(nonce), aad, sizeof(aad), mbuf, mlen, out, 16, gmac) != 1) {
		error_print();
		return -1;
	}
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
	size_t i;

	// nonce = (zeros|seq_num) xor (iv)
	nonce[0] = nonce[1] = nonce[2] = 0;
	memcpy(nonce + 3, seq_num, 8);
	gmssl_memxor(nonce, nonce, iv, 12);

	// aad = TLSCiphertext header
	aad[0] = TLS_record_application_data;
	aad[1] = TLS_version_tls12_major;
	aad[2] = TLS_version_tls12_minor;
	aad[3] = inlen >> 8;
	aad[4] = inlen;

	if (inlen < GHASH_SIZE) {
		error_print();
		return -1;
	}
	mlen = inlen - GHASH_SIZE;
	gmac = in + mlen;

	if (gcm_decrypt(key, iv, 12, aad, 5, in, mlen, gmac, GHASH_SIZE, out) != 1) {
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

	enced_record[0] = TLS_record_application_data;
	enced_record[1] = TLS_version_tls12_major;
	enced_record[2] = TLS_version_tls12_minor;
	enced_record[3] = (*enced_recordlen) >> 8;
	enced_record[4] = (*enced_recordlen);

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
	record[1] = TLS_version_tls12_major;
	record[2] = TLS_version_tls12_minor;
	record[3] = (*recordlen) >> 8;
	record[4] = (*recordlen);

	(*recordlen) += 5;
	return 1;
}

int tls13_send(TLS_CONNECT *conn, const uint8_t *data, size_t datalen, size_t padding_len)
{
	const BLOCK_CIPHER_KEY *key;
	const uint8_t *iv;
	uint8_t *seq_num;
	uint8_t *record = conn->record;
	size_t recordlen;

	tls_trace("<<<< [ApplicationData]\n");

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
	record[1] = TLS_version_tls12 >> 8;
	record[2] = TLS_version_tls12 & 0xff;
	record[3] = recordlen >> 8;
	record[4] = recordlen;
	recordlen += 5;

	tls_record_send(record, recordlen, conn->sock);
	tls_seq_num_incr(seq_num);

	return 1;
}

int tls13_recv(TLS_CONNECT *conn, uint8_t *data, size_t *datalen)
{
	int record_type;
	uint8_t *record = conn->record;
	size_t recordlen;
	const BLOCK_CIPHER_KEY *key;
	const uint8_t *iv;
	uint8_t *seq_num;


	tls_trace(">>>> [ApplicationData]\n");

	if (conn->is_client) {
		key = &conn->client_write_key;
		iv = conn->client_write_iv;
		seq_num = conn->client_seq_num;
	} else {
		key = &conn->server_write_key;
		iv = conn->server_write_iv;
		seq_num = conn->server_seq_num;
	}

	if (tls12_record_recv(record, &recordlen, conn->sock) != 1) {
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
	tls_seq_num_incr(seq_num);

	if (record_type != TLS_record_application_data) {
		error_print();
		return -1;
	}
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

	label_len = strlen("tls13") + strlen(label);
	tls_uint16_to_bytes((uint16_t)outlen, &p, &hkdf_label_len);
	tls_uint8_to_bytes(label_len, &p, &hkdf_label_len);
	tls_array_to_bytes((uint8_t *)"tls13", strlen("tls13"), &p, &hkdf_label_len);
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


/*
data to be signed in certificate_verify:
   -  A string that consists of octet 32 (0x20) repeated 64 times
   -  The context string
   -  A single 0 byte which serves as the separator
   -  The content to be signed
*/
int tls13_sign(const SM2_KEY *key, const DIGEST_CTX *dgst_ctx, uint8_t *sig, size_t *siglen, int is_server)
{
	uint8_t client_context_str[] = "TLS 1.3, client CertificateVerify";
	uint8_t server_context_str[] = "TLS 1.3, server CertificateVerify";

	SM2_SIGN_CTX sm2_ctx;
	DIGEST_CTX temp_dgst_ctx;
	uint8_t prefix[64];
	uint8_t *context_str = is_server ? server_context_str : client_context_str;
	size_t context_str_len = sizeof(client_context_str);
	uint8_t dgst[64];
	size_t dgstlen;

	memset(prefix, 0x20, 64);
	temp_dgst_ctx = *dgst_ctx;
	digest_finish(&temp_dgst_ctx, dgst, &dgstlen);

	sm2_sign_init(&sm2_ctx, key, SM2_DEFAULT_ID);
	sm2_sign_update(&sm2_ctx, prefix, 64);
	sm2_sign_update(&sm2_ctx, context_str, context_str_len);
	sm2_sign_update(&sm2_ctx, dgst, dgstlen);
	sm2_sign_finish(&sm2_ctx, sig, siglen);

	return 1;
}

int tls13_verify(const SM2_KEY *key, const DIGEST_CTX *dgst_ctx, const uint8_t *sig, size_t siglen, int is_server)
{
	uint8_t client_context_str[] = "TLS 1.3, client CertificateVerify";
	uint8_t server_context_str[] = "TLS 1.3, server CertificateVerify";

	int ret;
	SM2_SIGN_CTX sm2_ctx;
	DIGEST_CTX temp_dgst_ctx;
	uint8_t prefix[64];
	uint8_t dgst[64];
	size_t dgstlen;

	memset(prefix, 0x20, 64);
	temp_dgst_ctx = *dgst_ctx;
	digest_finish(&temp_dgst_ctx, dgst, &dgstlen);

	sm2_verify_init(&sm2_ctx, key, SM2_DEFAULT_ID);
	sm2_verify_update(&sm2_ctx, prefix, 64);
	sm2_verify_update(&sm2_ctx, is_server ? server_context_str : client_context_str, sizeof(server_context_str));
	sm2_verify_update(&sm2_ctx, dgst, dgstlen);
	ret = sm2_verify_finish(&sm2_ctx, sig, siglen);

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

int tls_ext_supported_versions_to_bytes(const int *versions, size_t versions_count,
	uint8_t **out, size_t *outlen)
{
	uint16_t ext_type = TLS_extension_supported_versions;
	uint8_t versions_len = sizeof(uint16_t) * versions_count;
	size_t i;

	tls_uint16_to_bytes(ext_type, out, outlen);
	tls_uint16_to_bytes(1 + versions_len, out, outlen);
	tls_uint8_to_bytes(versions_len, out, outlen);
	for (i = 0; i < versions_count; i++) {
		tls_uint16_to_bytes(versions[i], out, outlen);
	}
	return 1;
}

int tls_ext_signature_algorithms_to_bytes(const int *algors, size_t algors_count,
	uint8_t **out, size_t *outlen)
{
	uint16_t ext_type = TLS_extension_signature_algorithms;
	uint16_t algors_len = sizeof(uint16_t) * algors_count;
	size_t i;

	tls_uint16_to_bytes(ext_type, out, outlen);
	tls_uint16_to_bytes(2 + algors_len, out, outlen);
	tls_uint16_to_bytes(algors_len, out, outlen);
	for (i = 0; i < algors_count; i++) {
		tls_uint16_to_bytes(algors[i], out, outlen);
	}
	return 1;
}

int tls_ext_supported_groups_to_bytes(const int *groups, size_t groups_count,
	uint8_t **out, size_t *outlen)
{
	uint16_t ext_type = TLS_extension_supported_groups;
	uint16_t groups_len = sizeof(uint16_t) * groups_count;
	size_t i;

	tls_uint16_to_bytes(ext_type, out, outlen);
	tls_uint16_to_bytes(2 + groups_len, out, outlen);
	tls_uint16_to_bytes(groups_len, out, outlen);
	for (i = 0; i < groups_count; i++) {
		tls_uint16_to_bytes(groups[i], out, outlen);
	}
	return 1;
}

int tls_ext_key_share_client_hello_to_bytes(
	const SM2_POINT *sm2_point, const SM2_POINT *p256_point,
	uint8_t **out, size_t *outlen)
{
	uint16_t ext_type = TLS_extension_key_share;
	uint16_t client_shares_len = 0;
	uint8_t sm2_key_exchange[65];
	uint8_t p256_key_exchange[65];

	if (sm2_point) {
		sm2_point_to_uncompressed_octets(sm2_point, sm2_key_exchange);
		client_shares_len += 69;
	}
	if (p256_point) {
		sm2_point_to_uncompressed_octets(p256_point, p256_key_exchange);
		client_shares_len += 69;
	}

	tls_uint16_to_bytes(ext_type, out, outlen);
	tls_uint16_to_bytes(2 + client_shares_len, out, outlen);
	tls_uint16_to_bytes(client_shares_len, out, outlen);
	if (sm2_point) {
		tls_uint16_to_bytes(TLS_curve_sm2p256v1, out, outlen);
		tls_uint16array_to_bytes(sm2_key_exchange, 65, out, outlen);
	}
	if (p256_point) {
		tls_uint16_to_bytes(TLS_curve_secp256r1, out, outlen);
		tls_uint16array_to_bytes(p256_key_exchange, 65, out, outlen);
	}
	return 1;
}

int tls_ext_key_share_server_hello_to_bytes(const SM2_POINT *sm2_point, const SM2_POINT *p256_point,
	uint8_t **out, size_t *outlen)
{
	uint16_t ext_type = TLS_extension_key_share;
	uint16_t group;
	uint8_t key_exchange[65];

	if (sm2_point) {
		group = TLS_curve_sm2p256v1;
		sm2_point_to_uncompressed_octets(sm2_point, key_exchange);
	} else if (p256_point) {
		group = TLS_curve_secp256r1;
		sm2_point_to_uncompressed_octets(p256_point, key_exchange);
	}

	tls_uint16_to_bytes(ext_type, out, outlen);
	tls_uint16_to_bytes(69, out, outlen);
	tls_uint16_to_bytes(group, out, outlen);
	tls_uint16array_to_bytes(key_exchange, 65, out, outlen);
	return 1;
}

/*
ClientHello Extensions:
	supported_versions
	supported_groups
	signature_algorithms
*/
int tls13_client_hello_extensions_set(uint8_t *exts, size_t *extslen, const SM2_POINT *sm2_point)
{
	uint8_t *p = exts;
	int versions[] = { TLS_version_tls13 };
	int supported_groups[] = { TLS_curve_sm2p256v1 };
	int sign_algors[] = { TLS_sig_sm2sig_sm3 };

	*extslen = 0;
	tls_ext_supported_versions_to_bytes(versions, 1, &p, extslen);
	tls_ext_supported_groups_to_bytes(supported_groups, 1, &p, extslen);
	tls_ext_signature_algorithms_to_bytes(sign_algors, 1, &p, extslen);
	tls_ext_key_share_client_hello_to_bytes(sm2_point, NULL, &p, extslen);
	return 1;
}

int tls_ext_supported_groups_match(const uint8_t *ext_data, size_t ext_datalen, int group)
{
	const uint8_t *p;
	size_t len;

	if (tls_uint16array_from_bytes(&p, &len, &ext_data, &ext_datalen) != 1
		|| ext_datalen > 0) {
		error_print();
		return -1;
	}
	while (len) {
		uint16_t supported_group;
		if (tls_uint16_from_bytes(&supported_group, &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (supported_group == group) {
			return 1;
		}
	}
	error_print();
	return -1;
}

int tls_ext_signature_algorithms_match(const uint8_t *ext_data, size_t ext_datalen, int algor)
{
	const uint8_t *p;
	size_t len;

	if (tls_uint16array_from_bytes(&p, &len, &ext_data, &ext_datalen) != 1
		|| ext_datalen > 0) {
		error_print();
		return -1;
	}
	while (len) {
		uint16_t supported_algor;
		if (tls_uint16_from_bytes(&supported_algor, &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (supported_algor == algor) {
			return 1;
		}
	}
	error_print();
	return -1;
}

int tls_ext_supported_versions_match(const uint8_t *ext_data, size_t ext_datalen, int version)
{
	const uint8_t *p;
	size_t len;

	if (tls_uint8array_from_bytes(&p, &len, &ext_data, &ext_datalen) != 1
		|| ext_datalen > 0) {
		error_print();
		return -1;
	}
	while (len) {
		uint16_t supported_version;
		if (tls_uint16_from_bytes(&supported_version, &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (supported_version == version) {
			return 1;
		}
	}
	error_print();
	return -1;
}

int tls_ext_key_share_client_hello_get(const uint8_t *ext_data, size_t ext_datalen,
	int prefered_curve, int *curve, SM2_POINT *point)
{
	const uint8_t *client_shares;
	size_t client_shares_len;

	*curve = 0;

	if (tls_uint16array_from_bytes(&client_shares, &client_shares_len, &ext_data, &ext_datalen) != 1
		|| ext_datalen > 0) {
		error_print();
		return -1;
	}
	while (client_shares_len) {
		uint16_t group;
		const uint8_t *key_exchange;
		size_t key_exchange_len;

		if (tls_uint16_from_bytes(&group, &client_shares, &client_shares_len) != 1
			|| tls_uint16array_from_bytes(&key_exchange, &key_exchange_len, &client_shares, &client_shares_len) != 1) {
			error_print();
			return -1;
		}
		switch (group) {
		case TLS_curve_sm2p256v1:
		case TLS_curve_secp256r1:
			if (key_exchange_len != 65) {
				error_print();
				return -1;
			}
			if (sm2_point_from_octets(point, key_exchange, key_exchange_len) != 1) {
				error_print();
				return -1;
			}
			*curve = group;
			if (prefered_curve == group) {
				return 1;
			}
			break;
		}
	}

	error_print();
	return -1;
}

int tls13_client_hello_extensions_get(const uint8_t *exts, size_t extslen, SM2_POINT *client_ecdhe_public)
{
	/*
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
		case TLS_extension_supported_groups:
			if (sm2_point && tls_ext_supported_groups_match(ext_data, ext_datalen, TLS_curve_sm2p256v1)) {
			} else if (p256_point && tls_ext_supported_groups_match(ext_data, ext_datalen, TLS_curve_secp256r1)) {
				error_print();
				return -1;
			}
			break;
		case TLS_extension_signature_algorithms:
			if (sm2_point && tls_ext_signature_algorithms_match(ext_data, ext_datalen, TLS_sig_ecdsa_secp256r1_sha256)) {
			} else if (p256_point && tls_ext_signature_algorithms_match(ext_data, ext_datalen, TLS_sig_sm2sig_sm3)) {
			} else {
				error_print();
				return -1;
			}
			break;
		case TLS_extension_supported_versions:
			if (tls_ext_supported_versions_match(ext_data, ext_datalen, TLS_version_tls13) != 1) {
				error_print();
				return -1;
			}
			break;
		case TLS_extension_key_share:
			break;

		default:
			error_print();
			return -1;
		}
	}

	*/
	return 1;
}

int tls13_server_hello_extensions_set(uint8_t *exts, size_t *extslen,
	const SM2_POINT *sm2_point, const SM2_POINT *p256_point)
{
	uint8_t *p = exts;
	int version = TLS_version_tls13;

	*extslen = 0;
	tls_ext_supported_versions_to_bytes(&version, 1, &p, extslen);
	tls_ext_key_share_server_hello_to_bytes(sm2_point, p256_point, &p, extslen);
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

int tls13_server_hello_extensions_get(const uint8_t *exts, size_t extslen, SM2_POINT *sm2_point)
{
	uint16_t version;
	while (extslen) {
		uint16_t ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;
		const uint8_t *p;
		size_t len;

		tls_uint16_from_bytes(&ext_type, &exts, &extslen);
		tls_uint16array_from_bytes(&ext_data, &ext_datalen, &exts, &extslen);

		switch (ext_type) {
		case TLS_extension_supported_versions:
			if (tls_uint16_from_bytes(&version, &ext_data, &ext_datalen) != 1
				|| ext_datalen > 0) {
				error_print();
				return -1;
			}
			if (version != TLS_version_tls13) {
				error_print();
				return -1;
			}
			break;
		case TLS_extension_key_share:
			if (tls_client_key_shares_from_bytes(sm2_point, &ext_data, &ext_datalen) != 1) {
				error_print();
				return -1;
			}
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

int tls13_record_set_handshake_encrypted_extensions(uint8_t *record, size_t *recordlen,
	const uint8_t *exts_data, size_t exts_datalen)
{
	int type = TLS_handshake_encrypted_extensions;
	uint8_t *p = record + 5 + 4;
	size_t len = 0;

	tls_uint16array_to_bytes(exts_data, exts_datalen, &p, &len);
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
		error_print();
		return -1;
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

	if (tls_record_get_handshake(record, &type, &p, &len) != 1
		|| type != TLS_handshake_certificate_verify) {
		error_print();
		return -1;
	}

	*sign_algor = 0;
	tls_uint16_from_bytes((uint16_t *)sign_algor, &p, &len);
	tls_uint16array_from_bytes(sig, siglen, &p, &len);


	return 1;
}

/*
struct {
	opaque certificate_request_context<0..2^8-1>;
	Extension extensions<2..2^16-1>;
} CertificateRequest;
*/
static int tls13_certificate_request_exts[] = {
	TLS_extension_status_request,
	TLS_extension_signature_algorithms,
	TLS_extension_signed_certificate_timestamp,
	TLS_extension_certificate_authorities,
	TLS_extension_oid_filters,
	TLS_extension_signature_algorithms_cert,
};

int tls13_record_set_handshake_certificate_request(uint8_t *record, size_t *recordlen,
	const uint8_t *req_context, size_t req_context_len,
	const uint8_t *exts, size_t extslen)
{
	int type = TLS_handshake_certificate_request;
	uint8_t *p = record + 5 + 4;
	size_t len = 0;
	int sign_algors[] = { TLS_sig_sm2sig_sm3, TLS_sig_ecdsa_secp256r1_sha256 };
	size_t sign_algors_count = sizeof(sign_algors)/sizeof(sign_algors[0]);

	tls_ext_signature_algorithms_to_bytes(sign_algors, 2, NULL, &extslen);
	tls_uint8array_to_bytes(req_context, req_context_len, &p, &len);
	tls_uint16_to_bytes(extslen, &p, &len);
	tls_ext_signature_algorithms_to_bytes(sign_algors, sign_algors_count, &p, &len);
	tls_record_set_handshake(record, recordlen, type, NULL, len);

	return 1;
}

int tls13_record_get_handshake_certificate_request(const uint8_t *record,
	const uint8_t **req_context, size_t *req_context_len,
	const uint8_t **exts, size_t *extslen)
{

	return 1;
}


/*
struct {
	opaque cert_data<1..2^24-1>;
	Extension extensions<0..2^16-1>;
} CertificateEntry;

struct {
	opaque certificate_request_context<0..2^8-1>;
	CertificateEntry certificate_list<0..2^24-1>;
} TLS13Certificate;
*/

static const int tls13_handshake_certificate_exts[] = {
	TLS_extension_status_request,
	TLS_extension_signed_certificate_timestamp,
};

// TODO: 当前未设置CertificateEntry.extensions
int tls13_record_set_handshake_certificate_from_pem(uint8_t *record, size_t *recordlen, FILE *fp)
{
	int type = TLS_handshake_certificate;
	uint8_t *data = record + 5 + 4;
	uint8_t *certs = data + 3;
	size_t datalen, certslen = 0;

	for (;;) {
		int ret;
		X509_CERTIFICATE cert;
		uint8_t der[1024];
		const uint8_t *cp = der;
		size_t derlen;

		if ((ret = pem_read(fp, "CERTIFICATE", der, &derlen)) < 0) {
			error_print();
			return -1;
		} else if (ret == 0) {
			break;
		}
		tls_uint24array_to_bytes(der, derlen, &certs, &certslen);
		if (x509_certificate_from_der(&cert, &cp, &derlen) != 1
			|| derlen > 0) {
			error_print();
			return -1;
		}
		//x509_certificate_print(stderr, &cert, 0, 0);
	}
	datalen = certslen;
	tls_uint24_to_bytes((uint24_t)certslen, &data, &datalen);
	tls_record_set_handshake(record, recordlen, type, NULL, datalen);
	return 1;
}

int tls13_record_get_handshake_certificate(const uint8_t *record, uint8_t *data, size_t *datalen)
{
	int type;
	const uint8_t *cp;

	if (tls_record_get_handshake(record, &type, &cp, datalen) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_certificate) {
		error_print();
		return -1;
	}

	// 这里我还是要接收一下Extensions
	memcpy(data, cp, *datalen);
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

static const int tls13_ciphers[] = { TLS_cipher_sm4_gcm_sm3 };


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

int tls13_connect(TLS_CONNECT *conn, const char *hostname, int port, FILE *server_cacerts_fp,
	FILE *client_certs_fp, const SM2_KEY *client_sign_key)
{
	uint8_t *record = conn->record;
	size_t recordlen;

	uint8_t enced_record[256];
	size_t enced_recordlen;


	int type;
	const uint8_t *data;
	size_t datalen;

	uint8_t client_random[32];
	uint8_t server_random[32];
	uint8_t session_id[32];
	uint8_t exts[TLS_MAX_EXTENSIONS_SIZE];
	size_t extslen;
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
	const DIGEST *digest = NULL;
	DIGEST_CTX dgst_ctx;
	DIGEST_CTX null_dgst_ctx;
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
	tls_record_set_version(enced_record, TLS_version_tls12);




	// 1. send ClientHello

	tls_trace("<<<< ClientHello\n");
	tls_record_set_version(record, TLS_version_tls12);
	rand_bytes(client_random, 32);
	rand_bytes(session_id, 32);
	sm2_keygen(&client_ecdhe);
	tls13_client_hello_extensions_set(exts, &extslen, &(client_ecdhe.public_key));
	tls_record_set_handshake_client_hello(record, &recordlen,
		TLS_version_tls12, client_random, session_id, 32,
		tls13_ciphers, sizeof(tls13_ciphers)/sizeof(tls13_ciphers[0]),
		exts, extslen);
	tls_record_print(stderr, record, recordlen, 0, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	tls_seq_num_incr(conn->client_seq_num);

	// 2. recv ServerHello

	tls_trace(">>>> ServerHello\n");
	if (tls12_record_recv(enced_record, &enced_recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, enced_record, enced_recordlen, 0, 0);
	tls_seq_num_incr(conn->server_seq_num);

	if (tls_record_get_handshake_server_hello(enced_record,
		&conn->version, server_random, conn->session_id, &conn->session_id_len,
		&conn->cipher_suite, exts, &extslen) != 1) {
		error_print();
		return -1;
	}
	if (conn->version != TLS_version_tls12) {
		error_print();
		return -1;
	}
	if (tls_cipher_suite_in_list(conn->cipher_suite,
		tls13_ciphers, sizeof(tls13_ciphers)/sizeof(tls13_ciphers[0])) != 1) {
		error_print();
		return -1;
	}
	tls13_cipher_suite_get(conn->cipher_suite, &digest, &cipher);
	if (tls13_server_hello_extensions_get(exts, extslen, &server_ecdhe_public) != 1) {
		error_print();
		return -1;
	}

	/*
	generate handshake keys
		uint8_t client_write_key[32]
		uint8_t server_write_key[32]
		uint8_t client_write_iv[12]
		uint8_t server_write_iv[12]
	*/
	digest_init(&dgst_ctx, digest);
	null_dgst_ctx = dgst_ctx;
	digest_update(&dgst_ctx, record + 5, recordlen - 5); // update ClientHello
	digest_update(&dgst_ctx, enced_record + 5, enced_recordlen - 5); // update ServerHello

	sm2_ecdh(&client_ecdhe, &server_ecdhe_public, &server_ecdhe_public);

	/* 1  */ tls13_hkdf_extract(digest, zeros, psk, early_secret);
	/* 5  */ tls13_derive_secret(early_secret, "derived", &null_dgst_ctx, handshake_secret);
	/* 6  */ tls13_hkdf_extract(digest, (uint8_t *)&server_ecdhe_public, handshake_secret, handshake_secret);
	/* 7  */ tls13_derive_secret(handshake_secret, "c hs traffic", &dgst_ctx, client_handshake_traffic_secret);
	/* 8  */ tls13_derive_secret(handshake_secret, "s hs traffic", &dgst_ctx, server_handshake_traffic_secret);
	/* 9  */ tls13_derive_secret(handshake_secret, "derived", &null_dgst_ctx, master_secret);
	/* 10 */ tls13_hkdf_extract(digest, master_secret, zeros, master_secret);

	tls13_hkdf_expand_label(digest, client_handshake_traffic_secret, "key", NULL, 0, 16, client_write_key);
	tls13_hkdf_expand_label(digest, server_handshake_traffic_secret, "key", NULL, 0, 16, server_write_key);
	tls13_hkdf_expand_label(digest, client_handshake_traffic_secret, "iv", NULL, 0, 12, conn->client_write_iv);
	tls13_hkdf_expand_label(digest, server_handshake_traffic_secret, "iv", NULL, 0, 12, conn->server_write_iv);
	block_cipher_set_encrypt_key(&conn->client_write_key, cipher, client_write_key);
	block_cipher_set_encrypt_key(&conn->server_write_key, cipher, server_write_key);

	// 3. recv {EncryptedExtensions}
	if (tls12_record_recv(enced_record, &enced_recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	if (tls13_record_decrypt(&conn->server_write_key, conn->server_write_iv,
		conn->server_seq_num, enced_record, enced_recordlen,
		record, &recordlen) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, 0, 0);
	digest_update(&dgst_ctx, record + 5, recordlen - 5);
	tls_seq_num_incr(conn->server_seq_num);

	if (tls13_record_get_handshake_encrypted_extensions(record) != 1) {
		error_print();
		return -1;
	}

	// 5. recv {CertififcateRequest*} or {Certificate}
	if (tls12_record_recv(enced_record, &enced_recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	if (tls13_record_decrypt(&conn->server_write_key, conn->server_write_iv,
		conn->server_seq_num, enced_record, enced_recordlen,
		record, &recordlen) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, 0, 0);
	tls_seq_num_incr(conn->server_seq_num);

	if (tls_record_get_handshake(record, &type, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	if (type == TLS_handshake_certificate_request) {
		tls_trace("<<<< CertificateRequest\n");

		const uint8_t *request_context;
		size_t request_context_len;
		const uint8_t *cert_request_exts;
		size_t cert_request_extslen;

		// 暂时不处理certificate_request数据
		if (tls13_record_get_handshake_certificate_request(record,
			&request_context, &request_context_len,
			&cert_request_exts, &cert_request_extslen) != 1) {
			error_print();
			return -1;
		}

		if (tls_record_recv(record, &recordlen, conn->sock) != 1) {
			error_print();
			return -1;
		}
		if (tls13_record_decrypt(&conn->server_write_key, conn->server_write_iv,
			conn->server_seq_num, enced_record, enced_recordlen,
			record, &recordlen) != 1) {
			error_print();
			return -1;
		}
		tls_seq_num_incr(conn->server_seq_num);
		digest_update(&dgst_ctx, record + 5, recordlen - 5);

	} else {
		// 清空客户端签名密钥
		client_sign_key = NULL; // 指示不需要发送client Certificate
	}


	// 6. recv Server {Certificate}

	tls_trace(">>>> Server Certificate\n");
	tls_record_print(stderr, record, recordlen, 0, 0);
	if (tls13_record_get_handshake_certificate(record, conn->server_certs, &conn->server_certs_len) != 1) {
		error_print();
		return -1;
	}
	if (tls_certificate_get_public_keys(conn->server_certs, conn->server_certs_len,
		&server_sign_key, NULL) != 1) {
		error_print();
		return -1;
	}

	// 7. recv Server {CertificateVerify}

	tls_trace(">>>> {CertificateVerify}\n");
	if (tls12_record_recv(enced_record, &enced_recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	if (tls13_record_decrypt(&conn->server_write_key, conn->server_write_iv,
		conn->server_seq_num, enced_record, enced_recordlen,
		record, &recordlen) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, 0, 0);
	tls_seq_num_incr(conn->server_seq_num);
	digest_update(&dgst_ctx, record + 5, recordlen - 5);

	if (tls13_record_get_handshake_certificate_verify(record,
		&server_sign_algor, &server_sig, &server_siglen) != 1) {
		error_print();
		return -1;
	}
	if (server_sign_algor != TLS_sig_sm2sig_sm3) {
		error_print();
		return -1;
	}
	if (tls13_verify(&server_sign_key, &dgst_ctx, server_sig, server_siglen, 1) != 1) {
		error_print();
		return -1;
	}

	// use Transcript-Hash(Handshake Context, Certificate*, CertificateVerify*)
	tls13_compute_verify_data(server_handshake_traffic_secret,
		&dgst_ctx, verify_data, &verify_data_len);

	// 8. recv Server {Finished}
	tls_trace(">>>> server {Finished}\n");
	if (tls12_record_recv(enced_record, &enced_recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	if (tls13_record_decrypt(&conn->server_write_key, conn->server_write_iv,
		conn->server_seq_num, enced_record, enced_recordlen,
		record, &recordlen) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, 0, 0);
	tls_seq_num_incr(conn->server_seq_num);
	digest_update(&dgst_ctx, record + 5, recordlen - 5);

	if (tls13_record_get_handshake_finished(record,
		&server_verify_data, &server_verify_data_len) != 1) {
		error_print();
		return -1;
	}
	if (server_verify_data_len != verify_data_len
		|| memcmp(server_verify_data, verify_data, verify_data_len) != 0) {
		error_print();
		return -1;
	}

	// generate server_application_traffic_secret
	// update server_write_key, server_write_iv
	/* 12 */ tls13_derive_secret(master_secret, "s ap traffic", &dgst_ctx, server_application_traffic_secret);
	tls13_hkdf_expand_label(digest, server_application_traffic_secret, "key", NULL, 0, 16, server_write_key);
	block_cipher_set_encrypt_key(&conn->server_write_key, cipher, server_write_key);
	tls13_hkdf_expand_label(digest, server_application_traffic_secret, "iv", NULL, 0, 12, conn->server_write_iv);


	if (client_sign_key) {
		int client_sign_algor;
		uint8_t sig[TLS_MAX_SIGNATURE_SIZE];
		size_t siglen;

		// 9. send client {Certificate*}
		tls_trace("<<<< client {Certificate}\n");
		if (tls13_record_set_handshake_certificate_from_pem(record, &recordlen,
			client_certs_fp) != 1) {
			error_print();
			return -1;
		}
		digest_update(&dgst_ctx, record + 5, recordlen - 5);
		tls_record_print(stderr, record, recordlen, 0, 0);

		tls13_padding_len_rand(&padding_len);
		if (tls13_record_encrypt(&conn->client_write_key, conn->client_write_iv,
			conn->client_seq_num, record, recordlen, padding_len,
			enced_record, &enced_recordlen) != 1) {
			error_print();
			return -1;
		}
		tls_seq_num_incr(conn->client_seq_num);
		if (tls_record_send(enced_record, enced_recordlen, conn->sock) != 1) {
			error_print();
			return -1;
		}

		// 10. send client {CertificateVerify*}
		tls_trace("<<<< client {CertificateVerify}\n");
		client_sign_algor = TLS_sig_sm2sig_sm3;
		tls13_sign(client_sign_key, &dgst_ctx, sig, &siglen, 0);
		if (tls13_record_set_handshake_certificate_verify(record, &recordlen,
			client_sign_algor, sig, siglen) != 1) {
			error_print();
			return -1;
		}
		digest_update(&dgst_ctx, record + 5, recordlen - 5);
		tls_record_print(stderr, record, recordlen, 0, 0);

		tls13_padding_len_rand(&padding_len);
		if (tls13_record_encrypt(&conn->client_write_key, conn->client_write_iv,
			conn->client_seq_num, record, recordlen, padding_len,
			enced_record, &enced_recordlen) != 1) {
			error_print();
			return -1;
		}
		tls_seq_num_incr(conn->client_seq_num);
		if (tls_record_send(enced_record, enced_recordlen, conn->sock) != 1) {
			error_print();
			return -1;
		}
	}

	// 11. send client {Finished}

	tls_trace("<<<< client {Finished}\n");
	if (tls13_compute_verify_data(client_handshake_traffic_secret, &dgst_ctx,
		verify_data, &verify_data_len) != 1) {
		error_print();
		return -1;
	}
	if (tls_record_set_handshake_finished(record, &recordlen, verify_data) != 1) {
		error_print();
		return -1;
	}
	digest_update(&dgst_ctx, record + 5, recordlen - 5);
	tls_record_print(stderr, record, recordlen, 0, 0);

	tls13_padding_len_rand(&padding_len);
	if (tls13_record_encrypt(&conn->client_write_key, conn->client_write_iv,
		conn->client_seq_num, record, recordlen, padding_len,
		enced_record, &enced_recordlen) != 1) {
		error_print();
		return -1;
	}
	tls_seq_num_incr(conn->client_seq_num);
	if (tls_record_send(enced_record, enced_recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}

	// generate client_application_traffic_secret
	// update client_write_key, client_write_iv

	/* 11 */ tls13_derive_secret(master_secret, "c ap traffic", &dgst_ctx, client_application_traffic_secret);
	tls13_hkdf_expand_label(digest, client_application_traffic_secret, "key", NULL, 0, 16, client_write_key);
	block_cipher_set_encrypt_key(&conn->client_write_key, cipher, client_write_key);
	tls13_hkdf_expand_label(digest, client_application_traffic_secret, "iv", NULL, 0, 12, conn->client_write_iv);

	tls_trace("++++ Connection established\n");
	return 1;
}

int tls13_accept(TLS_CONNECT *conn, int port,
	FILE *server_certs_fp, const SM2_KEY *server_sign_key,
	FILE *client_cacerts_fp)
{
	uint8_t *record = conn->record;
	size_t recordlen;
	uint8_t enced_record[25600];
	size_t enced_recordlen = sizeof(enced_record);

	uint8_t client_random[32];
	uint8_t server_random[32];
	uint8_t session_id[32];
	size_t session_id_len;
	int client_ciphers[12] = {0};
	size_t client_ciphers_count = sizeof(client_ciphers)/sizeof(client_ciphers[0]);
	uint8_t exts[TLS_MAX_EXTENSIONS_SIZE];
	size_t extslen;

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


	size_t i;

	uint8_t client_write_key[16];
	uint8_t server_write_key[16];

	uint8_t zeros[32] = {0};
	uint8_t psk[32] = {0};
	uint8_t early_secret[32];
	uint8_t binder_key[32];
	uint8_t handshake_secret[32];
	uint8_t client_handshake_traffic_secret[32];
	uint8_t server_handshake_traffic_secret[32];
	uint8_t client_application_traffic_secret[32];
	uint8_t server_application_traffic_secret[32];
	uint8_t master_secret[32];


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


	// 1. Recv ClientHello

	tls_trace(">>>> ClientHello\n");
	if (tls12_record_recv(record, &recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, record, recordlen, 0, 0);
	tls_seq_num_incr(conn->client_seq_num);

	if (tls_record_get_handshake_client_hello(record,
		&conn->version, client_random, session_id, &session_id_len,
		client_ciphers, &client_ciphers_count, exts, &extslen) != 1) {
		error_print();
		return -1;
	}
	if (conn->version != TLS_version_tls12
		|| session_id_len != 32) {
		error_print();
		return -1;
	}
	for (i = 0; i < sizeof(tls13_ciphers)/sizeof(tls13_ciphers[0]); i++) {
		if (tls_cipher_suite_in_list(tls13_ciphers[i], client_ciphers, client_ciphers_count) == 1) {
			conn->cipher_suite = tls13_ciphers[i];
			break;
		}
	}
	if (conn->cipher_suite == 0) {
		error_puts("no common cipher_suite");
		return -1;
	}
	if (tls13_client_hello_extensions_get(exts, extslen, &client_ecdhe_public) != 1) {
		error_print();
		return -1;
	}

	tls13_cipher_suite_get(conn->cipher_suite, &digest, &cipher);
	digest_init(&dgst_ctx, digest);
	null_dgst_ctx = dgst_ctx;
	digest_update(&dgst_ctx, record + 5, recordlen - 5);


	// 2. Send ServerHello

	tls_trace("<<<< ServerHello\n");

	rand_bytes(server_random, 32);
	sm2_keygen(&server_ecdhe);
	tls13_server_hello_extensions_set(exts, &extslen, &(server_ecdhe.public_key), NULL);

	if (tls_record_set_handshake_server_hello(enced_record, &enced_recordlen,
		conn->version, server_random, session_id, 32,
		conn->cipher_suite, exts, extslen) != 1) {
		error_print();
		return -1;
	}
	tls_record_print(stderr, enced_record, enced_recordlen, 0, 0);

	digest_update(&dgst_ctx, record + 5, recordlen - 5);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	tls_seq_num_incr(conn->server_seq_num);


	sm2_ecdh(&server_ecdhe, &client_ecdhe_public, &client_ecdhe_public);

	/* 1  */ tls13_hkdf_extract(digest, zeros, psk, early_secret);
	/* 5  */ tls13_derive_secret(early_secret, "derived", &null_dgst_ctx, handshake_secret);
	/* 6  */ tls13_hkdf_extract(digest, (uint8_t *)&client_ecdhe_public, handshake_secret, handshake_secret);
	/* 7  */ tls13_derive_secret(handshake_secret, "c hs traffic", &dgst_ctx, client_handshake_traffic_secret);
	/* 8  */ tls13_derive_secret(handshake_secret, "s hs traffic", &dgst_ctx, server_handshake_traffic_secret);
	/* 9  */ tls13_derive_secret(handshake_secret, "derived", &null_dgst_ctx, master_secret);
	/* 10 */ tls13_hkdf_extract(digest, master_secret, zeros, master_secret);

	// generate client_write_key, client_write_iv
	tls13_hkdf_expand_label(digest, client_handshake_traffic_secret, "key", NULL, 0, 16, client_write_key);
	block_cipher_set_encrypt_key(&conn->client_write_key, cipher, client_write_key);
	tls13_hkdf_expand_label(digest, client_handshake_traffic_secret, "iv", NULL, 0, 12, conn->client_write_iv);

	// generate server_write_key, server_write_iv
	tls13_hkdf_expand_label(digest, server_handshake_traffic_secret, "key", NULL, 0, 16, server_write_key);
	block_cipher_set_encrypt_key(&conn->server_write_key, cipher, server_write_key);
	tls13_hkdf_expand_label(digest, server_handshake_traffic_secret, "iv", NULL, 0, 12, conn->server_write_iv);



	// 3. Send {EncryptedExtensions}


	tls_trace("<<<< {EncryptedExtensions}\n");
	tls13_record_set_handshake_encrypted_extensions(record, &recordlen, NULL, 0); // 不发送EncryptedExtensions扩展
	tls_record_print(stderr, record, recordlen, 0, 0);
	digest_update(&dgst_ctx, record + 5, recordlen - 5);

	tls13_padding_len_rand(&padding_len);
	if (tls13_record_encrypt(&conn->server_write_key, conn->server_write_iv,
		conn->server_seq_num, record, recordlen, padding_len,
		enced_record, &enced_recordlen) != 1) {
		error_print();
		return -1;
	}

	if (tls_record_send(enced_record, enced_recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	tls_seq_num_incr(conn->server_seq_num);





	// 4. Send {CertificateRequest*}

	if (client_cacerts_fp) {

		tls_trace("<<<< {CertificateRequest*}\n");
		uint8_t request_context[32];
		// TODO: 设置certificate_request中的extensions!
		if (tls13_record_set_handshake_certificate_request(record, &recordlen,
			request_context, 32, NULL, 0) != 1) {
			error_print();
			return -1;
		}
		digest_update(&dgst_ctx, record + 5, recordlen - 5);
		tls_record_print(stderr, record, recordlen, 0, 0);

		tls13_padding_len_rand(&padding_len);
		if (tls13_record_encrypt(&conn->server_write_key, conn->server_write_iv,
			conn->server_seq_num, record, recordlen, padding_len,
			enced_record, &enced_recordlen) != 1) {
			error_print();
			return -1;
		}
		if (tls_record_send(enced_record, enced_recordlen, conn->sock) != 1) {
			error_print();
			return -1;
		}
		tls_seq_num_incr(conn->server_seq_num);
	}

	// 6. send server {Certificate}

	tls_trace("<<<< server {Certificate}\n");
	if (tls13_record_set_handshake_certificate_from_pem(record, &recordlen, server_certs_fp) != 1) {
		error_print();
		return -1;
	}
	digest_update(&dgst_ctx, record + 5, recordlen - 5);
	tls_record_print(stderr, record, recordlen, 0, 0);

	tls13_padding_len_rand(&padding_len);
	if (tls13_record_encrypt(&conn->server_write_key, conn->server_write_iv,
		conn->server_seq_num, record, recordlen, padding_len,
		enced_record, &enced_recordlen) != 1) {
		error_print();
		return -1;
	}

	if (tls_record_send(enced_record, enced_recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	tls_seq_num_incr(conn->server_seq_num);


	if (tls_record_get_handshake_certificate(record, conn->server_certs, &conn->server_certs_len) != 1) {
		error_print();
		return -1;
	}



	// 7. Send {CertificateVerify}

	tls_trace("<<<< server {CertificateVerify}\n");
	tls13_sign(server_sign_key, &dgst_ctx, sig, &siglen, 1);
	if (tls13_record_set_handshake_certificate_verify(record, &recordlen,
		TLS_sig_sm2sig_sm3, sig, siglen) != 1) {
		error_print();
		return -1;
	}

	digest_update(&dgst_ctx, record + 5, recordlen - 5);
	tls_record_print(stderr, record, recordlen, 0, 0);

	tls13_padding_len_rand(&padding_len);
	if (tls13_record_encrypt(&conn->server_write_key, conn->server_write_iv,
		conn->server_seq_num, record, recordlen, padding_len,
		enced_record, &enced_recordlen) != 1) {
		error_print();
		return -1;
	}

	if (tls_record_send(enced_record, enced_recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	tls_seq_num_incr(conn->server_seq_num);


	// 8. Send server {Finished}

	tls_trace("<<<< server {Finished}\n");

	// compute server verify_data before digest_update()
	tls13_compute_verify_data(server_handshake_traffic_secret,
		&dgst_ctx, verify_data, &verify_data_len);

	if (tls13_record_set_handshake_finished(record, &recordlen, verify_data, verify_data_len) != 1) {
		error_print();
		return -1;
	}
	digest_update(&dgst_ctx, record + 5, recordlen - 5);
	tls_record_print(stderr, record, recordlen, 0, 0);

	tls13_padding_len_rand(&padding_len);
	if (tls13_record_encrypt(&conn->server_write_key, conn->server_write_iv,
		conn->server_seq_num, record, recordlen, padding_len,
		enced_record, &enced_recordlen) != 1) {
		error_print();
		return -1;
	}

	if (tls_record_send(enced_record, enced_recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	tls_seq_num_incr(conn->server_seq_num);


	// generate server_application_traffic_secret
	// update server_write_key, server_write_iv
	/* 12 */ tls13_derive_secret(master_secret, "s ap traffic", &dgst_ctx, server_application_traffic_secret);
	tls13_hkdf_expand_label(digest, server_application_traffic_secret, "key", NULL, 0, 16, server_write_key);
	block_cipher_set_encrypt_key(&conn->server_write_key, cipher, server_write_key);
	tls13_hkdf_expand_label(digest, server_application_traffic_secret, "iv", NULL, 0, 12, conn->server_write_iv);


	// 10. Recv client {Certificate*}

	if (client_cacerts_fp) {

		tls_trace(">>> client {Certificate*}\n");
		if (tls12_record_recv(enced_record, &enced_recordlen, conn->sock) != 1) {
			error_print();
			return -1;
		}
		if (tls13_record_decrypt(&conn->client_write_key, conn->client_write_iv,
			conn->client_seq_num, enced_record, enced_recordlen,
			record, &recordlen) != 1) {
			error_print();
			return -1;
		}
		tls_seq_num_incr(conn->client_seq_num);
		digest_update(&dgst_ctx, record + 5, recordlen - 5);
		tls_record_print(stderr, record, recordlen, 0, 0);

		if (tls13_record_get_handshake_certificate(record,
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
	}

	// 11. Recv client {CertificateVerify*}

	if (client_cacerts_fp) {

		int client_sign_algor;
		const uint8_t *client_sig;
		size_t client_siglen;

		tls_trace(">>>> client {CertificateVerify*}\n");
		if (tls_record_recv(enced_record, &enced_recordlen, conn->sock) != 1) {
			error_print();
			return -1;
		}
		if (tls13_record_decrypt(&conn->client_write_key, conn->client_write_iv,
			conn->client_seq_num, enced_record, enced_recordlen, record, &recordlen) != 1) {
			error_print();
			return -1;
		}
		tls_seq_num_incr(conn->client_seq_num);
		digest_update(&dgst_ctx, record + 5, recordlen - 5);
		tls_record_print(stderr, record, recordlen, 0, 0);

		if (tls13_record_get_handshake_certificate_verify(record, &client_sign_algor, &client_sig, &client_siglen) != 1) {
			error_print();
			return -1;
		}
		if (tls13_verify(&client_sign_key, &dgst_ctx, client_sig, client_siglen, 0) != 1) {
			error_print();
			return -1;
		}
	}

	// 12. Recv client {Finished}

	tls_trace(">>>> client {Finished}\n");
	if (tls12_record_recv(enced_record, &enced_recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}

	if (tls13_record_decrypt(&conn->client_write_key, conn->client_write_iv,
		conn->client_seq_num, enced_record, enced_recordlen,
		record, &recordlen) != 1) {
		error_print();
		return -1;
	}

	tls_seq_num_incr(conn->client_seq_num);
	if (tls13_record_get_handshake_finished(record, &client_verify_data, &client_verify_data_len) != 1) {
		error_print();
		return -1;
	}
	if (tls13_compute_verify_data(client_handshake_traffic_secret, &dgst_ctx, verify_data, &verify_data_len) != 1) {
		error_print();
		return -1;
	}
	if (client_verify_data_len != verify_data_len
		|| memcmp(client_verify_data, verify_data, verify_data_len) != 0) {
		error_print();
		return -1;
	}

	tls_trace("Connection Established!\n\n");
	return 1;
}
