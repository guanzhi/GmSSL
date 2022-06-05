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
#include <gmssl/mem.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/pem.h>
#include <gmssl/tls.h>


void tls_uint8_to_bytes(uint8_t a, uint8_t **out, size_t *outlen)
{
	if (out) {
		*(*out)++ = a;
	}
	(*outlen)++;
}

void tls_uint16_to_bytes(uint16_t a, uint8_t **out, size_t *outlen)
{
	if (out) {
		*(*out)++ = (uint8_t)(a >> 8);
		*(*out)++ = (uint8_t)a;
	}
	*outlen += 2;
}

void tls_uint24_to_bytes(uint24_t a, uint8_t **out, size_t *outlen)
{
	if (out) {
		*(*out)++ = (uint8_t)(a >> 16);
		*(*out)++ = (uint8_t)(a >> 8);
		*(*out)++ = (uint8_t)(a);
	}
	(*outlen) += 3;
}

void tls_uint32_to_bytes(uint32_t a, uint8_t **out, size_t *outlen)
{
	if (out) {
		*(*out)++ = (uint8_t)(a >> 24);
		*(*out)++ = (uint8_t)(a >> 16);
		*(*out)++ = (uint8_t)(a >>  8);
		*(*out)++ = (uint8_t)(a      );
	}
	(*outlen) += 4;
}

void tls_array_to_bytes(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen)
{
	if (*out) {
		if (data) {
			memcpy(*out, data, datalen);
		}
		*out += datalen;
	}
	*outlen += datalen;
}

void tls_uint8array_to_bytes(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen)
{
	tls_uint8_to_bytes((uint8_t)datalen, out, outlen);
	tls_array_to_bytes(data, datalen, out, outlen);
}

void tls_uint16array_to_bytes(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen)
{
	tls_uint16_to_bytes((uint16_t)datalen, out, outlen);
	tls_array_to_bytes(data, datalen, out, outlen);
}

void tls_uint24array_to_bytes(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen)
{
	tls_uint24_to_bytes((uint24_t)datalen, out, outlen);
	tls_array_to_bytes(data, datalen, out, outlen);
}

int tls_uint8_from_bytes(uint8_t *a, const uint8_t **in, size_t *inlen)
{
	if (*inlen < 1) {
		error_print();
		return -1;
	}
	*a = *(*in)++;
	(*inlen)--;
	return 1;
}

int tls_uint16_from_bytes(uint16_t *a, const uint8_t **in, size_t *inlen)
{
	if (*inlen < 2) {
		error_print();
		return -1;
	}
	*a = *(*in)++;
	*a <<= 8;
	*a |= *(*in)++;
	*inlen -= 2;
	return 1;
}

int tls_uint24_from_bytes(uint24_t *a, const uint8_t **in, size_t *inlen)
{
	if (*inlen < 3) {
		error_print();
		return -1;
	}
	*a = *(*in)++;
	*a <<= 8;
	*a |= *(*in)++;
	*a <<= 8;
	*a |= *(*in)++;
	*inlen -= 3;
	return 1;
}

int tls_uint32_from_bytes(uint32_t *a, const uint8_t **in, size_t *inlen)
{
	if (*inlen < 4) {
		error_print();
		return -1;
	}
	*a = *(*in)++;
	*a <<= 8;
	*a |= *(*in)++;
	*a <<= 8;
	*a |= *(*in)++;
	*a <<= 8;
	*a |= *(*in)++;
	*inlen -= 4;
	return 1;
}

int tls_array_from_bytes(const uint8_t **data, size_t datalen, const uint8_t **in, size_t *inlen)
{
	if (*inlen < datalen) {
		error_print();
		return -1;
	}
	*data = *in;
	*in += datalen;
	*inlen -= datalen;
	return 1;
}

int tls_uint8array_from_bytes(const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen)
{
	uint8_t len;
	if (tls_uint8_from_bytes(&len, in, inlen) != 1
		|| tls_array_from_bytes(data, len, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (!len) {
		*data = NULL;
	}
	*datalen = len;
	return 1;
}

int tls_uint16array_from_bytes(const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen)
{
	uint16_t len;
	if (tls_uint16_from_bytes(&len, in, inlen) != 1
		|| tls_array_from_bytes(data, len, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (!len) {
		*data = NULL;
	}
	*datalen = len;
	return 1;
}

int tls_uint24array_from_bytes(const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen)
{
	uint24_t len;
	if (tls_uint24_from_bytes(&len, in, inlen) != 1
		|| tls_array_from_bytes(data, len, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (!len) {
		*data = NULL;
	}
	*datalen = len;
	return 1;
}

// 获取记录基本信息，不做正确性检查，考虑实现为宏
int tls_record_type(const uint8_t *record)
{
	return record[0];
}

int tls_record_length(const uint8_t *record)
{
	int ret;
	ret = ((uint16_t)record[3] << 8) | record[4];
	return ret;
}

int tls_record_version(const uint8_t *record)
{
	int version = ((int)record[1] << 8) | record[2];
	return version;
}

int tls_record_set_type(uint8_t *record, int type)
{
	if (!tls_record_type_name(type)) {
		error_print();
		return -1;
	}
	record[0] = type;
	return 1;
}

int tls_record_set_version(uint8_t *record, int version)
{
	if (!tls_version_text(version)) {
		error_print();
		return -1;
	}
	record[1] = version >> 8;
	record[2] = version;
	return 1;
}

int tls_cbc_encrypt(const SM3_HMAC_CTX *inited_hmac_ctx, const SM4_KEY *enc_key,
	const uint8_t seq_num[8], const uint8_t header[5],
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	SM3_HMAC_CTX hmac_ctx;
	uint8_t last_blocks[32 + 16] = {0};
	uint8_t *mac, *padding, *iv;
	int rem, padding_len;
	int i;

	if (!inited_hmac_ctx || !enc_key || !seq_num || !header || (!in && inlen) || !out || !outlen) {
		error_print();
		return -1;
	}
	if (inlen > (1 << 14)) {
		error_print_msg("invalid tls record data length %zu\n", inlen);
		return -1;
	}

	rem = (inlen + 32) % 16;
	memcpy(last_blocks, in + inlen - rem, rem);
	mac = last_blocks + rem;

	memcpy(&hmac_ctx, inited_hmac_ctx, sizeof(SM3_HMAC_CTX));
	sm3_hmac_update(&hmac_ctx, seq_num, 8);
	sm3_hmac_update(&hmac_ctx, header, 5);
	sm3_hmac_update(&hmac_ctx, in, inlen);
	sm3_hmac_finish(&hmac_ctx, mac);

	padding = mac + 32;
	padding_len = 16 - rem - 1;
	for (i = 0; i <= padding_len; i++) {
		padding[i] = padding_len;
	}

	iv = out;
	if (rand_bytes(iv, 16) != 1) {
		error_print();
		return -1;
	}
	out += 16;

	if (inlen >= 16) {
		sm4_cbc_encrypt(enc_key, iv, in, inlen/16, out);
		out += inlen - rem;
		iv = out - 16;
	}
	sm4_cbc_encrypt(enc_key, iv, last_blocks, sizeof(last_blocks)/16, out);
	*outlen = 16 + inlen - rem + sizeof(last_blocks);
	return 1;
}

int tls_cbc_decrypt(const SM3_HMAC_CTX *inited_hmac_ctx, const SM4_KEY *dec_key,
	const uint8_t seq_num[8], const uint8_t enced_header[5],
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	SM3_HMAC_CTX hmac_ctx;
	const uint8_t *iv;
	const uint8_t *padding;
	const uint8_t *mac;
	uint8_t header[5];
	int padding_len;
	uint8_t hmac[32];
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

	iv = in;
	in += 16;
	inlen -= 16;

	sm4_cbc_decrypt(dec_key, iv, in, inlen/16, out);

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
	header[3] = (*outlen) >> 8;
	header[4] = (*outlen);
	mac = padding - 32;

	memcpy(&hmac_ctx, inited_hmac_ctx, sizeof(SM3_HMAC_CTX));
	sm3_hmac_update(&hmac_ctx, seq_num, 8);
	sm3_hmac_update(&hmac_ctx, header, 5);
	sm3_hmac_update(&hmac_ctx, out, *outlen);
	sm3_hmac_finish(&hmac_ctx, hmac);
	if (gmssl_secure_memcmp(mac, hmac, sizeof(hmac)) != 0) {
		error_puts("tls ciphertext mac check failure\n");
		return -1;
	}
	return 1;
}

int tls_record_encrypt(const SM3_HMAC_CTX *hmac_ctx, const SM4_KEY *cbc_key,
	const uint8_t seq_num[8], const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	if (tls_cbc_encrypt(hmac_ctx, cbc_key, seq_num, in,
		in + 5, inlen - 5,
		out + 5, outlen) != 1) {
		error_print();
		return -1;
	}

	out[0] = in[0];
	out[1] = in[1];
	out[2] = in[2];
	out[3] = (*outlen) >> 8;
	out[4] = (*outlen);
	(*outlen) += 5;
	return 1;
}

int tls_record_decrypt(const SM3_HMAC_CTX *hmac_ctx, const SM4_KEY *cbc_key,
	const uint8_t seq_num[8], const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	if (tls_cbc_decrypt(hmac_ctx, cbc_key, seq_num, in,
		in + 5, inlen - 5,
		out + 5, outlen) != 1) {
		error_print();
		return -1;
	}

	out[0] = in[0];
	out[1] = in[1];
	out[2] = in[2];
	out[3] = (*outlen) >> 8;
	out[4] = (*outlen);
	(*outlen) += 5;

	return 1;
}

int tls_random_generate(uint8_t random[32])
{
	uint32_t gmt_unix_time = (uint32_t)time(NULL);
	uint8_t *p = random;
	size_t len = 0;
	tls_uint32_to_bytes(gmt_unix_time, &p, &len);
	if (rand_bytes(random + 4, 28) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_prf(const uint8_t *secret, size_t secretlen, const char *label,
	const uint8_t *seed, size_t seedlen,
	const uint8_t *more, size_t morelen,
	size_t outlen, uint8_t *out)
{
	SM3_HMAC_CTX inited_hmac_ctx;
	SM3_HMAC_CTX hmac_ctx;
	uint8_t A[32];
	uint8_t hmac[32];
	size_t len;

	if (!secret || !secretlen || !label || !seed || !seedlen
		|| (!more && morelen) || !outlen || !out) {
		error_print();
		return -1;
	}

	sm3_hmac_init(&inited_hmac_ctx, secret, secretlen);

	memcpy(&hmac_ctx, &inited_hmac_ctx, sizeof(SM3_HMAC_CTX));
	sm3_hmac_update(&hmac_ctx, (uint8_t *)label, strlen(label));
	sm3_hmac_update(&hmac_ctx, seed, seedlen);
	sm3_hmac_update(&hmac_ctx, more, morelen);
	sm3_hmac_finish(&hmac_ctx, A);

	memcpy(&hmac_ctx, &inited_hmac_ctx, sizeof(SM3_HMAC_CTX));
	sm3_hmac_update(&hmac_ctx, A, sizeof(A));
	sm3_hmac_update(&hmac_ctx, (uint8_t *)label, strlen(label));
	sm3_hmac_update(&hmac_ctx, seed, seedlen);
	sm3_hmac_update(&hmac_ctx, more, morelen);
	sm3_hmac_finish(&hmac_ctx, hmac);

	len = outlen < sizeof(hmac) ? outlen : sizeof(hmac);
	memcpy(out, hmac, len);
	out += len;
	outlen -= len;

	while (outlen) {
		memcpy(&hmac_ctx, &inited_hmac_ctx, sizeof(SM3_HMAC_CTX));
		sm3_hmac_update(&hmac_ctx, A, sizeof(A));
		sm3_hmac_finish(&hmac_ctx, A);

		memcpy(&hmac_ctx, &inited_hmac_ctx, sizeof(SM3_HMAC_CTX));
		sm3_hmac_update(&hmac_ctx, A, sizeof(A));
		sm3_hmac_update(&hmac_ctx, (uint8_t *)label, strlen(label));
		sm3_hmac_update(&hmac_ctx, seed, seedlen);
		sm3_hmac_update(&hmac_ctx, more, morelen);
		sm3_hmac_finish(&hmac_ctx, hmac);

		len = outlen < sizeof(hmac) ? outlen : sizeof(hmac);
		memcpy(out, hmac, len);
		out += len;
		outlen -= len;
	}
	return 1;
}

int tls_pre_master_secret_generate(uint8_t pre_master_secret[48], int version)
{
	if (!tls_version_text(version)) {
		error_print();
		return -1;
	}
	pre_master_secret[0] = version >> 8;
	pre_master_secret[1] = version;
	if (rand_bytes(pre_master_secret + 2, 46) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

// 用于设置CertificateRequest
int tls_cert_type_from_oid(int oid)
{
	switch (oid) {
	case OID_sm2sign_with_sm3:
	case OID_ecdsa_with_sha1:
	case OID_ecdsa_with_sha224:
	case OID_ecdsa_with_sha256:
	case OID_ecdsa_with_sha512:
		return TLS_cert_type_ecdsa_sign;
	case OID_rsasign_with_sm3:
	case OID_rsasign_with_md5:
	case OID_rsasign_with_sha1:
	case OID_rsasign_with_sha224:
	case OID_rsasign_with_sha256:
	case OID_rsasign_with_sha384:
	case OID_rsasign_with_sha512:
		return TLS_cert_type_rsa_sign;
	}
	// TLS_cert_type_xxx 中没有为0的值
	return 0;
}

int tls_sign_server_ecdh_params(const SM2_KEY *server_sign_key,
	const uint8_t client_random[32], const uint8_t server_random[32],
	int curve, const SM2_POINT *point, uint8_t *sig, size_t *siglen)
{
	uint8_t server_ecdh_params[69];
	SM2_SIGN_CTX sign_ctx;

	if (!server_sign_key || !client_random || !server_random
		|| curve != TLS_curve_sm2p256v1 || !point || !sig || !siglen) {
		error_print();
		return -1;
	}
	server_ecdh_params[0] = TLS_curve_type_named_curve;
	server_ecdh_params[1] = curve >> 8;
	server_ecdh_params[2] = curve;
	server_ecdh_params[3] = 65;
	sm2_point_to_uncompressed_octets(point, server_ecdh_params + 4);

	sm2_sign_init(&sign_ctx, server_sign_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH);
	sm2_sign_update(&sign_ctx, client_random, 32);
	sm2_sign_update(&sign_ctx, server_random, 32);
	sm2_sign_update(&sign_ctx, server_ecdh_params, 69);
	sm2_sign_finish(&sign_ctx, sig, siglen);

	return 1;
}

int tls_verify_server_ecdh_params(const SM2_KEY *server_sign_key,
	const uint8_t client_random[32], const uint8_t server_random[32],
	int curve, const SM2_POINT *point, const uint8_t *sig, size_t siglen)
{
	int ret;
	uint8_t server_ecdh_params[69];
	SM2_SIGN_CTX verify_ctx;

	if (!server_sign_key || !client_random || !server_random
		|| curve != TLS_curve_sm2p256v1 || !point || !sig || !siglen
		|| siglen > SM2_MAX_SIGNATURE_SIZE) {
		error_print();
		return -1;
	}
	server_ecdh_params[0] = TLS_curve_type_named_curve;
	server_ecdh_params[1] = curve >> 8;
	server_ecdh_params[2] = curve;
	server_ecdh_params[3] = 65;
	sm2_point_to_uncompressed_octets(point, server_ecdh_params + 4);

	sm2_verify_init(&verify_ctx, server_sign_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH);
	sm2_verify_update(&verify_ctx, client_random, 32);
	sm2_verify_update(&verify_ctx, server_random, 32);
	sm2_verify_update(&verify_ctx, server_ecdh_params, 69);
	ret = sm2_verify_finish(&verify_ctx, sig, siglen);
	if (ret != 1) error_print();
	return ret;
}

int tls_record_set_handshake(uint8_t *record, size_t *recordlen,
	int type, const uint8_t *data, size_t datalen)
{
	size_t handshakelen;

	if (!record || !recordlen) {
		error_print();
		return -1;
	}
	// 这个长度限制应该修改为宏					
	if (datalen > (1 << 14) - 4) {
		error_puts("gmssl does not support handshake longer than record");
		return -1;
	}
	handshakelen = 4 + datalen;
	record[0] = TLS_record_handshake;
	record[3] = handshakelen >> 8;
	record[4] = handshakelen;
	record[5] = type;
	record[6] = datalen >> 16;
	record[7] = datalen >> 8;
	record[8] = datalen;
	if (data) {
		memcpy(record + 5 + 4, data, datalen);
	}
	*recordlen = 5 + handshakelen;
	return 1;
}

// 这个函数应该再仔细检查一下			
int tls_record_get_handshake(const uint8_t *record,
	int *type, const uint8_t **data, size_t *datalen)
{
	size_t record_datalen;


	if (!record || !type || !data || !datalen) {
		error_print();
		return -1;
	}
	if (record[0] != TLS_record_handshake) {
		error_print();
		return -1;
	}
	// 我们应该假定这个record是正确的，不再检查长度之类
	record_datalen = (size_t)record[3] << 8 | record[4];
	if (record_datalen > TLS_MAX_PLAINTEXT_SIZE
		|| record_datalen < 4) {
		error_print();
		return -1;
	}
	if (!tls_handshake_type_name(record[5])) {
		error_print();
		return -1;
	}

	*type = record[5];
	*datalen = ((size_t)record[6] << 16) | ((size_t)record[7] << 8) | record[8]; // FIXME：检查长度
	*data = record + 5 + 4;

	if (*datalen == 0) {
		*data = NULL;
	}
	return 1;
}

// handshake messages

int tls_record_set_handshake_client_hello(uint8_t *record, size_t *recordlen,
	int version, const uint8_t random[32],
	const uint8_t *session_id, size_t session_id_len,
	const int *cipher_suites, size_t cipher_suites_count,
	const uint8_t *exts, size_t exts_len)
{
	uint8_t type = TLS_handshake_client_hello;
	uint8_t *p = record + 5 + 4;
	size_t len = 0;

	if (!record || !recordlen || !random
		|| (!session_id && session_id_len) || session_id_len > 32
		|| !cipher_suites || !cipher_suites_count || cipher_suites_count > 64
		|| (!exts && exts_len) || exts_len > 512) {
		error_print();
		return -1;
	}
	if (!tls_version_text(version)) {
		error_print();
		return -1;
	}


	tls_uint16_to_bytes((uint16_t)version, &p, &len);
	tls_array_to_bytes(random, 32, &p, &len);
	tls_uint8array_to_bytes(session_id, session_id_len, &p, &len);
	tls_uint16_to_bytes(cipher_suites_count * 2, &p, &len);
	while (cipher_suites_count--) {
		tls_uint16_to_bytes((uint16_t)*cipher_suites, &p, &len);
		cipher_suites++;
	}
	tls_uint8_to_bytes(1, &p, &len);
	tls_uint8_to_bytes((uint8_t)TLS_compression_null, &p, &len);
	if (exts) {
		if (version < TLS_version_tls12) {
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

// 这样的函数是否会出现内部错误或者消息解析错误呢？
int tls_record_get_handshake_client_hello(const uint8_t *record,
	int *version, const uint8_t **random,
	const uint8_t **session_id, size_t *session_id_len,
	const uint8_t **cipher_suites, size_t *cipher_suites_len,
	const uint8_t **exts, size_t *exts_len)
{
	int type;
	const uint8_t *p;
	size_t len;
	uint16_t ver;
	const uint8_t *comp_meths;
	size_t comp_meths_len;

	if (!record || !random || !session_id || !session_id_len
		|| !cipher_suites || !cipher_suites_len
		|| record[0] != TLS_record_handshake) { // record_type应该有一个独立的错误
		error_print();
		return -1;
	}
	if (tls_record_type(record) != TLS_record_handshake) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, &p, &len) != 1
		|| type != TLS_handshake_client_hello) {
		error_print();
		return -1;
	}
	if (tls_uint16_from_bytes(&ver, &p, &len) != 1
		|| tls_array_from_bytes(random, 32, &p, &len) != 1
		|| tls_uint8array_from_bytes(session_id, session_id_len, &p, &len) != 1
		|| tls_uint16array_from_bytes(cipher_suites, cipher_suites_len, &p, &len) != 1
		|| tls_uint8array_from_bytes(&comp_meths, &comp_meths_len, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (!tls_version_text(ver)) {
		error_print();
		return -1;
	}
	*version = ver;
	if (*session_id_len > TLS_MAX_SESSION_ID_SIZE) {
		error_print();
		return -1;
	}
	// 是否允许未定义密码套件，留给调用方解析判断
	if (!cipher_suites) {
		error_print();
		return -1;
	}
	if (*cipher_suites_len % 2) {
		error_print();
		return -1;
	}
	if (len) {
		if (tls_uint16array_from_bytes(exts, exts_len, &p, &len) != 1) {
			error_print();
			return -1;
		}
	} else {
		*exts = NULL;
		*exts_len = 0;
	}
	if (len) {
		error_print();
		return -1;
	}
	return 1;
}

// 如果有错误，都是内部错误
int tls_record_set_handshake_server_hello(uint8_t *record, size_t *recordlen,
	int version, const uint8_t random[32],
	const uint8_t *session_id, size_t session_id_len, int cipher_suite,
	const uint8_t *exts, size_t exts_len)
{
	uint8_t type = TLS_handshake_server_hello;
	uint8_t *p = record + 5 + 4;
	size_t len = 0;

	if (!record || !recordlen) {
		error_print();
		return -1;
	}
	if (tls_version_text(version) == NULL || random == NULL) {
		error_print();
		return -1;
	}
	if (session_id != NULL) {
		if (session_id_len <= 0 || session_id_len > 32) {
			error_print();
			return -1;
		}
	}
	if (exts && exts_len > 512) {
		error_print();
		return -1;
	}

	if (record[0] != TLS_record_handshake) {
		error_print();
		return -1;
	}
	if (!tls_version_text(version)) {
		error_print();
		return -1;
	}
	if (!tls_cipher_suite_name(cipher_suite)) {
		error_print();
		return -1;
	}
	/*
	if (version < tls_record_version(record)) {
		error_print();
		return -1;
	}
	*/
	tls_uint16_to_bytes((uint16_t)version, &p, &len);
	tls_array_to_bytes(random, 32, &p, &len);
	tls_uint8array_to_bytes(session_id, session_id_len, &p, &len);
	tls_uint16_to_bytes((uint16_t)cipher_suite, &p, &len);
	tls_uint8_to_bytes((uint8_t)TLS_compression_null, &p, &len);
	if (exts) {
		if (version < TLS_version_tls12) {
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

int tls_record_get_handshake_server_hello(const uint8_t *record,
	int *version, const uint8_t **random, const uint8_t **session_id, size_t *session_id_len,
	int *cipher_suite, const uint8_t **exts, size_t *exts_len)
{
	int type;
	const uint8_t *p;
	size_t len;
	uint16_t ver; // 如果直接读取uint16到*version中，则*version的高16位没有初始化
	uint16_t cipher; // 同上
	uint8_t comp_meth;

	if (!record || !version || !random || !session_id || !session_id_len
		|| !cipher_suite) {
		error_print();
		return -1;
	}
	if (record[0] != TLS_record_handshake) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_server_hello) {
		error_print();
		return -1;
	}
	if (tls_uint16_from_bytes(&ver, &p, &len) != 1
		|| tls_array_from_bytes(random, 32, &p, &len) != 1
		|| tls_uint8array_from_bytes(session_id, session_id_len, &p, &len) != 1
		|| tls_uint16_from_bytes(&cipher, &p, &len) != 1
		|| tls_uint8_from_bytes(&comp_meth, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (!tls_version_text(ver)) {
		error_print();
		return -1;
	}
	if (ver < tls_record_version(record)) {
		error_print();
		return -1;
	}
	*version = ver;
	if (*session_id_len > TLS_MAX_SESSION_ID_SIZE) {
		error_print();
		return -1;
	}
	if (!tls_cipher_suite_name(cipher)) {
		error_print_msg("unknown server cipher_suite 0x%04x", *cipher_suite);
		return -1;
	}
	*cipher_suite = cipher;
	if (comp_meth != TLS_compression_null) {
		error_print();
		return -1;
	}
	if (len) {
		if (tls_uint16array_from_bytes(exts, exts_len, &p, &len) != 1) {
			error_print();
			return -1;
		}
	} else {
		*exts = NULL;
		*exts_len = 0;
	}
	if (len) {
		error_print();
		return -1;
	}
	return 1;
}


int tls_record_set_handshake_certificate(uint8_t *record, size_t *recordlen,
	const uint8_t *certs, size_t certslen)
{
	int type = TLS_handshake_certificate;
	const size_t maxlen = TLS_MAX_HANDSHAKE_DATA_SIZE - tls_uint24_size();
	uint8_t *data, *p;
	size_t datalen = 0;
	size_t len = 0;

	if (!record || !recordlen || !certs || !certslen) {
		error_print();
		return -1;
	}
	data = tls_handshake_data(tls_record_data(record));
	p = data + tls_uint24_size();

	// set (uint24 certlen, cert)*
	while (certslen) {
		const uint8_t *cert;
		size_t certlen;

		if (x509_cert_from_der(&cert, &certlen, &certs, &certslen) != 1) {
			error_print();
			return -1;
		}
		// 如何防止溢出
		if (3 + certlen > maxlen) {
			error_print();
			return -1;
		}
		tls_uint24array_to_bytes(cert, certlen, &p, &datalen);
	}
	tls_uint24_to_bytes(datalen, &data, &datalen);
	tls_record_set_handshake(record, recordlen, type, NULL, datalen);
	return 1;
}

/*
int tls_record_set_handshake_certificate_from_pem(uint8_t *record, size_t *recordlen, FILE *fp)
{
	int type = TLS_handshake_certificate;
	uint8_t *data = record + 5 + 4;
	uint8_t *certs = data + 3;
	size_t datalen, certslen = 0;

	for (;;) {
		int ret;
		uint8_t cert[1024];
		size_t certlen;

		if ((ret = x509_cert_from_pem(cert, &certlen, sizeof(cert), fp)) < 0) {
			error_print();
			return -1;
		} else if (!ret) {
			break;
		}
		tls_uint24array_to_bytes(cert, certlen, &certs, &certslen);
	}
	datalen = certslen;
	tls_uint24_to_bytes((uint24_t)certslen, &data, &datalen);
	tls_record_set_handshake(record, recordlen, type, NULL, datalen);
	return 1;
}
*/

// 如果certs长度超过限制怎么办？
// 在调用这个函数之前，应该保证准备的缓冲区为
int tls_record_get_handshake_certificate(const uint8_t *record, uint8_t *certs, size_t *certslen)
{
	int type;
	const uint8_t *data;
	size_t datalen;
	uint8_t *out = certs;
	const uint8_t *p;
	size_t len;

	if (tls_record_get_handshake(record, &type, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_certificate) {
		error_print();
		return -1;
	}
	if (tls_uint24array_from_bytes(&p, &len, &data, &datalen) != 1) {
		error_print();
		return -1;
	}

	*certslen = 0;
	while (len) {
		const uint8_t *d;
		size_t dlen;
		const uint8_t *cert;
		size_t certlen;

		if (tls_uint24array_from_bytes(&d, &dlen, &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (x509_cert_from_der(&cert, &certlen, &d, &dlen) != 1
			|| asn1_length_is_zero(dlen) != 1
			|| x509_cert_to_der(cert, certlen, &out, certslen) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int tls_record_set_handshake_certificate_request(uint8_t *record, size_t *recordlen,
	const uint8_t *cert_types, size_t cert_types_len,
	const uint8_t *ca_names, size_t ca_names_len)
{
	int type = TLS_handshake_certificate_request;
	uint8_t *p = record + 5 + 4;
	size_t len = 0;

	if (!record || !recordlen
		|| !cert_types || !cert_types_len || cert_types_len > TLS_MAX_CERTIFICATE_TYPES
		|| (!ca_names && ca_names_len) || ca_names_len > TLS_MAX_CA_NAMES_SIZE) {
		error_print();
		return -1;
	}
	// 对cert_types_len和ca_names_len的长度检查保证输出不会超过记录长度			
	tls_uint8array_to_bytes(cert_types, cert_types_len, &p, &len);
	tls_uint16array_to_bytes(ca_names, ca_names_len, &p, &len);
	tls_record_set_handshake(record, recordlen, type, NULL, len);
	return 1;
}

int tls_record_get_handshake_certificate_request(const uint8_t *record,
	const uint8_t **cert_types, size_t *cert_types_len,
	const uint8_t **ca_names, size_t *ca_names_len)
{
	int type;
	const uint8_t *cp;
	size_t len;
	const uint8_t *types;
	size_t count;

	if (!record
		|| !cert_types || !cert_types_len || !ca_names || !ca_names_len
		|| record[0] != TLS_record_handshake) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, &cp, &len) != 1
		|| tls_uint8array_from_bytes(cert_types, cert_types_len, &cp, &len) != 1
		|| tls_uint16array_from_bytes(ca_names, ca_names_len, &cp, &len) != 1
		|| len > 0) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_record_set_handshake_server_hello_done(uint8_t *record, size_t *recordlen)
{
	int type = TLS_handshake_server_hello_done;
	if (!record || !recordlen) {
		error_print();
		return -1;
	}
	tls_record_set_handshake(record, recordlen, type, NULL, 0);
	return 1;
}

int tls_record_get_handshake_server_hello_done(const uint8_t *record)
{
	int type;
	const uint8_t *p;
	size_t len;

	if (!record) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, &p, &len) != 1
		|| type != TLS_handshake_server_hello_done
		|| len != 0) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_record_set_handshake_client_key_exchange_pke(uint8_t *record, size_t *recordlen,
	const uint8_t *enced_pms, size_t enced_pms_len)
{
	int type = TLS_handshake_client_key_exchange;
	uint8_t *p = record + 5 + 4;
	size_t len = 0;
	if (!record || !recordlen
		|| !enced_pms || !enced_pms_len || enced_pms_len > 65535) {
		error_print();
		return -1;
	}
	tls_uint16array_to_bytes(enced_pms, enced_pms_len, &p, &len);
	tls_record_set_handshake(record, recordlen, type, NULL, len);
	return 1;
}

int tls_record_get_handshake_client_key_exchange_pke(const uint8_t *record,
	const uint8_t **enced_pms, size_t *enced_pms_len)
{
	int type;
	const uint8_t *p;
	size_t len;

	if (!record || !enced_pms || !enced_pms_len
		|| record[0] != TLS_record_handshake) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, &p, &len) != 1
		|| type != TLS_handshake_client_key_exchange) {
		error_print();
		return -1;
	}
	if (tls_uint16array_from_bytes(enced_pms, enced_pms_len, &p, &len) != 1
		|| len > 0) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_record_set_handshake_certificate_verify(uint8_t *record, size_t *recordlen,
	const uint8_t *sig, size_t siglen)
{
	int type = TLS_handshake_certificate_verify;
	tls_record_set_handshake(record, recordlen, type, sig, siglen);
	return 1;
}

int tls_record_get_handshake_certificate_verify(const uint8_t *record,
	const uint8_t **sig, size_t *siglen)
{
	int type;

	if (tls_record_get_handshake(record, &type, sig, siglen) != 1
		|| type != TLS_handshake_certificate_verify) {
		error_print();
		return -1;
	}
	if (*sig == NULL) {
		error_print();
		return -1;
	}
	return 1;
}

//FIXME: TLS 1.3 中的verify_data长度和hashLen一样,并且长度是不单独编码的，
// 因此这个函数应该改一下了
int tls_record_set_handshake_finished(uint8_t *record, size_t *recordlen,
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

int tls_record_get_handshake_finished(const uint8_t *record, const uint8_t **verify_data, size_t *verify_data_len)
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
	if (*verify_data == NULL) {
		error_print();
		return -1;
	}
	return 1;
}

// alert protocol


// 这个函数没有必要设置长度，因此Alert长度是固定的！
int tls_record_set_alert(uint8_t *record, size_t *recordlen,
	int alert_level,
	int alert_description)
{
	if (!record || !recordlen
		|| !tls_alert_level_name(alert_level)
		|| !tls_alert_description_text(alert_description)) {
		error_print();
		return -1;
	}
	record[0] = TLS_record_alert;
	record[3] = 0; // length
	record[4] = 2; // length
	record[5] = (uint8_t)alert_level;
	record[6] = (uint8_t)alert_description;
	*recordlen = 7;
	return 1;
}

int tls_record_get_alert(const uint8_t *record,
	int *alert_level,
	int *alert_description)
{
	if (!record || !alert_level || !alert_description) {
		error_print();
		return -1;
	}
	if (record[0] != TLS_record_alert) {
		error_print();
		return -1;
	}
	if (record[3] != 0 || record[4] != 2) {
		error_print();
		return -1;
	}
	*alert_level = record[5];
	*alert_description = record[6];
	if (!tls_alert_level_name(*alert_level)) {
		error_print();
		return -1;
	}
	if (!tls_alert_description_text(*alert_description)) {
		error_puts("warning");
		return -1;
	}
	return 1;
}


// change_cipher_spec protocol


int tls_record_set_change_cipher_spec(uint8_t *record, size_t *recordlen)
{
	if (!record || !recordlen) {
		error_print();
		return -1;
	}
	record[0] = TLS_record_change_cipher_spec;
	record[3] = 0;
	record[4] = 1;
	record[5] = TLS_change_cipher_spec;
	*recordlen = 6;
	return 1;
}

int tls_record_get_change_cipher_spec(const uint8_t *record)
{
	if (!record) {
		error_print();
		return -1;
	}
	if (record[0] != TLS_record_change_cipher_spec) {
		error_print();
		return -1;
	}
	if (record[3] != 0 || record[4] != 1) {
		error_print();
		return -1;
	}
	if (record[5] != TLS_change_cipher_spec) {
		error_print_msg("unknown ChangeCipherSpec value %d", record[5]);
		return -1;
	}
	return 1;
}

int tls_record_set_application_data(uint8_t *record, size_t *recordlen,
	const uint8_t *data, size_t datalen)
{
	record[0] = TLS_record_application_data;
	record[3] = (datalen >> 8) & 0xff;
	record[4] = datalen & 0xff;
	memcpy(record + 5, data, datalen);
	*recordlen = 5 + datalen;
	return 1;
}

int tls_record_get_application_data(uint8_t *record,
	const uint8_t **data, size_t *datalen)
{
	if (record[0] != TLS_record_application_data) {
		error_print();
		return -1;
	}
	*datalen = ((size_t)record[3] << 8) | record[4];
	*data = record + 5;
	return 1;
}


int tls_cipher_suite_in_list(int cipher, const int *list, size_t list_count)
{
	size_t i;
	for (i = 0; i < list_count; i++) {
		if (cipher == list[i]) {
			return 1;
		}
	}
	return 0;
}

// 两类错误，一种是输入的记录格式有问题，一种是网络问题
// 显然输入格式是编译期的错误，不应该发生
// 网络错误如果发生，那么也没有必要再发错误消息了
int tls_record_send(const uint8_t *record, size_t recordlen, int sock)
{
	ssize_t r;
	if (recordlen < 5
		|| recordlen - 5 != (((size_t)record[3] << 8) | record[4])) {
		error_print();
		return -1;
	}
	if ((r = send(sock, record, recordlen, 0)) < 0) {
		error_print();
		return -1;
	} else if (r != recordlen) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_record_recv(uint8_t *record, size_t *recordlen, int sock)
{
	ssize_t r;
	int type;
	size_t len;

retry:
	// TODO：支持非租塞socket或针对可能的网络延迟重新recv
	if ((r = recv(sock, record, 5, 0)) < 0) {
		error_print();
		return -1;
	}
	if (!tls_record_type_name(tls_record_type(record))) {
		error_print_msg("Invalid record type: %d\n", record[0]);
		return -1;
	}
	if (!tls_version_text(tls_record_version(record))) {
		error_print_msg("Invalid record version: %d.%d\n", record[1], record[2]);
		return -1;
	}
	len = (size_t)record[3] << 8 | record[4];
	*recordlen = 5 + len;
	if (*recordlen > TLS_MAX_RECORD_SIZE) {
		// 这里只检查是否超过最大长度，握手协议的长度检查由上层协议完成
		error_print();
		return -1;
	}
	if (len) {
		if ((r = recv(sock, record + 5, len, 0)) < 0) {
			error_print();
			return -1;
		} else if (r != len) {
			error_print();
			return -1;
		}
	}
	if (tls_record_type(record) == TLS_record_alert) {
		int level;
		int alert;
		if (tls_record_get_alert(record, &level, &alert) != 1) {
			error_print();
			return -1;
		}
		tls_record_trace(stderr, record, *recordlen, 0, 0);
		if (level == TLS_alert_level_warning) {
			// 忽略Warning，读取下一个记录
			error_puts("Warning record received!\n");
			goto retry;
		}
		if (alert == TLS_alert_close_notify) {
			// close_notify是唯一需要提供反馈的Fatal Alert，其他直接中止连接
			uint8_t alert_record[TLS_ALERT_RECORD_SIZE];
			size_t alert_record_len;
			tls_record_set_type(alert_record, TLS_record_alert);
			tls_record_set_version(alert_record, tls_record_version(record));
			tls_record_set_alert(alert_record, &alert_record_len, TLS_alert_level_fatal, TLS_alert_close_notify);
			tls_record_print(stderr, alert_record, alert_record_len, 0, 0);
			tls_record_send(alert_record, alert_record_len, sock);
		}
		// 返回错误0通知调用方不再做任何处理（无需再发送Alert）
		error_puts("Alert record received!\n");
		return 0;
	}
	return 1;
}

int tls_seq_num_incr(uint8_t seq_num[8])
{
	int i;
	for (i = 7; i > 0; i--) {
		seq_num[i]++;
		if (seq_num[i]) break;
	}
	// FIXME: 检查溢出
	return 1;
}

int tls_compression_methods_has_null_compression(const uint8_t *meths, size_t methslen)
{
	if (!meths || !methslen) {
		error_print();
		return -1;
	}
	while (methslen--) {
		if (*meths++ == TLS_compression_null) {
			return 1;
		}
	}
	return -1;
}

int tls_send_alert(TLS_CONNECT *conn, int alert)
{
	uint8_t record[5 + 2];
	size_t recordlen;

	tls_record_set_version(record, conn->version);
	tls_record_set_alert(record, &recordlen, TLS_alert_level_fatal, alert);
	tls_record_send(record, sizeof(record), conn->sock);
	tls_record_trace(stderr, record, sizeof(record), 0, 0);
	return 1;
}

int tls_alert_level(int alert)
{
	switch (alert) {
	case TLS_alert_bad_certificate:
	case TLS_alert_unsupported_certificate:
	case TLS_alert_certificate_revoked:
	case TLS_alert_certificate_expired:
	case TLS_alert_certificate_unknown:
		return 0;
	case TLS_alert_user_canceled:
	case TLS_alert_no_renegotiation:
		return TLS_alert_level_warning;
	default:
		return TLS_alert_level_fatal;
	}
	return -1;
}


int tls_send_warning(TLS_CONNECT *conn, int alert)
{
	uint8_t record[5 + 2];
	size_t recordlen;

	if (tls_alert_level(alert) == TLS_alert_level_fatal) {
		error_print();
		return -1;
	}
	tls_record_set_version(record, conn->version);
	tls_record_set_alert(record, &recordlen, TLS_alert_level_warning, alert);
	tls_record_send(record, sizeof(record), conn->sock);
	tls_record_trace(stderr, record, sizeof(record), 0, 0);
	return 1;
}




// FIXME: 设定支持的最大输入长度
// FIXME: 没回返回实际的发送长度
int tls_send(TLS_CONNECT *conn, const uint8_t *data, size_t datalen)
{
	const SM3_HMAC_CTX *hmac_ctx;
	const SM4_KEY *enc_key;
	uint8_t *seq_num;
	uint8_t mrec[1600];
	uint8_t crec[1600];
	size_t mlen = sizeof(mrec);
	size_t clen = sizeof(crec);

	// FIXME: 检查datalen的长度

	if (conn->is_client) {
		hmac_ctx = &conn->client_write_mac_ctx;
		enc_key = &conn->client_write_enc_key;
		seq_num = conn->client_seq_num;
	} else {
		hmac_ctx = &conn->server_write_mac_ctx;
		enc_key = &conn->server_write_enc_key;
		seq_num = conn->server_seq_num;
	}

	tls_trace("send ApplicationData\n");
	if (tls_record_set_version(mrec, conn->version) != 1
		|| tls_record_set_application_data(mrec, &mlen, data, datalen) != 1
		|| tls_record_encrypt(hmac_ctx, enc_key, seq_num, mrec, mlen, crec, &clen) != 1
		|| tls_seq_num_incr(seq_num) != 1
		|| tls_record_send(crec, clen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	tls_record_trace(stderr, crec, clen, 0, 0);
	return 1;
}

int tls_recv(TLS_CONNECT *conn, uint8_t *data, size_t *datalen)
{
	const SM3_HMAC_CTX *hmac_ctx;
	const SM4_KEY *dec_key;
	uint8_t *seq_num;
	uint8_t mrec[1600];
	uint8_t crec[1600];
	size_t mlen = sizeof(mrec);
	size_t clen = sizeof(crec);

	if (conn->is_client) {
		hmac_ctx = &conn->server_write_mac_ctx;
		dec_key = &conn->server_write_enc_key;
		seq_num = conn->server_seq_num;
	} else {
		hmac_ctx = &conn->client_write_mac_ctx;
		dec_key = &conn->client_write_enc_key;
		seq_num = conn->client_seq_num;
	}

	tls_trace("recv ApplicationData\n");
	if (tls_record_recv(crec, &clen, conn->sock) != 1) {
		error_print();
		return -1;
	}

	if (crec[0] == TLS_record_alert) {
		int level;
		int alert;

		if (tls_record_get_alert(crec, &level, &alert) != 1) {
			error_print();
			return -1;
		}
		if (alert == TLS_alert_close_notify) {
			if (tls_record_send(crec, clen, conn->sock) != 1) {
				error_print();
				return -1;
			}

		} else {
			error_print();
			return -1;
		}

		if (level == TLS_alert_level_fatal) {
			tls_trace("close Connection\n");
			return 0;
		}
	}


	// FIXME: 检查版本号
	if (tls_record_decrypt(hmac_ctx, dec_key, seq_num, crec, clen, mrec, &mlen) != 1
		|| tls_seq_num_incr(seq_num) != 1) {
		error_print();
		return -1;
	}
	tls_record_trace(stderr, mrec, mlen, 0, 0);
	memcpy(data, mrec + 5, mlen - 5);
	*datalen = mlen - 5;
	return 1;
}

//FIXME: any difference in TLS 1.2 and TLS 1.3?
int tls_shutdown(TLS_CONNECT *conn)
{
	uint8_t alert[128];
	size_t len;

	tls_record_set_version(alert, conn->version);
	tls_record_set_alert(alert, &len, TLS_alert_level_fatal, TLS_alert_close_notify);

	if (tls_record_send(alert, len, conn->sock) != 1) {
		error_print();
		return -1;
	}

	tls_trace("send Alert.close_notify\n");
	tls_record_trace(stderr, alert, len, 0, 0);


	memset(alert, 0, sizeof(alert));
	// 这里接收实际上只是检查一下对方是否合规，不管怎么说我们都要结束了
	if (tls_record_recv(alert, &len, conn->sock) != 1) {
		error_print();
		return -1;
	}
	tls_trace("recv Alert.close_notify\n");
	tls_record_trace(stderr, alert, len, 0, 0);

	return 1;
}

// 参考 man verify 的错误返回值
int tls_get_verify_result(TLS_CONNECT *conn, int *result)
{
	*result = 0;
	return 1;
}

// 这里的输出是record，因此是有一个长度限制的

int tls_authorities_from_certs(uint8_t *names, size_t *nameslen, size_t maxlen, const uint8_t *certs, size_t certslen)
{
	uint8_t *out = names;
	const uint8_t *cert;
	size_t certlen;
	const uint8_t *name;
	size_t namelen;

	*nameslen = 0;
	while (certslen) {
		size_t alen = 0;
		if (x509_cert_from_der(&cert, &certlen, &certs, &certslen) != 1
			|| x509_cert_get_subject(cert, certlen, &name, &namelen) != 1
			|| asn1_sequence_to_der(name, namelen, NULL, &alen) != 1) {
			error_print();
			return -1;
		}
		if (tls_uint16_size() + alen > maxlen) {

			fprintf(stderr, "alen = %zu\n", alen);
			fprintf(stderr, "maxlen = %zu\n", maxlen);

			error_print();
			return -1;
		}
		// 这里要兼容names == NULL的情况			
		tls_uint16_to_bytes(alen, &out, nameslen);
		if (asn1_sequence_to_der(name, namelen, &out, nameslen) != 1) {
			error_print();
			return -1;
		}
		maxlen -= alen;
	}
	return 1;
}

int tls_authorities_issued_certificate(const uint8_t *ca_names, size_t ca_names_len, const uint8_t *certs, size_t certslen)
{
	const uint8_t *cert;
	size_t certlen;
	const uint8_t *issuer;
	size_t issuer_len;

	if (x509_certs_get_last(certs, certslen, &cert, &certlen) != 1
		|| x509_cert_get_issuer(cert, certlen, &issuer, &issuer_len) != 1) {
		error_print();
		return -1;
	}
	while (ca_names_len) {
		const uint8_t *p;
		size_t len;
		const uint8_t *name;
		size_t namelen;

		if (tls_uint16array_from_bytes(&p, &len, &ca_names, &ca_names_len) != 1) {
			error_print();
			return -1;
		}
		if (asn1_sequence_from_der(&name, &namelen, &p, &len) != 1
			|| asn1_length_is_zero(len) != 1) {
			error_print();
			return -1;
		}
		if (x509_name_equ(name, namelen, issuer, issuer_len) == 1) {
			return 1;
		}
	}
	error_print();
	return 0;
}

int tls_cert_types_accepted(const uint8_t *types, size_t types_len, const uint8_t *client_certs, size_t client_certs_len)
{
	const uint8_t *cert;
	size_t certlen;
	int sig_alg;
	size_t i;

	if (x509_certs_get_cert_by_index(client_certs, client_certs_len, 0, &cert, &certlen) != 1) {
		error_print();
		return -1;
	}
	if ((sig_alg = tls_cert_type_from_oid(OID_sm2sign_with_sm3)) < 0) {
		error_print();
		return -1;
	}
	for (i = 0; i < types_len; i++) {
		if (sig_alg == types[i]) {
			return 1;
		}
	}
	return 0;
}


int tls_client_verify_init(TLS_CLIENT_VERIFY_CTX *ctx)
{
	memset(ctx, 0, sizeof(TLS_CLIENT_VERIFY_CTX));
	return 1;
}

int tls_client_verify_update(TLS_CLIENT_VERIFY_CTX *ctx, const uint8_t *handshake, size_t handshake_len)
{
	uint8_t *buf;
	if (ctx->index < 0 || ctx->index > 7) {
		error_print();
		return -1;
	}
	if (!(buf = malloc(handshake_len))) {
		error_print();
		return -1;
	}
	memcpy(buf, handshake, handshake_len);
	ctx->handshake[ctx->index] = buf;
	ctx->handshake_len[ctx->index] = handshake_len;
	ctx->index++;
	return 1;
}

int tls_client_verify_finish(TLS_CLIENT_VERIFY_CTX *ctx, const uint8_t *sig, size_t siglen, const SM2_KEY *public_key)
{
	int ret;
	SM2_SIGN_CTX sm2_ctx;
	int i;

	if (ctx->index != 8) {
		error_print();
		return -1;
	}
	if (sm2_verify_init(&sm2_ctx, public_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; i < 8; i++) {
		if (sm2_verify_update(&sm2_ctx, ctx->handshake[i], ctx->handshake_len[i]) != 1) {
			error_print();
			return -1;
		}
	}
	if ((ret = sm2_verify_finish(&sm2_ctx, sig, siglen)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

void tls_client_verify_cleanup(TLS_CLIENT_VERIFY_CTX *ctx)
{
	int i;
	for (i = 0; i< ctx->index; i++) {
		if (ctx->handshake[i]) {
			free(ctx->handshake[i]);
			ctx->handshake[i] = NULL;
			ctx->handshake_len[i] = 0;
		}
	}
}


int tls_cipher_suites_select(const uint8_t *client_ciphers, size_t client_ciphers_len,
	const int *server_ciphers, size_t server_ciphers_cnt,
	int *selected_cipher)
{
	while (server_ciphers_cnt--) {
		const uint8_t *p = client_ciphers;
		size_t len = client_ciphers_len;
		while (len) {
			uint16_t cipher;
			if (tls_uint16_from_bytes(&cipher, &p, &len) != 1) {
				error_print();
				return -1;
			}
			if (cipher == *server_ciphers) {
				*selected_cipher = *server_ciphers;
				return 1;
			}
		}
		server_ciphers++;
	}
	return 0;
}



