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
	if (out) {
		memcpy(*out, data, datalen);
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

int tls_array_copy_from_bytes(uint8_t *data, size_t datalen, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *p;
	if (tls_array_from_bytes(&p, datalen, in, inlen) != 1) {
		error_print();
		return -1;
	}
	memcpy(data, p, datalen);
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
	*datalen = len;
	return 1;
}

int tls_uint8array_copy_from_bytes(uint8_t *data, size_t *datalen, size_t maxlen, const uint8_t **in, size_t *inlen)
{
	const uint8_t *p;
	if (tls_uint8array_from_bytes(&p, datalen, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (*datalen > maxlen) {
		error_print();
		return -1;
	}
	memcpy(data, p, *datalen);
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
	*datalen = len;
	return 1;
}

int tls_uint16array_copy_from_bytes(uint8_t *data, size_t *datalen, size_t maxlen, const uint8_t **in, size_t *inlen)
{
	const uint8_t *p;
	if (tls_uint16array_from_bytes(&p, datalen, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (*datalen > maxlen) {
		error_print();
		return -1;
	}
	memcpy(data, p, *datalen);
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
	*datalen = len;
	return 1;
}

int tls_uint24array_copy_from_bytes(uint8_t *data, size_t *datalen, size_t maxlen, const uint8_t **in, size_t *inlen)
{
	const uint8_t *p;
	if (tls_uint24array_from_bytes(&p, datalen, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (*datalen > maxlen) {
		error_print();
		return -1;
	}
	memcpy(data, p, *datalen);
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

int tls_record_version(const uint8_t *record)
{
	int version = ((int)record[1] << 8) | record[2];
	return version;
}

//					
int tls_record_length(const uint8_t *record)
{
	int ret;
	ret = ((uint16_t)record[3] << 8) | record[4];
	return ret;
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
	if (memcmp(mac, hmac, sizeof(hmac)) != 0) { //FIXME: const time memcmp!
		error_puts("tls ciphertext mac check failure");
		return -1;
	}
	return 1;
}

// 这个函数应该是处理的，这个函数是不应该用的，通常我们在加密的时候，header ，明文数据是分离的，但是输出的record是一个
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

// handshake types

int tls_random_generate(uint8_t random[32])
{
	uint32_t gmt_unix_time = (uint32_t)time(NULL);
	uint8_t *p = random;
	size_t len = 0;
	tls_uint32_to_bytes(gmt_unix_time, &p, &len);
	rand_bytes(random + 4, 28);
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

	sm2_sign_init(&sign_ctx, server_sign_key, SM2_DEFAULT_ID);
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
		|| siglen > TLS_MAX_SIGNATURE_SIZE) {
		error_print();
		return -1;
	}
	server_ecdh_params[0] = TLS_curve_type_named_curve;
	server_ecdh_params[1] = curve >> 8;
	server_ecdh_params[2] = curve;
	server_ecdh_params[3] = 65;
	sm2_point_to_uncompressed_octets(point, server_ecdh_params + 4);

	sm2_verify_init(&verify_ctx, server_sign_key, SM2_DEFAULT_ID);
	sm2_verify_update(&verify_ctx, client_random, 32);
	sm2_verify_update(&verify_ctx, server_random, 32);
	sm2_verify_update(&verify_ctx, server_ecdh_params, 69);
	ret = sm2_verify_finish(&verify_ctx, sig, siglen);
	if (ret != 1) error_print();
	return ret;
}




// handshakes

int tls_record_set_handshake(uint8_t *record, size_t *recordlen,
	int type, const uint8_t *data, size_t datalen)
{
	size_t handshakelen;

	if (!record || !recordlen) {
		error_print();
		return -1;
	}
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
	if (record_datalen > TLS_RECORD_MAX_PLAINDATA_SIZE
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

int tls_record_get_handshake_client_hello(const uint8_t *record,
	int *version, uint8_t random[32], uint8_t *session_id, size_t *session_id_len,
	int *cipher_suites, size_t *cipher_suites_count,
	uint8_t *exts, size_t *exts_len)
{
	int type;
	const uint8_t *p;
	size_t len;
	const uint8_t *ciphers;
	size_t ciphers_len;
	const uint8_t *comp_meths;
	size_t comp_meths_len;

	if (!record || !random || !session_id || !session_id_len
		|| !cipher_suites || !cipher_suites_count || (exts && !exts_len)
		|| record[0] != TLS_record_handshake) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, &p, &len) != 1
		|| type != TLS_handshake_client_hello) {
		error_print();
		return -1;
	}
	*version = 0;
	if (tls_uint16_from_bytes((uint16_t *)version, &p, &len) != 1
		|| tls_array_copy_from_bytes(random, 32, &p, &len) != 1
		|| tls_uint8array_copy_from_bytes(session_id, session_id_len, 32, &p, &len) != 1
		|| tls_uint16array_from_bytes(&ciphers, &ciphers_len, &p, &len) != 1
		|| tls_uint8array_from_bytes(&comp_meths, &comp_meths_len, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (ciphers_len % 2) {
		error_print();
		return -1;
	}
	*cipher_suites_count = 0;
	while (ciphers_len) {
		uint16_t cipher_suite;
		tls_uint16_from_bytes(&cipher_suite, &ciphers, &ciphers_len);
		if (!tls_cipher_suite_name(cipher_suite)) {
			error_print();
			return -1;
		}
		*cipher_suites++ = cipher_suite;
		(*cipher_suites_count)++;
	}
	if (len > 0) {
		if (*version < TLS_version_tls12) {
			error_print();
			return -1;
		}
		if (!exts) {
			error_print();
			return -1;
		}
		if (tls_uint16array_copy_from_bytes(exts, exts_len, TLS_MAX_EXTENSIONS_SIZE, &p, &len) != 1
			|| len > 0) {
			error_print();
			return -1;
		}
	}
	return 1;
}


int tls_record_set_handshake_server_hello(uint8_t *record, size_t *recordlen,
	int version, const uint8_t random[32],
	const uint8_t *session_id, size_t session_id_len, int cipher_suite,
	const uint8_t *exts, size_t exts_len)
{
	uint8_t type = TLS_handshake_server_hello;
	uint8_t *p = record + 5 + 4;
	size_t len = 0;

	if (!record || !recordlen || !tls_version_text(version) || !random
		|| (!session_id && session_id_len) || session_id_len > 32
		|| (!exts && exts_len) || exts_len > 512) {
		error_print();
		return -1;
	}
	if (record[0] != TLS_record_handshake
		|| !tls_version_text(version)
		|| !tls_cipher_suite_name(cipher_suite)
		|| version < tls_record_version(record)) {
		error_print();
		return -1;
	}
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
	int *version, uint8_t random[32], uint8_t *session_id, size_t *session_id_len,
	int *cipher_suite, uint8_t *exts, size_t *exts_len)
{
	int type;
	const uint8_t *p;
	size_t len;
	uint8_t comp_meth;

	if (!record || !version || !random || !session_id || !session_id_len
		|| !cipher_suite || (exts && !exts_len)) {
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
	*version = 0;
	*cipher_suite = 0;
	if (tls_uint16_from_bytes((uint16_t *)version, &p, &len) != 1
		|| tls_array_copy_from_bytes(random, 32, &p, &len) != 1
		|| tls_uint8array_copy_from_bytes(session_id, session_id_len, 32, &p, &len) != 1
		|| tls_uint16_from_bytes((uint16_t *)cipher_suite, &p, &len) != 1
		|| tls_uint8_from_bytes(&comp_meth, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (!tls_version_text(*version)) {
		error_print();
		return -1;
	}
	if (*version < tls_record_version(record)) {
		error_print();
		return -1;
	}
	if (!tls_cipher_suite_name(*cipher_suite)) {
		error_print_msg("unknown server cipher_suite 0x%04x", *cipher_suite);
		return -1;
	}
	if (comp_meth != TLS_compression_null) {
		error_print();
		return -1;
	}
	if (len > 0) {
		if (tls_record_version(record) < TLS_version_tls12) {
			error_puts("warning: should not have extentions");
			return -1;
		}
		// FIXME: 用 tls_extensions_from_bytes() 解析		
		if (tls_uint16array_copy_from_bytes(exts, exts_len, TLS_MAX_EXTENSIONS_SIZE, &p, &len) != 1
			|| len > 0) {
			error_print();
			return -1;
		}
	}
	return 1;
}






int tls_record_set_handshake_certificate(uint8_t *record, size_t *recordlen,
	const uint8_t *data, size_t datalen)
{
	int type = TLS_handshake_certificate;
	const uint8_t *cp = data;
	size_t len = datalen;
	const uint8_t *certs;
	size_t certslen;

	if (!record || !recordlen
		|| !data || datalen <= 3 || datalen > 65535) {
		error_print();
		return -1;
	}
	if (tls_uint24array_from_bytes(&certs, &certslen, &cp, &len) != 1
		|| len > 0) {
		error_print();
		return -1;
	}
	// FIXME: check certificate		
	if (!certslen) {
		error_print();
		return -1;
	}
	tls_record_set_handshake(record, recordlen, type, data, datalen);
	return 1;
}

int tls_record_set_handshake_certificate_from_pem(uint8_t *record, size_t *recordlen, FILE *fp)
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

int tls_record_get_handshake_certificate(const uint8_t *record, uint8_t *data, size_t *datalen)
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
	memcpy(data, cp, *datalen);
	return 1;
}

int tls_certificate_get_subject_names(const uint8_t *certs, size_t certslen, uint8_t *names, size_t *nameslen)
{
	*nameslen = 0;
	const uint8_t *der;
	size_t derlen;

	while (certslen > 0) {
		X509_CERTIFICATE cert;

		if (tls_uint24array_from_bytes(&der, &derlen, &certs, &certslen) != 1) {
			error_print();
			return -1;
		}
		if (x509_certificate_from_der(&cert, &der, &derlen) != 1) {
			error_print();
			return -1;
		}
		if (derlen > 0) {
			error_print();
			return -1;
		}
		if (x509_name_to_der(&cert.tbs_certificate.subject, &names, nameslen) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int tls_certificate_get_first(const uint8_t *data, size_t datalen, const uint8_t **cert, size_t *certlen)
{
	const uint8_t *certs;
	size_t certslen;
	if (tls_uint24array_from_bytes(&certs, &certslen, &data, &datalen) != 1
		|| datalen > 0
		|| tls_uint24array_from_bytes(cert, certlen, &certs, &certslen) != 1) {
		error_print();
		return -1;
	}
	*cert -= 3;
	*certlen += 3;
	return 1;
}

int tls_certificate_get_second(const uint8_t *data, size_t datalen, const uint8_t **cert, size_t *certlen)
{
	const uint8_t *certs;
	size_t certslen;
	if (tls_uint24array_from_bytes(&certs, &certslen, &data, &datalen) != 1
		|| datalen > 0
		|| tls_uint24array_from_bytes(cert, certlen, &certs, &certslen) != 1
		|| tls_uint24array_from_bytes(cert, certlen, &certs, &certslen) != 1) {
		error_print();
		return -1;
	}
	*cert -= 3;
	*certlen += 3;
	return 1;
}

int tls_certificate_get_public_keys(const uint8_t *data, size_t datalen,
	SM2_KEY *sign_key, SM2_KEY *enc_key)
{
	X509_CERTIFICATE x509;
	const uint8_t *cert;
	const uint8_t *der;
	size_t certlen, derlen;

	if (!data || !datalen || !sign_key) {
		error_print();
		return -1;
	}
	if (tls_certificate_get_first(data, datalen, &cert, &certlen) != 1
		|| tls_uint24array_from_bytes(&der, &derlen, &cert, &certlen) != 1
		|| certlen > 0
		|| x509_certificate_from_der(&x509, &der, &derlen) != 1
		|| derlen > 0) {
		error_print();
		return -1;
	}
	memcpy(sign_key, &x509.tbs_certificate.subject_public_key_info.sm2_key, sizeof(SM2_KEY));
	if (enc_key) {
		if (tls_certificate_get_second(data, datalen, &cert, &certlen) != 1
			|| tls_uint24array_from_bytes(&der, &derlen, &cert, &certlen) != 1
			|| certlen > 0
			|| x509_certificate_from_der(&x509, &der, &derlen) != 1
			|| derlen > 0) {
			error_print();
			return -1;
		}
		memcpy(enc_key, &x509.tbs_certificate.subject_public_key_info.sm2_key, sizeof(SM2_KEY));
	}
	return 1;
}



int tls_certificate_chain_verify(const uint8_t *certs, size_t certslen, FILE *ca_certs_fp, int depth)
{
	X509_CERTIFICATE cert;
	X509_CERTIFICATE cacert;
	const uint8_t *der;
	size_t derlen;
	if (tls_uint24array_from_bytes(&der, &derlen, &certs, &certslen) != 1) {
		error_print();
		return -1;
	}
	if (x509_certificate_from_der(&cert, &der, &derlen) != 1
		|| derlen > 0) {
		error_print();
		return -1;
	}
	while (certslen > 0) {
		if (tls_uint24array_from_bytes(&der, &derlen, &certs, &certslen) != 1
			|| x509_certificate_from_der(&cacert, &der, &derlen) != 1
			|| derlen > 0) {
			error_print();
			return -1;
		}
		if (x509_certificate_verify_by_certificate(&cert, &cacert) != 1) {
			error_print();
			return -1;
		}
		memcpy(&cert, &cacert, sizeof(X509_CERTIFICATE));
	}
	if (x509_certificate_from_pem_by_name(&cacert, ca_certs_fp, &cert.tbs_certificate.issuer) != 1
		|| x509_certificate_verify_by_certificate(&cert, &cacert) != 1) {
		error_print();
		return -1;
	}
	return 1;
}


int tls_record_set_handshake_certificate_request(uint8_t *record, size_t *recordlen,
	const int *cert_types, size_t cert_types_count,
	const uint8_t *ca_names, size_t ca_names_len)
{
	int type = TLS_handshake_certificate_request;
	uint8_t *p = record + 5 + 4;
	size_t len = 0;

	if (!record || !recordlen
		|| !cert_types || !cert_types_count || cert_types_count > TLS_MAX_CERTIFICATE_TYPES
		|| (!ca_names && ca_names_len) || ca_names_len > TLS_MAX_CA_NAMES_SIZE) {
		error_print();
		return -1;
	}
	tls_uint8_to_bytes((uint8_t)cert_types_count, &p, &len);
	while (cert_types_count--) {
		tls_uint8_to_bytes((uint8_t)(*cert_types), &p, &len);
		cert_types++;
	}
	tls_uint16array_to_bytes(ca_names, ca_names_len, &p, &len);
	tls_record_set_handshake(record, recordlen, type, NULL, len);
	return 1;
}

int tls_record_get_handshake_certificate_request(const uint8_t *record,
	int *cert_types, size_t *cert_types_count,
	uint8_t *ca_names, size_t *ca_names_len)
{
	int type;
	const uint8_t *cp;
	size_t len;
	const uint8_t *types;
	size_t count;

	if (!record
		|| !cert_types || !cert_types_count || !ca_names || !ca_names_len
		|| record[0] != TLS_record_handshake) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, &cp, &len) != 1
		|| tls_uint8array_from_bytes(&types, &count, &cp, &len) != 1
		|| tls_uint16array_copy_from_bytes(ca_names, ca_names_len, TLS_MAX_CA_NAMES_SIZE, &cp, &len) != 1
		|| len > 0) {
		error_print();
		return -1;
	}
	if (count > TLS_MAX_CERTIFICATE_TYPES) {
		error_print();
		return -1;
	}
	while (count--) {
		*cert_types++ = *types++;
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
	uint8_t *enced_pms, size_t *enced_pms_len)
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
	if (tls_uint16array_copy_from_bytes(enced_pms, enced_pms_len, *enced_pms_len, &p, &len) != 1
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
	uint8_t *sig, size_t *siglen)
{
	int type;
	const uint8_t *p;
	size_t len ;

	if (tls_record_get_handshake(record, &type, &p, &len) != 1
		|| type != TLS_handshake_certificate_verify) {
		error_print();
		return -1;
	}
	memcpy(sig, p, len);
	*siglen = len;
	return 1;
}

//FIXME: TLS 1.3 中的verify_data长度和hashLen一样,并且长度是不单独编码的，
// 因此这个函数应该改一下了
int tls_record_set_handshake_finished(uint8_t *record, size_t *recordlen,
	const uint8_t verify_data[12])
{
	int type = TLS_handshake_finished;
	if (!record || !recordlen || !verify_data) {
		error_print();
		return -1;
	}
	tls_record_set_handshake(record, recordlen, type, verify_data, 12);
	return 1;
}

int tls_record_get_handshake_finished(const uint8_t *record, uint8_t verify_data[12])
{
	int type;
	const uint8_t *p;
	size_t len;

	if (tls_record_get_handshake(record, &type, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (len != 12) {
		error_print();
		return -1;
	}
	memcpy(verify_data, p, 12);
	return 1;
}

// alert protocol


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

	if ((r = recv(sock, record, 5, 0)) < 0) {
		error_print();
		return -1;
	} else if (r != 5) {
		// FIXME: 如果对方已经中断连接，那么我们要判断这个错误吗? 
		error_print();
		perror(""); // 否则打印ioctl错误
		return -1;
	}

	if (!tls_record_type_name(record[0])) {
		error_print_msg("invalid record type: %d\n", record[0]);
		return -1;
	}
	if (!tls_version_text(tls_record_version(record))) {
		error_print_msg("invalid record version: %d.%d\n", record[1], record[2]);
		return -1;
	}
	len = (size_t)record[3] << 8 | record[4];
	*recordlen = 5 + len;
	if (len) {
		if ((r = recv(sock, record + 5, len, 0)) < 0) {
			error_print();
			return -1;
		} else if (r != len) {
			error_print();
			return -1;
		}
	}

	if (record[0] == TLS_record_alert) {
		tls_record_print(stderr, record, *recordlen, 0, 0);
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

// FIXME: 设定支持的最大输入长度
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

	tls_trace(">>>> ApplicationData\n");
	if (tls_record_set_version(mrec, conn->version) != 1
		|| tls_record_set_application_data(mrec, &mlen, data, datalen) != 1
		|| tls_record_encrypt(hmac_ctx, enc_key, seq_num, mrec, mlen, crec, &clen) != 1
		|| tls_seq_num_incr(seq_num) != 1
		|| tls_record_send(crec, clen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	(void)tls_record_print(stderr, crec, clen, 0, 0);
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

	tls_trace("<<<< ApplicationData\n");
	if (tls_record_recv(crec, &clen, conn->sock) != 1
		// FIXME: 检查版本号
		|| tls_record_decrypt(hmac_ctx, dec_key, seq_num, crec, clen, mrec, &mlen) != 1
		|| tls_seq_num_incr(seq_num) != 1) {
		error_print();
		return -1;
	}
	(void)tls_record_print(stderr, mrec, mlen, 0, 0);
	memcpy(data, mrec + 5, mlen - 5);
	*datalen = mlen - 5;
	return 1;
}

//FIXME: any difference in TLS 1.2 and TLS 1.3?
int tls_shutdown(TLS_CONNECT *conn)
{
	return -1;
}
