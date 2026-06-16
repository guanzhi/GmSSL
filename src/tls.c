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
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <gmssl/rand.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>
#include <gmssl/mem.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/pem.h>
#include <gmssl/tls.h>


void tls_uint8_to_bytes(uint8_t a, uint8_t **out, size_t *outlen)
{
	if (out && *out) {
		*(*out)++ = a;
	}
	(*outlen)++;
}

void tls_uint16_to_bytes(uint16_t a, uint8_t **out, size_t *outlen)
{
	if (out && *out) {
		*(*out)++ = (uint8_t)(a >> 8);
		*(*out)++ = (uint8_t)a;
	}
	*outlen += 2;
}

void tls_uint24_to_bytes(uint24_t a, uint8_t **out, size_t *outlen)
{
	if (out && *out) {
		*(*out)++ = (uint8_t)(a >> 16);
		*(*out)++ = (uint8_t)(a >> 8);
		*(*out)++ = (uint8_t)(a);
	}
	(*outlen) += 3;
}

void tls_uint32_to_bytes(uint32_t a, uint8_t **out, size_t *outlen)
{
	if (out && *out) {
		*(*out)++ = (uint8_t)(a >> 24);
		*(*out)++ = (uint8_t)(a >> 16);
		*(*out)++ = (uint8_t)(a >>  8);
		*(*out)++ = (uint8_t)(a      );
	}
	(*outlen) += 4;
}

void tls_uint64_to_bytes(uint64_t a, uint8_t **out, size_t *outlen)
{
	if (out && *out) {
		PUTU64(*out, a);
	}
	(*outlen) += 8;
}

void tls_array_to_bytes(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen)
{
	if (out && *out) {
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

int tls_uint64_from_bytes(uint64_t *a, const uint8_t **in, size_t *inlen)
{
	if (*inlen < 8) {
		error_print();
		return -1;
	}
	*a = GETU64(*in);
	*in += 8;
	*inlen -= 8;
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

int tls_length_is_zero(size_t len)
{
	if (len) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_record_set_type(uint8_t *record, int type)
{
	if (!tls_record_type_name(type)) {
		error_print();
		return -1;
	}
	record[0] = (uint8_t)type;
	return 1;
}

int tls_record_set_protocol(uint8_t *record, int protocol)
{
	if (!tls_protocol_name(protocol)) {
		error_print();
		return -1;
	}
	record[1] = (uint8_t)(protocol >> 8);
	record[2] = (uint8_t)(protocol);
	return 1;
}

int tls_record_set_data_length(uint8_t *record, size_t length)
{
	uint8_t *p = record + 3;
	size_t len;
	if (length > TLS_MAX_CIPHERTEXT_SIZE) {
		error_print();
		return -1;
	}
	tls_uint16_to_bytes((uint16_t)length, &p, &len);
	return 1;
}

int tls_record_set_data(uint8_t *record, const uint8_t *data, size_t datalen)
{
	if (tls_record_set_data_length(record, datalen) != 1) {
		error_print();
		return -1;
	}
	memcpy(tls_record_data(record), data, datalen);
	return 1;
}

int tls_cipher_suite_get(int cipher_suite, const BLOCK_CIPHER **cipher, const DIGEST **digest)
{
	switch (cipher_suite) {
	case TLS_cipher_ecdhe_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_sm4_gcm_sm3:
	case TLS_cipher_sm4_gcm_sm3:
	case TLS_cipher_sm4_ccm_sm3:
		*cipher = BLOCK_CIPHER_sm4();
		*digest = DIGEST_sm3();
		break;

	case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_gcm_sha256:
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_ccm:
	case TLS_cipher_aes_128_gcm_sha256:
	case TLS_cipher_aes_128_ccm_sha256:
		*cipher = BLOCK_CIPHER_aes128();
		*digest = DIGEST_sha256();
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

int tls_cbc_encrypt(const HMAC_CTX *inited_hmac_ctx, const BLOCK_CIPHER_KEY *enc_key,
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

	if (!inited_hmac_ctx || !enc_key || !enc_key->cipher
		|| !seq_num || !header || (!in && inlen) || !out || !outlen) {
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
		size_t nblocks = inlen/16;

		switch (enc_key->cipher->oid) {
		case OID_sm4:
			sm4_cbc_encrypt_blocks(&enc_key->u.sm4_key, iv, in, nblocks, out);
			break;
#ifdef ENABLE_AES
		case OID_aes128:
		case OID_aes256:
			aes_cbc_encrypt_blocks(&enc_key->u.aes_key, iv, in, nblocks, out);
			break;
#endif
		default:
			error_print();
			return -1;
		}
		out += inlen - rem;
		memcpy(iv, out - 16, 16);
	}
	switch (enc_key->cipher->oid) {
	case OID_sm4:
		sm4_cbc_encrypt_blocks(&enc_key->u.sm4_key, iv, last_blocks, sizeof(last_blocks)/16, out);
		break;
#ifdef ENABLE_AES
	case OID_aes128:
	case OID_aes192:
	case OID_aes256:
		aes_cbc_encrypt_blocks(&enc_key->u.aes_key, iv, last_blocks, sizeof(last_blocks)/16, out);
		break;
#endif
	default:
		error_print();
		return -1;
	}
	*outlen = 16 + inlen - rem + sizeof(last_blocks);
	return 1;
}

int tls_cbc_decrypt(const HMAC_CTX *inited_hmac_ctx, const BLOCK_CIPHER_KEY *dec_key,
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

	if (!inited_hmac_ctx || !dec_key || !dec_key->cipher
		|| !seq_num || !enced_header || !in || !inlen || !out || !outlen) {
		error_print();
		return -1;
	}
	if (inlen % 16
		|| inlen < (16 + 0 + 32 + 16) // iv + data +  mac + padding
		|| inlen > (16 + (1<<14) + 32 + 256)) {
		error_print();
		return -1;
	}

	memcpy(iv, in, 16);
	in += 16;
	inlen -= 16;

	switch (dec_key->cipher->oid) {
	case OID_sm4:
		sm4_cbc_decrypt_blocks(&dec_key->u.sm4_key, iv, in, inlen/16, out);
		break;
#ifdef ENABLE_AES
	case OID_aes128:
	case OID_aes192:
	case OID_aes256:
		aes_cbc_decrypt_blocks(&dec_key->u.aes_key, iv, in, inlen/16, out);
		break;
#endif
	default:
		error_print();
		return -1;
	}

	padding_len = out[inlen - 1];
	padding = out + inlen - padding_len - 1;
	if (padding < out + 32) {
		error_print();
		return -1;
	}
	for (i = 0; i < padding_len; i++) {
		if (padding[i] != padding_len) {
			error_print();
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
		error_print();
		return -1;
	}
	return 1;
}

int tls_gcm_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t fixed_iv[4],
	const uint8_t seq_num[8], const uint8_t header[5],
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	uint8_t nonce[12];
	uint8_t aad[13];
	uint8_t *explicit_nonce;
	uint8_t *gmac;

	if (!key || !fixed_iv || !seq_num || !header || (!in && inlen) || !out || !outlen) {
		error_print();
		return -1;
	}
	if (inlen > TLS_MAX_PLAINTEXT_SIZE) {
		error_print();
		return -1;
	}
	if ((((size_t)header[3]) << 8) + header[4] != inlen) {
		error_print();
		return -1;
	}

	memcpy(nonce, fixed_iv, 4);
	memcpy(nonce + 4, seq_num, 8);

	memcpy(aad, seq_num, 8);
	memcpy(aad + 8, header, 5);

	explicit_nonce = out;
	memcpy(explicit_nonce, seq_num, 8);
	out += 8;

	gmac = out + inlen;

	switch (key->cipher->oid) {
	case OID_sm4:
		if (sm4_gcm_encrypt(&(key->u.sm4_key), nonce, sizeof(nonce), aad, sizeof(aad),
			in, inlen, out, GHASH_SIZE, gmac) != 1) {
			error_print();
			return -1;
		}
		break;
#ifdef ENABLE_AES
	case OID_aes128:
	case OID_aes192:
	case OID_aes256:
		if (aes_gcm_encrypt(&(key->u.aes_key), nonce, sizeof(nonce), aad, sizeof(aad),
			in, inlen, out, GHASH_SIZE, gmac) != 1) {
			error_print();
			return -1;
		}
		break;
#endif
	default:
		error_print();
		return -1;
	}

	*outlen = 8 + inlen + GHASH_SIZE;
	return 1;
}

int tls_gcm_decrypt(const BLOCK_CIPHER_KEY *key, const uint8_t fixed_iv[4],
	const uint8_t seq_num[8], const uint8_t header[5],
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	uint8_t nonce[12];
	uint8_t aad[13];
	const uint8_t *explicit_nonce;
	const uint8_t *gmac;
	size_t mlen;

	if (inlen < 8 + GHASH_SIZE) {
		error_print();
		return -1;
	}

	explicit_nonce = in;
	in += 8;
	inlen -= 8;

	if (inlen < GHASH_SIZE) {
		error_print();
		return -1;
	}
	mlen = inlen - GHASH_SIZE;
	gmac = in + mlen;

	memcpy(nonce, fixed_iv, 4);
	memcpy(nonce + 4, explicit_nonce, 8);

	memcpy(aad, seq_num, 8);
	memcpy(aad + 8, header, 5);
	aad[11] = (uint8_t)(mlen >> 8);
	aad[12] = (uint8_t)mlen;

	switch (key->cipher->oid) {
	case OID_sm4:
		if (sm4_gcm_decrypt(&(key->u.sm4_key), nonce, sizeof(nonce), aad, sizeof(aad),
			in, mlen, gmac, GHASH_SIZE, out) != 1) {
			error_print();
			return -1;
		}
		break;
#ifdef ENABLE_AES
	case OID_aes128:
	case OID_aes192:
	case OID_aes256:
		if (aes_gcm_decrypt(&(key->u.aes_key), nonce, sizeof(nonce), aad, sizeof(aad),
			in, mlen, gmac, GHASH_SIZE, out) != 1) {
			error_print();
			return -1;
		}
		break;
#endif
	default:
		error_print();
		return -1;
	}

	*outlen = mlen;
	return 1;
}

int tls_ccm_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t fixed_iv[4],
	const uint8_t seq_num[8], const uint8_t header[5],
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	uint8_t nonce[12];
	uint8_t aad[13];
	uint8_t *explicit_nonce;
	uint8_t *tag;

	if (!key || !fixed_iv || !seq_num || !header || (!in && inlen) || !out || !outlen) {
		error_print();
		return -1;
	}
	if (inlen > TLS_MAX_PLAINTEXT_SIZE) {
		error_print();
		return -1;
	}
	if ((((size_t)header[3]) << 8) + header[4] != inlen) {
		error_print();
		return -1;
	}

	memcpy(nonce, fixed_iv, 4);
	memcpy(nonce + 4, seq_num, 8);

	memcpy(aad, seq_num, 8);
	memcpy(aad + 8, header, 5);

	explicit_nonce = out;
	memcpy(explicit_nonce, seq_num, 8);
	out += 8;

	tag = out + inlen;

	switch (key->cipher->oid) {
#ifdef ENABLE_SM4_CCM
	case OID_sm4:
		if (sm4_ccm_encrypt(&(key->u.sm4_key), nonce, sizeof(nonce), aad, sizeof(aad),
			in, inlen, out, GHASH_SIZE, tag) != 1) {
			error_print();
			return -1;
		}
		break;
#endif
#ifdef ENABLE_AES_CCM
	case OID_aes128:
	case OID_aes192:
	case OID_aes256:
		if (aes_ccm_encrypt(&(key->u.aes_key), nonce, sizeof(nonce), aad, sizeof(aad),
			in, inlen, out, GHASH_SIZE, tag) != 1) {
			error_print();
			return -1;
		}
		break;
#endif
	default:
		error_print();
		return -1;
	}

	*outlen = 8 + inlen + GHASH_SIZE;
	return 1;
}

int tls_ccm_decrypt(const BLOCK_CIPHER_KEY *key, const uint8_t fixed_iv[4],
	const uint8_t seq_num[8], const uint8_t header[5],
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	uint8_t nonce[12];
	uint8_t aad[13];
	const uint8_t *explicit_nonce;
	const uint8_t *tag;
	size_t mlen;

	if (inlen < 8 + GHASH_SIZE) {
		error_print();
		return -1;
	}

	explicit_nonce = in;
	in += 8;
	inlen -= 8;

	if (inlen < GHASH_SIZE) {
		error_print();
		return -1;
	}
	mlen = inlen - GHASH_SIZE;
	tag = in + mlen;

	memcpy(nonce, fixed_iv, 4);
	memcpy(nonce + 4, explicit_nonce, 8);

	memcpy(aad, seq_num, 8);
	memcpy(aad + 8, header, 5);
	aad[11] = (uint8_t)(mlen >> 8);
	aad[12] = (uint8_t)mlen;

	switch (key->cipher->oid) {
#ifdef ENABLE_SM4_CCM
	case OID_sm4:
		if (sm4_ccm_decrypt(&(key->u.sm4_key), nonce, sizeof(nonce), aad, sizeof(aad),
			in, mlen, tag, GHASH_SIZE, out) != 1) {
			error_print();
			return -1;
		}
		break;
#endif
#ifdef ENABLE_AES_CCM
	case OID_aes128:
	case OID_aes192:
	case OID_aes256:
		if (aes_ccm_decrypt(&(key->u.aes_key), nonce, sizeof(nonce), aad, sizeof(aad),
			in, mlen, tag, GHASH_SIZE, out) != 1) {
			error_print();
			return -1;
		}
		break;
#endif
	default:
		error_print();
		return -1;
	}

	*outlen = mlen;
	return 1;
}

int tls_seq_num_incr(uint8_t seq_num[8])
{
	int i;
	for (i = 7; i > 0; i--) {
		seq_num[i]++;
		if (seq_num[i]) break;
	}
	return 1;
}

void tls_seq_num_reset(uint8_t seq_num[8])
{
	memset(seq_num, 0, 8);
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

int tls_prf(const DIGEST *digest, const uint8_t *secret, size_t secretlen, const char *label,
	const uint8_t *seed, size_t seedlen,
	const uint8_t *more, size_t morelen,
	size_t outlen, uint8_t *out)
{
	HMAC_CTX inited_hmac_ctx;
	HMAC_CTX hmac_ctx;
	uint8_t A[DIGEST_MAX_SIZE];
	uint8_t hmac[DIGEST_MAX_SIZE];
	size_t len;
	size_t hmaclen;

	if (!digest || !secret || !secretlen || !label || !seed || !seedlen
		|| (!more && morelen) || !outlen || !out) {
		error_print();
		return -1;
	}
	if (digest->digest_size > sizeof(hmac) || !digest->digest_size) {
		error_print();
		return -1;
	}
	hmaclen = digest->digest_size;

	hmac_init(&inited_hmac_ctx, digest, secret, secretlen);

	memcpy(&hmac_ctx, &inited_hmac_ctx, sizeof(HMAC_CTX));
	hmac_update(&hmac_ctx, (uint8_t *)label, strlen(label));
	hmac_update(&hmac_ctx, seed, seedlen);
	hmac_update(&hmac_ctx, more, morelen);
	hmac_finish(&hmac_ctx, A, &len);

	memcpy(&hmac_ctx, &inited_hmac_ctx, sizeof(HMAC_CTX));
	hmac_update(&hmac_ctx, A, hmaclen);
	hmac_update(&hmac_ctx, (uint8_t *)label, strlen(label));
	hmac_update(&hmac_ctx, seed, seedlen);
	hmac_update(&hmac_ctx, more, morelen);
	hmac_finish(&hmac_ctx, hmac, &len);

	len = outlen < hmaclen ? outlen : hmaclen;
	memcpy(out, hmac, len);
	out += len;
	outlen -= len;

	while (outlen) {
		memcpy(&hmac_ctx, &inited_hmac_ctx, sizeof(HMAC_CTX));
		hmac_update(&hmac_ctx, A, hmaclen);
		hmac_finish(&hmac_ctx, A, &len);

		memcpy(&hmac_ctx, &inited_hmac_ctx, sizeof(HMAC_CTX));
		hmac_update(&hmac_ctx, A, hmaclen);
		hmac_update(&hmac_ctx, (uint8_t *)label, strlen(label));
		hmac_update(&hmac_ctx, seed, seedlen);
		hmac_update(&hmac_ctx, more, morelen);
		hmac_finish(&hmac_ctx, hmac, &len);

		len = outlen < hmaclen ? outlen : hmaclen;
		memcpy(out, hmac, len);
		out += len;
		outlen -= len;
	}
	return 1;
}

int tls_update_transcript(TLS_CONNECT *conn, const uint8_t *record)
{
	size_t recordlen;

	if (!conn) {
		error_print();
		return -1;
	}
	if (record == conn->record) {
		recordlen = conn->recordlen;
	} else if (record == conn->plain_record) {
		recordlen = conn->plain_recordlen;
	} else {
		error_print();
		return -1;
	}
	if (recordlen < 5 || recordlen > TLS_MAX_PLAINTEXT_SIZE) {
		error_print();
		return -1;
	}
	if (conn->transcript_len + recordlen > sizeof(conn->transcript)) {
		error_print();
		return -1;
	}
	memcpy(conn->transcript + conn->transcript_len, record + 5, recordlen - 5);
	conn->transcript_len += recordlen - 5;
	return 1;
}

int tls_compute_verify_data(const DIGEST *digest, const uint8_t master_secret[48],
	const char *label, const DIGEST_CTX *dgst_ctx, uint8_t verify_data[12])
{
	const size_t master_secret_len = 48;
	const size_t verify_data_len = 12;
	DIGEST_CTX tmp_ctx;
	uint8_t dgst[DIGEST_MAX_SIZE];
	size_t dgstlen;

	if (!digest || !master_secret || !label || !dgst_ctx || !verify_data) {
		error_print();
		return -1;
	}
	if (strcmp(label, "client finished") && strcmp(label, "server finished")) {
		error_print();
		return -1;
	}

	tmp_ctx = *dgst_ctx;

	if (digest_finish(&tmp_ctx, dgst, &dgstlen) != 1) {
		error_print();
		return -1;
	}
	if (tls_prf(digest, master_secret, master_secret_len,
		label, dgst, dgstlen, NULL, 0,
		verify_data_len, verify_data) != 1) {
		error_print();
		return -1;
	}
	return 1;
}




int tls_derive_pre_master_secret(TLS_CONNECT *conn)
{
	if (!conn || conn->peer_key_exchange_len != 65) {
		error_print();
		return -1;
	}
	if (x509_key_exchange(&conn->key_exchanges[0], conn->peer_key_exchange,
		conn->peer_key_exchange_len, conn->pre_master_secret, &conn->pre_master_secret_len) != 1) {
		error_print();
		return -1;
	}
	if (conn->pre_master_secret_len != 32) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_derive_master_secret(TLS_CONNECT *conn)
{
	if (!conn || !conn->digest) {
		error_print();
		return -1;
	}
	switch (conn->protocol) {
	case TLS_protocol_tlcp:
	 	if (conn->pre_master_secret_len != 48) {
			error_print();
			return -1;
		}
		break;
	case TLS_protocol_tls12:
		if (conn->pre_master_secret_len != 32) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}
	if (tls_prf(conn->digest, conn->pre_master_secret, conn->pre_master_secret_len,
		"master secret",
		conn->client_random, 32,
		conn->server_random, 32,
		48, conn->master_secret) != 1) {
		error_print();
		return -1;
	}
	if (conn->verbose == 5) {
		format_bytes(stderr, 0, 0, "master_secret", conn->master_secret, 48);
	}
	return 1;
}

int tls_derive_key_block(TLS_CONNECT *conn)
{
	if (!conn || !conn->cipher || !conn->digest) {
		error_print();
		return -1;
	}

	switch (conn->cipher_suite) {
	case TLS_cipher_ecc_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
		conn->key_block_len = (conn->cipher->key_size + conn->digest->digest_size) * 2;
		assert(conn->key_block_len == 96);
		break;
	case TLS_cipher_ecc_sm4_gcm_sm3:
	case TLS_cipher_ecdhe_sm4_gcm_sm3:
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_gcm_sha256:
		conn->key_block_len = (conn->cipher->key_size + 4) * 2;
		assert(conn->key_block_len == 40);
		break;
	default:
		error_print();
		return -1;
	}

	if (tls_prf(conn->digest, conn->master_secret, 48, "key expansion",
		conn->server_random, 32,
		conn->client_random, 32,
		conn->key_block_len, conn->key_block) != 1) {
		error_print();
		return -1;
	}

	if (conn->verbose == 5) {
		format_bytes(stderr, 0, 0, "key_blocks", conn->key_block, conn->key_block_len);
	}
	return 1;
}

int tls_init_application_keys(TLS_CONNECT *conn)
{
	size_t keylen;

	if (!conn || !conn->cipher || !conn->digest || !conn->key_block_len) {
		error_print();
		return -1;
	}
	keylen = conn->cipher->key_size;

	switch (conn->cipher_suite) {
	case TLS_cipher_ecc_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
		{
			size_t dgstlen = conn->digest->digest_size;

			if (hmac_init(&conn->client_write_mac_ctx, conn->digest,
				conn->key_block, dgstlen) != 1
				|| hmac_init(&conn->server_write_mac_ctx, conn->digest,
				conn->key_block + dgstlen, dgstlen) != 1) {
				error_print();
				return -1;
			}
			if (conn->is_client) {
				if (block_cipher_set_encrypt_key(&conn->client_write_key, conn->cipher,
					conn->key_block + dgstlen * 2) != 1
					|| block_cipher_set_decrypt_key(&conn->server_write_key, conn->cipher,
					conn->key_block + dgstlen * 2 + keylen) != 1) {
					error_print();
					return -1;
				}
			} else {
				if (block_cipher_set_decrypt_key(&conn->client_write_key, conn->cipher,
					conn->key_block + dgstlen * 2) != 1
					|| block_cipher_set_encrypt_key(&conn->server_write_key, conn->cipher,
					conn->key_block + dgstlen * 2 + keylen) != 1) {
					error_print();
					return -1;
				}
			}
			if (conn->verbose >= 5) {
				format_bytes(stderr, 0, 0, "client_write_mac_key", conn->key_block, dgstlen);
				format_bytes(stderr, 0, 0, "server_write_mac_key", conn->key_block + dgstlen, dgstlen);
				format_bytes(stderr, 0, 0, "client_write_key", conn->key_block + dgstlen * 2, keylen);
				format_bytes(stderr, 0, 0, "server_write_key", conn->key_block + dgstlen * 2 + keylen, keylen);
			}
		}
		break;

	case TLS_cipher_ecc_sm4_gcm_sm3:
	case TLS_cipher_ecdhe_sm4_gcm_sm3:
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_gcm_sha256:
		if (block_cipher_set_encrypt_key(&conn->client_write_key, conn->cipher, conn->key_block) != 1
			|| block_cipher_set_encrypt_key(&conn->server_write_key, conn->cipher, conn->key_block + keylen) != 1) {
			error_print();
			return -1;
		}
		memset(conn->client_write_iv, 0, sizeof(conn->client_write_iv));
		memset(conn->server_write_iv, 0, sizeof(conn->server_write_iv));
		memcpy(conn->client_write_iv, conn->key_block + keylen * 2, 4);
		memcpy(conn->server_write_iv, conn->key_block + keylen * 2 + 4, 4);
		if (conn->verbose >= 5) {
			format_bytes(stderr, 0, 0, "client_write_key", conn->key_block, keylen);
			format_bytes(stderr, 0, 0, "server_write_key", conn->key_block + keylen, keylen);
			format_bytes(stderr, 0, 0, "client_write_iv", conn->key_block + keylen * 2, 4);
			format_bytes(stderr, 0, 0, "server_write_iv", conn->key_block + keylen * 2 + 4, 4);
		}
		break;

	default:
		error_print();
		return -1;
	}

	tls_seq_num_reset(conn->client_seq_num);
	tls_seq_num_reset(conn->server_seq_num);
	return 1;
}


int tls_client_verify_init(TLS_CLIENT_VERIFY_CTX *ctx)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	memset(ctx, 0, sizeof(TLS_CLIENT_VERIFY_CTX));
	return 1;
}

// FIXME: remove malloc!				
int tls_client_verify_update(TLS_CLIENT_VERIFY_CTX *ctx, const uint8_t *handshake, size_t handshake_len)
{
	uint8_t *buf;
	if (!ctx || !handshake || !handshake_len) {
		error_print();
		return -1;
	}
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
	SM2_VERIFY_CTX verify_ctx;
	int i;

	if (!ctx || !sig || !siglen || !public_key) {
		error_print();
		return -1;
	}

	if (ctx->index != 8) {
		error_print();
		return -1;
	}
	// 这里的主要困难是，SM2的签名验证需要以Z作为输入，但是在没有拿到客户端的公钥之前，无法启动验证
	if (sm2_verify_init(&verify_ctx, public_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; i < 8; i++) {
		if (sm2_verify_update(&verify_ctx, ctx->handshake[i], ctx->handshake_len[i]) != 1) {
			error_print();
			return -1;
		}
	}
	if ((ret = sm2_verify_finish(&verify_ctx, sig, siglen)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

void tls_client_verify_cleanup(TLS_CLIENT_VERIFY_CTX *ctx)
{
	if (ctx) {
		int i;
		for (i = 0; i< ctx->index; i++) {
			if (ctx->handshake[i]) {
				free(ctx->handshake[i]);
				ctx->handshake[i] = NULL;
				ctx->handshake_len[i] = 0;
			}
		}
	}
}









// 这个函数不对啊，应该以服务器优先来选择参数
int tls_cipher_suites_select(const uint8_t *client_ciphers, size_t client_ciphers_len,
	const int *server_ciphers, size_t server_ciphers_cnt,
	int *selected_cipher)
{
	if (!client_ciphers || !client_ciphers_len
		|| !server_ciphers || !server_ciphers_cnt || !selected_cipher) {
		error_print();
		return -1;
	}
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
	error_print();
	return -1;
}

int tls_record_encrypt(int cipher_suite,
	const HMAC_CTX *hmac_ctx, const BLOCK_CIPHER_KEY *key, const uint8_t fixed_iv[4],
	const uint8_t seq_num[8], const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	switch (cipher_suite) {
	case TLS_cipher_ecc_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
		if (tls_cbc_encrypt(hmac_ctx, key, seq_num, in,
			in + 5, inlen - 5,
			out + 5, outlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case TLS_cipher_ecc_sm4_gcm_sm3:
	case TLS_cipher_ecdhe_sm4_gcm_sm3:
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_gcm_sha256:
		if (tls_gcm_encrypt(key, fixed_iv, seq_num, in,
			in + 5, inlen - 5,
			out + 5, outlen) != 1) {
			error_print();
			return -1;
		}
		break;
#ifdef ENABLE_AES_CCM
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_ccm:
		if (tls_ccm_encrypt(key, fixed_iv, seq_num, in,
			in + 5, inlen - 5,
			out + 5, outlen) != 1) {
			error_print();
			return -1;
		}
		break;
#endif
	default:
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

int tls_record_decrypt(int cipher_suite, const HMAC_CTX *hmac_ctx,
	const BLOCK_CIPHER_KEY *key, const uint8_t fixed_iv[4],
	const uint8_t seq_num[8], const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	switch (cipher_suite) {
	case TLS_cipher_ecc_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
		if (tls_cbc_decrypt(hmac_ctx, key, seq_num, in,
			in + 5, inlen - 5,
			out + 5, outlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case TLS_cipher_ecc_sm4_gcm_sm3:
	case TLS_cipher_ecdhe_sm4_gcm_sm3:
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_gcm_sha256:
		if (tls_gcm_decrypt(key, fixed_iv, seq_num, in,
			in + 5, inlen - 5,
			out + 5, outlen) != 1) {
			error_print();
			return -1;
		}
		break;
#ifdef ENABLE_AES_CCM
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_ccm:
		if (tls_ccm_decrypt(key, fixed_iv, seq_num, in,
			in + 5, inlen - 5,
			out + 5, outlen) != 1) {
			error_print();
			return -1;
		}
		break;
#endif
	default:
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




int tls_record_set_handshake(uint8_t *record, size_t *recordlen,
	int type, const uint8_t *data, size_t datalen)
{
	size_t handshakelen;

	if (!record || !recordlen) {
		error_print();
		return -1;
	}
	if (datalen > TLS_MAX_PLAINTEXT_SIZE - TLS_HANDSHAKE_HEADER_SIZE) {
		error_print();
		return -1;
	}
	if (!tls_protocol_name(tls_record_protocol(record))) {
		error_print();
		return -1;
	}
	if (!tls_handshake_type_name(type)) {
		error_print();
		return -1;
	}
	handshakelen = TLS_HANDSHAKE_HEADER_SIZE + datalen;
	record[0] = TLS_record_handshake;
	record[3] = (uint8_t)(handshakelen >> 8);
	record[4] = (uint8_t)(handshakelen);
	record[5] = (uint8_t)(type);
	record[6] = (uint8_t)(datalen >> 16);
	record[7] = (uint8_t)(datalen >> 8);
	record[8] = (uint8_t)(datalen);
	if (data && datalen) {
		memcpy(tls_handshake_data(tls_record_data(record)), data, datalen);
	}
	*recordlen = TLS_RECORD_HEADER_SIZE + handshakelen;
	return 1;
}

int tls_record_set_handshake_header(uint8_t *record, size_t *recordlen,
	int type, int length)
{
	if (tls_record_set_handshake(record, recordlen, type, NULL, length) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_record_get_handshake(const uint8_t *record,
	int *type, const uint8_t **data, size_t *datalen)
{
	const uint8_t *handshake;
	size_t handshake_len;
	uint24_t handshake_datalen;

	if (!record || !type || !data || !datalen) {
		error_print();
		return -1;
	}
	if (!tls_protocol_name(tls_record_protocol(record))) {
		error_print();
		return -1;
	}
	if (tls_record_type(record) != TLS_record_handshake) {
		error_print();
		return -1;
	}
	handshake = tls_record_data(record);
	handshake_len = tls_record_data_length(record);

	if (handshake_len < TLS_HANDSHAKE_HEADER_SIZE) {
		error_print();
		return -1;
	}
	if (handshake_len > TLS_MAX_PLAINTEXT_SIZE) {
		// TODO: only valid when max_fragment_length is set
		error_print();
		return -1;
	}

	if (!tls_handshake_type_name(handshake[0])) {
		error_print();
		return -1;
	}
	*type = handshake[0];

	handshake++;
	handshake_len--;
	if (tls_uint24_from_bytes(&handshake_datalen, &handshake, &handshake_len) != 1) {
		error_print();
		return -1;
	}
	if (handshake_len != handshake_datalen) {
		error_print();
		return -1;
	}
	*data = handshake;
	*datalen = handshake_datalen;

	if (*datalen == 0) {
		*data = NULL;
	}
	return 1;
}

int tls_record_set_handshake_client_hello(uint8_t *record, size_t *recordlen,
	int protocol, const uint8_t random[32],
	const uint8_t *session_id, size_t session_id_len,
	const int *cipher_suites, size_t cipher_suites_count,
	const uint8_t *exts, size_t exts_len)
{
	uint8_t type = TLS_handshake_client_hello;
	uint8_t *p;
	size_t len;

	if (!record || !recordlen || !random || !cipher_suites || !cipher_suites_count) {
		error_print();
		return -1;
	}
	if (session_id) {
		if (!session_id_len
			|| session_id_len < TLS_MAX_SESSION_ID_SIZE
			|| session_id_len > TLS_MAX_SESSION_ID_SIZE) {
			error_print();
			return -1;
		}
	}
	if (cipher_suites_count > TLS_MAX_CIPHER_SUITES_COUNT) {
		error_print();
		return -1;
	}
	if (exts && !exts_len) {
		error_print();
		return -1;
	}


	p = tls_handshake_data(tls_record_data(record));
	len = 0;

	if (!tls_protocol_name(protocol)) {
		error_print();
		return -1;
	}
	tls_uint16_to_bytes((uint16_t)protocol, &p, &len);
	tls_array_to_bytes(random, 32, &p, &len);
	tls_uint8array_to_bytes(session_id, session_id_len, &p, &len);
	tls_uint16_to_bytes((uint16_t)(cipher_suites_count * 2), &p, &len);
	while (cipher_suites_count--) {
		if (!tls_cipher_suite_name(*cipher_suites)) {
			error_print();
			return -1;
		}
		tls_uint16_to_bytes((uint16_t)*cipher_suites, &p, &len);
		cipher_suites++;
	}
	tls_uint8_to_bytes(1, &p, &len);
	tls_uint8_to_bytes((uint8_t)TLS_compression_null, &p, &len);
	if (exts) {
		size_t tmp_len = len;
		if (protocol != TLS_protocol_tlcp && protocol < TLS_protocol_tls12) {
			error_print();
			return -1;
		}
		tls_uint16array_to_bytes(exts, exts_len, NULL, &tmp_len);
		if (tmp_len > TLS_MAX_HANDSHAKE_DATA_SIZE) {
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
	int *protocol, const uint8_t **random,
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

	if (!record || !protocol || !random
		|| !session_id || !session_id_len
		|| !cipher_suites || !cipher_suites_len
		|| !exts || !exts_len) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_client_hello) {
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

	if (!tls_protocol_name(ver)) {
		error_print();
		return -1;
	}
	*protocol = ver;

	if (*session_id) {
		if (*session_id_len == 0
			|| *session_id_len < TLS_MIN_SESSION_ID_SIZE
			|| *session_id_len > TLS_MAX_SESSION_ID_SIZE) {
			error_print();
			return -1;
		}
	}

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
		if (*exts == NULL) {
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

int tls_record_set_handshake_server_hello(uint8_t *record, size_t *recordlen,
	int protocol, const uint8_t random[32],
	const uint8_t *session_id, size_t session_id_len, int cipher_suite,
	const uint8_t *exts, size_t exts_len)
{
	uint8_t type = TLS_handshake_server_hello;
	uint8_t *p;
	size_t len;

	if (!record || !recordlen || !random) {
		error_print();
		return -1;
	}
	if (session_id) {
		if (session_id_len > TLS_MAX_SESSION_ID_SIZE) {
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
		if (protocol != TLS_protocol_tlcp && protocol < TLS_protocol_tls12) {
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
	int *protocol, const uint8_t **random, const uint8_t **session_id, size_t *session_id_len,
	int *cipher_suite, const uint8_t **exts, size_t *exts_len)
{
	int type;
	const uint8_t *p;
	size_t len;
	uint16_t ver;
	uint16_t cipher;
	uint8_t comp_meth;

	if (!record || !protocol || !random || !session_id || !session_id_len
		|| !cipher_suite || !exts || !exts_len) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_server_hello) {
		error_print();
		return 0;
	}
	if (tls_uint16_from_bytes(&ver, &p, &len) != 1
		|| tls_array_from_bytes(random, 32, &p, &len) != 1
		|| tls_uint8array_from_bytes(session_id, session_id_len, &p, &len) != 1
		|| tls_uint16_from_bytes(&cipher, &p, &len) != 1
		|| tls_uint8_from_bytes(&comp_meth, &p, &len) != 1) {
		error_print();
		return -1;
	}

	if (!tls_protocol_name(ver)) {
		error_print();
		return -1;
	}
	if (ver < tls_record_protocol(record)) {
		error_print();
		return -1;
	}
	*protocol = ver;

	if (*session_id) {
		if (*session_id == 0
			|| *session_id_len < TLS_MIN_SESSION_ID_SIZE
			|| *session_id_len > TLS_MAX_SESSION_ID_SIZE) {
			error_print();
			return -1;
		}
	}

	if (!tls_cipher_suite_name(cipher)) {
		error_print();
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
		// ClientHello Extensions in RFC 5246: Extension extensions<0..2^16-1>;
		// ClientHello Extensions in RFC 8446: Extension extensions<8..2^16-1>;
		// so exts == NULL is allowed
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
	uint8_t *data;
	size_t datalen;
	uint8_t *p;
	size_t len;

	if (!record || !recordlen || !certs || !certslen) {
		error_print();
		return -1;
	}
	data = tls_handshake_data(tls_record_data(record));
	p = data + tls_uint24_size();
	datalen = tls_uint24_size();
	len = 0;

	while (certslen) {
		const uint8_t *cert;
		size_t certlen;

		if (x509_cert_from_der(&cert, &certlen, &certs, &certslen) != 1) {
			error_print();
			return -1;
		}
		tls_uint24array_to_bytes(cert, certlen, NULL, &datalen);
		if (datalen > TLS_MAX_HANDSHAKE_DATA_SIZE) {
			error_print();
			return -1;
		}
		tls_uint24array_to_bytes(cert, certlen, &p, &len);
	}
	tls_uint24_to_bytes((uint24_t)len, &data, &len);
	tls_record_set_handshake(record, recordlen, type, NULL, datalen);
	return 1;
}

// FIXME: 这个函数语义应该修改，只返回 uint24array[] 的证书数组，然后整个库内部都用这个结构来存储证书链、证书数组
// 目前直接用DER格式拼接到一起的设计不好。这个函数容易发生溢出
int tls_record_get_handshake_certificate(const uint8_t *record, uint8_t *certs, size_t *certslen)
{
	int type;
	const uint8_t *data;
	size_t datalen;
	const uint8_t *cp;
	size_t len;

	if (tls_record_get_handshake(record, &type, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_certificate) {
		error_print();
		return -1;
	}
	if (tls_uint24array_from_bytes(&cp, &len, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	if (len > TLS_MAX_CERTIFICATES_SIZE) {
		error_print();
		return -1;
	}

	*certslen = 0;
	while (len) {
		const uint8_t *a;
		size_t alen;
		const uint8_t *cert;
		size_t certlen;

		if (tls_uint24array_from_bytes(&a, &alen, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (x509_cert_from_der(&cert, &certlen, &a, &alen) != 1
			|| asn1_length_is_zero(alen) != 1
			|| x509_cert_to_der(cert, certlen, &certs, certslen) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int tls_server_ecdh_params_to_bytes(const X509_KEY *public_key, uint8_t **out, size_t *outlen)
{
	int named_curve;
	uint8_t point[65];
	uint8_t *point_ptr = point;
	size_t point_len = 0;

	if (!public_key || !outlen) {
		error_print();
		return -1;
	}
	if (public_key->algor != OID_ec_public_key) {
		error_print();
		return -1;
	}
	if (!(named_curve = tls_named_curve_from_oid(public_key->algor_param))) {
		error_print();
		return -1;
	}
	if (x509_public_key_to_bytes(public_key, &point_ptr, &point_len) != 1) {
		error_print();
		return -1;
	}
	if (point_len > sizeof(point)) {
		error_print();
		return -1;
	}
	tls_uint8_to_bytes(TLS_curve_type_named_curve, out, outlen);
	tls_uint16_to_bytes((uint16_t)named_curve, out, outlen);
	tls_uint8array_to_bytes(point, point_len, out, outlen);
	return 1;
}

int tls_server_ecdh_params_from_bytes(int *key_exchange_group,
	const uint8_t **key_exchange, size_t *key_exchange_len,
	const uint8_t **in, size_t *inlen)
{
	uint8_t curve_type;
	uint16_t named_curve;
	uint16_t alg;

	if (tls_uint8_from_bytes(&curve_type, in, inlen) != 1
		|| tls_uint16_from_bytes(&named_curve, in, inlen) != 1
		|| tls_uint8array_from_bytes(key_exchange, key_exchange_len, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (curve_type != TLS_curve_type_named_curve) {
		error_print();
		return -1;
	}
	if (!tls_named_curve_name(named_curve)) {
		error_print();
		return -1;
	}
	if (*key_exchange == NULL) {
		error_print();
		return -1;
	}

	*key_exchange_group = named_curve;
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
		|| type != TLS_handshake_server_hello_done) {
		error_print();
		return -1;
	}
	if (p != NULL || len != 0) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_record_set_handshake_certificate_verify(uint8_t *record, size_t *recordlen,
	const uint8_t *sig, size_t siglen)
{
	int type = TLS_handshake_certificate_verify;
	uint8_t *p;
	size_t len = 0;

	if (!record || !recordlen || !sig || !siglen) {
		error_print();
		return -1;
	}
	if (siglen > TLS_MAX_SIGNATURE_SIZE) {
		error_print();
		return -1;
	}
	p = tls_handshake_data(tls_record_data(record));
	tls_uint16array_to_bytes(sig, siglen, &p, &len);
	tls_record_set_handshake(record, recordlen, type, NULL, len);
	return 1;
}

int tls_record_get_handshake_certificate_verify(const uint8_t *record,
	const uint8_t **sig, size_t *siglen)
{
	int type;
	const uint8_t *cp;
	size_t len;

	if (!record || !sig || !siglen) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_certificate_verify) {
		error_print();
		return -1;
	}
	if (tls_uint16array_from_bytes(sig, siglen, &cp, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_record_set_handshake_finished(uint8_t *record, size_t *recordlen,
	const uint8_t *verify_data, size_t verify_data_len)
{
	int type = TLS_handshake_finished;

	if (!record || !recordlen || !verify_data || !verify_data_len) {
		error_print();
		return -1;
	}
	if (verify_data_len != 12 && verify_data_len != 32) {
		error_print();
		return -1;
	}
	tls_record_set_handshake(record, recordlen, type, verify_data, verify_data_len);
	return 1;
}

int tls_record_get_handshake_finished(const uint8_t *record, const uint8_t **verify_data, size_t *verify_data_len)
{
	int type;

	if (!record || !verify_data || !verify_data_len) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, verify_data, verify_data_len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_finished) {
		error_print();
		return -1;
	}
	if (*verify_data == NULL || *verify_data_len == 0) {
		error_print();
		return -1;
	}
	if (*verify_data_len != 12) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_record_set_alert(uint8_t *record, size_t *recordlen,
	int alert_level,
	int alert_description)
{
	if (!record || !recordlen) {
		error_print();
		return -1;
	}
	if (!tls_alert_level_name(alert_level)) {
		error_print();
		return -1;
	}
	if (!tls_alert_description_text(alert_description)) {
		error_print();
		return -1;
	}
	record[0] = TLS_record_alert;
	//record[1] = protocol.major should be set by others
	//record[2] = protocol.minor should be set by others
	record[3] = 0; // length
	record[4] = 2; // length
	record[5] = (uint8_t)alert_level;
	record[6] = (uint8_t)alert_description;
	*recordlen = TLS_RECORD_HEADER_SIZE + 2;
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
	if (tls_record_type(record) != TLS_record_alert) {
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
	*recordlen = TLS_RECORD_HEADER_SIZE + 1;
	return 1;
}

int tls_record_get_change_cipher_spec(const uint8_t *record)
{
	if (!record) {
		error_print();
		return -1;
	}
	if (tls_record_type(record) != TLS_record_change_cipher_spec) {
		error_print();
		return -1;
	}
	if (record[3] != 0 || record[4] != 1) {
		error_print();
		return -1;
	}
	if (record[5] != TLS_change_cipher_spec) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_record_set_application_data(uint8_t *record, size_t *recordlen,
	const uint8_t *data, size_t datalen)
{
	if (!record || !recordlen || !data || !datalen) {
		error_print();
		return -1;
	}
	record[0] = TLS_record_application_data;
	record[3] = (datalen >> 8) & 0xff;
	record[4] = datalen & 0xff;
	memcpy(tls_record_data(record), data, datalen);
	*recordlen = TLS_RECORD_HEADER_SIZE + datalen;
	return 1;
}

int tls_record_get_application_data(uint8_t *record,
	const uint8_t **data, size_t *datalen)
{
	if (!record || !data || !datalen) {
		error_print();
		return -1;
	}
	if (tls_record_type(record) != TLS_record_application_data) {
		error_print();
		return -1;
	}
	*datalen = ((size_t)record[3] << 8) | record[4];
	*data = *datalen ? record + TLS_RECORD_HEADER_SIZE : 0;
	return 1;
}

int tls_type_is_in_list(int type, const int *list, size_t list_count)
{
	size_t i;
	for (i = 0; i < list_count; i++) {
		if (type == list[i]) {
			return 1;
		}
	}
	return 0;
}


// 这个函数用于send_alert，send_alert的时候不用conn内部的record吗？
int tls_record_send(const uint8_t *record, size_t recordlen, tls_socket_t sock)
{
	tls_ret_t n;

	if (!record) {
		error_print();
		return -1;
	}
	if (recordlen < TLS_RECORD_HEADER_SIZE) {
		error_print();
		return -1;
	}
	if (tls_record_length(record) != recordlen) {
		error_print();
		return -1;
	}

	while (recordlen) {
		if ((n = tls_socket_send(sock, record, recordlen, 0)) > 0) {
			record += n;
			recordlen -= n;

		} else if (n == 0) {
			error_puts("TCP connection closed");
			return TLS_ERROR_TCP_CLOSED;
		} else {
			int err = tls_socket_get_error();
			tls_socket_err_t type = tls_socket_get_error_type(err, 0);
			if (type == TLS_SOCKET_ERR_WANT_WRITE) {
				tls_socket_wait();
			} else if (type == TLS_SOCKET_ERR_INTERRUPTED) {
				continue;
			} else {
				error_print();
				return TLS_ERROR_SYSCALL;
			}
		}
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
			int err = tls_socket_get_error();
			tls_socket_err_t type = tls_socket_get_error_type(err, 0);
			if (type == TLS_SOCKET_ERR_WANT_WRITE) {
				return TLS_ERROR_SEND_AGAIN;
			} else if (type == TLS_SOCKET_ERR_INTERRUPTED) {
				continue;
			} else {
				error_print();
				return TLS_ERROR_SYSCALL;
			}
		} else if (n == 0) {
			return TLS_ERROR_TCP_CLOSED;
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
				int err = tls_socket_get_error();
				tls_socket_err_t type = tls_socket_get_error_type(err, 1);
				if (type == TLS_SOCKET_ERR_WANT_READ) {
					return TLS_ERROR_RECV_AGAIN;
				} else if (type == TLS_SOCKET_ERR_INTERRUPTED) {
					continue;
				} else {
					error_print();
					// TODO: check the usage of OpenSSL SSL_ERR_SYSCALL
					// if applications such as Nginx, HTTPD do not use this error, we just return -1
					return TLS_ERROR_SYSCALL;
				}
			} else if (n == 0) {
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
			int err = tls_socket_get_error();
			tls_socket_err_t type = tls_socket_get_error_type(err, 1);
			if (type == TLS_SOCKET_ERR_WANT_READ) {
				return TLS_ERROR_RECV_AGAIN;
			} else if (type == TLS_SOCKET_ERR_INTERRUPTED) {
				continue;
			} else {
				error_print();
				return TLS_ERROR_SYSCALL;
			}
		} else if (n == 0) {
			return TLS_ERROR_TCP_CLOSED;
		}
		conn->record_offset += n;
		left -= n;

	}

	conn->recordlen = conn->record_offset;


	// 应该判断是否为Alert这种异常状况

	return 1;
}



int tls_send_alert(TLS_CONNECT *conn, int alert)
{
	uint8_t record[5 + 2];
	size_t recordlen;

	if (!conn) {
		error_print();
		return -1;
	}

	tls_record_set_protocol(record, conn->protocol == TLS_protocol_tls13 ? TLS_protocol_tls12 : conn->protocol);
	tls_record_set_alert(record, &recordlen, TLS_alert_level_fatal, alert);

	if (tls_record_send(record, sizeof(record), conn->sock) != 1) {
		error_print();
		return -1;
	}
	if (conn->verbose) {
		tls_record_print(stderr, 0, 0, conn->cipher_suite, record, sizeof(record));
	}
	return 1;
}

int tls_alert_level(int alert)
{
	switch (alert) {
	case TLS_alert_unexpected_message:
	case TLS_alert_bad_record_mac:
	case TLS_alert_record_overflow:
	case TLS_alert_decompression_failure:
	case TLS_alert_handshake_failure:
	case TLS_alert_illegal_parameter:
	case TLS_alert_unknown_ca:
	case TLS_alert_access_denied:
	case TLS_alert_decode_error:
	case TLS_alert_decrypt_error:
	case TLS_alert_protocol_version:
	case TLS_alert_insufficient_security:
	case TLS_alert_internal_error:
	case TLS_alert_unsupported_extension:
		return TLS_alert_level_fatal;
	case TLS_alert_user_canceled:
	case TLS_alert_no_renegotiation:
		return TLS_alert_level_warning;
	}
	return TLS_alert_level_undefined;
}

int tls_send_warning(TLS_CONNECT *conn, int alert)
{
	uint8_t record[5 + 2];
	size_t recordlen;

	if (!conn) {
		error_print();
		return -1;
	}
	if (tls_alert_level(alert) == TLS_alert_level_fatal) {
		error_print();
		return -1;
	}
	tls_record_set_protocol(record, conn->protocol == TLS_protocol_tls13 ? TLS_protocol_tls12 : conn->protocol);
	tls_record_set_alert(record, &recordlen, TLS_alert_level_warning, alert);

	if (tls_record_send(record, sizeof(record), conn->sock) != 1) {
		error_print();
		return -1;
	}
	if (conn->verbose) {
		tls_record_print(stderr, 0, 0, conn->cipher_suite, record, sizeof(record));
	}
	return 1;
}

int tls_decrypt_recv(TLS_CONNECT *conn)
{
	int ret;
	const HMAC_CTX *hmac_ctx;
	const BLOCK_CIPHER_KEY *dec_key;
	const uint8_t *fixed_iv;
	uint8_t *seq_num;

	uint8_t *record = conn->record;
	size_t recordlen;

	if (conn->is_client) {
		hmac_ctx = &conn->server_write_mac_ctx;
		dec_key = &conn->server_write_key;
		fixed_iv = conn->server_write_iv;
		seq_num = conn->server_seq_num;
	} else {
		hmac_ctx = &conn->client_write_mac_ctx;
		dec_key = &conn->client_write_key;
		fixed_iv = conn->client_write_iv;
		seq_num = conn->client_seq_num;
	}

	if(conn->verbose) tls_trace("recv Encrypted Record\n");
	if (conn->send_state) {
		return TLS_ERROR_SEND_AGAIN;
	}
	conn->recv_state = TLS_state_recv_record_header;
	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			conn->recv_state = 0;
			tls_clean_record(conn);
			error_print();
		}
		return ret;
	}
	conn->recv_state = 0;
	recordlen = conn->recordlen;
	if (conn->verbose) {
		if (conn->protocol == TLS_protocol_tls12) {
			tls_encrypted_record_print(stderr, record, recordlen, 0, 0);
		} else {
			tls_encrypted_record_trace(stderr, record, recordlen, 0, 0);
		}
	}

	if (conn->protocol == TLS_protocol_tls12) {
		if (tls_record_decrypt(conn->cipher_suite, hmac_ctx, dec_key, fixed_iv, seq_num,
			record, recordlen, conn->databuf, &conn->datalen) != 1) {
			error_print();
			return -1;
		}
	} else if (conn->protocol == TLS_protocol_tlcp) {
		if (tls_record_decrypt(conn->cipher_suite, hmac_ctx, dec_key, fixed_iv, seq_num,
			record, recordlen, conn->databuf, &conn->datalen) != 1) {
			error_print();
			return -1;
		}
	} else {
		if (tls_cbc_decrypt(hmac_ctx, dec_key, seq_num, record,
			record + 5, recordlen - 5,
			conn->databuf + 5, &conn->datalen) != 1) {
			error_print();
			return -1;
		}
		conn->databuf[0] = record[0];
		conn->databuf[1] = record[1];
		conn->databuf[2] = record[2];
		conn->databuf[3] = (uint8_t)(conn->datalen >> 8);
		conn->databuf[4] = (uint8_t)(conn->datalen);
		conn->datalen += 5;
	}
	tls_seq_num_incr(seq_num);

	conn->data = tls_record_data(conn->databuf);
	conn->datalen = tls_record_data_length(conn->databuf);

	if (conn->verbose) {
		tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->databuf, tls_record_length(conn->databuf));
	}

	return 1;
}

int tls_send(TLS_CONNECT *conn, const uint8_t *in, size_t inlen, size_t *sentlen)
{
	if (!conn) {
		error_print();
		return -1;
	}

	switch (conn->protocol) {
	case TLS_protocol_tlcp:
		return tlcp_send(conn, in, inlen, sentlen);
	case TLS_protocol_tls12:
		return tls12_send(conn, in, inlen, sentlen);
	case TLS_protocol_tls13:
		return tls13_send(conn, in, inlen, sentlen);
	default:
		error_print();
		return -1;
	}
}

static int tls12_tlcp_recv(TLS_CONNECT *conn, uint8_t *out, size_t outlen, size_t *recvlen)
{
	if (!conn || !out || !outlen || !recvlen) {
		error_print();
		return -1;
	}

	if (conn->datalen == 0) {
		int ret;
		if ((ret = tls_decrypt_recv(conn)) != 1) {
			if (ret != TLS_ERROR_RECV_AGAIN && ret != TLS_ERROR_SEND_AGAIN) {
				error_print();
			}
			return ret;
		}

		switch (tls_record_type(conn->record)) {
		case TLS_record_application_data:
			tls_clean_record(conn);
			break;
		case TLS_record_change_cipher_spec:
			tls_clean_record(conn);
			error_print();
			return -1;
		case TLS_record_alert:
			{
			// should call tls_process_alert()
			int level;
			int alert;
			tls_record_get_alert(conn->databuf, &level, &alert);
			if (alert == TLS_alert_close_notify) {
				if(conn->verbose) tls_trace("recv Alert.close_notify\n");
				conn->close_notify_received = 1;
				conn->data = NULL;
				conn->datalen = 0;
				tls_clean_record(conn);
				return 0;
			}
			if(conn->verbose) tls_trace("alert received\n");
			conn->data = NULL;
			conn->datalen = 0;
			tls_clean_record(conn);
			return -1;
			}
		default:
			tls_clean_record(conn);
			error_print();
			return -1;
		}
	}

	*recvlen = outlen <= conn->datalen ? outlen : conn->datalen;
	memcpy(out, conn->data, *recvlen);
	conn->data += *recvlen;
	conn->datalen -= *recvlen;

	return 1;
}

int tls_recv(TLS_CONNECT *conn, uint8_t *out, size_t outlen, size_t *recvlen)
{
	if (!conn) {
		error_print();
		return -1;
	}

	switch (conn->protocol) {
	case TLS_protocol_tlcp:
	case TLS_protocol_tls12:
		return tls12_tlcp_recv(conn, out, outlen, recvlen);
	case TLS_protocol_tls13:
		return tls13_recv(conn, out, outlen, recvlen);
	default:
		error_print();
		return -1;
	}
}

static int tls12_send_close_notify(TLS_CONNECT *conn)
{
	int ret;
	const HMAC_CTX *hmac;
	const BLOCK_CIPHER_KEY *key;
	const uint8_t *iv;
	uint8_t *seq_num;

	if (!conn) {
		error_print();
		return -1;
	}

	if (!conn->recordlen) {
		if (conn->is_client) {
			hmac = &conn->client_write_mac_ctx;
			key = &conn->client_write_key;
			iv = conn->client_write_iv;
			seq_num = conn->client_seq_num;
		} else {
			hmac = &conn->server_write_mac_ctx;
			key = &conn->server_write_key;
			iv = conn->server_write_iv;
			seq_num = conn->server_seq_num;
		}

		if(conn->verbose) tls_trace("send Alert.close_notify\n");

		tls_record_set_alert(conn->plain_record, &conn->plain_recordlen,
			TLS_alert_level_warning, TLS_alert_close_notify);

		if (tls_record_encrypt(conn->cipher_suite, hmac, key, iv, seq_num,
			conn->plain_record, conn->plain_recordlen,
			conn->record, &conn->recordlen) != 1) {
			error_print();
			return -1;
		}
		tls_seq_num_incr(seq_num);
		conn->record_offset = 0;
		conn->send_state = TLS_state_send_record;
	}

	ret = tls_send_record(conn);
	if (ret != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	conn->send_state = 0;
	tls_clean_record(conn);
	return 1;
}

static int tls13_send_close_notify(TLS_CONNECT *conn)
{
	int ret;
	const BLOCK_CIPHER_KEY *key;
	const uint8_t *iv;
	uint8_t *seq_num;
	size_t padding_len;

	if (!conn) {
		error_print();
		return -1;
	}

	if (!conn->recordlen) {
		if (conn->is_client) {
			key = &conn->client_write_key;
			iv = conn->client_write_iv;
			seq_num = conn->client_seq_num;
		} else {
			key = &conn->server_write_key;
			iv = conn->server_write_iv;
			seq_num = conn->server_seq_num;
		}

		if(conn->verbose) tls_trace("send Alert.close_notify\n");

		tls_record_set_alert(conn->plain_record, &conn->plain_recordlen,
			TLS_alert_level_warning, TLS_alert_close_notify);
		tls13_padding_len_rand(&padding_len);
		if (tls13_record_encrypt(conn->cipher_suite, key, iv, seq_num, conn->plain_record, conn->plain_recordlen,
			padding_len, conn->record, &conn->recordlen) != 1) {
			error_print();
			return -1;
		}
		tls_seq_num_incr(seq_num);
		conn->record_offset = 0;
		conn->send_state = TLS_state_send_record;
	}

	ret = tls_send_record(conn);
	if (ret != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	conn->send_state = 0;
	tls_clean_record(conn);
	return 1;
}

static int tls_send_close_notify(TLS_CONNECT *conn)
{
	size_t sentlen;
	uint8_t alert[2];

	if (!conn) {
		error_print();
		return -1;
	}

	switch (conn->protocol) {
	case TLS_protocol_tlcp:
	case TLS_protocol_tls12:
		return tls12_send_close_notify(conn);
	case TLS_protocol_tls13:
		return tls13_send_close_notify(conn);
	}
	error_print();
	return -1;
}

int tls_shutdown(TLS_CONNECT *conn)
{
	int ret;
	uint8_t buf[1];
	size_t len;

	if (!conn) {
		error_print();
		return -1;
	}

	if (conn->handshake_state != TLS_state_handshake_over) {
		conn->shutdown_state = TLS_state_shutdown_over;
		return 1;
	}

	if (conn->shutdown_state == TLS_state_shutdown_over) {
		return 1;
	}
	if (!conn->shutdown_state) {
		conn->shutdown_state = TLS_state_shutdown_send_close_notify;
	}

	if (conn->shutdown_state == TLS_state_shutdown_send_close_notify) {
		if ((ret = tls_send_close_notify(conn)) != 1) {
			if (ret == TLS_ERROR_TCP_CLOSED) {
				conn->shutdown_state = TLS_state_shutdown_over;
				return 1;
			}
			return ret;
		}
		if (conn->close_notify_received) {
			conn->shutdown_state = TLS_state_shutdown_over;
			return 1;
		}
		conn->shutdown_state = TLS_state_shutdown_recv_close_notify;
	}

	if (conn->shutdown_state == TLS_state_shutdown_recv_close_notify) {
		if(conn->verbose) tls_trace("recv Alert.close_notify\n");
		for (;;) {
			ret = tls_recv(conn, buf, sizeof(buf), &len);
			if (ret == 1 && len > 0) {
				continue;
			}
			if (ret == 0 || ret == TLS_ERROR_TCP_CLOSED) {
				conn->shutdown_state = TLS_state_shutdown_over;
				return 1;
			}
			if (ret == TLS_ERROR_RECV_AGAIN || ret == TLS_ERROR_SEND_AGAIN) {
				return ret;
			}
			error_print();
			return -1;
		}
	}

	error_print();
	return -1;
}


int tls_ctx_init(TLS_CTX *ctx, int protocol, int is_client)
{
	const int supported_versions[] = {
		TLS_protocol_tls13,
		TLS_protocol_tls12,
		TLS_protocol_tlcp,
	};

	if (!ctx) {
		error_print();
		return -1;
	}
	memset(ctx, 0, sizeof(*ctx));


	// protocol
	switch (protocol) {
	case TLS_protocol_tlcp:
	case TLS_protocol_tls12:
	case TLS_protocol_tls13:
		ctx->protocol = protocol;
		break;
	default:
		error_print();
		return -1;
	}

	ctx->is_client = is_client ? 1 : 0;

	// TLS 1.3 middlebox compatibility
	ctx->accept_change_cipher_spec = 1;


	// supported_versions
	memcpy(ctx->supported_versions, supported_versions, sizeof(supported_versions));
	ctx->supported_versions_cnt = sizeof(supported_versions)/sizeof(supported_versions[0]);

	// 这个参数应该在设置证书的时候再设定
	ctx->verify_depth = 5;


	// 默认就发送一个，因为只要发送key_share，那么至少有一个group
	ctx->key_exchanges_cnt = TLS_DEFAULT_KEY_EXCHANGES_CNT;


	return 1;
}

void tls_ctx_cleanup(TLS_CTX *ctx)
{
	if (ctx) {
		size_t i;

		for (i = 0; i < ctx->x509_keys_cnt; i++) {
			x509_key_cleanup(&ctx->x509_keys[i]);
			x509_key_cleanup(&ctx->enc_keys[i]);
		}
		if (ctx->cacerts) free(ctx->cacerts);
		memset(ctx, 0, sizeof(TLS_CTX));
	}
}

int tls_ctx_set_supported_versions(TLS_CTX *ctx, const int *versions, size_t versions_cnt)
{
	size_t i;

	if (!ctx || !versions || !versions_cnt) {
		error_print();
		return -1;
	}
	if (versions_cnt > sizeof(ctx->supported_versions)/sizeof(ctx->supported_versions[0])) {
		error_print();
		return -1;
	}

	for (i = 0; i < versions_cnt; i++) {
		switch (versions[i]) {
		case TLS_protocol_tls13:
		case TLS_protocol_tls12:
		case TLS_protocol_tlcp:
			break;
		default:
			error_print();
			return -1;
		}
		ctx->supported_versions[i] = versions[i];
	}
	ctx->supported_versions_cnt = versions_cnt;

	return 1;
}

int tls_ctx_set_cipher_suites(TLS_CTX *ctx, const int *cipher_suites, size_t cipher_suites_cnt)
{
	const int *supported_cipher_suites;
	size_t supported_cipher_suites_cnt;
	size_t i;

	if (!ctx || !cipher_suites || !cipher_suites_cnt) {
		error_print();
		return -1;
	}
	if (cipher_suites_cnt > sizeof(ctx->cipher_suites)/sizeof(ctx->cipher_suites[0])) {
		error_print();
		return -1;
	}

	switch (ctx->protocol) {
	case TLS_protocol_tlcp:
		supported_cipher_suites = tlcp_cipher_suites;
		supported_cipher_suites_cnt = tlcp_cipher_suites_cnt;
		break;
	case TLS_protocol_tls12:
		supported_cipher_suites = tls12_cipher_suites;
		supported_cipher_suites_cnt = tls12_cipher_suites_cnt;
		break;
	case TLS_protocol_tls13:
		supported_cipher_suites = tls13_cipher_suites;
		supported_cipher_suites_cnt = tls13_cipher_suites_cnt;
		break;
	default:
		error_print();
		return -1;
	}

	for (i = 0; i < cipher_suites_cnt; i++) {
		if (!tls_type_is_in_list(cipher_suites[i], supported_cipher_suites, supported_cipher_suites_cnt)) {
			error_print();
			return -1;
		}
	}

	memcpy(ctx->cipher_suites, cipher_suites, cipher_suites_cnt * sizeof(cipher_suites[0]));
	ctx->cipher_suites_cnt = cipher_suites_cnt;

	return 1;
}


int tls_ctx_set_verbose(TLS_CTX *ctx, int verbose)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (verbose < 0 || verbose > 5) {
		error_print();
		return -1;
	}
	ctx->verbose = verbose;
	return 1;
}

int tls_ctx_enable_verbose(TLS_CTX *ctx, int enable)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	ctx->verbose = enable ? 1 : 0;
	return 1;
}

int tls_ctx_enable_trusted_ca_keys(TLS_CTX *ctx, int enable)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	ctx->trusted_ca_keys = enable ? 1 : 0;
	return 1;
}

int tls_ctx_enable_certificate_request(TLS_CTX *ctx, int enable)
{
	if (!ctx) {
		error_print();
		return -1;
	}

	if (ctx->is_client) {
		error_print();
		return -1;
	}

	ctx->certificate_request = enable ? 1 : 0;

	return 1;
}

int tls_ctx_set_supported_groups(TLS_CTX *ctx, const int *groups, size_t groups_cnt)
{
	const int *supported_groups;
	size_t supported_groups_cnt;
	size_t i;

	if (!ctx || !groups || !groups_cnt) {
		error_print();
		return -1;
	}
	if (groups_cnt > sizeof(ctx->supported_groups)/sizeof(ctx->supported_groups[0])) {
		error_print();
		return -1;
	}

	switch (ctx->protocol) {
	case TLS_protocol_tlcp:
		supported_groups = tlcp_supported_groups;
		supported_groups_cnt = tlcp_supported_groups_cnt;
		break;
	case TLS_protocol_tls12:
		supported_groups = tls12_supported_groups;
		supported_groups_cnt = tls12_supported_groups_cnt;
		break;
	case TLS_protocol_tls13:
		supported_groups = tls13_supported_groups;
		supported_groups_cnt = tls13_supported_groups_cnt;
		break;
	default:
		error_print();
		return -1;
	}

	for (i = 0; i < groups_cnt; i++) {
		if (!tls_type_is_in_list(groups[i], supported_groups, supported_groups_cnt)) {
			error_print();
			return -1;
		}
	}

	memcpy(ctx->supported_groups, groups, groups_cnt * sizeof(groups[0]));
	ctx->supported_groups_cnt = groups_cnt;

	return 1;
}

int tls_ctx_set_signature_algorithms(TLS_CTX *ctx, const int *sig_algs, size_t sig_algs_cnt)
{
	const int *supported_sig_algs;
	size_t supported_sig_algs_cnt;
	size_t i;

	if (!ctx || !sig_algs || !sig_algs_cnt) {
		error_print();
		return -1;
	}
	if (sig_algs_cnt > sizeof(ctx->signature_algorithms)/sizeof(ctx->signature_algorithms[0])) {
		error_print();
		return -1;
	}

	switch (ctx->protocol) {
	case TLS_protocol_tlcp:
		supported_sig_algs = tlcp_signature_algorithms;
		supported_sig_algs_cnt = tlcp_signature_algorithms_cnt;
		break;
	case TLS_protocol_tls12:
		supported_sig_algs = tls12_signature_algorithms;
		supported_sig_algs_cnt = tls12_signature_algorithms_cnt;
		break;
	case TLS_protocol_tls13:
		supported_sig_algs = tls13_signature_algorithms;
		supported_sig_algs_cnt = tls13_signature_algorithms_cnt;
		break;
	default:
		error_print();
		return -1;
	}

	for (i = 0; i < sig_algs_cnt; i++) {
		if (!tls_type_is_in_list(sig_algs[i], supported_sig_algs, supported_sig_algs_cnt)) {
			error_print();
			return -1;
		}
	}

	memcpy(ctx->signature_algorithms, sig_algs, sig_algs_cnt * sizeof(sig_algs[0]));
	ctx->signature_algorithms_cnt = sig_algs_cnt;

	return 1;
}

int tls_ctx_set_application_layer_protocol_negotiation(TLS_CTX *ctx,
	char *protocols[], size_t protocols_cnt)
{
	size_t i;

	if (!ctx || !protocols || !protocols_cnt) {
		error_print();
		return -1;
	}
	if (protocols_cnt > sizeof(ctx->alpn_protocols)/sizeof(ctx->alpn_protocols[0])) {
		error_print();
		return -1;
	}
	for (i = 0; i < protocols_cnt; i++) {
		size_t protocol_len;

		if (!protocols[i]) {
			error_print();
			return -1;
		}
		protocol_len = strlen(protocols[i]);
		if (protocol_len < 1 || protocol_len > 255) {
			error_print();
			return -1;
		}
		ctx->alpn_protocols[i] = protocols[i];
	}
	ctx->alpn_protocols_cnt = protocols_cnt;
	ctx->application_layer_protocol_negotiation = 1;

	return 1;
}

int tls_ctx_set_key_update_seq_num_limit(TLS_CTX *ctx, size_t max_seq_num)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	ctx->key_update_seq_num_limit = max_seq_num;
	return 1;
}

static int tls_ctx_get_certificate_chain(const TLS_CTX *ctx, size_t idx,
	const uint8_t **cert_chain, size_t *cert_chain_len)
{
	const uint8_t *p;
	size_t len;
	size_t i;

	if (!ctx || !cert_chain || !cert_chain_len || !idx) {
		error_print();
		return -1;
	}

	p = ctx->cert_chains;
	len = ctx->cert_chains_len;
	for (i = 1; i <= idx; i++) {
		if (tls_uint24array_from_bytes(cert_chain, cert_chain_len, &p, &len) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

static int tls_ctx_check(const TLS_CTX *ctx)
{
	const int *supported_cipher_suites = NULL;
	size_t supported_cipher_suites_cnt = 0;
	const int *supported_groups = NULL;
	size_t supported_groups_cnt = 0;
	const int *supported_sig_algs = NULL;
	size_t supported_sig_algs_cnt = 0;
	const uint8_t *cert_chains;
	size_t cert_chains_len;
	size_t cert_chains_cnt = 0;
	size_t i;

	if (!ctx) {
		error_print();
		return -1;
	}

	switch (ctx->protocol) {
	case TLS_protocol_tlcp:
		supported_cipher_suites = tlcp_cipher_suites;
		supported_cipher_suites_cnt = tlcp_cipher_suites_cnt;
		supported_groups = tlcp_supported_groups;
		supported_groups_cnt = tlcp_supported_groups_cnt;
		supported_sig_algs = tlcp_signature_algorithms;
		supported_sig_algs_cnt = tlcp_signature_algorithms_cnt;
		break;
	case TLS_protocol_tls12:
		supported_cipher_suites = tls12_cipher_suites;
		supported_cipher_suites_cnt = tls12_cipher_suites_cnt;
		supported_groups = tls12_supported_groups;
		supported_groups_cnt = tls12_supported_groups_cnt;
		supported_sig_algs = tls12_signature_algorithms;
		supported_sig_algs_cnt = tls12_signature_algorithms_cnt;
		break;
	case TLS_protocol_tls13:
		supported_cipher_suites = tls13_cipher_suites;
		supported_cipher_suites_cnt = tls13_cipher_suites_cnt;
		supported_groups = tls13_supported_groups;
		supported_groups_cnt = tls13_supported_groups_cnt;
		supported_sig_algs = tls13_signature_algorithms;
		supported_sig_algs_cnt = tls13_signature_algorithms_cnt;
		break;
	default:
		error_print();
		return -1;
	}

	if (!ctx->cipher_suites_cnt
		|| ctx->cipher_suites_cnt > sizeof(ctx->cipher_suites)/sizeof(ctx->cipher_suites[0])) {
		error_print();
		return -1;
	}
	for (i = 0; i < ctx->cipher_suites_cnt; i++) {
		if (!tls_type_is_in_list(ctx->cipher_suites[i],
			supported_cipher_suites, supported_cipher_suites_cnt)) {
			error_print();
			return -1;
		}
	}

	if (ctx->supported_groups_cnt > sizeof(ctx->supported_groups)/sizeof(ctx->supported_groups[0])) {
		error_print();
		return -1;
	}
	for (i = 0; i < ctx->supported_groups_cnt; i++) {
		if (!tls_type_is_in_list(ctx->supported_groups[i], supported_groups, supported_groups_cnt)) {
			error_print();
			return -1;
		}
	}

	if (ctx->signature_algorithms_cnt
		> sizeof(ctx->signature_algorithms)/sizeof(ctx->signature_algorithms[0])) {
		error_print();
		return -1;
	}
	for (i = 0; i < ctx->signature_algorithms_cnt; i++) {
		if (!tls_type_is_in_list(ctx->signature_algorithms[i],
			supported_sig_algs, supported_sig_algs_cnt)) {
			error_print();
			return -1;
		}
	}

	if (!ctx->supported_versions_cnt
		|| ctx->supported_versions_cnt > sizeof(ctx->supported_versions)/sizeof(ctx->supported_versions[0])) {
		error_print();
		return -1;
	}
	for (i = 0; i < ctx->supported_versions_cnt; i++) {
		switch (ctx->supported_versions[i]) {
		case TLS_protocol_tls13:
		case TLS_protocol_tls12:
		case TLS_protocol_tlcp:
			break;
		default:
			error_print();
			return -1;
		}
	}
	if (!tls_type_is_in_list(ctx->protocol, ctx->supported_versions, ctx->supported_versions_cnt)) {
		error_print();
		return -1;
	}

	if (ctx->key_exchanges_cnt > sizeof(ctx->supported_groups)/sizeof(ctx->supported_groups[0])) {
		error_print();
		return -1;
	}
	if (ctx->supported_groups_cnt && ctx->key_exchanges_cnt > ctx->supported_groups_cnt) {
		error_print();
		return -1;
	}

	if (ctx->application_layer_protocol_negotiation && !ctx->alpn_protocols_cnt) {
		error_print();
		return -1;
	}
	if (!ctx->application_layer_protocol_negotiation && ctx->alpn_protocols_cnt) {
		error_print();
		return -1;
	}
	if (ctx->alpn_protocols_cnt > sizeof(ctx->alpn_protocols)/sizeof(ctx->alpn_protocols[0])) {
		error_print();
		return -1;
	}
	for (i = 0; i < ctx->alpn_protocols_cnt; i++) {
		size_t protocol_len;

		if (!ctx->alpn_protocols[i]) {
			error_print();
			return -1;
		}
		protocol_len = strlen(ctx->alpn_protocols[i]);
		if (protocol_len < 1 || protocol_len > 255) {
			error_print();
			return -1;
		}
	}

	if (ctx->is_client && ctx->certificate_request) {
		error_print();
		return -1;
	}
	if (ctx->protocol != TLS_protocol_tls13 && ctx->psk_key_exchange_modes) {
		error_print();
		return -1;
	}
	if (ctx->protocol != TLS_protocol_tls13 && ctx->early_data) {
		error_print();
		return -1;
	}
	if (ctx->early_data && !(ctx->psk_key_exchange_modes & (TLS_KE_PSK_DHE|TLS_KE_PSK))) {
		error_print();
		return -1;
	}
	if (!ctx->early_data && ctx->max_early_data_size) {
		error_print();
		return -1;
	}
	if ((ctx->psk_key_exchange_modes & TLS_KE_PSK_DHE) && !ctx->supported_groups_cnt) {
		error_print();
		return -1;
	}

	cert_chains = ctx->cert_chains;
	cert_chains_len = ctx->cert_chains_len;
	while (cert_chains_len) {
		const uint8_t *cert_chain;
		size_t cert_chain_len;
		size_t certs_cnt;

		if (tls_uint24array_from_bytes(&cert_chain, &cert_chain_len,
			&cert_chains, &cert_chains_len) != 1
			|| x509_certs_get_count(cert_chain, cert_chain_len, &certs_cnt) != 1) {
			error_print();
			return -1;
		}
		if (!certs_cnt) {
			error_print();
			return -1;
		}
		if (ctx->protocol == TLS_protocol_tlcp && !ctx->is_client && certs_cnt < 2) {
			error_print();
			return -1;
		}
		cert_chains_cnt++;
	}

	if (ctx->protocol == TLS_protocol_tlcp && !ctx->is_client) {
		if (!ctx->cert_chains_len || !ctx->x509_keys_cnt || cert_chains_cnt != ctx->x509_keys_cnt) {
			error_print();
			return -1;
		}
	} else if (ctx->cert_chains_len) {
		if (!ctx->x509_keys_cnt || cert_chains_cnt != ctx->x509_keys_cnt) {
			error_print();
			return -1;
		}
	} else if (ctx->x509_keys_cnt) {
		error_print();
		return -1;
	}

	if (ctx->protocol == TLS_protocol_tls13) {
		int key_exchange_modes = ctx->psk_key_exchange_modes;

		if (ctx->supported_groups_cnt && ctx->signature_algorithms_cnt) {
			key_exchange_modes |= TLS_KE_CERT_DHE;
		}
		if (!ctx->supported_groups_cnt) {
			key_exchange_modes &= ~(TLS_KE_CERT_DHE|TLS_KE_PSK_DHE);
		}
		if (!key_exchange_modes) {
			error_print();
			return -1;
		}
	}

	return 1;
}

int tls_init(TLS_CONNECT *conn, TLS_CTX *ctx)
{
	if (!conn || !ctx) {
		error_print();
		return -1;
	}

	if (tls_ctx_check(ctx) != 1) {
		error_print();
		return -1;
	}

	if (ctx->protocol == TLS_protocol_tls13) {
		return tls13_init(conn, ctx);
	}

	memset(conn, 0, sizeof(*conn));

	conn->is_client = ctx->is_client; // TODO: remove conn->is_client
	conn->protocol = ctx->protocol;
	conn->verbose = ctx->verbose;


	if (conn->is_client && ctx->cert_chains_len) {
		if (tls_ctx_get_certificate_chain(ctx, 1,
			&conn->cert_chain, &conn->cert_chain_len) != 1) {
			error_print();
			return -1;
		}
		if (conn->cert_chain_len > sizeof(conn->client_certs)) {
			error_print();
			return -1;
		}
		memcpy(conn->client_certs, conn->cert_chain, conn->cert_chain_len);
		conn->client_certs_len = conn->cert_chain_len;
		conn->cert_chain_idx = 1;
	}


	conn->ctx = ctx;

	conn->key_exchanges_cnt = ctx->key_exchanges_cnt;

	conn->new_session_ticket = ctx->new_session_ticket;


	// init key_exchange_modes
	conn->key_exchange_modes = ctx->psk_key_exchange_modes;
	if (ctx->supported_groups_cnt && ctx->signature_algorithms_cnt) {
		conn->key_exchange_modes |= TLS_KE_CERT_DHE;
	}

	if (ctx->protocol == TLS_protocol_tls13) {
		if (!conn->key_exchange_modes) {
			error_print();
			return -1;
		}

		if(conn->verbose) {
			fprintf(stderr, "%s %d: conn->key_exchange_modes = %d\n", __FILE__, __LINE__, conn->key_exchange_modes);
		}

		if (conn->key_exchange_modes & (TLS_KE_CERT_DHE|TLS_KE_PSK_DHE)) {
			conn->key_share = 1;
		}

	}

	if (ctx->protocol == TLS_protocol_tlcp) {
		//sm3_init(&conn->sm3_ctx);
	}


	conn->signed_certificate_timestamp = ctx->signed_certificate_timestamp;

	// early_data
	conn->early_data = ctx->early_data;
	conn->max_early_data_size = ctx->max_early_data_size;

	// pre_shared_key
	if (conn->key_exchange_modes & (TLS_KE_PSK_DHE|TLS_KE_PSK)) {
		conn->pre_shared_key = 1;
	}



	if (ctx->certificate_request) {
		conn->client_certificate_verify = 1;
	}


	return 1;
}

void tls_cleanup(TLS_CONNECT *conn)
{
	gmssl_secure_clear(conn, sizeof(TLS_CONNECT));
}

int tls_set_verbose(TLS_CONNECT *conn, int verbose)
{
	if (!conn) {
		error_print();
		return -1;
	}
	if (verbose < 0 || verbose > 5) {
		error_print();
		return -1;
	}
	conn->verbose = verbose;
	return 1;
}

int tls_set_socket(TLS_CONNECT *conn, tls_socket_t sock)
{
	if (!conn || !tls_socket_is_valid(sock)) {
		error_print();
		return -1;
	}
	conn->sock = sock;
	return 1;
}

int tls_do_handshake(TLS_CONNECT *conn)
{
	switch (conn->protocol) {
	case TLS_protocol_tlcp:
		if (conn->is_client) return tlcp_do_connect(conn);
		else return tlcp_do_accept(conn);
	case TLS_protocol_tls12:
		if (conn->is_client) return tls12_do_connect(conn);
		else return tls12_do_accept(conn);
	case TLS_protocol_tls13:
		if (conn->is_client) return tls13_do_connect(conn);
		else return tls13_do_accept(conn);
	}
	error_print();
	return -1;
}

int tls_get_verify_result(TLS_CONNECT *conn, int *result)
{
	*result = conn->verify_result;
	return 1;
}

void tls_clean_record(TLS_CONNECT *conn)
{
	conn->record_offset = 0;
	conn->recordlen = 0;
}
