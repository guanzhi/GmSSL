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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <gmssl/tls.h>
#include <gmssl/x509.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>


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
		error_print("invalid tls record data length %zu\n", inlen);
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
	int i;

	if (!inited_hmac_ctx || !dec_key || !seq_num || !enced_header || !in || !inlen || !out || !outlen) {
		error_print();
		return -1;
	}
	if (inlen % 16
		|| inlen < (16 + 0 + 32 + 16) // iv + data +  mac + padding
		|| inlen > (16 + (1<<14) + 32 + 256)) {
		error_print("invalid tls cbc ciphertext length %zu\n", inlen);
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
			error_print("tls ciphertext cbc-padding check failure");
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
	if (sm3_hmac_finish_and_verify(&hmac_ctx, mac) != 1) {
		error_print("tls ciphertext mac check failure");
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
