/*
 * Copyright (c) 2014 - 2020 The GmSSL Project.  All rights reserved.
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
#include <string.h>
#include <stdlib.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/sm2.h>
#include <gmssl/pkcs8.h>


static int test_sm2_point(void)
{
	SM2_POINT P, Q;
	uint8_t k[32] = {0};
	uint8_t buf[65] = {0};
	int i;

	for (i = 1; i < 8; i++) {
		k[31] = (uint8_t)i;

		if (sm2_point_mul_generator(&P, k) != 1
			|| sm2_point_is_on_curve(&P) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 0, "k = %d, ", i);
		sm2_point_print(stderr, 0, 0, "k * G", &P);

		memset(buf, 0, sizeof(buf));
		sm2_point_to_compressed_octets(&P, buf);
		format_bytes(stderr, 0, 4, "compressedPoint", buf, 33);
		memset(&Q, 0, sizeof(Q));
		if (sm2_point_from_x(&Q, buf + 1, buf[0]) != 1
			|| memcmp(&P, &Q, sizeof(SM2_POINT)) != 0) {

			sm2_point_print(stderr, 0, 4, "P", &P);
			sm2_point_print(stderr, 0, 4, "Q", &Q);

			error_print();
			return -1;
		}

		memset(buf, 0, sizeof(buf));
		sm2_point_to_uncompressed_octets(&P, buf);
		format_bytes(stderr, 0, 4, "compressedPoint", buf, 65);
		memset(&Q, 0, sizeof(Q));
		if (sm2_point_from_octets(&Q, buf, 65) != 1
			|| memcmp(&P, &Q, sizeof(SM2_POINT)) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_sm2_point_der(void)
{
	SM2_POINT P, Q;
	uint8_t k[32] = {0};
	uint8_t buf[512];
	int i;

	for (i = 1; i < 8; i++) {
		uint8_t *p = buf;
		const uint8_t *cp = buf;
		size_t len = 0;

		k[31] = i;
		memset(&P, 0, sizeof(P));
		memset(&Q, 0, sizeof(Q));

		if (sm2_point_mul_generator(&P, k) != 1
			|| sm2_point_to_der(&P, &p, &len) != 1
			|| format_bytes(stderr, 0, 4, "ECPoint", buf, len) != 1
			|| sm2_point_from_der(&Q, &cp, &len) != 1
			|| asn1_length_is_zero(len) != 1) {
			error_print();
			return -1;
		}
		if (memcmp(&P, &Q, sizeof(SM2_POINT)) != 0) {
			error_print();
			sm2_point_print(stderr, 0, 4, "P", &P);
			sm2_point_print(stderr, 0, 4, "Q", &Q);
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_sm2_point_octets(void)
{
	SM2_POINT P, Q;
	uint8_t k[32] = {0};
	uint8_t buf[33];
	int i;

	for (i = 1; i < 8; i++) {
		uint8_t *p = buf;
		const uint8_t *cp = buf;
		size_t len = 0;

		k[31] = i;
		memset(&P, 0, sizeof(P));
		memset(&Q, 0, sizeof(Q));

		if (sm2_point_mul_generator(&P, k) != 1) {
			error_print();
			return -1;
		}
		sm2_point_to_compressed_octets(&P, buf);
		format_bytes(stderr, 0, 4, "compressedPoint", buf, sizeof(buf));
		if (sm2_point_from_octets(&Q, buf, sizeof(buf)) != 1) {
			error_print();
			return -1;
		}
		if (memcmp(&P, &Q, sizeof(SM2_POINT)) != 0) {
			error_print();
			sm2_point_print(stderr, 0, 4, "P", &P);
			sm2_point_print(stderr, 0, 4, "Q", &Q);
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_sm2_point_from_x(void)
{
	SM2_POINT P, Q;
	uint8_t k[32] = {0};
	uint8_t buf[33];
	int i;

	for (i = 1; i < 8; i++) {
		uint8_t *p = buf;
		const uint8_t *cp = buf;
		size_t len = 0;

		k[31] = i;
		memset(&P, 0, sizeof(P));
		memset(&Q, 0, sizeof(Q));

		if (sm2_point_mul_generator(&P, k) != 1) {
			error_print();
			return -1;
		}
		sm2_point_to_compressed_octets(&P, buf);
		if (sm2_point_from_x(&Q, buf + 1, buf[0]) != 1) {
			error_print();
			return -1;
		}
		if (memcmp(&P, &Q, sizeof(SM2_POINT)) != 0) {
			error_print();
			sm2_point_print(stderr, 0, 4, "P", &P);
			sm2_point_print(stderr, 0, 4, "Q", &Q);
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_sm2_signature(void)
{
	SM2_SIGNATURE sig;
	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	// MinLen
	memset(&sig, 0x00, sizeof(sig));
	cp = p = buf; len = 0;
	if (sm2_signature_to_der(&sig, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "SM2_MIN_SIGNATURE_SIZE: %zu\n", len);
	format_bytes(stderr, 0, 4, "", buf, len);
	sm2_signature_print(stderr, 0, 4, "signature", buf, len);
	if (len != SM2_MIN_SIGNATURE_SIZE) {
		error_print();
		return -1;
	}
	if (sm2_signature_from_der(&sig, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}


	// MaxLen
	memset(&sig, 0x80, sizeof(sig));
	cp = p = buf; len = 0;
	if (sm2_signature_to_der(&sig, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "SM2_MAX_SIGNATURE_SIZE: %zu\n", len);
	format_bytes(stderr, 0, 4, "", buf, len);
	sm2_signature_print(stderr, 0, 4, "signature", buf, len);
	if (len != SM2_MAX_SIGNATURE_SIZE) {
		error_print();
		return -1;
	}
	if (sm2_signature_from_der(&sig, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}


	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_sm2_sign(void)
{
	int ret;
	SM2_KEY sm2_key;
	SM2_SIGN_CTX sign_ctx;
	uint8_t msg[] = "Hello World!";
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE] = {0};
	size_t siglen;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}
	sm2_key_print(stderr, 0, 4, "SM2_KEY", &sm2_key);

	if (sm2_sign_init(&sign_ctx, &sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1
		|| sm2_sign_update(&sign_ctx, msg, sizeof(msg)) != 1
		|| sm2_sign_finish(&sign_ctx, sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 4, "signature", sig, siglen);
	sm2_signature_print(stderr, 0, 4, "signature", sig, siglen);

	if (sm2_verify_init(&sign_ctx, &sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1
		|| sm2_verify_update(&sign_ctx, msg, sizeof(msg)) != 1
		|| (ret = sm2_verify_finish(&sign_ctx, sig, siglen)) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "verification: %s\n", ret ? "success" : "failed");


	// FIXME: 还应该增加验证不通过的测试
	// 还应该增加底层的参数
	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_sm2_ciphertext(void)
{
	SM2_CIPHERTEXT C;
	uint8_t buf[1024];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	// {0, 0, Hash, NULL}
	memset(&C, 0, sizeof(SM2_CIPHERTEXT));
	cp = p = buf; len = 0;
	if (sm2_ciphertext_to_der(&C, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "SM2_NULL_CIPHERTEXT_SIZE: %zu\n", len);
	format_bytes(stderr, 0, 4, "", buf, len);
	if (sm2_ciphertext_from_der(&C, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	// {0, 0, Hash, MinLen}
	C.ciphertext_size = SM2_MIN_PLAINTEXT_SIZE;
	cp = p = buf; len = 0;
	if (sm2_ciphertext_to_der(&C, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "SM2_MIN_PLAINTEXT_SIZE: %zu\n", SM2_MIN_PLAINTEXT_SIZE);
	format_print(stderr, 0, 4, "SM2_MIN_CIPHERTEXT_SIZE: %zu\n", len);
	format_bytes(stderr, 0, 4, "", buf, len);
	if (len != SM2_MIN_CIPHERTEXT_SIZE) {
		error_print();
		return -1;
	}
	if (sm2_ciphertext_from_der(&C, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	// { 33, 33, Hash, NULL }
	memset(&C, 0x80, sizeof(SM2_POINT));
	cp = p = buf; len = 0;
	if (sm2_ciphertext_to_der(&C, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "ciphertext len: %zu\n", len);
	format_bytes(stderr, 0, 4, "", buf, len);
	if (sm2_ciphertext_from_der(&C, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	// { 33, 33, Hash, MaxLen }
	C.ciphertext_size = SM2_MAX_PLAINTEXT_SIZE;//SM2_MAX_PLAINTEXT_SIZE;
	cp = p = buf; len = 0;
	if (sm2_ciphertext_to_der(&C, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "SM2_MAX_PLAINTEXT_SIZE: %zu\n", SM2_MAX_PLAINTEXT_SIZE);
	format_print(stderr, 0, 4, "SM2_MAX_CIPHERTEXT_SIZE: %zu\n", len);
	format_bytes(stderr, 0, 4, "", buf, len);
	if (len != SM2_MAX_CIPHERTEXT_SIZE) {
		error_print();
		return -1;
	}
	if (sm2_ciphertext_from_der(&C, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 0;
}


static int test_sm2_do_encrypt(void)
{
	SM2_KEY sm2_key;
	uint8_t plaintext[] = "Hello World!";
	SM2_CIPHERTEXT ciphertext;

	uint8_t plainbuf[SM2_MAX_PLAINTEXT_SIZE] = {0};
	size_t plainlen = 0;
	int r = 0;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}

	if (sm2_do_encrypt(&sm2_key, plaintext, sizeof(plaintext), &ciphertext) != 1
		|| sm2_do_decrypt(&sm2_key, &ciphertext, plainbuf, &plainlen) != 1) {
		error_print();
		return -1;
	}

	if (plainlen != sizeof(plaintext)
		|| memcmp(plainbuf, plaintext, sizeof(plaintext)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 0;
}


static int test_sm2_encrypt(void)
{
	SM2_KEY sm2_key;
	uint8_t msg[SM2_MAX_PLAINTEXT_SIZE];
	uint8_t cbuf[SM2_MAX_CIPHERTEXT_SIZE+100];
	uint8_t mbuf[SM2_MAX_CIPHERTEXT_SIZE];
	size_t lens[] = {
//		0,
		1,
		16,
		SM2_MAX_PLAINTEXT_SIZE,
	};
	size_t clen, mlen;
	int i;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}

	for (i = 0; i < sizeof(msg); i++) {
		msg[i] = (uint8_t)i;
	}

	for (i = 0; i < sizeof(lens)/sizeof(lens[0]); i++) {

		format_bytes(stderr, 0, 4, "mesg", msg, lens[i]);

		if (sm2_encrypt(&sm2_key, msg, lens[i], cbuf, &clen) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "inlen = %zu, outlen = %zu\n", lens[i], clen);
		format_bytes(stderr, 0, 4, "", cbuf, clen);
		sm2_ciphertext_print(stderr, 0, 4, "ciphertext", cbuf, clen);

		if (sm2_decrypt(&sm2_key, cbuf, clen, mbuf, &mlen) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "mbuf", mbuf, mlen);

		if (mlen != lens[i]
			|| memcmp(mbuf, msg, lens[i]) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 0;
}



static int test_sm2_private_key(void)
{
	SM2_KEY sm2_key;
	SM2_KEY tmp_key;
	uint8_t buf[SM2_PRIVATE_KEY_BUF_SIZE];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}
	sm2_key_print(stderr, 0, 4, "SM2_KEY", &sm2_key);

	if (sm2_private_key_to_der(&sm2_key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 4, "ECPrivateKey", buf, len);
	format_print(stderr, 0, 4, "#define SM2_PRIVATE_KEY_DEFAULT_SIZE %zu\n", len);
	if (sm2_private_key_from_der(&tmp_key, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1
		|| memcmp(&tmp_key, &sm2_key, sizeof(SM2_KEY)) != 0) {
		error_print();
		return -1;
	}

	cp = p = buf; len = 0;
	memset(&tmp_key, 0, sizeof(tmp_key));
	if (sm2_private_key_to_der(&sm2_key, &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	sm2_private_key_print(stderr, 0, 4, "ECPrivateKey", d, dlen);

	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_sm2_private_key_info(void)
{
	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	SM2_KEY sm2_key;
	SM2_KEY tmp_key;
	const uint8_t *attrs;
	size_t attrs_len;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}
	sm2_key_print(stderr, 0, 4, "SM2_KEY", &sm2_key);

	if (sm2_private_key_info_to_der(&sm2_key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 4, "PrivateKeyInfo", buf, len);
	format_print(stderr, 0, 4, "sizeof(PrivateKeyInfo): %zu\n", len);
	if (asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	sm2_private_key_info_print(stderr, 0, 4, "PrivateKeyInfo", d, dlen);

	cp = p = buf; len = 0;
	if (sm2_private_key_info_to_der(&sm2_key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (sm2_private_key_info_from_der(&tmp_key, &attrs, &attrs_len, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1
		|| memcmp(&tmp_key, &sm2_key, sizeof(SM2_KEY)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_sm2_enced_private_key_info(void)
{
	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	SM2_KEY sm2_key;
	SM2_KEY tmp_key;
	const uint8_t *attrs;
	size_t attrs_len;
	const char *pass = "Password";

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}
	sm2_key_print(stderr, 0, 4, "SM2_KEY", &sm2_key);

	if (sm2_private_key_info_encrypt_to_der(&sm2_key, pass, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 4, "EncryptedPrivateKeyInfo", buf, len);
	format_print(stderr, 0, 4, "sizeof(EncryptedPrivateKeyInfo): %zu\n", len);
	if (asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	pkcs8_enced_private_key_info_print(stderr, 0, 4, "EncryptedPrivateKeyInfo", d, dlen);


	cp = p = buf; len = 0;
	if (sm2_private_key_info_encrypt_to_der(&sm2_key, pass, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (sm2_private_key_info_decrypt_from_der(&tmp_key, &attrs, &attrs_len, pass, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1
		|| memcmp(&tmp_key, &sm2_key, sizeof(SM2_KEY)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 0;
}


int main(void)
{
	int err = 0;
	err += sm2_selftest();
	err += test_sm2_point();
	err += test_sm2_point_octets();
	err += test_sm2_point_from_x();
	err += test_sm2_point_der();
	err += test_sm2_private_key();
	err += test_sm2_private_key_info();
	err += test_sm2_enced_private_key_info();
	err += test_sm2_signature();
	err += test_sm2_sign();
	err += test_sm2_ciphertext();
	err += test_sm2_do_encrypt();
	err += test_sm2_encrypt();
	if (!err) printf("%s all tests passed\n", __FILE__);
	return err;
}
