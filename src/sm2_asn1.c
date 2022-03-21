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

#include <string.h>
#include <gmssl/sm2.h>
#include <gmssl/oid.h>
#include <gmssl/asn1.h>
#include <gmssl/pem.h>
#include <gmssl/sm4.h>
#include <gmssl/rand.h>
#include <gmssl/pbkdf2.h>
#include <gmssl/pkcs8.h>
#include <gmssl/error.h>
#include <gmssl/ec.h>
#include <gmssl/x509_alg.h>


void sm2_point_to_compressed_octets(const SM2_POINT *P, uint8_t out[33])
{
	*out++ = (P->y[31] & 0x01) ? 0x03 : 0x02;
	memcpy(out, P->x, 32);
}

void sm2_point_to_uncompressed_octets(const SM2_POINT *P, uint8_t out[65])
{
	*out++ = 0x04;
	memcpy(out, P, 64);
}

int sm2_point_from_octets(SM2_POINT *P, const uint8_t *in, size_t inlen)
{
	if ((*in == 0x02 || *in == 0x03) && inlen == 33) {
		if (sm2_point_from_x(P, in + 1, *in) != 1) {
			error_print();
			return -1;
		}
	} else if (*in == 0x04 && inlen == 65) {
		if (sm2_point_from_xy(P, in + 1, in + 33) != 1) {
			error_print();
			return -1;
		}
	} else {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_point_to_der(const SM2_POINT *P, uint8_t **out, size_t *outlen)
{
	uint8_t octets[65];
	if (!P) {
		return 0;
	}
	sm2_point_to_uncompressed_octets(P, octets);
	if (asn1_octet_string_to_der(octets, sizeof(octets), out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_point_from_der(SM2_POINT *P, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_octet_string_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (dlen != 65) {
		error_print();
		return -1;
	}
	if (sm2_point_from_octets(P, d, dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_signature_to_der(const SM2_SIGNATURE *sig, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (!sig) {
		return 0;
	}
	if (asn1_integer_to_der(sig->r, 32, NULL, &len) != 1
		|| asn1_integer_to_der(sig->s, 32, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_integer_to_der(sig->r, 32, out, outlen) != 1
		|| asn1_integer_to_der(sig->s, 32, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_signature_from_der(SM2_SIGNATURE *sig, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *r;
	size_t rlen;
	const uint8_t *s;
	size_t slen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_integer_from_der(&r, &rlen, &d, &dlen) != 1
		|| asn1_integer_from_der(&s, &slen, &d, &dlen) != 1
		|| asn1_length_le(rlen, 32) != 1
		|| asn1_length_le(slen, 32) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	memset(sig, 0, sizeof(*sig));
	memcpy(sig->r + 32 - rlen, r, rlen); // 需要测试当r, s是比较小的整数时
	memcpy(sig->s + 32 - slen, s, slen);
	return 1;
}

/*
int sm2_ciphertext_size(size_t inlen, size_t *outlen)
{
	*outlen = sizeof(SM2_CIPHERTEXT)-1+inlen;
	return 1;
}
*/

int sm2_ciphertext_to_der(const SM2_CIPHERTEXT *C, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (!C) {
		return 0;
	}
	if (asn1_integer_to_der(C->point.x, 32, NULL, &len) != 1
		|| asn1_integer_to_der(C->point.y, 32, NULL, &len) != 1
		|| asn1_octet_string_to_der(C->hash, 32, NULL, &len) != 1
		|| asn1_octet_string_to_der(C->ciphertext, C->ciphertext_size, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_integer_to_der(C->point.x, 32, out, outlen) != 1
		|| asn1_integer_to_der(C->point.y, 32, out, outlen) != 1
		|| asn1_octet_string_to_der(C->hash, 32, out, outlen) != 1
		|| asn1_octet_string_to_der(C->ciphertext, C->ciphertext_size, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_ciphertext_from_der(SM2_CIPHERTEXT *C, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *x;
	const uint8_t *y;
	const uint8_t *hash;
	const uint8_t *c;
	size_t xlen, ylen, hashlen, clen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_integer_from_der(&x, &xlen, &d, &dlen) != 1
		|| asn1_integer_from_der(&y, &ylen, &d, &dlen) != 1
		|| asn1_octet_string_from_der(&hash, &hashlen, &d, &dlen) != 1
		|| asn1_octet_string_from_der(&c, &clen, &d, &dlen) != 1
		|| asn1_length_le(xlen, 32) != 1
		|| asn1_length_le(ylen, 32) != 1
		|| asn1_check(hashlen == 32) != 1
		|| asn1_length_le(clen, SM2_MAX_PLAINTEXT_SIZE) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	memset(C, 0, sizeof(SM2_CIPHERTEXT));
	memcpy(C->point.x, x, xlen);
	memcpy(C->point.y, y, ylen);
	memcpy(C->hash, hash, hashlen);
	memcpy(C->ciphertext, c, clen);
	C->ciphertext_size = (uint8_t)clen;
	return 1;
}

// BIT STRING wrapping of uncompressed point
int sm2_public_key_to_der(const SM2_KEY *key, uint8_t **out, size_t *outlen)
{
	uint8_t buf[65];
	size_t len = 0;

	if (!key) {
		return 0;
	}
	sm2_point_to_uncompressed_octets(&key->public_key, buf);
	if (asn1_bit_octets_to_der(buf, sizeof(buf), out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_public_key_from_der(SM2_KEY *key, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	SM2_POINT P;

	if ((ret = asn1_bit_octets_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (dlen != 65) {
		error_print();
		return -1;
	}
	if (sm2_point_from_octets(&P, d, dlen) != 1
		|| sm2_key_set_public_key(key, &P) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

/*
int sm2_public_key_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen)
{
	const uint8_t *d;
	size_t dlen;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_bit_octets_from_der(&d, &dlen, &a, &alen) != 1) goto err;
	format_bytes(fp, fmt, ind, "", d, dlen);


	return 1;
}
*/

int sm2_private_key_to_der(const SM2_KEY *key, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	uint8_t params[64];
	uint8_t pubkey[128];
	uint8_t *params_ptr = params;
	uint8_t *pubkey_ptr = pubkey;
	size_t params_len = 0;
	size_t pubkey_len = 0;

	if (ec_named_curve_to_der(OID_sm2, &params_ptr, &params_len) != 1
		|| sm2_public_key_to_der(key, &pubkey_ptr, &pubkey_len) != 1) {
		error_print();
		return -1;
	}
	if (asn1_int_to_der(EC_private_key_version, NULL, &len) != 1
		|| asn1_octet_string_to_der(key->private_key, 32, NULL, &len) != 1
		|| asn1_explicit_to_der(0, params, params_len, NULL, &len) != 1
		|| asn1_explicit_to_der(1, pubkey, pubkey_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(EC_private_key_version, out, outlen) != 1
		|| asn1_octet_string_to_der(key->private_key, 32, out, outlen) != 1
		|| asn1_explicit_to_der(0, params, params_len, out, outlen) != 1
		|| asn1_explicit_to_der(1, pubkey, pubkey_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_private_key_from_der(SM2_KEY *key, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	int ver;
	const uint8_t *prikey;
	const uint8_t *params;
	const uint8_t *pubkey;
	size_t prikey_len, params_len, pubkey_len;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(&ver, &d, &dlen) != 1
		|| asn1_octet_string_from_der(&prikey, &prikey_len, &d, &dlen) != 1
		|| asn1_explicit_from_der(0, &params, &params_len, &d, &dlen) != 1
		|| asn1_explicit_from_der(1, &pubkey, &pubkey_len, &d, &dlen) != 1
		|| asn1_check(ver == EC_private_key_version) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (params) {
		int curve;
		if (ec_named_curve_from_der(&curve, &params, &params_len) != 1
			|| asn1_check(curve == OID_sm2) != 1
			|| asn1_length_is_zero(params_len) != 1) {
			error_print();
			return -1;
		}
	}
	if (asn1_check(prikey_len == 32) != 1
		|| sm2_key_set_private_key(key, prikey) != 1) {
		error_print();
		return -1;
	}
	if (pubkey) {
		if (sm2_public_key_from_der(key, &pubkey, &pubkey_len) != 1
			|| asn1_length_is_zero(pubkey_len) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int sm2_private_key_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	return ec_private_key_print(fp, fmt, ind, label, d, dlen);
}



int sm2_public_key_algor_to_der(uint8_t **out, size_t *outlen)
{
	if (x509_public_key_algor_to_der(OID_ec_public_key, OID_sm2, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_public_key_algor_from_der(const uint8_t **in, size_t *inlen)
{
	int ret;
	int oid;
	int curve;

	if ((ret = x509_public_key_algor_from_der(&oid, &curve, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (oid != OID_ec_public_key) {
		printf("%s %d: oid = %d\n", __FILE__, __LINE__, oid);
		error_print();
		return -1;
	}
	if (curve != OID_sm2) {
		error_print();
		return -1;
	}
	return 1;
}

#define SM2_PRIVATE_KEY_MAX_SIZE 512 // 需要测试这个buffer的最大值

int sm2_private_key_info_to_der(const SM2_KEY *sm2_key, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	uint8_t prikey[SM2_PRIVATE_KEY_MAX_SIZE];
	uint8_t *p = prikey;
	size_t prikey_len = 0;

	if (sm2_private_key_to_der(sm2_key, &p, &prikey_len) != 1) {
		error_print();
		return -1;
	}
	if (asn1_int_to_der(PKCS8_private_key_info_version, NULL, &len) != 1
		|| sm2_public_key_algor_to_der(NULL, &len) != 1
		|| asn1_octet_string_to_der(prikey, prikey_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(PKCS8_private_key_info_version, out, outlen) != 1
		|| sm2_public_key_algor_to_der(out, outlen) != 1
		|| asn1_octet_string_to_der(prikey, prikey_len, out, outlen) != 1) {
		memset(prikey, 0, sizeof(prikey));
		error_print();
		return -1;
	}
	memset(prikey, 0, sizeof(prikey));
	return 1;
}

int sm2_private_key_info_from_der(SM2_KEY *sm2_key, const uint8_t **attrs, size_t *attrslen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	int version;
	const uint8_t *prikey;
	size_t prikey_len;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(&version, &d, &dlen) != 1
		|| sm2_public_key_algor_from_der(&d, &dlen) != 1
		|| asn1_octet_string_from_der(&prikey, &prikey_len, &d, &dlen) != 1
		|| asn1_implicit_set_from_der(0, attrs, attrslen, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (asn1_check(version == PKCS8_private_key_info_version) != 1
		|| sm2_private_key_from_der(sm2_key, &prikey, &prikey_len) != 1
		|| asn1_length_is_zero(prikey_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_private_key_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret;
	const uint8_t *p;
	size_t len;
	int val;
	const uint8_t *prikey;
	size_t prikey_len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_int_from_der(&val, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "version: %d\n", val);
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_public_key_algor_print(fp, fmt, ind, "privateKeyAlgorithm", p, len);
	if (asn1_octet_string_from_der(&p, &len, &d, &dlen) != 1) goto err;
	if (asn1_sequence_from_der(&prikey, &prikey_len, &p, &len) != 1) goto err;
	ec_private_key_print(fp, fmt, ind + 4, "privateKey", prikey, prikey_len);
	if (asn1_length_is_zero(len) != 1) goto err;
	if ((ret = asn1_implicit_set_from_der(0, &p, &len, &d, &dlen)) < 0) goto err;
	else if (ret) format_bytes(fp, fmt, ind, "attributes", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}


#define SM2_PRIVATE_KEY_INFO_MAX_SIZE 512 // 计算长度

int sm2_private_key_info_to_pem(const SM2_KEY *key, FILE *fp)
{
	uint8_t buf[SM2_PRIVATE_KEY_INFO_MAX_SIZE];
	uint8_t *p = buf;
	size_t len = 0;

	if (sm2_private_key_info_to_der(key, &p, &len) != 1
		|| pem_write(fp, "PRIVATE KEY", buf, len) != 1) {
		memset(buf, 0, sizeof(buf));
		error_print();
		return -1;
	}
	memset(buf, 0, sizeof(buf));
	return 1;
}

int sm2_private_key_info_from_pem(SM2_KEY *sm2_key, const uint8_t **attrs, size_t *attrslen, FILE *fp)
{
	uint8_t buf[512]; // 这个可能是不够用的，因为attributes可能很长
	const uint8_t *cp = buf;
	size_t len;

	if (pem_read(fp, "PRIVATE KEY", buf, &len, sizeof(buf)) != 1
		|| sm2_private_key_info_from_der(sm2_key, attrs, attrslen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}


#define SM2_POINT_MAX_SIZE (2 + 65)

int sm2_public_key_info_to_der(const SM2_KEY *pub_key, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (sm2_public_key_algor_to_der(NULL, &len) != 1
		|| sm2_public_key_to_der(pub_key, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| sm2_public_key_algor_to_der(out, outlen) != 1
		|| sm2_public_key_to_der(pub_key, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_public_key_info_from_der(SM2_KEY *pub_key, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (sm2_public_key_algor_from_der(&d, &dlen) != 1
		|| sm2_public_key_from_der(pub_key, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_private_key_to_pem(const SM2_KEY *a, FILE *fp)
{
	uint8_t buf[512];
	uint8_t *p = buf;
	size_t len = 0;

	if (sm2_private_key_to_der(a, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (pem_write(fp, "EC PRIVATE KEY", buf, len) <= 0) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_private_key_from_pem(SM2_KEY *a, FILE *fp)
{
	uint8_t buf[512];
	const uint8_t *cp = buf;
	size_t len;

	if (pem_read(fp, "EC PRIVATE KEY", buf, &len, sizeof(buf)) != 1) {
		error_print();
		return -1;
	}
	if (sm2_private_key_from_der(a, &cp, &len) != 1
		|| len > 0) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_public_key_info_to_pem(const SM2_KEY *a, FILE *fp)
{
	uint8_t buf[512];
	uint8_t *p = buf;
	size_t len = 0;

	if (sm2_public_key_info_to_der(a, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (pem_write(fp, "PUBLIC KEY", buf, len) <= 0) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_public_key_info_from_pem(SM2_KEY *a, FILE *fp)
{
	uint8_t buf[512];
	const uint8_t *cp = buf;
	size_t len;

	if (pem_read(fp, "PUBLIC KEY", buf, &len, sizeof(buf)) != 1) {
		error_print();
		return -1;
	}
	if (sm2_public_key_info_from_der(a, &cp, &len) != 1
		|| len > 0) {
		return -1;
	}
	return 1;
}

int sm2_public_key_equ(const SM2_KEY *sm2_key, const SM2_KEY *pub_key)
{
	if (memcmp(sm2_key, pub_key, sizeof(SM2_POINT)) == 0) {
		return 1;
	}
	return 0;
}

int sm2_public_key_copy(SM2_KEY *sm2_key, const SM2_KEY *pub_key)
{
	return sm2_key_set_public_key(sm2_key, &pub_key->public_key);
}

int sm2_public_key_digest(const SM2_KEY *sm2_key, uint8_t dgst[32])
{
	uint8_t bits[65];
	sm2_point_to_uncompressed_octets(&sm2_key->public_key, bits);
	sm3_digest(bits, sizeof(bits), dgst);
	return 1;
}

int sm2_private_key_info_encrypt_to_der(const SM2_KEY *sm2_key, const char *pass,
	uint8_t **out, size_t *outlen)
{
	int ret = -1;
	uint8_t pkey_info[2560];
	uint8_t *p = pkey_info;
	size_t pkey_info_len = 0;
	uint8_t salt[16];
	int iter = 65536;
	uint8_t iv[16];
	uint8_t key[16];
	SM4_KEY sm4_key;
	uint8_t enced_pkey_info[5120];
	size_t enced_pkey_info_len;

	if (sm2_private_key_info_to_der(sm2_key, &p, &pkey_info_len) != 1
		|| rand_bytes(salt, sizeof(salt)) != 1
		|| rand_bytes(iv, sizeof(iv)) != 1
		|| pbkdf2_genkey(DIGEST_sm3(), pass, strlen(pass),
			salt, sizeof(salt), iter, sizeof(key), key) != 1) {
		error_print();
		goto end;
	}
	sm4_set_encrypt_key(&sm4_key, key);
	if (sm4_cbc_padding_encrypt(
			&sm4_key, iv, pkey_info, pkey_info_len,
			enced_pkey_info, &enced_pkey_info_len) != 1
		|| pkcs8_enced_private_key_info_to_der(
			salt, sizeof(salt), iter, sizeof(key), OID_hmac_sm3,
			OID_sm4_cbc, iv, sizeof(iv),
			enced_pkey_info, enced_pkey_info_len, out, outlen) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	memset(pkey_info, 0, sizeof(pkey_info));
	memset(key, 0, sizeof(key));
	memset(&sm4_key, 0, sizeof(sm4_key));
	return ret;
}

int sm2_private_key_info_decrypt_from_der(SM2_KEY *sm2,
	const uint8_t **attrs, size_t *attrs_len,
	const char *pass, const uint8_t **in, size_t *inlen)
{
	int ret = -1;
	const uint8_t *salt;
	size_t saltlen;
	int iter;
	int keylen;
	int prf;
	int cipher;
	const uint8_t *iv;
	size_t ivlen;
	uint8_t key[16];
	SM4_KEY sm4_key;
	const uint8_t *enced_pkey_info;
	size_t enced_pkey_info_len;
	uint8_t pkey_info[256];
	const uint8_t *cp = pkey_info;
	size_t pkey_info_len;

	if (pkcs8_enced_private_key_info_from_der(&salt, &saltlen, &iter, &keylen, &prf,
		&cipher, &iv, &ivlen, &enced_pkey_info, &enced_pkey_info_len, in, inlen) != 1
		|| asn1_check(keylen == -1 || keylen == 16) != 1
		|| asn1_check(prf == - 1 || prf == OID_hmac_sm3) != 1
		|| asn1_check(cipher == OID_sm4_cbc) != 1
		|| asn1_check(ivlen == 16) != 1
		|| asn1_length_le(enced_pkey_info_len, sizeof(pkey_info)) != 1) {
		error_print();
		return -1;
	}
	if (pbkdf2_genkey(DIGEST_sm3(), pass, strlen(pass), salt, saltlen, iter, sizeof(key), key) != 1) {
		error_print();
		goto end;
	}
	sm4_set_decrypt_key(&sm4_key, key);
	if (sm4_cbc_padding_decrypt(&sm4_key, iv, enced_pkey_info, enced_pkey_info_len,
			pkey_info, &pkey_info_len) != 1
		|| sm2_private_key_info_from_der(sm2, attrs, attrs_len, &cp, &pkey_info_len) != 1
		|| asn1_length_is_zero(pkey_info_len) != 1) {
		error_print();

		if (pkey_info_len) {
			format_bytes(stderr, 0, 0, "700", cp, pkey_info_len);
		}


		goto end;
	}
	ret = 1;
end:
	memset(&sm4_key, 0, sizeof(sm4_key));
	memset(key, 0, sizeof(key));
	memset(pkey_info, 0, sizeof(pkey_info));
	return ret;
}

int sm2_private_key_info_encrypt_to_pem(const SM2_KEY *sm2_key, const char *pass, FILE *fp)
{
	uint8_t buf[1024];
	uint8_t *p = buf;
	size_t len = 0;

	if (sm2_private_key_info_encrypt_to_der(sm2_key, pass, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (pem_write(fp, "ENCRYPTED PRIVATE KEY", buf, len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_private_key_info_decrypt_from_pem(SM2_KEY *key, const char *pass, FILE *fp)
{
	uint8_t buf[512];
	const uint8_t *cp = buf;
	size_t len;
	const uint8_t *attrs;
	size_t attrs_len;

	if (pem_read(fp, "ENCRYPTED PRIVATE KEY", buf, &len, sizeof(buf)) != 1
		|| sm2_private_key_info_decrypt_from_der(key, &attrs, &attrs_len, pass, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (asn1_length_is_zero(len) != 1) {
		format_bytes(stderr, 0, 0, "", cp, len);
		error_print();
		return -1;
	}
	return 1;
}
