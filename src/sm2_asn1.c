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
#include <gmssl/error.h>

// sm2 curve 1.2.156.10197.1.301


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
		return sm2_point_from_x(P, in + 1, *in);
	} else if (*in == 0x04 && inlen == 65) {
		return sm2_point_from_xy(P, in + 1, in + 33);
	} else {
		error_print();
		return -1;
	}
}

int sm2_point_to_der(const SM2_POINT *a, uint8_t **out, size_t *outlen)
{
	uint8_t buf[65];
	sm2_point_to_uncompressed_octets(a, buf);
	asn1_octet_string_to_der(buf, sizeof(buf), out, outlen);
	return 1;
}

int sm2_point_from_der(SM2_POINT *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	error_print_msg("inlen = %zu\n", *inlen);

	if ((ret = asn1_octet_string_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else error_print();
		return ret;
	}
	if (sm2_point_from_octets(a, data, datalen) != 1) {
		error_print();
		return -1;
	}
	error_print_msg("inlen = %zu\n", *inlen);
	return 1;
}

int sm2_signature_to_der(const SM2_SIGNATURE *sig, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	asn1_integer_to_der(sig->r, 32, NULL, &len);
	asn1_integer_to_der(sig->s, 32, NULL, &len);
	asn1_sequence_header_to_der(len, out, outlen);
	asn1_integer_to_der(sig->r, 32, out, outlen);
	asn1_integer_to_der(sig->s, 32, out, outlen);
	return 1;
}

int sm2_signature_from_der(SM2_SIGNATURE *sig, const uint8_t **in, size_t *inlen)
{
	const uint8_t *data, *r, *s;
	size_t datalen, rlen, slen;

	if (asn1_sequence_from_der(&data, &datalen, in, inlen) < 0
		|| asn1_integer_from_der(&r, &rlen, &data, &datalen) < 0
		|| asn1_integer_from_der(&s, &slen, &data, &datalen) < 0
		|| datalen > 0) {
		return -1;
	}
	if (rlen != 32 || slen != 32) {
		return -2;
	}

	memcpy(sig->r, r, 32);
	memcpy(sig->s, s, 32);
	return 1;
}

int sm2_ciphertext_size(size_t inlen, size_t *outlen)
{
	*outlen = sizeof(SM2_CIPHERTEXT)-1+inlen;
	return 1;
}

int sm2_ciphertext_to_der(const SM2_CIPHERTEXT *c, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	asn1_integer_to_der(c->point.x, 32, NULL, &len);
	asn1_integer_to_der(c->point.y, 32, NULL, &len);
	asn1_octet_string_to_der(c->hash, 32, NULL, &len);
	asn1_octet_string_to_der(c->ciphertext, c->ciphertext_size, NULL, &len);
	asn1_sequence_header_to_der(len, out, outlen);
	asn1_integer_to_der(c->point.x, 32, out, outlen);
	asn1_integer_to_der(c->point.y, 32, out, outlen);
	asn1_octet_string_to_der(c->hash, 32, out, outlen);
	asn1_octet_string_to_der(c->ciphertext, c->ciphertext_size, out, outlen);
	return 1;
}

int sm2_ciphertext_from_der(SM2_CIPHERTEXT *a, const uint8_t **in, size_t *inlen)
{
	const uint8_t *data, *x, *y, *hash, *c;
	size_t datalen, xlen, ylen, hashlen, clen;

	if (asn1_sequence_from_der(&data, &datalen, in, inlen) < 0
		|| asn1_integer_from_der(&x, &xlen, &data, &datalen) < 0
		|| asn1_integer_from_der(&y, &ylen, &data, &datalen) < 0
		|| asn1_octet_string_from_der(&hash, &hashlen, &data, &datalen) < 0
		|| asn1_octet_string_from_der(&c, &clen, &data, &datalen) < 0
		|| datalen > 0) {
		return -1;
	}
	if (xlen != 32
		|| ylen != 32
		|| hashlen != 32
		|| clen < 1) {
		return -1;
	}

	memcpy(a->point.x, x, 32);
	memcpy(a->point.y, y, 32);
	memcpy(a->hash, hash, 32);
	memcpy(a->ciphertext, c, clen);
	a->ciphertext_size = (uint32_t)clen;
	return 1;
}



// TODO: sm2, ecPublicKey 这些公用的OID应该提取到一个地方
static const uint32_t oid_sm2[] = { 1,2,156,10197,1,301 };
static const size_t oid_sm2_count = sizeof(oid_sm2)/sizeof(oid_sm2[0]);

int sm2_private_key_to_der(const SM2_KEY *key, uint8_t **out, size_t *outlen)
{
	int version = 1;
	uint8_t public_key[65];
	size_t len = 0;
	size_t params_len = 0;
	size_t pubkey_len = 0;

	sm2_point_to_uncompressed_octets(&key->public_key, public_key);

	asn1_int_to_der(version, NULL, &len);
	asn1_octet_string_to_der(key->private_key, 32, NULL, &len);
	asn1_object_identifier_to_der(oid_sm2, oid_sm2_count, NULL, &params_len);
	asn1_explicit_to_der(0, NULL, params_len, NULL, &len);
	asn1_bit_string_to_der(public_key, sizeof(public_key) * 8, NULL, &pubkey_len);
	asn1_explicit_to_der(1, NULL, pubkey_len, NULL, &len);

	asn1_sequence_header_to_der(len, out, outlen);
	asn1_int_to_der(version, out, outlen);
	asn1_octet_string_to_der(key->private_key, 32, out, outlen);
	asn1_explicit_header_to_der(0, params_len, out, outlen);
	asn1_object_identifier_to_der(oid_sm2, oid_sm2_count, out, outlen);
	asn1_explicit_header_to_der(1, pubkey_len, out, outlen);
	asn1_bit_string_to_der(public_key, sizeof(public_key) * 8, out, outlen);

	return 1;
}

int sm2_private_key_from_der(SM2_KEY *key, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	int version;
	const uint8_t *prikey;
	const uint8_t *params;
	const uint8_t *pubkey;
	size_t prikey_len;
	size_t params_len;
	size_t pubkey_len;

	memset(key, 0, sizeof(SM2_KEY));

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(&version, &data, &datalen) != 1
		|| asn1_octet_string_from_der(&prikey, &prikey_len, &data, &datalen) != 1
		|| asn1_explicit_from_der(0, &params, &params_len, &data, &datalen) < 0
		|| asn1_explicit_from_der(1, &pubkey, &pubkey_len, &data, &datalen) < 0
		|| datalen > 0) {
		return -1;
	}
	if (version != 1) {
		error_print();
		return -1;
	}
	if (prikey_len != 32) {
		error_print();
		return -1;
	}
	if (sm2_key_set_private_key(key, prikey) != 1) {
		error_print();
		return -1;
	}
	if (params) {
		uint32_t nodes[16]; // FIXME: 这个长度不对啊！					
		size_t nodes_count;

		if (asn1_object_identifier_from_der(nodes, &nodes_count, &params, &params_len) != 1
			|| params_len > 0) {
			error_print();
			return -1;
		}
		if (nodes_count != oid_sm2_count
			|| memcmp(nodes, oid_sm2, sizeof(oid_sm2)) != 0) {
			error_print();
			return -1;
		}
	}
	if (pubkey) {
		const uint8_t *bits;
		size_t nbits;

		if (asn1_bit_string_from_der(&bits, &nbits, &pubkey, &pubkey_len) != 1
			|| pubkey_len > 0) {
			error_print();
			return -1;
		}
		if (nbits % 8) {
			error_print();
			return -1;
		}
		if (sm2_point_from_octets(&key->public_key, bits, nbits/8) != 1) {
			error_print();
			return -1;
		}
	}

	return 1;
}



static const uint32_t oid_ec_public_key[] = { 1,2,840,10045,2,1 };
static const size_t oid_ec_public_key_count = sizeof(oid_ec_public_key)/sizeof(oid_ec_public_key[0]);

int sm2_public_key_algor_to_der(uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_object_identifier_to_der(oid_ec_public_key, oid_ec_public_key_count, NULL, &len) != 1
		|| asn1_object_identifier_to_der(oid_sm2, oid_sm2_count, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(oid_ec_public_key, oid_ec_public_key_count, out, outlen) != 1
		|| asn1_object_identifier_to_der(oid_sm2, oid_sm2_count, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_public_key_algor_from_der(const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	uint32_t nodes[ASN1_OID_MAX_NODES];
	size_t nodes_count;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_object_identifier_from_der(nodes, &nodes_count, &data, &datalen) != 1
		|| asn1_object_identifier_equ(nodes, nodes_count, oid_ec_public_key, oid_ec_public_key_count) != 1) {
		error_print();
		return -1;
	}
	if (asn1_object_identifier_from_der(nodes, &nodes_count, &data, &datalen) != 1
		|| asn1_object_identifier_equ(nodes, nodes_count, oid_sm2, oid_sm2_count) != 1) {
		error_print();
		return -1;
	}
	if (datalen) {
		error_print();
		return -1;
	}
	return 1;
}


int sm2_private_key_info_to_der(const SM2_KEY *key, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	uint8_t prikey[512];
	uint8_t *p = prikey;
	size_t prikey_len = 0;

	sm2_private_key_to_der(key, &p, &prikey_len);

	asn1_int_to_der(0, NULL, &len);
	sm2_public_key_algor_to_der(NULL, &len);
	asn1_octet_string_to_der(prikey, prikey_len, NULL, &len);
	asn1_sequence_header_to_der(len, out, outlen);
	asn1_int_to_der(0, out, outlen);
	sm2_public_key_algor_to_der(out, outlen);
	asn1_octet_string_to_der(prikey, prikey_len, out, outlen);
	return 1;
}

int sm2_private_key_info_from_der(SM2_KEY *key, const uint8_t **attrs, size_t *attrslen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	int version;
	const uint8_t *prikey;
	size_t prikeylen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(&version, &data, &datalen) != 1
		|| sm2_public_key_algor_from_der(&data, &datalen) != 1
		|| asn1_octet_string_from_der(&prikey, &prikeylen, &data, &datalen) != 1
		|| asn1_implicit_set_from_der(0, attrs, attrslen, &data, &datalen) < 0
		|| datalen > 0) {
		error_print();
		return -1;
	}
	if (version != 0) {
		error_print();
		return -1;
	}
	if (sm2_private_key_from_der(key, &prikey, &prikeylen) != 1
		|| prikeylen > 0) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_private_key_info_to_pem(const SM2_KEY *key, FILE *fp)
{
	uint8_t buf[512];
	uint8_t *p = buf;
	size_t len = 0;

	if (sm2_private_key_info_to_der(key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (pem_write(fp, "PRIVATE KEY", buf, len) <= 0) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_private_key_info_from_pem(SM2_KEY *key, const uint8_t **attrs, size_t *attrslen, FILE *fp)
{
	uint8_t buf[512];
	const uint8_t *cp = buf;
	size_t len;

	if (pem_read(fp, "PRIVATE KEY", buf, &len, sizeof(buf)) != 1) {
		error_print();
		return -1;
	}
	if (sm2_private_key_info_from_der(key, attrs, attrslen, &cp, &len) != 1
		|| len > 0) {
		return -1;
	}
	return 1;
}


int sm2_public_key_info_to_der(const SM2_KEY *a, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	uint8_t bits[65];

	sm2_point_to_uncompressed_octets(&a->public_key, bits);

	sm2_public_key_algor_to_der(NULL, &len);
	asn1_bit_string_to_der(bits, sizeof(bits)*8, NULL, &len);
	asn1_sequence_header_to_der(len, out, outlen);
	sm2_public_key_algor_to_der(out, outlen);
	asn1_bit_string_to_der(bits, sizeof(bits)*8, out, outlen);
	return 1;
}

int sm2_public_key_info_from_der(SM2_KEY *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	const uint8_t *bits;
	size_t nbits;
	SM2_POINT point;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (sm2_public_key_algor_from_der(&data, &datalen) != 1
		|| asn1_bit_string_from_der(&bits, &nbits, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}

	if (nbits % 8) {
		error_print();
		return -1;
	}
	if (sm2_point_from_octets(&point, bits, nbits/8) != 1) {
		error_print();
		return -1;
	}
	memset(a, 0, sizeof(SM2_KEY));
	if (sm2_key_set_public_key(a, &point) != 1) {
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

