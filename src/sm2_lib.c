/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/mem.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>


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
	memcpy(sig->r + 32 - rlen, r, rlen);
	memcpy(sig->s + 32 - slen, s, slen);
	return 1;
}

int sm2_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen)
{
	SM2_SIGNATURE sig;
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	if (sm2_signature_from_der(&sig, &a, &alen) != 1
		|| asn1_length_is_zero(alen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "r", sig.r, 32);
	format_bytes(fp, fmt, ind, "s", sig.s, 32);
	return 1;
}

int sm2_sign(const SM2_KEY *key, const uint8_t dgst[32], uint8_t *sigbuf, size_t *siglen)
{
	SM2_SIGNATURE sig;

	if (!key || !dgst || !sigbuf || !siglen) {
		error_print();
		return -1;
	}

	if (sm2_do_sign(key, dgst, &sig) != 1) {
		error_print();
		return -1;
	}

	*siglen = 0;
	if (sm2_signature_to_der(&sig, &sigbuf, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_sign_fixlen(const SM2_KEY *key, const uint8_t dgst[32], size_t siglen, uint8_t *sig)
{
	unsigned int trys = 200; // 200 trys is engouh
	uint8_t buf[SM2_MAX_SIGNATURE_SIZE];
	size_t len;

	switch (siglen) {
	case SM2_signature_compact_size:
	case SM2_signature_typical_size:
	case SM2_signature_max_size:
		break;
	default:
		error_print();
		return -1;
	}

	while (trys--) {
		if (sm2_sign(key, dgst, buf, &len) != 1) {
			error_print();
			return -1;
		}
		if (len == siglen) {
			memcpy(sig, buf, len);
			return 1;
		}
	}

	// might caused by bad randomness
	error_print();
	return -1;
}

int sm2_verify(const SM2_KEY *key, const uint8_t dgst[32], const uint8_t *sigbuf, size_t siglen)
{
	SM2_SIGNATURE sig;

	if (!key || !dgst || !sigbuf || !siglen) {
		error_print();
		return -1;
	}

	if (sm2_signature_from_der(&sig, &sigbuf, &siglen) != 1
		|| asn1_length_is_zero(siglen) != 1) {
		error_print();
		return -1;
	}
	if (sm2_do_verify(key, dgst, &sig) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_compute_z(uint8_t z[32], const SM2_POINT *pub, const char *id, size_t idlen)
{
	SM3_CTX ctx;
	uint8_t zin[18 + 32 * 6] = {
		0x00, 0x80,
		0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
		0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC,
		0x28,0xE9,0xFA,0x9E,0x9D,0x9F,0x5E,0x34,0x4D,0x5A,0x9E,0x4B,0xCF,0x65,0x09,0xA7,
		0xF3,0x97,0x89,0xF5,0x15,0xAB,0x8F,0x92,0xDD,0xBC,0xBD,0x41,0x4D,0x94,0x0E,0x93,
       		0x32,0xC4,0xAE,0x2C,0x1F,0x19,0x81,0x19,0x5F,0x99,0x04,0x46,0x6A,0x39,0xC9,0x94,
		0x8F,0xE3,0x0B,0xBF,0xF2,0x66,0x0B,0xE1,0x71,0x5A,0x45,0x89,0x33,0x4C,0x74,0xC7,
		0xBC,0x37,0x36,0xA2,0xF4,0xF6,0x77,0x9C,0x59,0xBD,0xCE,0xE3,0x6B,0x69,0x21,0x53,
		0xD0,0xA9,0x87,0x7C,0xC6,0x2A,0x47,0x40,0x02,0xDF,0x32,0xE5,0x21,0x39,0xF0,0xA0,
	};

	if (!z || !pub || !id) {
		error_print();
		return -1;
	}

	memcpy(&zin[18 + 32 * 4], pub->x, 32);
	memcpy(&zin[18 + 32 * 5], pub->y, 32);

	sm3_init(&ctx);
	if (strcmp(id, SM2_DEFAULT_ID) == 0) {
		sm3_update(&ctx, zin, sizeof(zin));
	} else {
		uint8_t idbits[2];
		idbits[0] = (uint8_t)(idlen >> 5);
		idbits[1] = (uint8_t)(idlen << 3);
		sm3_update(&ctx, idbits, 2);
		sm3_update(&ctx, (uint8_t *)id, idlen);
		sm3_update(&ctx, zin + 18, 32 * 6);
	}
	sm3_finish(&ctx, z);
	return 1;
}

int sm2_kdf(const uint8_t *in, size_t inlen, size_t outlen, uint8_t *out)
{
	SM3_CTX ctx;
	uint8_t counter_be[4];
	uint8_t dgst[SM3_DIGEST_SIZE];
	uint32_t counter = 1;
	size_t len;

	while (outlen) {
		PUTU32(counter_be, counter);
		counter++;

		sm3_init(&ctx);
		sm3_update(&ctx, in, inlen);
		sm3_update(&ctx, counter_be, sizeof(counter_be));
		sm3_finish(&ctx, dgst);

		len = outlen < SM3_DIGEST_SIZE ? outlen : SM3_DIGEST_SIZE;
		memcpy(out, dgst, len);
		out += len;
		outlen -= len;
	}

	memset(&ctx, 0, sizeof(SM3_CTX));
	memset(dgst, 0, sizeof(dgst));
	return 1;
}

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
		|| asn1_length_le(xlen, 32) != 1) {
		error_print();
		return -1;
	}
	if (asn1_integer_from_der(&y, &ylen, &d, &dlen) != 1
		|| asn1_length_le(ylen, 32) != 1) {
		error_print();
		return -1;
	}
	if (asn1_octet_string_from_der(&hash, &hashlen, &d, &dlen) != 1
		|| asn1_check(hashlen == 32) != 1) {
		error_print();
		return -1;
	}
	if (asn1_octet_string_from_der(&c, &clen, &d, &dlen) != 1
	//	|| asn1_length_is_zero(clen) == 1
		|| asn1_length_le(clen, SM2_MAX_PLAINTEXT_SIZE) != 1) {
		error_print();
		return -1;
	}
	if (asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	memset(C, 0, sizeof(SM2_CIPHERTEXT));
	memcpy(C->point.x + 32 - xlen, x, xlen);
	memcpy(C->point.y + 32 - ylen, y, ylen);
	if (sm2_point_is_on_curve(&C->point) != 1) {
		error_print();
		return -1;
	}
	memcpy(C->hash, hash, hashlen);
	memcpy(C->ciphertext, c, clen);
	C->ciphertext_size = (uint8_t)clen;
	return 1;
}

int sm2_ciphertext_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen)
{
	uint8_t buf[512] = {0};
	SM2_CIPHERTEXT *c = (SM2_CIPHERTEXT *)buf;

	if (sm2_ciphertext_from_der(c, &a, &alen) != 1
		|| asn1_length_is_zero(alen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	format_bytes(fp, fmt, ind, "XCoordinate", c->point.x, 32);
	format_bytes(fp, fmt, ind, "YCoordinate", c->point.y, 32);
	format_bytes(fp, fmt, ind, "HASH", c->hash, 32);
	format_bytes(fp, fmt, ind, "CipherText", c->ciphertext, c->ciphertext_size);
	return 1;
}

int sm2_encrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	SM2_CIPHERTEXT C;

	if (!key || !in || !out || !outlen) {
		error_print();
		return -1;
	}
	if (!inlen) {
		error_print();
		return -1;
	}

	if (sm2_do_encrypt(key, in, inlen, &C) != 1) {
		error_print();
		return -1;
	}
	*outlen = 0;
	if (sm2_ciphertext_to_der(&C, &out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_encrypt_fixlen(const SM2_KEY *key, const uint8_t *in, size_t inlen, int point_size, uint8_t *out, size_t *outlen)
{
	SM2_CIPHERTEXT C;

	if (!key || !in || !out || !outlen) {
		error_print();
		return -1;
	}
	if (!inlen) {
		error_print();
		return -1;
	}

	if (sm2_do_encrypt_fixlen(key, in, inlen, point_size, &C) != 1) {
		error_print();
		return -1;
	}
	*outlen = 0;
	if (sm2_ciphertext_to_der(&C, &out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_decrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	SM2_CIPHERTEXT C;

	if (!key || !in || !out || !outlen) {
		error_print();
		return -1;
	}
	if (sm2_ciphertext_from_der(&C, &in, &inlen) != 1
		|| asn1_length_is_zero(inlen) != 1) {
		error_print();
		return -1;
	}
	if (sm2_do_decrypt(key, &C, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_do_ecdh(const SM2_KEY *key, const SM2_POINT *peer_public, SM2_POINT *out)
{
	/*
	if (sm2_point_is_on_curve(peer_public) != 1) {
		error_print();
		return -1;
	}
	*/
	if (sm2_point_mul(out, key->private_key, peer_public) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_ecdh(const SM2_KEY *key, const uint8_t *peer_public, size_t peer_public_len, SM2_POINT *out)
{
	SM2_POINT point;

	if (!key || !peer_public || !peer_public_len || !out) {
		error_print();
		return -1;
	}
	if (sm2_point_from_octets(&point, peer_public, peer_public_len) != 1) {
		error_print();
		return -1;
	}
	if (sm2_do_ecdh(key, &point, out) != 1) {
		error_print();
		return -1;
	}
	return 1;
}
