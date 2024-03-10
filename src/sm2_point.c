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
#include <assert.h>
#include <gmssl/sm2.h>
#include <gmssl/sm2_z256.h>
#include <gmssl/mem.h>
#include <gmssl/asn1.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>


int sm2_point_is_on_curve(const SM2_POINT *P)
{
	SM2_Z256_POINT T;
	sm2_z256_point_from_bytes(&T, (const uint8_t *)P);

	if (sm2_z256_point_is_on_curve(&T) == 1) {
		return 1;
	} else {
		return 0;
	}
}

int sm2_point_is_at_infinity(const SM2_POINT *P)
{
	return mem_is_zero((uint8_t *)P, sizeof(SM2_POINT));
}

int sm2_point_from_x(SM2_POINT *P, const uint8_t x[32], int y_is_odd)
{

	SM2_Z256_POINT T;

	if (sm2_z256_point_from_x_bytes(&T, x, y_is_odd) != 1) {
		error_print();
		return -1;
	}

	sm2_z256_point_to_bytes(&T, (uint8_t *)P);
	return 1;
}

int sm2_point_from_xy(SM2_POINT *P, const uint8_t x[32], const uint8_t y[32])
{
	memcpy(P->x, x, 32);
	memcpy(P->y, y, 32);
	return sm2_point_is_on_curve(P);
}

int sm2_point_add(SM2_POINT *R, const SM2_POINT *P, const SM2_POINT *Q)
{
	SM2_Z256_POINT P_;
	SM2_Z256_POINT Q_;

	sm2_z256_point_from_bytes(&P_, (uint8_t *)P);
	sm2_z256_point_from_bytes(&Q_, (uint8_t *)Q);
	sm2_z256_point_add(&P_, &P_, &Q_);
	sm2_z256_point_to_bytes(&P_, (uint8_t *)R);

	return 1;
}

int sm2_point_sub(SM2_POINT *R, const SM2_POINT *P, const SM2_POINT *Q)
{
	SM2_Z256_POINT P_;
	SM2_Z256_POINT Q_;

	sm2_z256_point_from_bytes(&P_, (uint8_t *)P);
	sm2_z256_point_from_bytes(&Q_, (uint8_t *)Q);
	sm2_z256_point_sub(&P_, &P_, &Q_);
	sm2_z256_point_to_bytes(&P_, (uint8_t *)R);

	return 1;
}

int sm2_point_neg(SM2_POINT *R, const SM2_POINT *P)
{
	SM2_Z256_POINT P_;

	sm2_z256_point_from_bytes(&P_, (uint8_t *)P);
	sm2_z256_point_neg(&P_, &P_);
	sm2_z256_point_to_bytes(&P_, (uint8_t *)R);

	return 1;
}

int sm2_point_dbl(SM2_POINT *R, const SM2_POINT *P)
{
	SM2_Z256_POINT P_;

	sm2_z256_point_from_bytes(&P_, (uint8_t *)P);
	sm2_z256_point_dbl(&P_, &P_);
	sm2_z256_point_to_bytes(&P_, (uint8_t *)R);

	return 1;
}

int sm2_point_mul(SM2_POINT *R, const uint8_t k[32], const SM2_POINT *P)
{
	uint64_t _k[4];
	SM2_Z256_POINT _P;

	sm2_z256_from_bytes(_k, k);
	sm2_z256_point_from_bytes(&_P, (uint8_t *)P);
	sm2_z256_point_mul(&_P, _k, &_P);
	sm2_z256_point_to_bytes(&_P, (uint8_t *)R);

	memset(_k, 0, sizeof(_k));
	return 1;
}

int sm2_point_mul_generator(SM2_POINT *R, const uint8_t k[32])
{
	uint64_t _k[4];
	SM2_Z256_POINT _R;

	sm2_z256_from_bytes(_k, k);
	sm2_z256_point_mul_generator(&_R, _k);
	sm2_z256_point_to_bytes(&_R, (uint8_t *)R);

	memset(_k, 0, sizeof(_k));
	return 1;
}

int sm2_point_mul_sum(SM2_POINT *R, const uint8_t k[32], const SM2_POINT *P, const uint8_t s[32])
{
	uint64_t _k[4];
	SM2_Z256_POINT _P;
	uint64_t _s[4];

	sm2_z256_from_bytes(_k, k);
	sm2_z256_point_from_bytes(&_P, (uint8_t *)P);
	sm2_z256_from_bytes(_s, s);
	sm2_z256_point_mul_sum(&_P, _k, &_P, _s);
	sm2_z256_point_to_bytes(&_P, (uint8_t *)R);

	memset(_k, 0, sizeof(_k));
	memset(_s, 0, sizeof(_s));
	return 1;
}

int sm2_point_print(FILE *fp, int fmt, int ind, const char *label, const SM2_POINT *P)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	format_bytes(fp, fmt, ind, "x", P->x, 32);
	format_bytes(fp, fmt, ind, "y", P->y, 32);
	return 1;
}

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

int sm2_z256_point_from_octets(SM2_Z256_POINT *P, const uint8_t *in, size_t inlen)
{
	switch (*in) {
	case SM2_point_at_infinity:
		if (inlen != 1) {
			error_print();
			return -1;
		}
		sm2_z256_point_set_infinity(P);
		break;
	case SM2_point_compressed_y_even:
		if (inlen != 33) {
			error_print();
			return -1;
		}
		if (sm2_z256_point_from_x_bytes(P, in + 1, 0) != 1) {
			error_print();
			return -1;
		}
		break;
	case SM2_point_compressed_y_odd:
		if (inlen != 33) {
			error_print();
			return -1;
		}
		if (sm2_z256_point_from_x_bytes(P, in + 1, 1) != 1) {
			error_print();
			return -1;
		}
		break;
	case SM2_point_uncompressed:
		if (inlen != 65) {
			error_print();
			return -1;
		}
		sm2_z256_point_from_bytes(P, in + 1);
		if (sm2_z256_point_is_on_curve(P) != 1) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}

	return 1;
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

int sm2_point_from_hash(SM2_POINT *R, const uint8_t *data, size_t datalen)
{
	return 1;
}

