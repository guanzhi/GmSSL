/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm2.h>
#include <gmssl/pem.h>
#include <gmssl/oid.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/pbkdf2.h>
#include <gmssl/digest.h>
#include <gmssl/sm4.h>
#include <gmssl/rand.h>
#include <gmssl/x509_alg.h>


static const uint32_t oid_hmac_sm3[] = { oid_sm_algors,401,2 };
static const size_t oid_hmac_sm3_cnt = sizeof(oid_hmac_sm3)/sizeof(oid_hmac_sm3[0]);

char *pbkdf2_prf_name(int oid)
{
	switch (oid) {
	case OID_hmac_sm3: return "hmac-sm3";
	}
	return NULL;
}

int pbkdf2_prf_from_name(const char *name)
{
	if (strcmp(name, "hmac-sm3") == 0) {
		return OID_hmac_sm3;
	}
	return 0;
}

int pbkdf2_prf_to_der(int oid, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (oid == -1)
		return 0;

	if (oid != OID_hmac_sm3) {
		error_print();
		return -1;
	}
	if (asn1_object_identifier_to_der(oid_hmac_sm3, oid_hmac_sm3_cnt, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(oid_hmac_sm3, oid_hmac_sm3_cnt, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int pbkdf2_prf_from_der(int *oid, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	uint32_t nodes[32];
	size_t nodes_cnt;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else *oid = -1;
		return ret;
	}
	if (asn1_object_identifier_from_der(nodes, &nodes_cnt, &d, &dlen) != 1
		|| asn1_object_identifier_equ(nodes, nodes_cnt, oid_hmac_sm3, oid_hmac_sm3_cnt) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	*oid = OID_hmac_sm3;
	return 1;
}

int pbkdf2_params_to_der(
	const uint8_t *salt, size_t saltlen,
	int iter,
	int keylen,
	int prf,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_octet_string_to_der(salt, saltlen, NULL, &len) != 1
		|| asn1_int_to_der(iter, NULL, &len) != 1
		|| asn1_int_to_der(keylen, NULL, &len) < 0
		|| pbkdf2_prf_to_der(prf, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_octet_string_to_der(salt, saltlen, out, outlen) != 1
		|| asn1_int_to_der(iter, out, outlen) != 1
		|| asn1_int_to_der(keylen, out, outlen) < 0
		|| pbkdf2_prf_to_der(prf, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int pbkdf2_params_from_der(
	const uint8_t **salt, size_t *saltlen,
	int *iter,
	int *keylen,
	int *prf,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_octet_string_from_der(salt, saltlen, &d, &dlen) != 1
		|| asn1_int_from_der(iter, &d, &dlen) != 1
		|| asn1_int_from_der(keylen, &d, &dlen) < 0
		|| pbkdf2_prf_from_der(prf, &d, &dlen) < 0
		|| asn1_check(*saltlen > 0) != 1
		|| asn1_check(*iter > 0) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int pbkdf2_params_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret;
	const uint8_t *p;
	size_t len;
	int val;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_octet_string_from_der(&p, &len, &d, &dlen) != 1) goto err;
	format_bytes(fp, fmt, ind, "salt", p, len);
	if (asn1_int_from_der(&val, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "iterationCount: %d\n", val);
	if ((ret = asn1_int_from_der(&val, &d, &dlen)) < 0) goto err;
	if (ret) format_print(fp, fmt, ind, "keyLength: %d\n", val);
	if ((ret = pbkdf2_prf_from_der(&val, &d, &dlen)) < 0) goto err;
	if (ret) format_print(fp, fmt, ind, "prf: %s\n", pbkdf2_prf_name(val));
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

static const uint32_t oid_pbkdf2[] = { oid_pkcs5,12 };
static const size_t oid_pbkdf2_cnt = sizeof(oid_pbkdf2)/sizeof(oid_pbkdf2[0]);

int pbkdf2_algor_to_der(
	const uint8_t *salt, size_t saltlen,
	int iter,
	int keylen,
	int prf,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_object_identifier_to_der(oid_pbkdf2, oid_pbkdf2_cnt, NULL, &len) != 1
		|| pbkdf2_params_to_der(salt, saltlen, iter, keylen, prf, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(oid_pbkdf2, oid_pbkdf2_cnt, out, outlen) != 1
		|| pbkdf2_params_to_der(salt, saltlen, iter, keylen, prf, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int pbkdf2_algor_from_der(
	const uint8_t **salt, size_t *saltlen,
	int *iter,
	int *keylen,
	int *prf,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	uint32_t nodes[32];
	size_t nodes_cnt;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_object_identifier_from_der(nodes, &nodes_cnt, &d, &dlen) != 1
		|| asn1_object_identifier_equ(nodes, nodes_cnt, oid_pbkdf2, oid_pbkdf2_cnt) != 1
		|| pbkdf2_params_from_der(salt, saltlen, iter, keylen, prf, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int pbkdf2_algor_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	uint32_t nodes[32];
	size_t nodes_cnt;
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_object_identifier_from_der(nodes, &nodes_cnt, &d, &dlen) != 1
		|| asn1_object_identifier_equ(nodes, nodes_cnt, oid_pbkdf2, oid_pbkdf2_cnt) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "algorithm: %s\n", "pbkdf2");
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	pbkdf2_params_print(fp, fmt, ind, "parameters", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int pbes2_enc_algor_to_der(int oid, const uint8_t *iv, size_t ivlen, uint8_t **out, size_t *outlen)
{
	if (oid != OID_sm4_cbc) {
		error_print();
		return -1;
	}
	if (x509_encryption_algor_to_der(oid, iv, ivlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int pbes2_enc_algor_from_der(int *oid, const uint8_t **iv, size_t *ivlen, const uint8_t **in, size_t *inlen)
{
	int ret;
	if ((ret = x509_encryption_algor_from_der(oid, iv, ivlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (*oid != OID_sm4_cbc) {
		error_print();
		return -1;
	}
	return 1;
}

int pbes2_enc_algor_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	return x509_encryption_algor_print(fp, fmt, ind, label, d, dlen);
}

int pbes2_params_to_der(
	const uint8_t *salt, size_t saltlen, int iter, int keylen, int prf,
	int cipher, const uint8_t *iv, size_t ivlen,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (pbkdf2_algor_to_der(salt, saltlen, iter, keylen, prf, NULL, &len) != 1
		|| pbes2_enc_algor_to_der(cipher, iv, ivlen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| pbkdf2_algor_to_der(salt, saltlen, iter, keylen, prf, out, outlen) != 1
		|| pbes2_enc_algor_to_der(cipher, iv, ivlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int pbes2_params_from_der(
	const uint8_t **salt, size_t *saltlen, int *iter, int *keylen, int *prf,
	int *cipher, const uint8_t **iv, size_t *ivlen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (pbkdf2_algor_from_der(salt, saltlen, iter, keylen, prf, &d, &dlen) != 1
		|| pbes2_enc_algor_from_der(cipher, iv, ivlen, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int pbes2_params_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	pbkdf2_algor_print(fp, fmt, ind, "keyDerivationFunc", p, len);
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	pbes2_enc_algor_print(fp, fmt, ind, "encryptionScheme", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}


static const uint32_t oid_pbes2[] = { oid_pkcs5,13 };
static const size_t oid_pbes2_cnt = sizeof(oid_pbes2)/sizeof(oid_pbes2[0]);

int pbes2_algor_to_der(
	const uint8_t *salt, size_t saltlen, int iter, int keylen, int prf,
	int cipher, const uint8_t *iv, size_t ivlen,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_object_identifier_to_der(oid_pbes2, oid_pbes2_cnt, NULL, &len) != 1
		|| pbes2_params_to_der(salt, saltlen, iter, keylen, prf, cipher, iv, ivlen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(oid_pbes2, oid_pbes2_cnt, out, outlen) != 1
		|| pbes2_params_to_der(salt, saltlen, iter, keylen, prf, cipher, iv, ivlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int pbes2_algor_from_der(
	const uint8_t **salt, size_t *saltlen, int *iter, int *keylen, int *prf,
	int *cipher, const uint8_t **iv, size_t *ivlen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	uint32_t nodes[32];
	size_t nodes_cnt;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_object_identifier_from_der(nodes, &nodes_cnt, &d, &dlen) != 1
		|| asn1_object_identifier_equ(nodes, nodes_cnt, oid_pbes2, oid_pbes2_cnt) != 1
		|| pbes2_params_from_der(salt, saltlen, iter, keylen, prf, cipher, iv, ivlen, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int pbes2_algor_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	uint32_t nodes[32];
	size_t nodes_cnt;
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_object_identifier_from_der(nodes, &nodes_cnt, &d, &dlen) != 1
		|| asn1_object_identifier_equ(nodes, nodes_cnt, oid_pbes2, oid_pbes2_cnt) != 1)
		goto err;
	format_print(fp, fmt, ind, "algorithm: %s\n", "pbes2");
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	pbes2_params_print(fp, fmt, ind, "parameters", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int pkcs8_enced_private_key_info_to_der(
	const uint8_t *salt, size_t saltlen, int iter, int keylen, int prf,
	int cipher, const uint8_t *iv, size_t ivlen,
	const uint8_t *enced, size_t encedlen,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (pbes2_algor_to_der(salt, saltlen, iter, keylen, prf, cipher, iv, ivlen, NULL, &len) != 1
		|| asn1_octet_string_to_der(enced, encedlen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| pbes2_algor_to_der(salt, saltlen, iter, keylen, prf, cipher, iv, ivlen, out, outlen) != 1
		|| asn1_octet_string_to_der(enced, encedlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int pkcs8_enced_private_key_info_from_der(
	const uint8_t **salt, size_t *saltlen, int *iter, int *keylen, int *prf,
	int *cipher, const uint8_t **iv, size_t *ivlen,
	const uint8_t **enced, size_t *encedlen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (pbes2_algor_from_der(salt, saltlen, iter, keylen, prf, cipher, iv, ivlen, &d, &dlen) != 1
		|| asn1_octet_string_from_der(enced, encedlen, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int pkcs8_enced_private_key_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	pbes2_algor_print(fp, fmt, ind, "encryptionAlgorithm", p, len);
	if (asn1_octet_string_from_der(&p, &len, &d, &dlen) != 1) goto err;
	format_bytes(fp, fmt, ind, "encryptedData", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}
