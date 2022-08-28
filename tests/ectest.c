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
#include <gmssl/ec.h>
#include <gmssl/error.h>


static int test_ec_named_curve(void)
{
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	char *curves[] = {
		"sm2p256v1",
		"prime192v1",
		"prime256v1",
		"secp256k1",
		"secp384r1",
		"secp521r1",
	};
	int oid;
	int i;

	for (i = 0; i < sizeof(curves)/sizeof(curves[0]); i++) {
		if ((oid = ec_named_curve_from_name(curves[i])) == OID_undef) {
			error_print();
			return -1;
		}
		if (ec_named_curve_to_der(oid, &p, &len) != 1) {
			error_print();
			return -1;
		}
	}

	for (i = 0; i < sizeof(curves)/sizeof(curves[0]); i++) {
		if (ec_named_curve_from_der(&oid, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (oid != ec_named_curve_from_name(curves[i])) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%s\n", ec_named_curve_name(oid));
	}
	(void)asn1_length_is_zero(len);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_ec_point_print(void)
{
	SM2_KEY sm2_key;
	uint8_t buf[256];
	uint8_t *p = buf;
	size_t len = 0;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}
	if (sm2_point_to_der(&(sm2_key.public_key), &p, &len) != 1) {
		error_print();
		return -1;
	}
	ec_point_print(stderr, 0, 4, "ECPoint", buf, len);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_ec_private_key_print(void)
{
	SM2_KEY sm2_key;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}
	if (sm2_private_key_to_der(&sm2_key, &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	ec_private_key_print(stderr, 0, 4, "ECPrivateKey", d, dlen);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_ec_named_curve() != 1) goto err;
	if (test_ec_point_print() != 1) goto err;
	if (test_ec_private_key_print() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return -1;
}
