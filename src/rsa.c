/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <gmssl/rsa.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>


int rsa_public_key_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen)
{
	const uint8_t *d;
	size_t dlen;
	const uint8_t *p;
	size_t len;
	int val;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	if (asn1_sequence_from_der(&d, &dlen, &a, &alen) != 1) goto err;
	if (asn1_integer_from_der(&p, &len, &d, &dlen) != 1) goto err;
	format_bytes(fp, fmt, ind, "modulus", p, len);
	if (asn1_int_from_der(&val, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "publicExponent: %d\n",val);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	if (asn1_length_is_zero(alen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}
