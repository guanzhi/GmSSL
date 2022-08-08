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
#include <gmssl/ec.h>
#include <gmssl/error.h>


#define oid_sm_scheme 1,2,156,10197,1
static uint32_t oid_sm2[] = { oid_sm_scheme,301 };

#define oid_x9_62_curves oid_x9_62,3
#define oid_x9_62_prime_curves oid_x9_62_curves,1
static uint32_t oid_prime192v1[] = { oid_x9_62_prime_curves,1 };
static uint32_t oid_prime256v1[] = { oid_x9_62_prime_curves,7 }; // NIST P-256

#define oid_secg_curve 1,3,132,0
static uint32_t oid_secp256k1[] = { oid_secg_curve,10 };
static uint32_t oid_secp384r1[] = { oid_secg_curve,34 }; // NIST P-384
static uint32_t oid_secp521r1[] = { oid_secg_curve,35 }; // NIST P-521


static const ASN1_OID_INFO ec_named_curves[] = {
	{ OID_sm2, "sm2p256v1", oid_sm2, sizeof(oid_sm2)/sizeof(int), 0, "SM2" },
	{ OID_prime192v1, "prime192v1", oid_prime192v1, sizeof(oid_prime192v1)/sizeof(int), 0, },
	{ OID_prime256v1, "prime256v1", oid_prime256v1, sizeof(oid_prime256v1)/sizeof(int), 0, "NIST P-256" },
	{ OID_secp256k1, "secp256k1", oid_secp256k1, sizeof(oid_secp256k1)/sizeof(int) },
	{ OID_secp384r1, "secp384r1", oid_secp384r1, sizeof(oid_secp384r1)/sizeof(int), 0, "NIST P-384" },
	{ OID_secp521r1, "secp521r1", oid_secp521r1, sizeof(oid_secp521r1)/sizeof(int), 0, "NIST P-521" }
};

static const int ec_named_curves_count =
	sizeof(ec_named_curves)/sizeof(ec_named_curves[0]);

const char *ec_named_curve_name(int oid)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(ec_named_curves, ec_named_curves_count, oid))) {
		error_print();
		return NULL;
	}
	return info->name;
}

int ec_named_curve_from_name(const char *name)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_name(ec_named_curves, ec_named_curves_count, name))) {
		error_print();
		return OID_undef;
	}
	return info->oid;
}

int ec_named_curve_to_der(int oid, uint8_t **out, size_t *outlen)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(ec_named_curves, ec_named_curves_count, oid))) {
		error_print();
		return -1;
	}
	if (asn1_object_identifier_to_der(info->nodes, info->nodes_cnt, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int ec_named_curve_from_der(int *oid, const uint8_t **in, size_t *inlen)
{
	int ret;
	const ASN1_OID_INFO *info;
	if ((ret = asn1_oid_info_from_der(&info, ec_named_curves, ec_named_curves_count, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else *oid = -1;
		return ret;
	}
	*oid = info->oid;
	return 1;
}

int ec_point_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;

	if (asn1_octet_string_from_der(&p, &len, &d, &dlen) != 1) goto err;
	format_bytes(fp, fmt, ind, label, p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int ec_private_key_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret;
	const uint8_t *a;
	size_t alen;
	const uint8_t *p;
	size_t len;
	int val;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_int_from_der(&val, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "version: %d\n", val);
	if (asn1_octet_string_from_der(&p, &len, &d, &dlen) != 1) goto err;
	format_bytes(fp, fmt, ind, "privateKey", p, len);
	if ((ret = asn1_explicit_from_der(0, &a, &alen, &d, &dlen)) < 0) goto err;
	else if (ret) {
		if (ec_named_curve_from_der(&val, &a, &alen) != 1) goto err;
		format_print(fp, fmt, ind, "parameters: %s\n", ec_named_curve_name(val));
		if (asn1_length_is_zero(alen) != 1) goto err;
	}
	format_print(fp, fmt, ind, "publicKey\n");
	ind += 4;
	if ((ret = asn1_explicit_from_der(1, &a, &alen, &d, &dlen)) < 0) goto err;
	else if (ret) {
		if (asn1_bit_octets_from_der(&p, &len, &a, &alen) != 1) goto err;
		format_bytes(fp, fmt, ind, "ECPoint", p, len);
		if (asn1_length_is_zero(alen) != 1) goto err;
	}
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}
