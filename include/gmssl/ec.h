/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_EC_H
#define GMSSL_EC_H

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmssl/oid.h>
#include <gmssl/asn1.h>


#ifdef __cplusplus
extern "C" {
#endif

/*
NamedCurve:
	OID_sm2
	OID_prime192v1
	OID_prime256v1
	OID_secp256k1
	OID_secp384r1
	OID_secp521r1
*/
const char *ec_named_curve_name(int curve);
int ec_named_curve_from_name(const char *name);
int ec_named_curve_to_der(int curve, uint8_t **out, size_t *outlen);
int ec_named_curve_from_der(int *curve, const uint8_t **in, size_t *inlen);

#ifdef __cplusplus
}
#endif
#endif
