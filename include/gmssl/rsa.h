/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#ifndef GMSSL_RSA_H
#define GMSSL_RSA_H


#include <stdio.h>
#include <string.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


/*
RSAPublicKey ::= SEQUENCE {
	modulus			INTEGER,  -- n
	publicExponent		INTEGER   -- e
}

RSAPrivateKey ::= SEQUENCE {
	version			INTEGER, -- 0
	modulus			INTEGER, -- n
	publicExponent		INTEGER, -- e
	privateExponent		INTEGER, -- d
	prime1			INTEGER, -- p
	prime2			INTEGER, -- q
	exponent1		INTEGER, -- d mod (p-1)
	exponent2		INTEGER, -- d mod (q-1)
	coefficient		INTEGER  -- q^-1 mod p
}
*/


int rsa_public_key_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);






#ifdef __cplusplus
}
#endif
#endif
