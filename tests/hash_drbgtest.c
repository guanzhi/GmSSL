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
#include <stdint.h>
#include <gmssl/hex.h>
#include <gmssl/digest.h>
#include <gmssl/hash_drbg.h>
#include <gmssl/error.h>


#define EntropyInput "212956390783381dbfc6362dd0da9a09"
#define Nonce "5280987fc5e27a49"
#define PersonalizationString ""
#define AdditionalInput	""
#define V0 "02b84eba8121ca090b6b66d3371609eaf76405a5c2807d80035c1a13dfed5aa18e536af599a7b3c68b2c56240ed11997f4048910d84604"
#define C0 "a677e4921587563eebe55d1b25e59c3f3d200bc61aaee665e7a6858c2857c45dba4bce8182252962ae86de491046a5e3450eec44938a0a"

#define AdditionalInput1 ""
#define EntropyInputPR1 "2edb396eeb8960f77943c2a59075a786"
#define V1 "f9afadfbbf2c3d1004f9baca38be247342e5fbb83281915d5de18beb963712a344e89bb0e6b925a7bbc32eadb8b441efc1fa0c649df42a"
#define C1 "1d41cbbd634909e4761c232fcfd6a6c2edf0a7f4d3d3c164f74a88955f355efce2d86c1e9fa897b7005ef9d4d3a51bf4fc0b805ab896c9"

#define PR1 "2edb396eeb8960f77943c2a59075a786"
#define PR2 "30b565b63a5012676940d3ef17d9e996"


int main(void)
{
// currently we only has SHA-1 test suites
#ifdef ENABLE_BROKEN_CRYPTO
	HASH_DRBG drbg;

	uint8_t entropy[sizeof(EntropyInput)/2];
	uint8_t nonce[sizeof(Nonce)/2];
	uint8_t personalstr[1 + sizeof(PersonalizationString)/2];
	uint8_t v[sizeof(V0)/2];
	uint8_t c[sizeof(C0)/2];
	uint8_t entropy_pr1[sizeof(EntropyInputPR1)/2];
	uint8_t pr1[sizeof(PR1)/2];
	uint8_t pr2[sizeof(PR2)/2];
	size_t entropy_len, nonce_len, personalstr_len, vlen, clen;
	size_t entropy_pr1len;
	size_t pr1_len, pr2_len;
	unsigned char out[640/8];
	int i;

	hex_to_bytes(EntropyInput, strlen(EntropyInput), entropy, &entropy_len);
	hex_to_bytes(Nonce, strlen(Nonce), nonce, &nonce_len);
	hex_to_bytes(PersonalizationString, strlen(PersonalizationString), personalstr, &personalstr_len);
	hex_to_bytes(V0, strlen(V0), v, &vlen);
	hex_to_bytes(C0, strlen(C0), c, &clen);
	hex_to_bytes(EntropyInputPR1, strlen(EntropyInputPR1), entropy_pr1, &entropy_pr1len);
	hex_to_bytes(PR1, strlen(PR1), pr1, &pr1_len);
	hex_to_bytes(PR2, strlen(PR2), pr2, &pr2_len);

	hash_drbg_init(&drbg, DIGEST_sha1(),
		entropy, entropy_len,
		nonce, nonce_len,
		personalstr, personalstr_len);

	printf("sha1_drbg test 1 ");
	if (drbg.seedlen != vlen
		|| memcmp(drbg.V, v, vlen) != 0
		|| memcmp(drbg.C, c, clen) != 0
		|| drbg.reseed_counter != 1) {
		printf("failed\n");
		return 1;
	} else {
		printf("ok\n");
	}

	hash_drbg_reseed(&drbg, pr1, pr1_len, NULL, 0);
	hash_drbg_generate(&drbg, NULL, 0, 640/8, out);

	hash_drbg_reseed(&drbg, pr2, pr2_len, NULL, 0);
	hash_drbg_generate(&drbg, NULL, 0, 640/8, out);

	for (i = 0; i < sizeof(out); i++) {
		printf("%02x", out[i]);
	}
	printf("\n");
#endif
	return 0;
}
