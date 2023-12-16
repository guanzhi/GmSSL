/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
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


int main(void)
{
//	Alice						Bob

	SM2_KEY alice_ecdhe;				SM2_KEY bob_ecdhe;
	uint8_t alice_public[65];			uint8_t bob_public[65];
	SM2_POINT alice_share_point;			SM2_POINT bob_share_point;
	SM3_KDF_CTX alice_ctx;				SM3_KDF_CTX bob_ctx;
	uint8_t alice_share_key[32];			uint8_t bob_share_key[32];


	sm2_key_generate(&alice_ecdhe);			sm2_key_generate(&bob_ecdhe);


	sm2_point_to_uncompressed_octets(
		&alice_ecdhe.public_key,
		alice_public);
//	                              alice_public
//	                         ====================>
							sm2_point_to_uncompressed_octets(
								&bob_ecdhe.public_key,
								bob_public);

							if (sm2_ecdh(&bob_ecdhe,
								alice_public, sizeof(alice_public),
								&bob_share_point) != 1) {
								fprintf(stderr, "bob error\n");
								goto err;
							}
							sm3_kdf_init(&bob_ctx, 32);
							sm3_kdf_update(&bob_ctx,
								(uint8_t *)&bob_share_point, sizeof(SM2_POINT));
							sm3_kdf_finish(&bob_ctx, bob_share_key);
//	                               bob_public
//	                         <====================

	if (sm2_ecdh(&alice_ecdhe,
		bob_public, sizeof(bob_public),
		&alice_share_point) != 1) {
		fprintf(stderr, "Alice failed\n");
		goto err;
	}

	sm3_kdf_init(&alice_ctx, 32);
	sm3_kdf_update(&alice_ctx, (uint8_t *)&alice_share_point, sizeof(SM2_POINT));
	sm3_kdf_finish(&alice_ctx, alice_share_key);

err:
	// FIXME: clean all
	return 0;
}
