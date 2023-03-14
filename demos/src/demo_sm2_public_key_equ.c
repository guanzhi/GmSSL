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
#include <gmssl/mem.h>
#include <gmssl/sm2.h>

int main(void){
	SM2_KEY sm2_key;
	SM2_KEY pub_key;

	printf("Read SM2 public key1 file (PEM) from stdin ...\n");

	if (sm2_public_key_info_from_pem(&sm2_key, stdin) != 1) {
		fprintf(stderr, "error\n");
		return 1;
	}

	printf("Read SM2 public key2 file (PEM) from stdin ...\n");

	if (sm2_public_key_info_from_pem(&pub_key, stdin) != 1) {
		fprintf(stderr, "error\n");
		return 1;
	}
	
	if (sm2_public_key_equ(&sm2_key, &pub_key) == 1) {
		printf("equal\n");
	} else {
		printf("not equal\n");
	}
	
	gmssl_secure_clear(&sm2_key, sizeof(sm2_key));
	gmssl_secure_clear(&pub_key, sizeof(pub_key));
	return 0;
}
