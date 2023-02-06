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
#include <gmssl/sm9.h>


int main(void)
{
	SM9_SIGN_MASTER_KEY sign_master;
	SM9_SIGN_KEY sign_key;

	sm9_sign_master_key_generate(&sign_master);

	printf("SM9 Master Secret\n");
	sm9_sign_master_key_info_encrypt_to_pem(&sign_master, "P@ssw0rd", stdout);

	printf("SM9 Public Parameters\n");
	sm9_sign_master_public_key_to_pem(&sign_master, stdout);

	sm9_sign_master_key_extract_key(&sign_master, "alice", strlen("alice"), &sign_key);

	printf("SM9 private key for ID '%s'\n", "alice");
	sm9_sign_key_info_encrypt_to_pem(&sign_key, "123456", stdout);

	return 0;
}
