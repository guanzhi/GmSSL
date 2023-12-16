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
#include <gmssl/sdf.h>
#include <gmssl/error.h>


int main(void)
{
	int ret = -1;
	char *so_path = "libsdf_dummy.so";
	SDF_DEVICE dev;

	SDF_KEY sign_key;
	int key_index = 0;
	char *key_pass = "P@ssw0rd";

	uint8_t dgst[32];
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;

	if (sdf_load_library(so_path, NULL) != 1) {
		error_print();
		return -1;
	}

	if (sdf_open_device(&dev) != 1) {
		error_print();
		goto err;
	}

	if (sdf_load_sign_key(&dev, &sign_key, key_index, key_pass) != 1) {
		error_print();
		goto err;
	}

	if (sdf_sign(&sign_key, dgst, sig, &siglen) != 1) {
		error_print();
		goto err;
	}

#if 0
	// TODO: verify_key ...
	if (sm2_verify(&verify_key, dgst, sig, siglen) != 1) {
		error_print();
		goto err;
	}
#endif

	ret = 0;

err:
	sdf_release_key(&sign_key);
	sdf_close_device(&dev);
	sdf_unload_library();
	return ret;
}
