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
#include <limits.h>
#include <windows.h>
#include <wincrypt.h>
#include <gmssl/error.h>


int rand_bytes(uint8_t *buf, size_t len)
{
	HCRYPTPROV hCryptProv;
	int ret = -1;

	if (!buf) {
		error_print();
		return -1;
	}
	if (len > INT_MAX) {
		error_print();
		return -1;
	}
	if (CryptAcquireContextA(&hCryptProv, NULL, NULL, PROV_RSA_FULL,
		CRYPT_VERIFYCONTEXT|CRYPT_SILENT) != TRUE) {
		error_print();
		return -1;
	}
	if (CryptGenRandom(hCryptProv, (DWORD)len, buf) != TRUE) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (CryptReleaseContext(hCryptProv, 0) != TRUE) {
		error_print();
		ret = -1;
	}
	return ret;
}
