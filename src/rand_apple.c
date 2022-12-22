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
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <Security/Security.h> // clang -framework Security


int rand_bytes(uint8_t *buf, size_t len)
{
	int errCode;
	if ((errCode = SecRandomCopyBytes(kSecRandomDefault, len, buf)) != errSecSuccess) {
		error_print();
		fprintf(stderr, "%s:%d: SecRandomCopyBytes() return OSStatus = %d\n", __FILE__, __LINE__, errCode);
		/*
		CFStringRef errStr;
		errStr = SecCopyErrorMessageString(errCode, NULL);
		fprintf(stderr, "error: %s\n", CFStringGetCStringPtr(errStr, kCFStringEncodingMacRoman));
		CFRelease(errStr); // -framework CoreFoundation
		*/
		return -1;
	}
	return 1;
}
