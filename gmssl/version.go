/*
 * Copyright 2020 The Hyperledger-TWGC Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* +build cgo */
package gmssl

/*
#include <openssl/crypto.h>
*/
import "C"

func GetVersions() []string {
	versions := []string{
		"GmSSL Go API 1.6  Aug 7 2018",
		C.GoString(C.OpenSSL_version(C.OPENSSL_VERSION)),
		C.GoString(C.OpenSSL_version(C.OPENSSL_BUILT_ON)),
		C.GoString(C.OpenSSL_version(C.OPENSSL_CFLAGS)),
		C.GoString(C.OpenSSL_version(C.OPENSSL_PLATFORM)),
		C.GoString(C.OpenSSL_version(C.OPENSSL_DIR)),
		C.GoString(C.OpenSSL_version(C.OPENSSL_ENGINES_DIR)),
	}
	return versions
}
