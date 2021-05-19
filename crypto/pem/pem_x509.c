/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <gmssl/bio.h>
#include <gmssl/evp.h>
#include <gmssl/x509.h>
#include <gmssl/pkcs7.h>
#include <gmssl/pem.h>

IMPLEMENT_PEM_rw(X509, X509, PEM_STRING_X509, X509)
