/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_PASSWD_H
#define GMSSL_PASSWD_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif


int gmssl_read_password(const char *prompt, char *pass, size_t passlen);


#ifdef __cplusplus
}
#endif
#endif
