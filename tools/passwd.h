/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_TOOL_PASSWD_H
#define GMSSL_TOOL_PASSWD_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif


#define GMSSL_PASSWORD_MAX_SIZE 256

int gmssl_tool_read_password(const char *prog, const char *label,
	const char *file, char *pass, size_t passlen, int do_confirm);
int gmssl_tool_get_password(const char *prog, const char *label,
	const char *file, char **pass, char *passbuf, size_t passlen, int do_confirm);


#ifdef __cplusplus
}
#endif
#endif
