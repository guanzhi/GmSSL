/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <gmssl/passwd.h>
#include "passwd.h"


int gmssl_tool_read_password(const char *prog, const char *label,
	const char *file, char *pass, size_t passlen)
{
	char prompt[512];
	int len;

	if (!prog) prog = "gmssl";
	if (!label) label = "Password";

	if (file && file[0]) {
		len = snprintf(prompt, sizeof(prompt), "gmssl %s: %s '%s': ", prog, label, file);
	} else {
		len = snprintf(prompt, sizeof(prompt), "gmssl %s: %s: ", prog, label);
	}
	if (len < 0 || len >= (int)sizeof(prompt)) {
		return -1;
	}

	return gmssl_read_password(prompt, pass, passlen);
}

int gmssl_tool_get_password(const char *prog, const char *label,
	const char *file, char **pass, char *passbuf, size_t passlen)
{
	if (!pass || !passbuf) {
		return -1;
	}
	if (*pass) {
		return 1;
	}
	if (gmssl_tool_read_password(prog, label, file, passbuf, passlen) != 1) {
		return -1;
	}
	*pass = passbuf;
	return 1;
}
