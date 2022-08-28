/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#include <gmssl/version.h>

int gmssl_version_num(void)
{
	return GMSSL_VERSION_NUM;
}

const char *gmssl_version_str(void)
{
	return GMSSL_VERSION_STR;
}
