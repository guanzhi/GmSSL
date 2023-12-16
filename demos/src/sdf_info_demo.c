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

	if (sdf_load_library(so_path, NULL) != 1) {
		error_print();
		return -1;
	}

	if (sdf_open_device(&dev) != 1) {
		error_print();
		goto err;
	}

	sdf_print_device_info(stdout, 0, 0, "SDF Device Info", &dev);

	ret = 0;
err:
	sdf_close_device(&dev);
	sdf_unload_library();
	return ret;
}
