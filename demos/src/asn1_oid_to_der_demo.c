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
#include <gmssl/oid.h>
#include <gmssl/asn1.h>


int main(int argc, char **argv)
{
	int ret = -1;
	uint32_t oid[] = {1,2,156,10197,1};
	uint8_t buf[64];
	uint8_t *p;
	size_t len;
	size_t i;

	p = buf;
	len = 0;
	if (asn1_object_identifier_to_der(oid, sizeof(oid)/sizeof(oid[0]), &p, &len) != 1) {
		fprintf(stderr, "asn1_object_identifier_to_der() error\n");
		goto err;
	}

	printf("oid: ");
	for (i = 0; i < sizeof(oid)/sizeof(oid[0]); i++) {
		printf("%u ", oid[i]);
	}
	printf("\n");

	printf("der: ");
	for (i = 0; i < len; i++) {
		printf("%02x ", buf[i]);
	}
	printf("\n");

	ret = 0;
err:
	return ret;
}
