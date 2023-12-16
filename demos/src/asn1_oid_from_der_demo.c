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
	uint8_t der[] = { 0x06,0x06,0x2a,0x81,0x1c,0xcf,0x55,0x01 };
	uint32_t oid[32];
	size_t oid_num;
	const uint8_t *cp;
	size_t len;
	size_t i;

	cp = der;
	len = sizeof(der);
	if (asn1_object_identifier_from_der(oid, &oid_num, &cp, &len) != 1) {
		fprintf(stderr, "asn1_object_identifier_from_der() error\n");
		goto err;
	}

	printf("oid: ");
	for (i = 0; i < oid_num; i++) {
		printf("%u ", oid[i]);
	}
	printf("\n");

	ret = 0;
err:
	return ret;
}
