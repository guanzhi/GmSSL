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
#include <gmssl/file.h>
#include <gmssl/x509_crl.h>

// 为了这些demo，应该准备好测试的文件，而不是把文件都放在源代码里面
// 这样会更灵活一些

int main(int argc, char **argv)
{
	int ret = -1;

	uint8_t *crl;
	size_t crllen;
	char *cacert;
	size_t cacertlen;

	printf("Demo - Check if a Certificate has been revoked in a CRL\n");


126         if ((rv = x509_crl_verify_by_ca_cert(crl, crl_len, cacert, cacertlen, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID))) < 0) {
127                 fprintf(stderr, "%s: verification inner error\n", prog);
128                 goto end;
129         }






	ret = 0;
err:
	if (crl) free(crl);
	if (cacert) free(cacert);
	return ret;
}
