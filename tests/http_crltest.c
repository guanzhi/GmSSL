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
#include <gmssl/x509_alg.h>
#include <gmssl/x509_crl.h>
#include <gmssl/x509_ext.h>
#include <gmssl/x509.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>


static int test_x509_crl_new_from_uri(void)
{
	char *tests[] = {
		"http://crl.microsoft.com/pki/mscorp/crl/Microsoft%20RSA%20TLS%20CA%2002.crl", // from bing.com entity-cert
		"http://crl3.digicert.com/Omniroot2025.crl", // from bing.com mid-CA cert
		"http://crl.globalsign.com/gsrsaovsslca2018.crl", // from baidu.com entity cert
		"http://crl.globalsign.com/root-r3.crl", // from baidu.com mid-CA cert
		"http://crl.globalsign.com/gs/gsorganizationvalsha2g2.crl", // from taobao.com entity cert
	};
	size_t i;

	uint8_t *crl = NULL;
	size_t crl_len;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (x509_crl_new_from_uri(&crl, &crl_len, tests[i], strlen(tests[i])) != 1) {
			error_print();
			fprintf(stderr, "test %zu: %s\n", i, tests[i]);
			return -1;
		}
		x509_crl_print(stderr, 0, 0, "CRL", crl, crl_len);
		fprintf(stderr, "\n\n");
		free(crl);
		crl = NULL;
	}
	return 1;
}

int main(void)
{
	if (test_x509_crl_new_from_uri() != 1) { error_print(); return -1; }

	printf("%s all tests passed\n", __FILE__);
	return 0;
}
