/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/pem.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>


int main(void)
{
	X509_CERTIFICATE cert;
	for (;;) {
		int ret = x509_certificate_from_pem(&cert, stdin);
		if (ret < 0) {
			error_print();
			return -1;
		}
		if (ret == 0) {
			goto end;
		}
		fprintf(stdout, "Certificate\n");
		x509_certificate_print(stdout, &cert, 0, 0);
		x509_certificate_to_pem(&cert, stdout);
		fprintf(stdout, "\n");
	}
end:
	return 0;
}
