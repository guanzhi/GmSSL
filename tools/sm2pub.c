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
#include <unistd.h>
#include <gmssl/sm2.h>
#include <gmssl/pem.h>
#include <gmssl/pkcs8.h>
#include <gmssl/error.h>

// 输入一个PKCS #8 加密格式的私钥，输出一个EC公钥


int main(void)
{
	SM2_KEY key;
	char *pass = NULL;
	char passbuf[64] = {0};

	pass = getpass("Encryption Password : ");
	strncpy(passbuf, pass, sizeof(passbuf));
	pass = getpass("Encryption Password (Again) : ");
	if (strcmp(passbuf, pass) != 0) {
		fprintf(stderr, "error: passwords not match\n");
		return -1;
	}

	sm2_keygen(&key);
	sm2_enced_private_key_info_to_pem(&key, pass, stdout);

	return 0;
}
