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
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <openmp.h>
#include <gmssl/sm4.h>


int main(int argc, char **argv)
{
	SM4_KEY sm4_key;
	unsigned char user_key[16] = {
		0x11,  0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x11,  0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	};
	size_t buflen = SM4_BLOCK_SIZE * 8 * 3 * 1000 * 1000;
	unsigned char *buf = NULL;
	unsigned char *p;
	int i;


	if (!(buf = (unsigned char *)malloc(buflen))) {
		fprintf(stderr, "malloc failed\n");
		return -1;
	}

	sm4_set_encrypt_key(&sm4_key, user_key);

	#pragma omp parallel for
	for (i = 0, p = buf; i < buflen/(SM4_BLOCK_SIZE * 16); i++, p += SM4_BLOCK_SIZE * 16) {
		sm4_encrypt_16blocks(&sms4_key, p, p);
	}

	return 0;
}

