/* ====================================================================
 * Copyright (c) 2014 - 2016 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../e_os.h"

#ifdef OPENSSL_NO_ZUC
int main(int argc, char **argv)
{
	printf("NO ZUC support\n");
	return 0;
}
#else
# include <openssl/evp.h>
# include <openssl/zuc.h>

static int zuc_eia3_test1(void)
{
	unsigned char key[16] = {0};
	uint32_t count = 0;
	uint32_t bearer = 0;
	int direction = 0;
	uint32_t m[1] = {0};
	uint32_t mac1 = 0xc8a9595e;
	uint32_t mac2 = 0;

	eia3(key, count, bearer, direction, m, sizeof(m), &mac2);
	if (mac1 != mac2) {
		return 0;
	}

	return 1;
}

static int zuc_eia3_test2(int verbose)
{
	unsigned char key[16] = {
		0xc9, 0xe6, 0xce, 0xc4, 0x60, 0x7c, 0x72, 0xdb,
		0x00, 0x0a, 0xef, 0xa8, 0x83, 0x85, 0xab, 0x0a,
	};
	uint32_t count = 0xa94059da;
	uint32_t bearer = 0x0a;
	int direction = 1;
	int length = 241;
	uint32_t m[] = {
		0x01,
	};
	uint32_t mac1;
	uint32_t mac2;

	eia3(key, count, bearer, direction, m, sizeof(m), &mac2);
	if (mac1 != mac2) {
		return 0;
	}

	return 1;
}

int main(int argc, char **argv)
{
	int err = 0;


	return err;
}
#endif
