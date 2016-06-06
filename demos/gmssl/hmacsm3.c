/* demo/gmssl/sm3hmac.c */
/* ====================================================================
 * Copyright (c) 2014 - 2015 The GmSSL Project.  All rights reserved.
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
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

int main(int argc, char **argv)
{
	int ret = -1;
	FILE *fp = stdin;
	unsigned char key[32];
	unsigned char buf[1024];
	int len;
	const EVP_MD *md;
	HMAC_CTX hmctx;
	unsigned char mac[EVP_MAX_MD_SIZE];
	unsigned int maclen, i;

	if (argc == 2) {
		if (!(fp = fopen(argv[1], "r"))) {
			fprintf(stderr, "open file %s failed\n", argv[1]);
			return -1;
		}
	}

	HMAC_CTX_init(&hmctx);

	RAND_bytes(key, sizeof(key));

	OpenSSL_add_all_digests();
	if (!(md = EVP_get_digestbyname("sm3"))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	HMAC_Init_ex(&hmctx, key, sizeof(key), md, NULL);

	while ((len = fread(buf, 1, sizeof(buf), fp))) {
		HMAC_Update(&hmctx, buf, len);
	}

	HMAC_Final(&hmctx, mac, &maclen);

	for (i = 0; i < maclen; i++) {
		printf("%02x", mac[i]);
	}
	printf("\n");
	ret = 0;

end:
	fclose(fp);
	HMAC_CTX_cleanup(&hmctx);
	EVP_cleanup();
	return ret;
}

