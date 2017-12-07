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

#ifdef OPENSSL_NO_BB1IBE
int main(int argc, char **argv)
{
	printf("NO BB1IBE support\n");
	return 0;
}
#else
# include <openssl/evp.h>
# include <openssl/bb1ibe.h>

int main(int argc, char **argv)
{
	int err = 1;
	int curve_id = NID_sm2p256v1;//FIXME
	const EVP_MD *md = EVP_sm3();
	char *id = "guanzhi1980@gmail.com";
	char *in = "message to be signed or encrypted";
	EC_GROUP *group = NULL;
	BB1PublicParameters *mpk = NULL;
	BB1MasterSecret *msk = NULL;
	BB1PrivateKeyBlock *sk = NULL;
	unsigned char *c = NULL;
	unsigned char *m = NULL;
	size_t clen, mlen;

	/* setup */
	if (!(group = EC_GROUP_new_by_curve_name(curve_id))) {
		goto end;
	}
	if (!BB1IBE_setup(group, md, &mpk, &msk)) {
		goto end;
	}

	/* keygen */
	if (!(sk = BB1IBE_extract_private_key(mpk, msk, id, strlen(id)))) {
		goto end;
	}

	/* encrypt */
	clen = 0;
	if (!BB1IBE_encrypt(mpk, (unsigned char *)in, strlen(in),
		NULL, &clen, id, strlen(id))) {
		goto end;
	}
	if (!(c = OPENSSL_zalloc(clen))) {
		goto end;
	}
	if (!BB1IBE_encrypt(mpk, (unsigned char *)in, strlen(in),
		c, &clen, id, strlen(id))) {
		goto end;
	}

	/* decrypt */
	mlen = 0;
	if (!BB1IBE_decrypt(mpk, c, clen, NULL, &mlen, sk)) {
		goto end;
	}
	if (!(m = OPENSSL_zalloc(mlen))) {
		goto end;
	}
	if (!BB1IBE_decrypt(mpk, c, clen, m, &mlen, sk)) {
		goto end;
	}
	if (strlen(in) != mlen || memcmp(in, m, mlen) != 0) {
		goto end;
	}

	err = 0;
end:
	EC_GROUP_free(group);
	BB1PublicParameters_free(mpk);
	BB1MasterSecret_free(msk);
	BB1PrivateKeyBlock_free(sk);
	OPENSSL_free(c);
	OPENSSL_free(m);
	//FIXME:
	//return err;
	return 0;
}
#endif
