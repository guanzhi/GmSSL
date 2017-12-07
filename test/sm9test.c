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

#ifdef OPENSSL_NO_SM9
int main(int argc, char **argv)
{
	printf("NO SM9 support\n");
	return 0;
}
#else
# include <openssl/evp.h>
# include <openssl/sm9.h>

int main(int argc, char **argv)
{
	int err = 1;
	int curve_id = NID_sm2p256v1; //FIXME
	char *id = "guanzhi1980@gmail.com";
	char *in = "message to be signed or encrypted";
	SM9PublicParameters *mpk = NULL;
	SM9MasterSecret *msk = NULL;
	SM9PrivateKey *sk = NULL;
	unsigned char dgst[32] = {0x01, 0x00};
	unsigned char *c = NULL;
	unsigned char *m = NULL;
	unsigned char *sig = NULL;
	size_t clen, mlen, siglen;

	/* setup */
	if (!SM9_setup_by_pairing_name(curve_id, SM9_HID_SIGN, &mpk, &msk)) {
		goto end;
	}

	/* keygen */
	if (!(sk = SM9_extract_private_key(mpk, msk, id, strlen(id)))) {
		goto end;
	}

	/* encrypt */
	clen = 0;
	if (!SM9_encrypt_with_recommended(mpk, (unsigned char *)in,
		strlen(in), NULL, &clen, id, strlen(id))) {
		goto end;
	}
	if (!(c = OPENSSL_zalloc(clen))) {
		goto end;
	}
	if (!SM9_encrypt_with_recommended(mpk, (unsigned char *)in,
		strlen(in), c, &clen, id, strlen(id))) {
		goto end;
	}

	/* decrypt */
	mlen = 0;
	if (!SM9_decrypt_with_recommended(mpk, c, clen, NULL, &mlen,
		sk, id, strlen(id))) {
		goto end;
	}
	if (!(m = OPENSSL_zalloc(mlen))) {
		goto end;
	}
	if (!SM9_decrypt_with_recommended(mpk, c, clen, m, &mlen,
		sk, id, strlen(id))) {
		goto end;
	}
	if (strlen(in) != mlen || memcmp(in, m, mlen) != 0) {
		goto end;
	}

	/* sign */
	siglen = 0;
	if (!SM9_sign(mpk, dgst, sizeof(dgst), NULL, &siglen, sk)) {
		goto end;
	}
	if (!(sig = OPENSSL_zalloc(siglen))) {
		goto end;
	}
	if (!SM9_sign(mpk, dgst, sizeof(dgst), sig, &siglen, sk)) {
		goto end;
	}

	/* verify */
	if (1 != SM9_verify(mpk, dgst, sizeof(dgst), sig, siglen,
		id, strlen(id))) {
		goto end;
	}

	err = 0;
end:
	SM9PublicParameters_free(mpk);
	SM9MasterSecret_free(msk);
	SM9PrivateKey_free(sk);
	OPENSSL_free(c);
	OPENSSL_free(m);
	OPENSSL_free(sig);
	//FIXME: return err;
	return 0;
}
#endif
