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
# include <openssl/err.h>
# include <openssl/sm9.h>

static int sm9test_sign(const char *id, const unsigned char *msg, size_t msglen)
{
	int ret = 0;
	SM9PublicParameters *mpk = NULL;
	SM9MasterSecret *msk = NULL;
	SM9PrivateKey *sk = NULL;
	unsigned char sig[256];
	size_t siglen = sizeof(sig);

	if (!SM9_setup(NID_sm9bn256v1, NID_sm9sign, NID_sm9hash1_with_sm3, &mpk, &msk)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	if (!(sk = SM9_extract_private_key(msk, id, strlen(id)))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	if (!SM9_sign(NID_sm3, msg, sizeof(msg), sig, &siglen, sk)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	if (1 != SM9_verify(NID_sm3, msg, sizeof(msg), sig, siglen, mpk, id, strlen(id))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	
	ret = 1;
end:
	SM9PublicParameters_free(mpk);
	SM9MasterSecret_free(msk);
	SM9PrivateKey_free(sk);
	return ret;
}

static int sm9test_enc(const char *id, const unsigned char *data, size_t datalen)
{
	int ret = 0;
	SM9PublicParameters *mpk = NULL;
	SM9MasterSecret *msk = NULL;
	SM9PrivateKey *sk = NULL;
	unsigned char mbuf[1024] = {0};
	unsigned char cbuf[1024] = {0};
	size_t clen, mlen;

	if (!SM9_setup(NID_sm9bn256v1, NID_sm9encrypt, NID_sm9hash1_with_sm3, &mpk, &msk)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	if (!(sk = SM9_extract_private_key(msk, id, strlen(id)))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	if (!SM9_encrypt(NID_sm9encrypt_with_sm3_xor, data, datalen,
		cbuf, &clen, mpk, id, strlen(id))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	if (!SM9_decrypt(NID_sm9encrypt_with_sm3_xor, cbuf, clen,
		mbuf, &mlen, sk)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	if (mlen != datalen || memcmp(mbuf, data, datalen) != 0) {
		goto end;
	}

	ret = 1;
end:
	SM9PublicParameters_free(mpk);
	SM9MasterSecret_free(msk);
	SM9PrivateKey_free(sk);
	return ret;
}

int main(int argc, char **argv)
{
	int err = 0;
	char *id = "guanzhi1980@gmail.com";
	unsigned char in[] = "message to be signed or encrypted";

	if (!sm9test_sign(id, in, sizeof(in))) {
		err++;
	}
	if (!sm9test_enc(id, in, sizeof(in))) {
		err++;
	}

	return err;
}
#endif
