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
	if (!SM9_sign(NID_sm3, msg, msglen, sig, &siglen, sk)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	ret = SM9_verify(NID_sm3, msg, msglen, sig, siglen, mpk, id, strlen(id));
	if (ret < 0) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

end:
	SM9PublicParameters_free(mpk);
	SM9MasterSecret_free(msk);
	SM9PrivateKey_free(sk);
	return ret;
}

static int sm9test_wrap(const char *id)
{
	int ret = 0;
	SM9PublicParameters *mpk = NULL;
	SM9MasterSecret *msk = NULL;
	SM9PrivateKey *sk = NULL;
	unsigned char key[56] = {0};
	unsigned char key2[56] = {0};
	unsigned char C[65];
	size_t Clen;

	if (!SM9_setup(NID_sm9bn256v1, NID_sm9encrypt, NID_sm9hash1_with_sm3, &mpk, &msk)) {
		goto end;
	}
	if (!(sk = SM9_extract_private_key(msk, id, strlen(id)))) {
		goto end;
	}
	if (!SM9_wrap_key(NID_sm9kdf_with_sm3, key, sizeof(key), C, &Clen, mpk, id, strlen(id))) {
		goto end;
	}
	if (!SM9_unwrap_key(NID_sm9kdf_with_sm3, key2, sizeof(key2), C, sizeof(C), sk)) {
		goto end;
	}
	if (memcmp(key, key2, sizeof(key2)) != 0) {
		goto end;
	}

	ret = 1;
end:
	SM9PublicParameters_free(mpk);
	SM9MasterSecret_free(msk);
	SM9PrivateKey_free(sk);
	return ret;

}

static int sm9test_exch(const char *idA, const char *idB)
{
	int ret = 0;
	SM9PublicParameters *mpk = NULL;
	SM9MasterSecret *msk = NULL;
	SM9PrivateKey *skA = NULL;
	SM9PrivateKey *skB = NULL;
	BIGNUM *rA = BN_new();
	BIGNUM *rB = BN_new();
	unsigned char RA[65];
	unsigned char RB[65];
	unsigned char gA[384];
	unsigned char gB[384];
	size_t RAlen = sizeof(RA);
	size_t RBlen = sizeof(RB);
	size_t gAlen = sizeof(gA);
	size_t gBlen = sizeof(gB);
	int type = NID_sm9kdf_with_sm3;
	unsigned char SKA[16];
	unsigned char SKB[16];
	unsigned char SA[32];
	unsigned char SB[32];
	unsigned char S2[32];

	if (!SM9_setup(NID_sm9bn256v1, NID_sm9keyagreement, NID_sm9hash1_with_sm3, &mpk, &msk)
		|| !(skA = SM9_extract_private_key(msk, idA, strlen(idA)))
		|| !(skB = SM9_extract_private_key(msk, idB, strlen(idB)))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!SM9_generate_key_exchange(RA, &RAlen, rA, gA, &gAlen, idB, strlen(idB), skA, 1)
		|| !SM9_generate_key_exchange(RB, &RBlen, rB, gB, &gBlen, idA, strlen(idA), skB, 0)
		|| !SM9_compute_share_key_B(type, SKB, sizeof(SKB), SB, S2, rB, RB, RA, gB, idA, strlen(idA), skB)
		|| !SM9_compute_share_key_A(type, SKA, sizeof(SKA), SA, SB, rA, RA, RB, gA, idB, strlen(idB), skA)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (memcmp(SKA, SKA, sizeof(SKA)) != 0 || memcmp(SA, S2, sizeof(SA)) != 0) {
		goto end;
	}

	ret = 1;
end:
	BN_free(rA);
	BN_free(rB);
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

	if (!sm9test_sign(id, in, sizeof(in)-1)) {
		printf("sm9 sign tests failed\n");
		err++;
	}
	printf("sm9 sign tests passed\n");

	if (!sm9test_exch(id, "guan@pku.edu.cn")) {
		printf("sm9 exch tests failed\n");
		err++;
	}
	printf("sm9 exch tests passed\n");

	if (!sm9test_wrap(id)) {
		printf("sm9 key wrap tests failed\n");
		err++;
	}
	printf("sm9 key wrap tests passed\n");

	if (!sm9test_enc(id, in, sizeof(in)-1)) {
		printf("sm9 encrypt tests failed\n");
		err++;
	}
	printf("sm9 encrypt tests passed\n");

	return err;
}
#endif
