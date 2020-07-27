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
# include <openssl/rand.h>
# include "../crypto/sm9/sm9_lcl.h"

RAND_METHOD fake_rand;
const RAND_METHOD *old_rand = NULL;

static const char rnd_seed[] =
	"string to make the random number generator think it has entropy";
static const char *rnd_number = NULL;

static int fbytes(unsigned char *buf, int num)
{
	int ret = 0;
	BIGNUM *bn = NULL;

	if (!BN_hex2bn(&bn, rnd_number)) {
		goto end;
	}
	if (BN_num_bytes(bn) > num) {
		goto end;
	}
	memset(buf, 0, num);
	if (!BN_bn2bin(bn, buf + num - BN_num_bytes(bn))) {
		goto end;
	}
	ret = 1;
end:
	BN_free(bn);
	return ret;
}

static int change_rand(const char *hex)
{
	if (!(old_rand = RAND_get_rand_method())) {
		return 0;
	}

	fake_rand.seed		= old_rand->seed;
	fake_rand.cleanup	= old_rand->cleanup;
	fake_rand.add		= old_rand->add;
	fake_rand.status	= old_rand->status;
	fake_rand.bytes		= fbytes;
	fake_rand.pseudorand	= old_rand->bytes;

	if (!RAND_set_rand_method(&fake_rand)) {
		return 0;
	}

	rnd_number = hex;
	return 1;
}

static int restore_rand(void)
{
	rnd_number = NULL;
	if (!RAND_set_rand_method(old_rand))
		return 0;
	else	return 1;
}

static int hexequbin(const char *hex, const unsigned char *bin, size_t binlen)
{
	int ret = 0;
	char *buf = NULL;
	size_t i = 0;
	size_t buflen = binlen * 2 + 1;


	if (binlen * 2 != strlen(hex)) {
		return 0;
	}
	if (!(buf = malloc(binlen * 2 + 1))) {
		return 0;
	}
	for (i = 0; i < binlen; i++) {
		sprintf(buf + i*2, "%02X", bin[i]);
	}
	buf[buflen - 1] = 0;

	if (memcmp(hex, buf, binlen * 2) == 0) {
		ret = 1;
	}

	free(buf);
	return ret;
}

static int sm9test_sign(const char *id, const unsigned char *msg, size_t msglen,
	int use_test_vector)
{
	int ret = 0;
	SM9PublicParameters *mpk = NULL;
	SM9MasterSecret *msk = NULL;
	SM9PrivateKey *sk = NULL;
	unsigned char sig[256];
	size_t siglen = sizeof(sig);
	/* test vector */
	char *ks =	"0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4";
	char *Ppubs =	"04"
			"9F64080B3084F733E48AFF4B41B565011CE0711C5E392CFB0AB1B6791B94C408"
			"29DBA116152D1F786CE843ED24A3B573414D2177386A92DD8F14D65696EA5E32"
			"69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25"
			"41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF0730E75C05FB4E3216D";
	char *ID_A =	"Alice";
	char *dsA =	"04"
			"A5702F05CF1315305E2D6EB64B0DEB923DB1A0BCF0CAFF90523AC8754AA69820"
			"78559A844411F9825C109F5EE3F52D720DD01785392A727BB1556952B2B013D3";
	char *M =	"Chinese IBS standard";
	char *r =	"033C8616B06704813203DFD00965022ED15975C662337AED648835DC4B1CBE";
	char *h =	"823C4B21E4BD2DFE1ED92C606653E996668563152FC33F55D7BFBB9BD9705ADB";
	/*
	char *S =	"04"
			"73BF96923CE58B6AD0E13E9643A406D8EB98417C50EF1B29CEF9ADB48B6D598C"
			"856712F1C2E0968AB7769F42A99586AED139D5B8B3E15891827CC2ACED9BAA05";
	*/
	char *S_comp =	"03"
			"73BF96923CE58B6AD0E13E9643A406D8EB98417C50EF1B29CEF9ADB48B6D598C";

	if (use_test_vector) {
		id = ID_A;
		msg = (unsigned char *)M;
		msglen = strlen(M);

		/* generate master secret with test vector */
		change_rand(ks);
	}

	if (!SM9_setup(NID_sm9bn256v1, NID_sm9sign, NID_sm9hash1_with_sm3, &mpk, &msk)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	/* check msk->masterSecret == ks, msk->publicPpub == Ppubs */
	if (use_test_vector) {
		BIGNUM *masterSecret = NULL;
		if (!BN_hex2bn(&masterSecret, ks)) {
			ERR_print_errors_fp(stderr);
			goto end;
		}
		if (BN_cmp(masterSecret, msk->masterSecret) != 0) {
			fprintf(stderr, "%s %d: masterSecret failed\n", __FILE__, __LINE__);
			goto end;
		}

		if (!hexequbin(Ppubs, ASN1_STRING_get0_data(msk->pointPpub),
			ASN1_STRING_length(msk->pointPpub))) {
			fprintf(stderr, "%s %d: publicPoint failed\n", __FILE__, __LINE__);
			goto end;
		}
	}

	/* generate private key */
	if (!(sk = SM9_extract_private_key(msk, id, strlen(id)))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (use_test_vector) {
		/* check sk->privatePoint == dsA */
		if (!hexequbin(dsA, ASN1_STRING_get0_data(sk->privatePoint),
			ASN1_STRING_length(sk->privatePoint))) {
			fprintf(stderr, "%s %d: dsA for '%s' failed\n", __FILE__, __LINE__, id);
			goto end;
		}

		/* sign with test vector */
		change_rand(r);
	}

	if (!SM9_sign(NID_sm3, msg, msglen, sig, &siglen, sk)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (use_test_vector) {
		const unsigned char *p = sig;
		SM9Signature *sig = NULL;
		BIGNUM *bn = NULL;
		int err = 0;

		if (!(sig = d2i_SM9Signature(NULL, &p, siglen))) {
			ERR_print_errors_fp(stderr);
			goto end;
		}

		if (!BN_hex2bn(&bn, h)) {
			SM9Signature_free(sig);
			ERR_print_errors_fp(stderr);
			goto end;
		}

		if (BN_cmp(bn, sig->h) != 0) {
			fprintf(stderr, "%s %d: sig->h failed\n", __FILE__, __LINE__);
			err++;
		}

		if (!hexequbin(S_comp, ASN1_STRING_get0_data(sig->pointS),
			ASN1_STRING_length(sig->pointS))) {
			fprintf(stderr, "%s %d: sig->S failed\n", __FILE__, __LINE__);
			err++;
		}

		SM9Signature_free(sig);
		BN_free(bn);
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

	if (memcmp(SKA, SKB, sizeof(SKA)) != 0 || memcmp(SA, S2, sizeof(SA)) != 0) {
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
	int use_test_vector = 1;

	RAND_seed(rnd_seed, sizeof(rnd_seed));

#if SM9_TEST
	if (!rate_test()) {
		printf("sm9 rate pairing test failed\n");
		err++;
	} else
		printf("sm9 rate pairing test passed\n");
#endif

	if (!sm9test_sign(id, in, sizeof(in)-1, use_test_vector)) {
		printf("sm9 sign tests failed\n");
		err++;
	} else
		printf("sm9 sign tests passed\n");

	if (!sm9test_exch(id, "guan@pku.edu.cn")) {
		printf("sm9 exch tests failed\n");
		err++;
	} else
		printf("sm9 exch tests passed\n");

	if (!sm9test_wrap(id)) {
		printf("sm9 key wrap tests failed\n");
		err++;
	} else
		printf("sm9 key wrap tests passed\n");

	if (!sm9test_enc(id, in, sizeof(in)-1)) {
		printf("sm9 encrypt tests failed\n");
		err++;
	} else
		printf("sm9 encrypt tests passed\n");

	if (old_rand)
		restore_rand();
	return err;
}
#endif
