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

#ifdef OPENSSL_NO_SM2
int main(int argc, char **argv)
{
	printf("NO SM2 support\n");
	return 0;
}
#else
# include <openssl/bn.h>
# include <openssl/ec.h>
# include <openssl/evp.h>
# include <openssl/rand.h>
# include <openssl/engine.h>
# include <openssl/sm2.h>
# include "../crypto/sm2/sm2_lcl.h"

# define VERBOSE 1

RAND_METHOD fake_rand;
const RAND_METHOD *old_rand;

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
	size_t buflen = binlen * 2 + 1;
	size_t i = 0;


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

static EC_GROUP *new_ec_group(int is_prime_field,
	const char *p_hex, const char *a_hex, const char *b_hex,
	const char *x_hex, const char *y_hex, const char *n_hex, const char *h_hex)
{
	int ok = 0;
	EC_GROUP *group = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *p = NULL;
	BIGNUM *a = NULL;
	BIGNUM *b = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	BIGNUM *n = NULL;
	BIGNUM *h = NULL;
	EC_POINT *G = NULL;
	point_conversion_form_t form = SM2_DEFAULT_POINT_CONVERSION_FORM;
	int flag = 0;

	if (!(ctx = BN_CTX_new())) {
		goto err;
	}

	if (!BN_hex2bn(&p, p_hex) ||
	    !BN_hex2bn(&a, a_hex) ||
	    !BN_hex2bn(&b, b_hex) ||
	    !BN_hex2bn(&x, x_hex) ||
	    !BN_hex2bn(&y, y_hex) ||
	    !BN_hex2bn(&n, n_hex) ||
	    !BN_hex2bn(&h, h_hex)) {
		goto err;
	}

	if (is_prime_field) {
		if (!(group = EC_GROUP_new_curve_GFp(p, a, b, ctx))) {
			goto err;
		}
		if (!(G = EC_POINT_new(group))) {
			goto err;
		}
		if (!EC_POINT_set_affine_coordinates_GFp(group, G, x, y, ctx)) {
			goto err;
		}
	} else {
		if (!(group = EC_GROUP_new_curve_GF2m(p, a, b, ctx))) {
			goto err;
		}
		if (!(G = EC_POINT_new(group))) {
			goto err;
		}
		if (!EC_POINT_set_affine_coordinates_GF2m(group, G, x, y, ctx)) {
			goto err;
		}
	}

	if (!EC_GROUP_set_generator(group, G, n, h)) {
		goto err;
	}

	EC_GROUP_set_asn1_flag(group, flag);
	EC_GROUP_set_point_conversion_form(group, form);

	ok = 1;
err:
	BN_CTX_free(ctx);
	BN_free(p);
	BN_free(a);
	BN_free(b);
	BN_free(x);
	BN_free(y);
	BN_free(n);
	BN_free(h);
	EC_POINT_free(G);
	if (!ok && group) {
		ERR_print_errors_fp(stderr);
		EC_GROUP_free(group);
		group = NULL;
	}

	return group;
}

static EC_KEY *new_ec_key(const EC_GROUP *group,
	const char *sk, const char *xP, const char *yP)
{
	int ok = 0;
	EC_KEY *ec_key = NULL;
	BIGNUM *d = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;

	OPENSSL_assert(group);
	OPENSSL_assert(xP);
	OPENSSL_assert(yP);

	if (!(ec_key = EC_KEY_new())) {
		goto end;
	}
	if (!EC_KEY_set_group(ec_key, group)) {
		goto end;
	}

	if (sk) {
		if (!BN_hex2bn(&d, sk)) {
			goto end;
		}
		if (!EC_KEY_set_private_key(ec_key, d)) {
			goto end;
		}
	}

	if (xP && yP) {
		if (!BN_hex2bn(&x, xP)) {
			goto end;
		}
		if (!BN_hex2bn(&y, yP)) {
			goto end;
		}
		if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) {
			goto end;
		}
	}

	ok = 1;
end:
	if (d) BN_free(d);
	if (x) BN_free(x);
	if (y) BN_free(y);
	if (!ok && ec_key) {
		ERR_print_errors_fp(stderr);
		EC_KEY_free(ec_key);
		ec_key = NULL;
	}
	return ec_key;
}

static int test_sm2_sign(const EC_GROUP *group,
	const char *sk, const char *xP, const char *yP,
	const char *id, const char *Z,
	const char *M, const char *e,
	const char *k, const char *r, const char *s)
{
	int ret = 0;
	int verbose = VERBOSE;
	const EVP_MD *id_md = EVP_sm3();
	const EVP_MD *msg_md = EVP_sm3();
	int type = NID_undef;
	unsigned char dgst[EVP_MAX_MD_SIZE];
	size_t dgstlen;
	unsigned char sig[256];
	unsigned int siglen;
	const unsigned char *p;
	EC_KEY *ec_key = NULL;
	EC_KEY *pubkey = NULL;
	ECDSA_SIG *sm2sig = NULL;
	BIGNUM *rr = NULL;
	BIGNUM *ss = NULL;
	const BIGNUM *sig_r;
	const BIGNUM *sig_s;

	change_rand(k);

	if (!(ec_key = new_ec_key(group, sk, xP, yP))) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}

	if (verbose > 1) {
		EC_KEY_print_fp(stdout, ec_key, 4);
	}

	dgstlen = sizeof(dgst);
	if (!SM2_compute_id_digest(id_md, id, strlen(id), dgst, &dgstlen, ec_key)) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}

	if (verbose > 1) {
		size_t j;
		printf("id=%s\n", id);
		printf("zid(xx):");
		for (j = 0; j < dgstlen; j++) { printf("%02x", dgst[j]); } printf("\n");
	}

	if (!hexequbin(Z, dgst, dgstlen)) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}

	dgstlen = sizeof(dgst);
	if (!SM2_compute_message_digest(id_md, msg_md,
		(const unsigned char *)M, strlen(M), id, strlen(id),
		dgst, &dgstlen, ec_key)) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}
	if (!hexequbin(e, dgst, dgstlen)) {
		size_t i;
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);

		printf("%s\n", e);
		printf(" my: "); for (i = 0; i < dgstlen; i++) { printf("%02x", dgst[i]); } printf("\n");

		goto err;
	}


	/* sign */
	siglen = sizeof(sig);
	if (!SM2_sign(type, dgst, dgstlen, sig, &siglen, ec_key)) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}

	p = sig;
	if (!(sm2sig = d2i_ECDSA_SIG(NULL, &p, siglen))) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}
	if (!BN_hex2bn(&rr, r) || !BN_hex2bn(&ss, s)) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}

	ECDSA_SIG_get0(sm2sig, &sig_r, &sig_s);

	if (BN_cmp(sig_r, rr) || BN_cmp(sig_s, ss)) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}


	/* verify */
	if (!(pubkey = new_ec_key(group, NULL, xP, yP))) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}

	if (1 != SM2_verify(type, dgst, dgstlen, sig, siglen, pubkey)) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}

	ret = 1;
err:
	restore_rand();
	if (ec_key) EC_KEY_free(ec_key);
	if (pubkey) EC_KEY_free(pubkey);
	if (sm2sig) ECDSA_SIG_free(sm2sig);
	if (rr) BN_free(rr);
	if (ss) BN_free(ss);
	return ret;
}

static int test_sm2_enc(const EC_GROUP *group, const EVP_MD *md,
	const char *d, const char *xP, const char *yP,
	const char *M, const char *k, const char *C)
{
	int ret = 0;
	EC_KEY *pub_key = NULL;
	EC_KEY *pri_key = NULL;
	SM2CiphertextValue *cv = NULL;
	unsigned char *tbuf = NULL;
	long tlen;
	unsigned char mbuf[128] = {0};
	unsigned char cbuf[sizeof(mbuf) + 256] = {0};
	size_t mlen, clen;
	unsigned char *p;

	/* test encrypt */
	if (!(pub_key = new_ec_key(group, NULL, xP, yP))) {
		goto end;
	}

	change_rand(k);
	if (!(cv = SM2_do_encrypt(md, (unsigned char *)M, strlen(M), pub_key))) {
		goto end;
	}

	p = cbuf;
	if ((clen = i2o_SM2CiphertextValue(group, cv, &p)) <= 0) {
		goto end;
	}

	if (!(tbuf = OPENSSL_hexstr2buf(C, &tlen))) {
		EXIT(1);
	}

	if ((size_t)tlen != clen || memcmp(tbuf, cbuf, clen) != 0) {
		goto end;
	}

	/* test decrypt */
	if (!(pri_key = new_ec_key(group, d, xP, yP))) {
		goto end;
	}

	mlen = sizeof(mbuf);
	if (!SM2_do_decrypt(md, cv, mbuf, &mlen, pri_key)) {
		goto end;
	}

	if (mlen != strlen(M) || memcmp(mbuf, M, strlen(M))) {
		goto end;
	}

	ret = 1;

end:
	ERR_print_errors_fp(stderr);
	restore_rand();
	EC_KEY_free(pub_key);
	EC_KEY_free(pri_key);
	SM2CiphertextValue_free(cv);
	OPENSSL_free(tbuf);
	return ret;
}

static int test_sm2_kap(const EC_GROUP *group,
	const char *A, const char *dA, const char *xA, const char *yA, const char *ZA,
	const char *B, const char *dB, const char *xB, const char *yB, const char *ZB,
	const char *rA, const char *rB, const char *KAB, const char *S1, const char *S2)
{
	int ret = 0;
	EC_KEY *eckeyA = NULL;
	EC_KEY *eckeyB = NULL;
	EC_KEY *pubkeyA = NULL;
	EC_KEY *pubkeyB = NULL;
	SM2_KAP_CTX ctxA;
	SM2_KAP_CTX ctxB;
	unsigned char RA[256];
	unsigned char RB[256];
	size_t RAlen = sizeof(RA);
	size_t RBlen = sizeof(RB);
	unsigned char kab[64];
	unsigned char kba[64];
	size_t kablen = strlen(KAB)/2;
	size_t kbalen = strlen(KAB)/2;
	unsigned char s1[64];
	unsigned char s2[64];
	size_t s1len, s2len;

	memset(&ctxA, 0, sizeof(ctxA));
	memset(&ctxB, 0, sizeof(ctxB));

	eckeyA = new_ec_key(group, dA, xA, yA);
	eckeyB = new_ec_key(group, dB, xB, yB);
	pubkeyA = new_ec_key(group, NULL, xA, yA);
	pubkeyB = new_ec_key(group, NULL, xB, yB);
	if (!eckeyA || !eckeyB || !pubkeyA || !pubkeyB) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!SM2_KAP_CTX_init(&ctxA, eckeyA, A, strlen(A), pubkeyB, B, strlen(B), 1, 1)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}
	if (!SM2_KAP_CTX_init(&ctxB, eckeyB, B, strlen(B), pubkeyA, A, strlen(A), 0, 1)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	change_rand(rA);
	if (!SM2_KAP_prepare(&ctxA, RA, &RAlen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}
	restore_rand();

	change_rand(rB);
	if (!SM2_KAP_prepare(&ctxB, RB, &RBlen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}
	restore_rand();

	if (!SM2_KAP_compute_key(&ctxA, RB, RBlen, kab, kablen, s1, &s1len)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!SM2_KAP_compute_key(&ctxB, RA, RAlen, kba, kbalen, s2, &s2len)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!SM2_KAP_final_check(&ctxA, s2, s2len)) {
		goto end;
	}
	if (!SM2_KAP_final_check(&ctxB, s1, s1len)) {
		goto end;
	}

	ret = 1;

end:
	ERR_print_errors_fp(stderr);
	EC_KEY_free(eckeyA);
	EC_KEY_free(eckeyB);
	EC_KEY_free(pubkeyA);
	EC_KEY_free(pubkeyB);
	SM2_KAP_CTX_cleanup(&ctxA);
	SM2_KAP_CTX_cleanup(&ctxB);
	return ret;
}

int main(int argc, char **argv)
{
	int err = 0;
	EC_GROUP *sm2p192test = NULL;
	EC_GROUP *sm2p256test = NULL;
	EC_GROUP *sm2b193test = NULL;
	EC_GROUP *sm2b257test = NULL;

	RAND_seed(rnd_seed, sizeof(rnd_seed));

	sm2p192test = new_ec_group(1,
		"BDB6F4FE3E8B1D9E0DA8C0D46F4C318CEFE4AFE3B6B8551F",
		"BB8E5E8FBC115E139FE6A814FE48AAA6F0ADA1AA5DF91985",
		"1854BEBDC31B21B7AEFC80AB0ECD10D5B1B3308E6DBF11C1",
		"4AD5F7048DE709AD51236DE65E4D4B482C836DC6E4106640",
		"02BB3A02D4AAADACAE24817A4CA3A1B014B5270432DB27D2",
		"BDB6F4FE3E8B1D9E0DA8C0D40FC962195DFAE76F56564677",
		"1");

	sm2p256test = new_ec_group(1,
		"8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
		"787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
		"63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
		"421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
		"0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",
		"8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
		"1");

	sm2b193test = new_ec_group(0,
		"2000000000000000000000000000000000000000000008001",
		"0",
		"002FE22037B624DBEBC4C618E13FD998B1A18E1EE0D05C46FB",
		"00D78D47E85C93644071BC1C212CF994E4D21293AAD8060A84",
		"00615B9E98A31B7B2FDDEEECB76B5D875586293725F9D2FC0C",
		"80000000000000000000000043E9885C46BF45D8C5EBF3A1",
		"1");

	sm2b257test = new_ec_group(0,
		"20000000000000000000000000000000000000000000000000000000000001001",
		"0",
		"00E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B",
		"00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD",
		"013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E",
		"7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBC972CF7E6B6F900945B3C6A0CF6161D",
		"4");

	if (!sm2p192test || !sm2p256test || !sm2b193test || !sm2b257test) {
		err++;
		goto end;
	}

	if (!test_sm2_sign(
		sm2p256test,
		"128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263",
		"0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A",
		"7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857",
		"ALICE123@YAHOO.COM",
		"F4A38489E32B45B6F876E3AC2168CA392362DC8F23459C1D1146FC3DBFB7BC9A",
		"message digest",
		"B524F552CD82B8B028476E005C377FB19A87E6FC682D48BB5D42E3D9B9EFFE76",
		"6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F",
		"40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1",
		"6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7")) {
		printf("sm2 sign p256 failed\n");
		err++;
	} else {
		printf("sm2 sign p256 passed\n");
	}


	if (!test_sm2_sign(
		sm2b257test,
		"771EF3DBFF5F1CDC32B9C572930476191998B2BF7CB981D7F5B39202645F0931",
		"0165961645281A8626607B917F657D7E9382F1EA5CD931F40F6627F357542653B2",
		"01686522130D590FB8DE635D8FCA715CC6BF3D05BEF3F75DA5D543454448166612",
		"ALICE123@YAHOO.COM",
		"26352AF82EC19F207BBC6F9474E11E90CE0F7DDACE03B27F801817E897A81FD5",
		"message digest",
		"AD673CBDA311417129A9EAA5F9AB1AA1633AD47718A84DFD46C17C6FA0AA3B12",
		"36CD79FC8E24B7357A8A7B4A46D454C397703D6498158C605399B341ADA186D6",
		"6D3FBA26EAB2A1054F5D198332E335817C8AC453ED26D3391CD4439D825BF25B",
		"3124C5688D95F0A10252A9BED033BEC84439DA384621B6D6FAD77F94B74A9556")) {
		printf("sm2 sign b257 failed\n");
		err++;
	} else {
		printf("sm2 sign b257 passed\n");
	}

	if (!test_sm2_enc(
		sm2p256test, EVP_sm3(),
		"1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0",
		"435B39CCA8F3B508C1488AFC67BE491A0F7BA07E581A0E4849A5CF70628A7E0A",
		"75DDBA78F15FEECB4C7895E2C1CDF5FE01DEBB2CDBADF45399CCF77BBA076A42",
		"encryption standard",
		"4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F",
		"04"
		"245C26FB68B1DDDDB12C4B6BF9F2B6D5FE60A383B0D18D1C4144ABF17F6252E7"
		"76CB9264C2A7E88E52B19903FDC47378F605E36811F5C07423A24B84400F01B8"
		"650053A89B41C418B0C3AAD00D886C00286467"
		"9C3D7360C30156FAB7C80A0276712DA9D8094A634B766D3A285E07480653426D")) {
		printf("sm2 enc p256 failed\n");
		err++;
	} else {
		printf("sm2 enc p256 passed\n");
	}

	if (!test_sm2_enc(
		sm2b257test, EVP_sm3(),
		"56A270D17377AA9A367CFA82E46FA5267713A9B91101D0777B07FCE018C757EB",
		"00A67941E6DE8A61805F7BCFF0985BB3BED986F1C297E4D8880D82B821C624EE57",
		"0193ED5A6707B5908781B860841085F52EEFA7FE329A5C811843533A874D027271",
		"encryption standard",
		"6D3B497153E3E92524E5C122682DBDC8705062E20B917A5F8FCDB8EE4C66663D",
		"04"
		"019D236DDB305009AD52C51BB932709BD534D476FBB7B0DF9542A8A4D890A3F2E1"
		"00B23B938DC0A94D1DF8F42CF45D2D6601BF638C3D7DE75A29F02AFB7E45E91771"
		"FD55AC6213C2A8A040E4CAB5B26A9CFCDA7373"
		"73A48625D3758FA37B3EAB80E9CFCABA665E3199EA15A1FA8189D96F579125E4")) {
		printf("sm2 enc b257 failed\n");
		err++;
	} else {
		printf("sm2 enc b257 passed\n");
	}

	if (!test_sm2_kap(
		sm2p256test,
		"ALICE123@YAHOO.COM",
		"6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE",
		"3099093BF3C137D8FCBBCDF4A2AE50F3B0F216C3122D79425FE03A45DBFE1655",
		"3DF79E8DAC1CF0ECBAA2F2B49D51A4B387F2EFAF482339086A27A8E05BAED98B",
		"E4D1D0C3CA4C7F11BC8FF8CB3F4C02A78F108FA098E51A668487240F75E20F31",
		"BILL456@YAHOO.COM",
		"5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53",
		"245493D446C38D8CC0F118374690E7DF633A8A4BFB3329B5ECE604B2B4F37F43",
		"53C0869F4B9E17773DE68FEC45E14904E0DEA45BF6CECF9918C85EA047C60A4C",
		"6B4B6D0E276691BD4A11BF72F4FB501AE309FDACB72FA6CC336E6656119ABD67",
		"83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563",
		"33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80",
		"55B0AC62A6B927BA23703832C853DED4",
		"284C8F198F141B502E81250F1581C7E9EEB4CA6990F9E02DF388B45471F5BC5C",
		"23444DAF8ED7534366CB901C84B3BDBB63504F4065C1116C91A4C00697E6CF7A")) {
		printf("sm2 kap p256 failed\n");
		err++;
	} else {
		printf("sm2 kap p256 passed\n");
	}

	/* ZA will not pass! */
	if (!test_sm2_kap(
		sm2b257test,
		"ALICE123@YAHOO.COM",
		"4813903D254F2C20A94BC5704238496954BB5279F861952EF2C5298E84D2CEAA",
		"008E3BDB2E11F9193388F1F901CCC857BF49CFC065FB38B9069CAAE6D5AFC3592F",
		"004555122AAC0075F42E0A8BBD2C0665C789120DF19D77B4E3EE4712F598040415",
		"ECF0080215977B2E5D6D61B98A99442F03E8803DC39E349F8DCA5621A9ACDF2B",
		"BILL456@YAHOO.COM",
		"08F41BAE0922F47C212803FE681AD52B9BF28A35E1CD0EC273A2CF813E8FD1DC",
		"0034297DD83AB14D5B393B6712F32B2F2E938D4690B095424B89DA880C52D4A7D9",
		"0199BBF11AC95A0EA34BBD00CA50B93EC24ACB68335D20BA5DCFE3B33BDBD2B62D",
		"557BAD30 E183559A EEC3B2256E1C7C11F870D22B165D015ACF9465B09B87B527",
		"54A3D6673FF3A6BD6B02EBB164C2A3AF6D4A4906229D9BFCE68CC366A2E64BA4",
		"1F21933387BEF781D0A8F7FD708C5AE0A56EE3F423DBC2FE5BDF6F068C53F7AD",
		"4E587E5C66634F22D973A7D98BF8BE23",
		"4EB47D28AD3906D6244D01E0F6AEC73B0B51DE1574C13798184E4833DBAE295A",
		"588AA67064F24DC27CCAA1FAB7E27DFF811D500AD7EF2FB8F69DDF48CC0FECB7")) {
		printf("sm2 kap b257 failed\n");
		err++;
	} else {
		printf("sm2 kap b257 passed\n");
	}

end:
	EC_GROUP_free(sm2p192test);
	EC_GROUP_free(sm2p256test);
	EC_GROUP_free(sm2b193test);
	EC_GROUP_free(sm2b257test);
	EXIT(err);
}
#endif
