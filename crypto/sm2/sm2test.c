#include <stdio.h>
#include <string.h>
#include <openssl/sm2.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

static int test_sm2_sign(void)
{
	int rv;
	EC_KEY *ec_key = NULL;
	unsigned char dgst[32];
	ECDSA_SIG *sig = NULL;
	unsigned char sigbuf[128];
	unsigned int siglen;

	ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	OPENSSL_assert(ec_key);
	rv = EC_KEY_generate_key(ec_key);
	OPENSSL_assert(rv == 1);

	RAND_bytes(dgst, sizeof(dgst));
	
	sig = SM2_do_sign(dgst, (int)sizeof(dgst), ec_key);
	OPENSSL_assert(sig);
	rv = SM2_do_verify(dgst, (int)sizeof(dgst), sig, ec_key);
	OPENSSL_assert(rv == 1);

	rv = SM2_sign(0, dgst, sizeof(dgst), sigbuf, &siglen, ec_key);
	OPENSSL_assert(rv == 1);
	rv = SM2_verify(0, dgst, sizeof(dgst), sigbuf, siglen, ec_key);
	OPENSSL_assert(rv == 1);

	EC_KEY_free(ec_key);
	ECDSA_SIG_free(sig);

	printf("%s() success\n", __FUNCTION__);
	return 0;
}

static int test_sm2_enc(void)
{
	int rv;
	EC_KEY *ec_key = NULL;
	char *msg = "Hello world!";
	SM2_CIPHERTEXT_VALUE *cv = NULL;
	unsigned char ctbuf[512];
	unsigned char ptbuf[512];	
	size_t len;
	

	ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	OPENSSL_assert(ec_key);
	rv = EC_KEY_generate_key(ec_key);
	OPENSSL_assert(rv == 1);

	cv = SM2_do_encrypt(EVP_sm3(), EVP_sm3(), msg, (size_t)strlen(msg), ec_key);
	OPENSSL_assert(cv);

	{
		BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);
		SM2_CIPHERTEXT_VALUE_print(bio, EC_KEY_get0_group(ec_key), cv, 0, 0);	
	}
	
	len = sizeof(ptbuf);
	rv = SM2_do_decrypt(EVP_sm3(), EVP_sm3(), cv, ptbuf, &len, ec_key);
	OPENSSL_assert(rv == 1);

	printf("%s() success\n", __FUNCTION__);
	return 0;
}

int main(int argc, char **argv)
{
	test_sm2_sign();
	test_sm2_enc();
	return 0;
}

