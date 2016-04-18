#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <openssl/sm2.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

static void test_sm2_sign(void)
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
}

static void test_sm2_enc(void)
{
	int rv;
	EC_KEY *ec_key = NULL;
	char *msg = "Hello world!";
	SM2_CIPHERTEXT_VALUE *cv = NULL;
	unsigned char ctbuf[512];
	unsigned char ptbuf[512];	
	size_t len, len2;
	BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);	

	ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	OPENSSL_assert(ec_key);
	rv = EC_KEY_generate_key(ec_key);
	OPENSSL_assert(rv == 1);

	cv = SM2_do_encrypt(EVP_sm3(), EVP_sm3(), (unsigned char *)msg, (size_t)strlen(msg), ec_key);
	OPENSSL_assert(cv);
	SM2_CIPHERTEXT_VALUE_print(bio, EC_KEY_get0_group(ec_key), cv, 0, 0);

	bzero(ptbuf, sizeof(ptbuf));	
	len = sizeof(ptbuf);
	rv = SM2_do_decrypt(EVP_sm3(), EVP_sm3(), cv, ptbuf, &len, ec_key);
	OPENSSL_assert(rv == 1);

	len = sizeof(ctbuf);
	rv = SM2_encrypt(EVP_sm3(), EVP_sm3(),
		SM2_DEFAULT_POINT_CONVERSION_FORM,
		(unsigned char *)msg, (size_t)strlen(msg), ctbuf, &len, ec_key);
	OPENSSL_assert(rv == 1);

	bzero(ptbuf, sizeof(ptbuf));
	len2 = sizeof(ptbuf);
	rv = SM2_decrypt(EVP_sm3(), EVP_sm3(),
		SM2_DEFAULT_POINT_CONVERSION_FORM,
		ctbuf, len, ptbuf, &len2, ec_key);
	OPENSSL_assert(rv == 1);

	/*
	printf("original  plaintext: %s\n", msg);
	printf("decrypted plaintext: %s\n", ptbuf);
	*/
	printf("%s() success\n", __FUNCTION__);
}

static void test_sm2_kap(void)
{
	int rv = 0;

	int curve_name = NID_sm2p256v1;
	EC_KEY *eckey1 = NULL;
	EC_KEY *eckey2 = NULL;
	SM2_KAP_CTX ctx1;
	SM2_KAP_CTX ctx2;

	eckey1 = EC_KEY_new_by_curve_name(curve_name);
	OPENSSL_assert(eckey1 != NULL);

	eckey2 = EC_KEY_new_by_curve_name(curve_name);
	OPENSSL_assert(eckey2 != NULL);

	rv = EC_KEY_generate_key(eckey1);
	OPENSSL_assert(rv == 1);

	rv = EC_KEY_generate_key(eckey2);
	OPENSSL_assert(rv == 1);

	rv = SM2_set_id(eckey1, "Alice");
	OPENSSL_assert(rv == 1);

	rv = SM2_set_id(eckey2, "Bob");
	OPENSSL_assert(rv == 1);


	rv = SM2_KAP_init();
	OPENSSL_assert(rv == 1);

	rv = SM2_KAP_prepare(&ctx1);
	OPENSSL_assert(rv == 1);

	rv = SM2_KAP_prepare(&ctx2);
	OPENSSL_assert(rv == 1);

	rv = SM2_KAP_compute_key(&ctx1);
	OPENSSL_assert(rv == 1);

	rv = SM2_KAP_compute_key(&ctx2);
	OPENSSL_assert(rv == 1);

	rv = SM2_KAP_final_check(&ctx1);
	OPENSSL_assert(rv == 1);
	
	rv = SM2_KAP_final_check(&ctx2);
	OPENSSL_assert(rv == 1);
}

int main(int argc, char **argv)
{
	int rv;
	EC_KEY *ec_key = NULL;
	EVP_PKEY *pkey = NULL;
	const EVP_PKEY_METHOD *pmeth;
	const EVP_PKEY_ASN1_METHOD *ameth;
	BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);

	ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	OPENSSL_assert(ec_key);

	rv = EC_KEY_generate_key(ec_key);
	OPENSSL_assert(rv == 1);
		
	pkey = EVP_PKEY_new();
	OPENSSL_assert(pkey);

	pmeth = EVP_PKEY_meth_find(EVP_PKEY_SM2);
	OPENSSL_assert(pmeth);

	ameth = EVP_PKEY_asn1_find(NULL, EVP_PKEY_SM2);
	OPENSSL_assert(ameth);

	rv = EVP_PKEY_set1_SM2(pkey, ec_key);
	OPENSSL_assert(rv == 1);

	printf("pkey type    : %d\n", EVP_PKEY_type(pkey->type));
	printf("pkey id      : %d\n", EVP_PKEY_id(pkey));
	printf("pkey base id : %d\n", EVP_PKEY_base_id(pkey));
	printf("pkey bits    : %d\n", EVP_PKEY_bits(pkey));

	rv = EVP_PKEY_print_public(bio, pkey, 0, NULL);
	OPENSSL_assert(rv == 1);

	rv = EVP_PKEY_print_private(bio, pkey, 0, NULL);
	OPENSSL_assert(rv == 1);

	rv = EVP_PKEY_print_params(bio, pkey, 0, NULL);
	OPENSSL_assert(rv == 1);

	printf("%s() success!\n", __FUNCTION__);
	return 0;
}


int test_sm2_evp_digestsign(void)
{
	int rv;
	EC_KEY *ec_key = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pk_ctx = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	const *EVP_MD *md = EVP_sm3();
	char *msg1 = "Hello ";
	char *msg2 = "World!";
	unsigned char sig[512];
	size_t siglen = sizeof(sig);


	/* init EVP_PKEY */

	ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	OPENSSL_assert(ec_key);

	rv = EC_KEY_generate_key(ec_key);
	OPENSSL_assert(rv == 1);

	pkey = EVP_PKEY_new(); 
	OPENSSL_assert(pkey != NULL);

	rv = EVP_PKEY_set1_SM2(pkey, ec_key);
	OPENSSL_assert(rv == 1);

	/* test EVP_DigestSignInit/Update/Final */

	md_ctx = EVP_MD_CTX_create();
	OPENSSL_assert(md_ctx != NULL);

	rv = EVP_DigestSignInit(md_ctx, &pk_ctx, md, NULL, pkey);
	if (rv != 1)
		ERR_print_errors_fp(stderr);
	OPENSSL_assert(rv == 1);
	OPENSSL_assert(pkctx != NULL);

	rv = EVP_DigestSignUpdate(md_ctx, msg1, strlen(msg1));
	OPENSSL_assert(rv == 1);
	
	rv = EVP_DigestSignUpdate(md_ctx, msg2, strlen(msg2));
	OPENSSL_assert(rv == 1);

	rv = EVP_DigestSignFinal(md_ctx, sig, &siglen);
	OPENSSL_assert(rv == 1);

	EC_KEY_free(ec_key);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pk_ctx);
	EVP_MD_CTX_destroy(md_ctx);

	printf("%s() success!\n", __FUNCTION__);
	return 0;
}

int sm2_test_evp_pkey_encrypt(void)
{
	EC_KEY *ec_key = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	char *msg = "Hello world!";
	unsigned char ptbuf[256];
	unsigned char ctbuf[256];
	size_t ptlen, ctlen, i;

	/* Generate SM2 EVP_PKEY */
	ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	pkey = EVP_PKEY_new();
	EC_KEY_generate_key(ec_key);
	EVP_PKEY_set1_SM2(pkey, ec_key);

	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	
	/* Encrypt */
	EVP_PKEY_encrypt_init(ctx);
	ctlen = sizeof(ctbuf);
	bzero(ctbuf, ctlen);
	EVP_PKEY_encrypt(ctx, ctbuf, &ctlen, (unsigned char *)msg, strlen(msg) + 1);
	
	printf("encrypted message (%zu bytes) : ", ctlen);
	for (i = 0; i < ctlen; i++) {
		printf("%02x", ctbuf[i]);
	}
	printf("\n");

	/* Decrypt */
	EVP_PKEY_decrypt_init(ctx);
	ptlen = sizeof(ptbuf);
	bzero(ptbuf, ptlen);
	if (!EVP_PKEY_decrypt(ctx, ptbuf, &ptlen, ctbuf, ctlen)) {
		fprintf(stderr, "sm2 decrypt failed.\n");
	}

	printf("decrypted message : %s\n", ptbuf);

	EVP_PKEY_free(pkey);
	EC_KEY_free(ec_key);
	EVP_PKEY_CTX_free(ctx);
	return 0;
}

EVP_PKEY *pkey_new_ec()
{
	int rv;
	ECIES_PARAMS param;
	EC_KEY *ec_key = NULL;
	EVP_PKEY *pkey = NULL;

	ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	OPENSSL_assert(ec_key);
	rv = EC_KEY_generate_key(ec_key);
	OPENSSL_assert(rv == 1);
	
	param.mac_nid = NID_hmac_full_ecies;
	param.kdf_md = EVP_sha1();
	param.sym_cipher = EVP_aes_128_cbc();
	param.mac_md = EVP_sha1();
	rv = ECIES_set_parameters(ec_key, &param);
	ERR_print_errors_fp(stderr);
	OPENSSL_assert(rv == 1);	
	OPENSSL_assert(ECIES_get_parameters(ec_key) != NULL);
	
	pkey = EVP_PKEY_new();
	OPENSSL_assert(pkey);

	const EVP_PKEY_ASN1_METHOD *ameth = EVP_PKEY_asn1_find(NULL, EVP_PKEY_SM2);
	OPENSSL_assert(ameth);

	rv = EVP_PKEY_set1_SM2(pkey, ec_key);
	ERR_print_errors_fp(stderr);
	OPENSSL_assert(rv == 1);

	return pkey;		
}

int test_sm2_pkey_seal(void)
{
	int rv;
	EVP_PKEY *pkey[2];
	int num_pkeys = sizeof(pkey)/sizeof(pkey[0]);
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *cipher = EVP_sms4_cbc();
	unsigned char iv[16];
	unsigned char ek[2][256];
	int eklen[sizeof(pkey)/sizeof(pkey[0])];
	char *msg1 = "Hello ";
	char *msg2 = "World!";
	unsigned char ctbuf[256];
	unsigned char ptbuf[256];
	unsigned char *p;
	int len, ctlen;
	int i;

	for (i = 0; i < num_pkeys; i++) {
		pkey[i] = pkey_new_ec();
	}

	EVP_CIPHER_CTX_init(&ctx);

	RAND_bytes(iv, sizeof(iv));


	/* EVP_SealInit/Update/Final() */

	rv = EVP_SealInit(&ctx, cipher, ek, eklen, iv, pkey, num_pkeys);
	OPENSSL_assert(rv == num_pkeys);

	p = ctbuf;

	rv = EVP_SealUpdate(&ctx, p, &len, (unsigned char *)msg1, strlen(msg1));
	OPENSSL_assert(rv == 1);

	p += len;

	rv = EVP_SealUpdate(&ctx, p, &len, (unsigned char *)msg2, strlen(msg2));
	OPENSSL_assert(rv == 1);

	p += len;

	rv = EVP_SealFinal(&ctx, p, &len);
	OPENSSL_assert(rv == 1);

	p += len;

	ctlen = p - ctbuf;

	
	/* EVP_OpenInit/Update/Final() */	
	// TODO

	
	printf("%s() success!\n", __FUNCTION__);
	return 0;
}

int main(int argc, char **argv)
{
	test_sm2_sign();
	test_sm2_enc();
	return 0;
}


