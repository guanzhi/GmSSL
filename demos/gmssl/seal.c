#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ecies.h>
#include <openssl/objects.h>



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


int test_pkey_enc(void)
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
	
	printf("%s() success!\n", __FUNCTION__);
	return 0;
}

int main(int argc, char **argv)
{
	test_pkey_enc();
	return 0;
}

