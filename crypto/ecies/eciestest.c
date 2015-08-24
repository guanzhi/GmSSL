#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "ecies.h"

int ecies_test_ECIESParameters(void)
{
	int ret = 0;

	ECIES_PARAMS buffer;
	ECIES_PARAMS *param = &buffer;
	unsigned char *der = NULL;
	int derlen;
	unsigned char *p;
	const unsigned char *cp;

	param->kdf_md = EVP_sha1();
	param->sym_cipher = NULL;
	param->mac_md = EVP_sha1();

	derlen = i2d_ECIESParameters(param, NULL);
	if (derlen <= 0) {
		fprintf(stderr, "test i2d_ECIESParameters failed test suite 1\n");
		goto end;
	}
	der = OPENSSL_malloc(derlen);
	OPENSSL_assert(der);
	p = der;
	derlen = i2d_ECIESParameters(param, &p);

	param = NULL;
	cp = der;
	param = d2i_ECIESParameters(NULL, &cp, derlen);
	if (!param) {
		fprintf(stderr, "test d2i_ECIESParameters faild\n");
		goto end;
	}
	OPENSSL_free(param);

	param = NULL;
	cp = der;
	d2i_ECIESParameters(&param, &cp, derlen);
	if (!param) {
		fprintf(stderr, "test failed\n");
		goto end;
	}
	
	ret = 1;

end:
	return ret;	
}

void ecies_test(void)
{
	int r;
	EC_GROUP *ec_group = NULL;
	EC_KEY *ec_key = NULL;
	ECIES_PARAMS params;
	ECIES_PARAMS *param2 = NULL;
	ECIES_CIPHERTEXT_VALUE *cv = NULL;
	unsigned char buffer1[1024];
	unsigned char buffer2[1024];
	unsigned char buffer3[1024];
	unsigned char *der = NULL;
	int derlen;
	unsigned char *p;
	const unsigned char *cp;

	ec_key = EC_KEY_new_by_curve_name(OBJ_sn2nid("secp192k1"));
	OPENSSL_assert(ec_key);
	r = EC_KEY_generate_key(ec_key);
	assert(r);

	/* set ECIESParameters */
	params.kdf_md = EVP_sha1();
	params.sym_cipher = EVP_aes_128_cbc();
	params.mac_md = EVP_sha1();

	derlen = i2d_ECIESParameters(&params, NULL);
	printf("ECIESParameters DER length = %d\n", derlen);
	
	memset(buffer1, 0, sizeof(buffer1));
	strcpy((char *)buffer1, "hello");
	cv = ECIES_do_encrypt(&params, buffer1, strlen(buffer1) + 1, ec_key);
	assert(cv);

	memset(buffer3, 0, sizeof(buffer3));
	if (!ECIES_do_decrypt(cv, &params, buffer3, &derlen, ec_key)) {
		ERR_print_errors_fp(stderr);
		return;
	}

	printf("decrypted plaintext length = %d\n", derlen);
	printf("%s\n", buffer3);

	derlen = i2d_ECIES_CIPHERTEXT_VALUE(cv, NULL);
	printf("ECIES Test: ECIES_CIPHERTEXT_VALUE DER encoding length = %d\n", derlen);
	der = OPENSSL_malloc(derlen);
	assert(der);
	p = der;
	i2d_ECIES_CIPHERTEXT_VALUE(cv, &p);
	
	ECIES_CIPHERTEXT_VALUE_free(cv);
	cv = NULL;

	cp = der;
	cv = d2i_ECIES_CIPHERTEXT_VALUE(NULL, &cp, derlen);
	assert(cv);

	ecies_test_ECIESParameters();

}

int main(int argc, char **argv)
{
	ecies_test();
	return 0;
}

