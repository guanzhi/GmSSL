#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ec.h>

int main(int argc, char **argv)
{
	BIO *in = BIO_new_fp(stdin, BIO_NOCLOSE);
	EC_GROUP *group = NULL;
	EC_KEY *ec_key = NULL;
	ERR_load_crypto_strings();



	group = PEM_read_bio_SM2PKParameters(in, NULL, NULL, NULL);
	if (!group) {
		ERR_print_errors_fp(stderr);
		return 0;
	}

	if (!EC_GROUP_check(group, NULL)) {
		ERR_print_errors_fp(stderr);
		return 0;
	}

	return 0;

	ec_key = EC_KEY_new();
	EC_KEY_set_group(ec_key, group);

	return 0;
}
