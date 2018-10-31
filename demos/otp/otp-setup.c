#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/is_gmssl.h>

int main(int argc, char **argv)
{
	BIO *bio = NULL;
	unsigned char key[32];

	if (!RAND_bytes(key, sizeof(key))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (!(bio = BIO_new_file(".otp_secret", "w"))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (BIO_write(bio, key, sizeof(key)) != sizeof(key)) {
		ERR_print_errors_fp(stderr);
		BIO_free(bio);
		return -1;
	}

	printf("generate OTP seed in '.otp_secret'\n");

	BIO_free(bio);
	OPENSSL_cleanse(key, sizeof(key));

	return 0;
}
