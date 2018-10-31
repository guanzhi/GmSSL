#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <openssl/err.h>
#include <openssl/otp.h>
#include <openssl/objects.h>
#include <openssl/is_gmssl.h>

int main(int argc, char **argv)
{
	char *prog = basename(argv[0]);
	BIO *bio = NULL;
	OTP_PARAMS params;
	unsigned char key[32] = {0};
	unsigned char event[] = "this is a fixed value";
	unsigned int otp;

	params.type = NID_sm3;
	params.te = 1;
	params.option = NULL;
	params.option_size = 0;
	params.otp_digits = 6;

	if (!(bio = BIO_new_file(".otp_secret", "r"))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	if (BIO_read(bio, key, sizeof(key)) != sizeof(key)) {
		ERR_print_errors_fp(stderr);
		BIO_free(bio);
		return -1;
	}
	BIO_free(bio);

	if (!OTP_generate(&params, event, sizeof(event), &otp, key, sizeof(key))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	printf("%06u\n", otp);
	return 0;
}
