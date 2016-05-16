#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/otp.h>
#include <openssl/rand.h>


int main(int argc, char **argv)
{
	char *prog;
	char *id;
	char *mk;
	int offset;
	OTP_PARAMS params;
	unsigned int otp;

	prog = basename(argv[0]);

	if (argc < 3) {
		printf("usage: %s <event> <key> [<offset>]\n", prog);
		return 0;
	}

	id = argv[1];
	mk = argv[2];

	if (argc > 3)
		offset = atoi(argv[3]);

	params.type = NID_sm3;
	params.te = 60;
	params.option = "end";
	params.option_size = strlen(params.option);
	params.otp_digits = 6;
	params.offset = offset;

	OpenSSL_add_all_algorithms();
	if (!OTP_generate(&params, id, strlen(id), &otp, (unsigned char *)mk, strlen(mk))) {
		fprintf(stderr, "failed\n");
	}

	printf("OTP = %06u\n", otp);	
	return 0;
}

