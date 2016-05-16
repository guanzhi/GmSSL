#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/otp.h>


int main(int argc, char **argv)
{
	OTP_PARAMS params;
	unsigned char key[] = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};
	unsigned char event[] = "this is a fixed value";
	unsigned int otp;

	params.type = NID_sm3;
	params.te = 60;
	params.option = NULL;
	params.option_size = 0;
	params.otp_digits = 6;

	OpenSSL_add_all_algorithms();

	if (!OTP_generate(&params, event, sizeof(event), &otp, key, sizeof(key))) {
		printf("OTP_generate() failed\n");
		return -1;
	}

	printf("OTP = %06u\n", otp);
	return 0;
}
