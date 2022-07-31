#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm2.h>

int main(void)
{
	SM2_KEY sm2_key;
	char *password = "123456";

	if (sm2_key_generate(&sm2_key) != 1) {
		fprintf(stderr, "error\n");
		return 1;
	}

	if (sm2_private_key_info_encrypt_to_pem(&sm2_key, password, stdout) != 1) {
		fprintf(stderr, "error\n");
		return 1;
	}

	return 0;
}
