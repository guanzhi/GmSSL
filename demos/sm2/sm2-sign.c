#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <openssl/ec.h>
#include <openssl/sm2.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/is_gmssl.h>


int main(int argc, char **argv)
{
	int ret = -1;
	EC_KEY *ec_key = NULL;
	char *id = "Alice";
	unsigned char msg[] = "This is the message to be signed";
	unsigned char dgst[EVP_MAX_MD_SIZE];
	size_t dgstlen = sizeof(dgst);
	unsigned char sig[256];
	unsigned int siglen = sizeof(sig);
	int i;

	if (!(ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1))
		|| !EC_KEY_generate_key(ec_key)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	printf("M = %s\n", (char *)msg);
	printf("ID = %s\n", id);

	if (!SM2_compute_message_digest(EVP_sm3(), EVP_sm3(), msg, sizeof(msg),
		id, strlen(id), dgst, &dgstlen, ec_key)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	printf("H(Z||M) = ");
	for (i = 0; i < dgstlen; i++) {
		printf("%02X", dgst[i]);
	}
	printf("\n");

	if (!SM2_sign(NID_undef, dgst, dgstlen, sig, &siglen, ec_key)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	printf("Signature = ");
	for (i = 0; i < siglen; i++) {
		printf("%02X", sig[i]);
	}
	printf("\n");

	if (1 != SM2_verify(NID_undef, dgst, dgstlen, sig, siglen, ec_key)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	printf("Verification Success!\n");

	ret = 0;

end:
	EC_KEY_free(ec_key);
	return ret;
}
