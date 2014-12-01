#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>

int main(int argc, char **argv)
{
	char *prog = basename(argv[0]);
	EC_GROUP *ec_group = NULL;
	EC_KEY *ec_key = NULL;
	BN_CTX *ctx = BN_CTX_new();
	const char *id = "Alice@YAHOO.COM";
	unsigned char za[32];
	BIGNUM *k = NULL;
	BIGNUM *x = NULL;
	ECDSA_SIG *sig = NULL;
	unsigned char dgst[20] = "abc";	
	int ret;

	if (!(ec_group = EC_GROUP_new_by_curve_name(NID_sm2t257v1))) {
		fprintf(stderr, "%s: no such curve\n", prog);
		return -1;
	}
	if (!(ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1))) {
		fprintf(stderr, "%s: %s %d\n", prog, __FUNCTION__, __LINE__);
		return -1;
	}
	if (!EC_KEY_generate_key(ec_key)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	
	if ((ret = EC_KEY_compute_za(za, EVP_sha256(), id, strlen(id), ec_key)) < 0) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	printf("Za length = %d\n", ret);

	if (!(sig = ECDSA_do_sign(dgst, sizeof(dgst), ec_key))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	if ((ret = ECDSA_do_verify(dgst, sizeof(dgst), sig, ec_key)) < 0) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	printf("result = %d\n", ret);

	if (!ECDSA_sign_setup(ec_key, ctx, &k, &x)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	if (!(sig = ECDSA_do_sign_ex(dgst, sizeof(dgst), k, x, ec_key))) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	if ((ret = ECDSA_do_verify(dgst, sizeof(dgst), sig, ec_key)) < 0) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	printf("result = %d\n", ret);

	
	return 0;
}
