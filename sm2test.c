#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>

int main(int argc, char **argv)
{
	int ok;
	EC_KEY *ec_key;
	ECDSA_SIG *sig;
	unsigned char dgst[32];

	ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	OPENSSL_assert(ec_key);

	ok = EC_KEY_generate_key(ec_key);
	OPENSSL_assert(ok);

	sig = ECDSA_do_sign(dgst, 32, ec_key);
	ok = ECDSA_do_verify(dgst, 32, sig, ec_key);

	printf("ok = %d\n", ok);

	return 0;
}

