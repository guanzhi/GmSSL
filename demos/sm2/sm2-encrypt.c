#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <openssl/ec.h>
#include <openssl/sm2.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/is_gmssl.h>


int main(int argc, char **argv)
{
	int ret = -1;
	EC_KEY *ec_key = NULL;
	unsigned char key[64];
	unsigned char cbuf[1024];
	unsigned char pbuf[1024] = {0};
	size_t clen = sizeof(cbuf);
	size_t plen = sizeof(pbuf);
	int i;

	/* generate sm2 key pair */
	if (!(ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1))
		|| !EC_KEY_generate_key(ec_key)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	/* generate to be encrypted symmetric key
	 * Notice: sm2 encrypt should only be used to encrypt short data
	 */
	if (!RAND_bytes(key, sizeof(key))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	printf("M = ");
	for (i = 0; i < sizeof(key); i++) {
		printf("%02X", key[i]);
	}
	printf("\n");

	/* sm2 encrypt, hash algorithm is required for KDF */
	if (!SM2_encrypt(NID_sm3, key, sizeof(key), cbuf, &clen, ec_key)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	printf("C = ");
	for (i = 0; i < clen; i++) {
		printf("%02X", cbuf[i]);
	}
	printf("\n");

	/* sm2 decrypt */
	if (!SM2_decrypt(NID_sm3, cbuf, clen, pbuf, &plen, ec_key)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	printf("M' = ");
	for (i = 0; i < plen; i++) {
		printf("%02X", pbuf[i]);
	}
	printf("\n");

	ret = 0;

end:
	EC_KEY_free(ec_key);
	return ret;
}
