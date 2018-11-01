
/*
 * This demo shows how to:
 *  - generate SM2 private
 *  - encrypt SM2 private key with SM4
 *  - output public/private key in PEM format
 *  - generate the SM2 Z value from public key
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sm2.h>
#include <openssl/objects.h>
#include <openssl/is_gmssl.h>

int main(int argc, char **argv)
{
	int ret = -1;
	char *prog = basename(argv[0]);
	EC_KEY *ec_key = NULL;
	EVP_PKEY *pkey = NULL;
	const EVP_CIPHER *cipher = NULL;
	char *pass = NULL;
	char *id = "12345678";
	unsigned char z[64];
	size_t zlen = sizeof(z);
	int i;

	if (argc > 2) {
		printf("usage: %s <id>\n", prog);
		return -1;
	}
	if (argc == 2) {
		id = argv[1];
	}

	/* generate sm2 private key using EC_KEY API */
	if (!(ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!EC_KEY_generate_key(ec_key)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	/* assign EC_KEY to EVP_PKEY */
	if (!(pkey = EVP_PKEY_new())) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	ec_key = NULL; /* free-ed by EVP_PKEY */

#ifdef ENCRYPT_KEY
	/* generate PKCS #8 EncryptedPrivateKeyInfo with SM4
	 * else unencrypted PKCS #8 PrivateKeyInfo is generated.
	 */
	cipher = EVP_sms4_cbc();
# ifdef NO_PROMPT
	/* else user need to input password from prompt */
	pass = "P@ssw0rd";
# endif
#endif
	/* generate PKCS #8 in PEM format */
	if (!PEM_write_PKCS8PrivateKey(stdout, pkey, cipher, NULL, 0, 0, pass)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	/* generate public key in pem format */
	if (!PEM_write_EC_PUBKEY(stdout, EVP_PKEY_get0_EC_KEY(pkey))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	/* generate Z value in HEX */
	if (!SM2_compute_id_digest(EVP_sm3(), id, strlen(id), z, &zlen,
		EVP_PKEY_get0_EC_KEY(pkey))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	printf("Z = ");
	for (i = 0; i < zlen; i++) {
		printf("%02X", z[i]);
	}
	printf("\n");

	ret = 0;

end:
	EC_KEY_free(ec_key);
	EVP_PKEY_free(pkey);
	return ret;
}
