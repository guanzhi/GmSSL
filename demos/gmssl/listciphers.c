#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>

int main(int argc, char **argv)
{
	int i;
	char *names[] = {
		"sms4-ecb",
		"sms4-cbc",
		"sms4-cfb",
		"sms4-ofb",
		"sms4-ctr",
	};
	const EVP_CIPHER *cipher;
	
	OpenSSL_add_all_ciphers();

	printf("%s new ciphers:\n\n", OPENSSL_VERSION_TEXT);

	for (i = 0; i < sizeof(names)/sizeof(names[i]); i++) {
		if (!(cipher = EVP_get_cipherbyname(names[i]))) {
			fprintf(stderr, "cipher \"%s\" is not supported\n", names[i]);
			continue;
		}

		printf("  cipher nid : %d\n", EVP_CIPHER_nid(cipher));
		printf(" cipher name : %s\n", EVP_CIPHER_name(cipher));
		printf("  block size : %d\n", EVP_CIPHER_block_size(cipher));
		printf("  key length : %d\n", EVP_CIPHER_key_length(cipher));
		printf("   iv length : %d\n", EVP_CIPHER_iv_length(cipher));
		printf("       flags : 0x%016lx\n", EVP_CIPHER_flags(cipher));
		printf("\n");
	}

	return 0;
}
