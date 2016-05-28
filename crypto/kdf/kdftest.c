#include <stdio.h>
#include <string.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

int main(int argc, char **argv)
{
	KDF_FUNC kdf = KDF_get_x9_63(EVP_sm3());
	unsigned char buf[1024];
	unsigned char key[128];
	size_t keylen = 12;
	int i;

	memset(buf, 0x32, sizeof(buf));
	kdf(buf, sizeof(buf), key, &keylen);

	for (i = 0; i < keylen; i++) {
		printf("%02x", key[i]);
	}
	printf("\n");

	return 0;
}
