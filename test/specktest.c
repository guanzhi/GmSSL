#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../e_os.h"

#ifdef OPENSSL_NO_SPECK
int main(int argc, char **argv)
{
	printf("No Speck support\n");
	return 0;
}
#else

#include <openssl/speck.h>

int main(int argc, char **argv)
{
	speck_key_t key;
	unsigned char userkey[2] = { 0x01, 0x02, };
	unsigned char msg[2] = { 0xab, 0xcd, };
	SPECK_TYPE S[SPECK_ROUNDS];
	
	unsigned char cbuf[2];
	unsigned char mbuf[2];

	speck_set_encrypt_key(&key, userkey);
	speck_expand(&key, S);
	speck_encrypt(msg, cbuf, S);
	speck_decrypt(cbuf, mbuf, S);

	if (memcmp(msg, mbuf, 2)) {
		return -1;
	}

	return 0;
}
#endif
