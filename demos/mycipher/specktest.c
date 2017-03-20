#include"speck.h"
int main(int argc, char **argv)
{
	mycipher_key_t key;
	unsigned char userkey[2] = { 0x01, 0x02, };
	unsigned char msg[2] = { 0xab, 0xcd, };
	SPECK_TYPE S[SPECK_ROUNDS];
	
	unsigned char cbuf[2];
	unsigned char mbuf[2];

	mycipher_set_encrypt_key(&key, userkey);
	speck_expand(&key, S);
	speck_encrypt(msg, cbuf, S);
	speck_decrypt(cbuf, mbuf, S);

	if (memcmp(msg, mbuf, 2)) {
		return -1;
	}

	return 0;
}
