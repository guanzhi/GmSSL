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

int main(int argc, char** argv)
{
	int sum = 0;
#ifdef SPECK_32_64
	uint16_t key[4] = { 0x0100, 0x0908, 0x1110, 0x1918 };
	uint16_t plain[2] = { 0x694c, 0x6574 };
	uint16_t enc[2] = { 0x42f2, 0xa868 };
#endif

#ifdef SPECK_64_128
	uint32_t key[4] = { 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918 };
	uint32_t plain[2] = { 0x7475432d, 0x3b726574 };
	uint32_t enc[2] = { 0x454e028b, 0x8c6fa548 };
#endif

#ifdef SPECK_128_256
	uint64_t key[4] = { 0x0706050403020100, 0x0f0e0d0c0b0a0908, 0x1716151413121110, 0x1f1e1d1c1b1a1918 };
	uint64_t plain[2] = { 0x202e72656e6f6f70, 0x65736f6874206e49 };
	uint64_t enc[2] = { 0x4eeeb48d9c188f43, 0x4109010405c0f53e };
#endif
	SPECK_TYPE buffer[2] = { 0 };
	SPECK_TYPE exp[SPECK_ROUNDS];
	speck_set_encrypt_key(key, exp);
	speck_encrypt(plain, buffer, exp);
	speck_decrypt(enc, buffer, exp);
	if (memcmp(buffer, plain, sizeof(enc)))
	{
		sum++;
	}
	
	return sum;
}
#endif
