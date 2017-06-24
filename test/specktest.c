#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/speck.h>

int main(int argc, char** argv)
{
	int sum = 0;
	uint16_t key16[4] = { 0x0100, 0x0908, 0x1110, 0x1918 };
	uint16_t plain16[2] = { 0x694c, 0x6574 };
	uint16_t enc16[2] = { 0x42f2, 0xa868 };


	uint32_t key32[4] = { 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918 };
	uint32_t plain32[2] = { 0x7475432d, 0x3b726574 };
	uint32_t enc32[2] = { 0x454e028b, 0x8c6fa548 };



	uint64_t key64[4] = { 0x0706050403020100, 0x0f0e0d0c0b0a0908, 0x1716151413121110, 0x1f1e1d1c1b1a1918 };
	uint64_t plain64[2] = { 0x202e72656e6f6f70, 0x65736f6874206e49 };
	uint64_t enc64[2] = { 0x4eeeb48d9c188f43, 0x4109010405c0f53e };

	SPECK_TYPE16 buffer[2] = { 0 };
	SPECK_TYPE16 exp[SPECK_ROUNDS16];
	speck_set_encrypt_key16(key16, exp);
	speck_encrypt16(plain16, buffer, exp);
	if (memcmp(buffer, enc16, sizeof(enc16)))
	{
		sum++;
	}
	speck_decrypt16(enc16, buffer, exp);
	if (memcmp(buffer, plain16, sizeof(enc16)))
	{
		sum++;
	}

	SPECK_TYPE32 exp32[SPECK_ROUNDS32];
	SPECK_TYPE32 buffer32[2] = { 0 };
	speck_set_encrypt_key32(key32, exp32);
	speck_encrypt32(plain32, buffer32, exp32);
	if (memcmp(buffer, enc32, sizeof(enc32)))
	{
		sum++;
	}
	speck_decrypt32(enc32, buffer32, exp32);
	if (memcmp(buffer32, plain32, sizeof(enc32)))
	{
		sum++;
	}

	SPECK_TYPE64 exp64[SPECK_ROUNDS64];
	SPECK_TYPE64 buffer64[2] = { 0 };
	speck_set_encrypt_key64(key64, exp64);
	speck_encrypt64(plain64, buffer64, exp64);
	if (memcmp(buffer64, enc64, sizeof(enc64)))
	{
		sum++;
		system("pause");
	}
	speck_decrypt64(enc64, buffer64, exp64);
	if (memcmp(buffer64, plain64, sizeof(enc64)))
	{
		sum++;
		system("pause");
	}
	return sum;
}
