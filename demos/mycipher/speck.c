#include "speck.h"

#define ROR(x, r) ((x >> r) | (x << ((sizeof(SPECK_TYPE) * 8) - r)))//循环右移
#define ROL(x, r) ((x << r) | (x >> ((sizeof(SPECK_TYPE) * 8) - r)))//循环左移

#ifdef SPECK_32_64
#define R(x, y, k) (x = ROR(x, 7), x += y, x ^= k, y = ROL(y, 2), y ^= x)
#define RR(x, y, k) (y ^= x, y = ROR(y, 2), x ^= k, x -= y, x = ROL(x, 7))
#else
#define R(x, y, k) (x = ROR(x, 8), x += y, x ^= k, y = ROL(y, 3), y ^= x)
#define RR(x, y, k) (y ^= x, y = ROR(y, 3), x ^= k, x -= y, x = ROL(x, 8))
#endif

void mycipher_set_encrypt_key(mycipher_key_t *key, const unsigned char *user_key)
{
	int i;
	for (i = 0; i < num_word; i++)
	{
		if (user_key[i] == '\0')
			break;
		key->rk[i] = user_key[i];
	}
	int j = 0;
	for (; i < num_word; i++)
	{
		key->rk[i] = user_key[j++];
	}
}
void speck_expand(SPECK_TYPE const K[ SPECK_KEY_LEN], SPECK_TYPE S[ SPECK_ROUNDS])
{
	SPECK_TYPE i, b = K[0];
	SPECK_TYPE a[SPECK_KEY_LEN - 1];
	for (i = 0; i < (SPECK_KEY_LEN - 1); i++)
	{
		a[i] = K[i + 1];
	}
	S[0] = b;
	for (i = 0; i < SPECK_ROUNDS - 1; i++) {
		R(a[i % (SPECK_KEY_LEN - 1)], b, i);
		S[i + 1] = b;
	}
}
void speck_encrypt(SPECK_TYPE const pt[ 2], SPECK_TYPE ct[ 2], SPECK_TYPE const K[ SPECK_ROUNDS])
{
	SPECK_TYPE i;
	ct[0] = pt[0]; ct[1] = pt[1];
	for (i = 0; i < SPECK_ROUNDS; i++){
		R(ct[1], ct[0], K[i]);
	}
}

void speck_decrypt(SPECK_TYPE const ct[ 2], SPECK_TYPE pt[ 2], SPECK_TYPE const K[ SPECK_ROUNDS])
{
	SPECK_TYPE i;
	pt[0] = ct[0]; pt[1] = ct[1];

	for (i = 0; i < SPECK_ROUNDS; i++){
		RR(pt[1], pt[0], K[(SPECK_ROUNDS - 1) - i]);
	}
}
