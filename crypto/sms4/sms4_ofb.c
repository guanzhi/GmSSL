#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sms4.h"

#ifndef MODES_DEBUG
# ifndef NDEBUG
#  define NDEBUG
# endif
#endif
#include <assert.h>


void sms4_ofb128_encrypt(const unsigned char *in, unsigned char *out,
			size_t length, const sms4_key_t *key,
			unsigned char ivec[SMS4_BLOCK_SIZE],
			unsigned int *num) {
	CRYPTO_ofb128_encrypt(in,out,length,key,ivec,num,(block128_f)sms4_encrypt);
}
//cprefix##_ofb##cbits##_encrypt