#ifndef _SimpleFIPS202_h_
#define _SimpleFIPS202_h_

#include "KeccakSponge.h"
#include "string.h"

int SHAKE128(unsigned char *output, size_t outputByteLen, const unsigned char *input, size_t inputByteLen);

int SHAKE256(unsigned char *output, size_t outputByteLen, const unsigned char *input, size_t inputByteLen);

int SHA3_224(unsigned char *output, const unsigned char *input, size_t inputByteLen);

int SHA3_256(unsigned char *output, const unsigned char *input, size_t inputByteLen);

int SHA3_384(unsigned char *output, const unsigned char *input, size_t inputByteLen);

int SHA3_512(unsigned char *output, const unsigned char *input, size_t inputByteLen);

#endif
