#include "SimpleFIPS202.h"

int SHAKE128(unsigned char *output, size_t outputByteLen, const unsigned char *input, size_t inputByteLen)
{
    return KeccakWidth1600_Sponge(1344, 256, input, inputByteLen, 0x1F, output, outputByteLen);
}

int SHAKE256(unsigned char *output, size_t outputByteLen, const unsigned char *input, size_t inputByteLen)
{
    return KeccakWidth1600_Sponge(1088, 512, input, inputByteLen, 0x1F, output, outputByteLen);
}

int SHA3_224(unsigned char *output, const unsigned char *input, size_t inputByteLen)
{
    return KeccakWidth1600_Sponge(1152, 448, input, inputByteLen, 0x06, output, 224/8);
}

int SHA3_256(unsigned char *output, const unsigned char *input, size_t inputByteLen)
{
    return KeccakWidth1600_Sponge(1088, 512, input, inputByteLen, 0x06, output, 256/8);
}

int SHA3_384(unsigned char *output, const unsigned char *input, size_t inputByteLen)
{
    return KeccakWidth1600_Sponge( 832, 768, input, inputByteLen, 0x06, output, 384/8);
}

int SHA3_512(unsigned char *output, const unsigned char *input, size_t inputByteLen)
{
    return KeccakWidth1600_Sponge(576, 1024, input, inputByteLen, 0x06, output, 512/8);
}
