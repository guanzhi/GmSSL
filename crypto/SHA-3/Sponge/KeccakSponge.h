#ifndef _KeccakSponge_h_
#define _KeccakSponge_h_

#include <string.h>
#include <align.h>
#include "KeccakP-1600-Snp.h"
ALIGN(KeccakP1600_stateAlignment) typedef struct KeccakWidth1600_SpongeInstanceStruct { \
        unsigned char state[KeccakP1600_stateSizeInBytes]; \
        unsigned int rate; \
        unsigned int byteIOIndex; \
        int squeezing; \
    } KeccakWidth1600_SpongeInstance;

int KeccakWidth1600_Sponge(unsigned int rate, unsigned int capacity, const unsigned char *input, 
			size_t inputByteLen, unsigned char suffix, unsigned char *output, size_t outputByteLen);

int KeccakWidth1600_SpongeInitialize(KeccakWidth1600_SpongeInstance *spongeInstance, unsigned int rate, unsigned int capacity);

int KeccakWidth1600_SpongeAbsorb(KeccakWidth1600_SpongeInstance *spongeInstance, const unsigned char *data, size_t dataByteLen);

int KeccakWidth1600_SpongeAbsorbLastFewBits(KeccakWidth1600_SpongeInstance *spongeInstance, unsigned char delimitedData);

int KeccakWidth1600_SpongeSqueeze(KeccakWidth1600_SpongeInstance *spongeInstance, unsigned char *data, size_t dataByteLen);

#endif
