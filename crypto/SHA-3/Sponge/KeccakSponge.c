#include "KeccakSponge.h"
#define Sponge                          KeccakWidth1600_Sponge
#define SpongeInstance                  KeccakWidth1600_SpongeInstance
#define SpongeInitialize                KeccakWidth1600_SpongeInitialize
#define SpongeAbsorb                    KeccakWidth1600_SpongeAbsorb
#define SpongeAbsorbLastFewBits         KeccakWidth1600_SpongeAbsorbLastFewBits
#define SpongeSqueeze                   KeccakWidth1600_SpongeSqueeze

#define SnP_stateSizeInBytes            KeccakP1600_stateSizeInBytes
#define SnP_stateAlignment              KeccakP1600_stateAlignment
#define SnP_StaticInitialize            KeccakP1600_StaticInitialize
#define SnP_Initialize                  KeccakP1600_Initialize
#define SnP_AddByte                     KeccakP1600_AddByte
#define SnP_AddBytes                    KeccakP1600_AddBytes
#define SnP_ExtractBytes                KeccakP1600_ExtractBytes
#define SnP_width 						1600
#define SnP_Permute 					KeccakP1600_Permute_24rounds

int Sponge(unsigned int rate, unsigned int capacity, const unsigned char *input, size_t inputByteLen, unsigned char suffix, unsigned char *output, size_t outputByteLen)
{
    ALIGN(SnP_stateAlignment) unsigned char state[SnP_stateSizeInBytes];
    unsigned int partialBlock;
    const unsigned char *curInput = input;
    unsigned char *curOutput = output;
    unsigned int rateInBytes = rate/8;

    if (rate+capacity != SnP_width)
        return 1;
    if ((rate <= 0) || (rate > SnP_width) || ((rate % 8) != 0))
        return 1;
    if (suffix == 0)
        return 1;

    /* Initialize the state */
    SnP_StaticInitialize();
    SnP_Initialize(state);

    /* First, absorb whole blocks */
    while(inputByteLen >= (size_t)rateInBytes) {
        SnP_AddBytes(state, curInput, 0, rateInBytes);
        SnP_Permute(state);
        curInput += rateInBytes;
        inputByteLen -= rateInBytes;
    }

    /* Then, absorb what remains */
    partialBlock = (unsigned int)inputByteLen;
    SnP_AddBytes(state, curInput, 0, partialBlock);

    /* Finally, absorb the suffix */
    /* Last few bits, whose delimiter coincides with first bit of padding */
    SnP_AddByte(state, suffix, partialBlock);
    /* If the first bit of padding is at position rate-1, we need a whole new block for the second bit of padding */
    if ((suffix >= 0x80) && (partialBlock == (rateInBytes-1)))
        SnP_Permute(state);
    /* Second bit of padding */
    SnP_AddByte(state, 0x80, rateInBytes-1);
    SnP_Permute(state);

    /* First, output whole blocks */
    while(outputByteLen > (size_t)rateInBytes) {
        SnP_ExtractBytes(state, curOutput, 0, rateInBytes);
        SnP_Permute(state);
        curOutput += rateInBytes;
        outputByteLen -= rateInBytes;
    }

    /* Finally, output what remains */
    partialBlock = (unsigned int)outputByteLen;
    SnP_ExtractBytes(state, curOutput, 0, partialBlock);

    return 0;
}
/*-------------------------------------------------------------------------------------*/
int SpongeInitialize(SpongeInstance *instance, unsigned int rate, unsigned int capacity)
{
    if (rate+capacity != SnP_width)
        return 1;
    if ((rate <= 0) || (rate > SnP_width) || ((rate % 8) != 0))
        return 1;
    SnP_StaticInitialize();
    SnP_Initialize(instance->state);
    instance->rate = rate;
    instance->byteIOIndex = 0;
    instance->squeezing = 0;

    return 0;
}
/*---------------------------------------------------------------------------------------*/
int SpongeAbsorb(SpongeInstance *instance, const unsigned char *data, size_t dataByteLen)
{
    size_t i, j;
    unsigned int partialBlock;
    const unsigned char *curData;
    unsigned int rateInBytes = instance->rate/8;

    if (instance->squeezing)
        return 1; /* Too late for additional input */

    i = 0;
    curData = data;
    while(i < dataByteLen) {
        if ((instance->byteIOIndex == 0) && (dataByteLen >= (i + rateInBytes))) {
                for(j=dataByteLen-i; j>=rateInBytes; j-=rateInBytes) {
                    SnP_AddBytes(instance->state, curData, 0, rateInBytes);
                    SnP_Permute(instance->state);
                    curData+=rateInBytes;
                }
                i = dataByteLen - j;
        }
        else {
            /* normal lane: using the message queue */
            partialBlock = (unsigned int)(dataByteLen - i);
            if (partialBlock+instance->byteIOIndex > rateInBytes)
                partialBlock = rateInBytes-instance->byteIOIndex;
            i += partialBlock;

            SnP_AddBytes(instance->state, curData, instance->byteIOIndex, partialBlock);
            curData += partialBlock;
            instance->byteIOIndex += partialBlock;
            if (instance->byteIOIndex == rateInBytes) {
                SnP_Permute(instance->state);
                instance->byteIOIndex = 0;
            }
        }
    }
    return 0;
}

/* ---------------------------------------------------------------- */

int SpongeAbsorbLastFewBits(SpongeInstance *instance, unsigned char delimitedData)
{
    unsigned int rateInBytes = instance->rate/8;

    if (delimitedData == 0)
        return 1;
    if (instance->squeezing)
        return 1; /* Too late for additional input */

   
    /* Last few bits, whose delimiter coincides with first bit of padding */
    SnP_AddByte(instance->state, delimitedData, instance->byteIOIndex);
    /* If the first bit of padding is at position rate-1, we need a whole new block for the second bit of padding */
    if ((delimitedData >= 0x80) && (instance->byteIOIndex == (rateInBytes-1)))
        SnP_Permute(instance->state);
    /* Second bit of padding */
    SnP_AddByte(instance->state, 0x80, rateInBytes-1);
    SnP_Permute(instance->state);
    instance->byteIOIndex = 0;
    instance->squeezing = 1;
    return 0;
}

/* ---------------------------------------------------------------- */
int SpongeSqueeze(SpongeInstance *instance, unsigned char *data, size_t dataByteLen)
{
    size_t i, j;
    unsigned int partialBlock;
    unsigned int rateInBytes = instance->rate/8;
    unsigned char *curData;

    if (!instance->squeezing)
        SpongeAbsorbLastFewBits(instance, 0x01);

    i = 0;
    curData = data;
    while(i < dataByteLen) {
        if ((instance->byteIOIndex == rateInBytes) && (dataByteLen >= (i + rateInBytes))) {
            for(j=dataByteLen-i; j>=rateInBytes; j-=rateInBytes) {
                SnP_Permute(instance->state);
                SnP_ExtractBytes(instance->state, curData, 0, rateInBytes);
                curData+=rateInBytes;
            }
            i = dataByteLen - j;
        }
        else {
            /* normal lane: using the message queue */
            if (instance->byteIOIndex == rateInBytes) {
                SnP_Permute(instance->state);
                instance->byteIOIndex = 0;
            }
            partialBlock = (unsigned int)(dataByteLen - i);
            if (partialBlock+instance->byteIOIndex > rateInBytes)
                partialBlock = rateInBytes-instance->byteIOIndex;
            i += partialBlock;

            SnP_ExtractBytes(instance->state, curData, instance->byteIOIndex, partialBlock);
            curData += partialBlock;
            instance->byteIOIndex += partialBlock;
        }
    }
    return 0;
}
