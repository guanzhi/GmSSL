#ifndef HEADER_ZUC_H
#define HEADER_ZUC_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
    uint32_t lfsr[16];  // The state registers of LFSR.
    uint32_t r[2];      // The registers of F.
    uint32_t x[4];      // The outputs of the bit-reorganization.
} ZUC_KEY;

void ZUC_set_key(ZUC_KEY *key, const unsigned char *k, const unsigned char *iv);
void ZUC_encrypt(ZUC_KEY *key, size_t inlen, const unsigned char *in, unsigned char *out);



#ifdef __cplusplus
}
#endif
#endif

