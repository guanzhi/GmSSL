#ifndef HEADER_ZUC_H
#define HEADER_ZUC_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	uint32_t LFSR_S0;
	uint32_t LFSR_S1;
	uint32_t LFSR_S2;
	uint32_t LFSR_S3;
	uint32_t LFSR_S4;
	uint32_t LFSR_S5;
	uint32_t LFSR_S6;
	uint32_t LFSR_S7;
	uint32_t LFSR_S8;
	uint32_t LFSR_S9;
	uint32_t LFSR_S10;
	uint32_t LFSR_S11;
	uint32_t LFSR_S12;
	uint32_t LFSR_S13;
	uint32_t LFSR_S14;
	uint32_t LFSR_S15;

	/* the registers of F */
	uint32_t F_R1;
	uint32_t F_R2;

	/* the outputs of BitReorganization */
	uint32_t BRC_X0;
	uint32_t BRC_X1;
	uint32_t BRC_X2;
	uint32_t BRC_X3;

	/* word buffer */
	unsigned char buf[4];
	int buflen;
} ZUC_KEY;


void ZUC_set_key(ZUC_KEY *key, const unsigned char *k, const unsigned char *iv);
void ZUC_encrypt(ZUC_KEY *key, size_t inlen, const unsigned char *in, unsigned char *out);



#ifdef __cplusplus
}
#endif
#endif

