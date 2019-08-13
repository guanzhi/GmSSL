

#include <openssl/zuc.h>

static const ZUC_UINT7 ZUC256_MAC32_D[] = {
	0x22,0x2F,0x25,0x2A,0x6D,0x40,0x40,0x40,
	0x40,0x40,0x40,0x40,0x40,0x52,0x10,0x30
};

static const ZUC_UINT7 ZUC256_MAC64_D[] = {
	0x23,0x2F,0x24,0x2A,0x6D,0x40,0x40,0x40,
	0x40,0x40,0x40,0x40,0x40,0x52,0x10,0x30,
};

static const ZUC_UINT7 ZUC256_MAC128_D[] = {
	0x23,0x2F,0x25,0x2A,0x6D,0x40,0x40,0x40,
	0x40,0x40,0x40,0x40,0x40,0x52,0x10,0x30,
};

typedef struct {
	ZUC_KEY zuc;
	ZUC_MAC_TAG t1;
	ZUC_MAC_TAG t2;
	int macbits;
} ZUC256_MAC_CTX;


int ZUC_MAC_init(ZUC_MAC *ctx, const unsigned char *key, int bits,
	const unsigned char *iv, int macbits)
{
	const ZUC_UINT7 *K;
	ZUC_UINT31 *LFSR = key->LFSR;
	uint32_t R1, R2;
	uint32_t X0, X1, X2;
	uint32_t W, W1, W2, U, V;
	int i;

	switch (macbits) {
	case 32:
		K = KD32;
		break;
	case 64:
		K = KD64;
		break;
	case 128:
		K = KD128;
		break;
	default:
		return 0;
	}

	LFSR[0] = MAKEU31(K[0], D[0], K[21], K[16]);
	LFSR[1] = MAKEU31(K[1], D[1], K[22], K[17]);
	LFSR[2] = MAKEU31(K[2], D[2], K[23], K[18]);
	LFSR[3] = MAKEU31(K[3], D[3], K[24], K[19]);
	LFSR[4] = MAKEU31(K[4], D[4], K[25], K[20]);
	LFSR[5] = MAKEU31(IV[0], (D[5] | IV[17]), K[5], K[26]);
	LFSR[6] = MAKEU31(IV[1], (D[6] | IV[18]), K[6], K[27]);
	LFSR[7] = MAKEU31(IV[10], (D[7] | IV[19]), K[7], IV[2]);
	LFSR[8] = MAKEU31(K[8], (D[8] | IV[20]), IV[13], IV[11]);
	LFSR[9] = MAKEU31(K[9], (D[9] | IV[21]), IV[12], IV[4]);
	LFSR[10] = MAKEU31(IV[5], (D[10] | IV[22]), K[10], K[28]);
	LFSR[11] = MAKEU31(K[11], (D[11] | IV[23]), IV[6], IV[13]);
	LFSR[12] = MAKEU31(K[12], (D[12] | IV[24]), IV[7], IV[14]);
	LFSR[13] = MAKEU31(K[13], D[13], IV[15], IV[8]);
	LFSR[14] = MAKEU31(K[14], (D[14] | (K[31] >> 4)), IV[16], IV[9]);
	LFSR[15] = MAKEU31(K[15], (D[15] | (K[31] & 0xF0)), K[30], K[29]);

	R1 = 0;
	R2 = 0;

	for (i = 0; i < 32; i++) {
		BitReconstruction3(X0, X1, X2);
		W = F(X0, X1, X2);
		LFSRWithInitialisationMode(W >> 1);
	}

	BitReconstruction2(X1, X2);
	F_(X1, X2);
	LFSRWithWorkMode();

	key->R1 = R1;
	key->R2 = R2;

}


#define MAKEU32(i,A,B)		(((A) << (i)) | ((B) >> (32 - (i))))
#define MASKU8(i,M)		(-(((M) >> (7-i)) & 0x01))

int ZUC256_MAC32(ZUC256_MAC_CTX *ctx, const unsigned char *data, size_t len)
{
	uint32_t T;
	uint32_t Z;
	uint32_t *m = data;

	T = ZUC256_generate_keyword(key);
	Z0 = ZUC256_generate_keyword(key);
	Z1 = ZUC256_generate_keyword(key);

	for (i = 0; i < len; i++) {

		T ^= MAKEU32(Z0, Z1, (i * 8 + 0) % 32) & MASKU8(data[i], 7);
		T ^= MAKEU32(Z0, Z1, (i * 8 + 1) % 32) & MASKU8(data[i], 6);
		T ^= MAKEU32(Z0, Z1, (i * 8 + 2) % 32) & MASKU8(data[i], 5);
		T ^= MAKEU32(Z0, Z1, (i * 8 + 3) % 32) & MASKU8(data[i], 4);
		T ^= MAKEU32(Z0, Z1, (i * 8 + 4) % 32) & MASKU8(data[i], 3);
		T ^= MAKEU32(Z0, Z1, (i * 8 + 5) % 32) & MASKU8(data[i], 2);
		T ^= MAKEU32(Z0, Z1, (i * 8 + 6) % 32) & MASKU8(data[i], 1);
		T ^= MAKEU32(Z0, Z1, (i * 8 + 7) % 32) & MASKU8(data[i], 0);

		if (i % 4 == 3) {
			Z0 = Z1;
			Z1 = ZUC256_generate_keyword(key);
		}
	}

	T ^= MAKEU32(Z0, Z1, (i * 8) % 32);

	return 0;
}
