
ZUC_UINT7 D[16] = {
	0x22,
	0x2F,
	0x24,
	0x2A,
	0x6D,
	0x40,
	0x40,
	0x40,
	0x40,
	0x40,
	0x40,
	0x40,
	0x52,
	0x10,
	0x30
};

void ZUC_set_key(ZUC_KEY *key, const unsigned char *user_key, const unsigned char *iv)
{
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

	R1 = R2 = 0;

	for (i = 0; i < 32; i++) {
		BitReconstruction3(X0, X1, X2);
	}


}

