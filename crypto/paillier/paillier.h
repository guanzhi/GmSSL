#ifndef HEADER_PAILLIER_H
#define HEADER_PAILLIER_H


#include <openssl/bn.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct paillier_st {
	int bits;
	BIGNUM *n;		/* public key */
	BIGNUM *lambda;		/* private key, lambda(n) = lcm(p-1, q-1) */
	BIGNUM *n_squared;	/* online */
	BIGNUM *n_plusone;	/* online */
	BIGNUM *x;		/* online */
} PAILLIER;

PAILLIER *PAILLIER_new(void);
void PAILLIER_free(PAILLIER *key);

int PAILLIER_generate_key(PAILLIER *key, int bits);
int PAILLIER_check_key(PAILLIER *key);
int PAILLIER_encrypt(BIGNUM *out, const BIGNUM *in, PAILLIER *pub_key);
int PAILLIER_decrypt(BIGNUM *out, const BIGNUM *in, PAILLIER *pri_key);
int PAILLIER_ciphertext_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, PAILLIER *pub_key);
int PAILLIER_ciphertext_scalar_mul(BIGNUM *r, unsigned int k,
	const BIGNUM *a, PAILLIER *pub_key)


#ifdef __cplusplus
}
#endif
#endif

