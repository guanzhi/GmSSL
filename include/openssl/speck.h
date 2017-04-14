#ifndef SPECK_H
#define SPECK_H

/*
* define speck type to use
*(one of SPECK_32_64, SPECK_64_128, SPECK_128_256)
*/
#define SPECK_32_64

#ifdef SPECK_32_64
#define SPECK_TYPE uint16_t
#define SPECK_ROUNDS 22
#define SPECK_KEY_LEN 4
#endif

#ifdef SPECK_64_128
#define SPECK_TYPE uint32_t
#define SPECK_ROUNDS 27
#define SPECK_KEY_LEN 4
#endif

#ifdef SPECK_128_256
#define SPECK_TYPE uint64_t
#define SPECK_ROUNDS 34
#define SPECK_KEY_LEN 4
#endif

#define num_word sizeof(SPECK_TYPE)
#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include<iostream>
#ifdef __cplusplus
extern "C" {
#endif


	void speck_set_encrypt_key(SPECK_TYPE const K[SPECK_KEY_LEN], SPECK_TYPE S[SPECK_ROUNDS]);
	void speck_encrypt(SPECK_TYPE const pt[2], SPECK_TYPE ct[2], SPECK_TYPE const K[SPECK_ROUNDS]);
	void speck_decrypt(SPECK_TYPE const ct[2], SPECK_TYPE pt[2], SPECK_TYPE const K[SPECK_ROUNDS]);

#ifdef __cplusplus
}
#endif
#endif
