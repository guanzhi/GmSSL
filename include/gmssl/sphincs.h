/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_SPHINCS_H
#define GMSSL_SPHINCS_H


#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <gmssl/sm3.h>
#include <gmssl/hash256.h>
#ifdef ENABLE_SHA2
#include <gmssl/sha2.h>
#endif


#ifdef __cplusplus
extern "C" {
#endif


#if defined(ENABLE_SPHINCS_CROSSCHECK) && defined(ENABLE_SHA2)
# define HASH256_CTX		SHA256_CTX
# define hash256_init		sha256_init
# define hash256_update		sha256_update
# define hash256_finish		sha256_finish
# define HASH256_BLOCK_SIZE	SHA256_BLOCK_SIZE
#else
# define HASH256_CTX		SM3_CTX
# define hash256_init		sm3_init
# define hash256_update		sm3_update
# define hash256_finish		sm3_finish
# define HASH256_BLOCK_SIZE	SM3_BLOCK_SIZE
#endif

/*
In order to make keeping track of the types easier throughout the pseudo-code in the rest of
this document, we refer to them respectively using the constants WOTS_HASH, WOTS_PK, TREE,
FORS_TREE, FORS_ROOTS, WOTS_PRF, and FORS_PRF.
*/

enum {
	SPHINCS_ADRS_TYPE_WOTS_PRF	= 0,
	SPHINCS_ADRS_TYPE_WOTS_PK	= 1,
	SPHINCS_ADRS_TYPE_HASHTREE	= 2,
	SPHINCS_ADRS_TYPE_FORS_TREE	= 3,
	SPHINCS_ADRS_TYPE_FORS_ROOT	= 4,
	SPHINCS_ADRS_TYPE_WOTS_KEYGEN	= 5,
	SPHINCS_ADRS_TYPE_FORS_KEYGEN	= 6,
};

typedef uint8_t sphincs_adrs_t[32];

typedef struct {
	uint32_t layer_address;
	uint32_t tree_address[3];
	uint32_t type; // = 0
	uint32_t keypair_address;
	uint32_t chain_address;
	uint32_t hash_address;
} SPHINCS_ADRS_WOTS_HASH;

void sphincs_adrs_copy_layer_address(sphincs_adrs_t dst, const sphincs_adrs_t src);
void sphincs_adrs_copy_tree_address(sphincs_adrs_t dst, const sphincs_adrs_t src);
void sphincs_adrs_copy_type(sphincs_adrs_t dst, const sphincs_adrs_t src);
void sphincs_adrs_copy_keypair_address(sphincs_adrs_t dst, const sphincs_adrs_t src);
void sphincs_adrs_copy_chain_address(sphincs_adrs_t dst, const sphincs_adrs_t src);
void sphincs_adrs_copy_hash_address(sphincs_adrs_t dst, const sphincs_adrs_t src);

void sphincs_adrs_set_layer_address(sphincs_adrs_t adrs, const uint32_t address);
void sphincs_adrs_set_tree_address(sphincs_adrs_t adrs, const uint64_t address);
void sphincs_adrs_set_type(sphincs_adrs_t adrs, const uint32_t type);
void sphincs_adrs_set_keypair_address(sphincs_adrs_t adrs, const uint32_t address);
void sphincs_adrs_set_chain_address(sphincs_adrs_t adrs, const uint32_t address);
void sphincs_adrs_set_hash_address(sphincs_adrs_t adrs, const uint32_t address);

// 所有的padding都在最后，是否意味着可以不用padding?
typedef struct {
	uint32_t layer_address;
	uint32_t tree_address[3];
	uint32_t type; // = 1
	uint32_t keypair_address;
	uint32_t padding[3]; // = {0,0,0}
} SPHINCS_ADRS_WOTS_PK_COMP;

typedef struct {
	uint32_t layer_address;
	uint32_t tree_address[3];
	uint32_t type; // = 2
	uint32_t padding; // = 0
	uint32_t tree_height;
	uint32_t tree_index;
} SPHINCS_ADRS_HASHTREE;

void sphincs_adrs_copy_tree_height(sphincs_adrs_t dst, const sphincs_adrs_t src);
void sphincs_adrs_copy_tree_index(sphincs_adrs_t dst, const sphincs_adrs_t src);
void sphincs_adrs_set_tree_height(sphincs_adrs_t adrs, uint32_t height);
void sphincs_adrs_set_tree_index(sphincs_adrs_t adrs, uint32_t index);

typedef struct {
	uint32_t layer_address;
	uint32_t tree_address[3];
	uint32_t type; // = 3
	uint32_t keypair_address;
	uint32_t tree_height;
	uint32_t tree_index;
} SPHINCS_ADRS_FORS_TREE;

typedef struct {
	uint32_t layer_address;
	uint32_t tree_address[3];
	uint32_t type; // = 4
	uint32_t keypair_address;
	uint32_t padding[2]; // = {0,0}
} SPHINCS_ADRS_FORS_ROOT;

typedef struct {
	uint32_t layer_address;
	uint32_t tree_address[3];
	uint32_t type; // = 5
	uint32_t keypair_address;
	uint32_t chain_address;
	uint32_t hash_address; // = 0
} SPHINCS_ADRS_WOTS_KEYGEN;

typedef struct {
	uint32_t layer_address;
	uint32_t tree_address[3];
	uint32_t type; // = 6
	uint32_t keypair_address;
	uint32_t tree_height; // = 0
	uint32_t tree_index;
} SPHINCS_ADRS_FORS_KEYGEN;

typedef uint8_t sphincs_adrsc_t[22];

void sphincs_adrs_compress(const sphincs_adrs_t adrs, sphincs_adrsc_t adrsc);

// 这里比较奇怪的是，fors的参数以及哈希值是多少？
// 哈希值被分成两部分，一部分用来从hypertree上找到树的地址，一个是用于fors的输入
typedef struct {
	char *name;
	size_t secret_size; // 这个是n，当sm3/sha256时n==16
	size_t height;
	size_t layers;
	size_t fors_height;
	size_t fors_trees;
	int winternitz_w;
	int bitsec;
	int sec_level;
	size_t siglen;
} SPHINCS_PARAMS;

// sizeof(sphincs_secret_t) == n, when sm3/sha256, n == 16
typedef uint8_t sphincs_secret_t[16];



void sphincs_wots_chain(const sphincs_secret_t x,
	const sphincs_secret_t seed, const sphincs_adrs_t ots_adrs,
	int start, int steps, sphincs_secret_t y);


typedef sphincs_secret_t sphincs_wots_key_t[35];
typedef sphincs_secret_t sphincs_wots_sig_t[35];


void sphincs_wots_derive_sk(const sphincs_secret_t secret,
	const sphincs_secret_t seed, const sphincs_adrs_t adrs,
	sphincs_wots_key_t sk);


#ifdef __cplusplus
}
#endif
#endif

