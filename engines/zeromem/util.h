#ifndef _UTIL_H_
#define _UTIL_H_

#include "ec.h"
#include <openssl/bn.h>

//#define DEBUG

//#define PRINT_DEC
#ifdef PRINT_DEC
#define BN_bn2str(bn)	BN_bn2dec(bn)
#else
#define BN_bn2str(bn)	BN_bn2hex(bn)
#endif

extern void dummy_print(const char* format, ...);

#ifdef DEBUG
#define debug printf
#else
#define debug dummy_print
#endif

extern unsigned int sqr_table[1 << 16];

#define rdtsc_begin(hi, lo)\
	asm volatile ("CPUID\n\t"\
			"RDTSCP\n\t"\
			"movq %%rdx, %0\n\t"\
			"movq %%rax, %1\n\t" : "=r" (hi), "=r" (lo) :: "%rax", "%rbx", "%rcx", "%rdx");

#define rdtsc_end(hi, lo)\
	asm volatile ("RDTSCP\n\t"\
			"movq %%rdx, %0\n\t"\
			"movq %%rax, %1\n\t"\
			"CPUID\n\t" : "=r" (hi), "=r" (lo) :: "%rax", "%rbx", "%rcx", "%rdx");

typedef struct {
	BIGNUM *X; 
	BIGNUM *Y; 
	BIGNUM *Z; 
} ec_point_t;

typedef struct{
	const struct EC_METHOD *meth;

	/* All members except 'meth' are handled by the method functions,
	 * even if they appear generic */

	BIGNUM X;
	BIGNUM Y;
	BIGNUM Z; /* Jacobian projective coordinates:
	           * (X, Y, Z)  represents  (X/Z^2, Y/Z^3)  if  Z != 0 */
	int Z_is_one; /* enable optimized point arithmetics for special case */
} ec_point_st /* EC_POINT */;

extern void init_sqr_table();
extern void bn_to_mm256(const BIGNUM* bn, mm_256 *m);
extern void mm256_to_bn(const mm_256 *m, BIGNUM* bn);
extern void bn_point_to_mm_point(const ec_point_t* src, mm256_point_t* dst);
extern void mm_point_to_bn_point(const mm256_point_t* src, ec_point_t* dst);
extern void EC_POINT_to_mm_point(const ec_point_st* src, mm256_point_t* dst);
extern void mm_point_to_EC_POINT(const mm256_point_t* src, ec_point_st* dst);

extern void ec_point_init(ec_point_t *P);
extern void ec_point_free(ec_point_t *P);

extern int cmp_mm_256_with_bn(mm_256* a, BIGNUM* bn);
extern int cmp_mm_point_with_bn_point(mm256_point_t* a, ec_point_t* b);

extern void print_affine_bn_point(ec_point_t* p);
extern void print_affine_mm_point(mm256_point_t* p);
extern void print_bn_point(ec_point_t* p);
extern void print_mm_point(mm256_point_t* p);
extern void print_EC_POINT(ec_point_st* p);

extern void printHex(uint8_t* str, uint32_t len);

extern void save_ymm_group(uint8_t* buf);
extern void load_ymm_group(uint8_t* buf);

#endif
