#ifndef _EC_H_
#define _EC_H_

#ifdef EC_DEV
#include <stdint.h>
#else
#include <linux/types.h>
#endif
//extern unsigned int sqr_table[1 << 16];

typedef struct _struct_mm_128{
	union{
		float fv[4];
		double dv[2];
		uint64_t iv[2];
		uint8_t bv[16];
	};
} mm_128;

typedef struct _struct_mm_256{
	union{
		float fv[8];
		double dv[4];
		uint64_t iv[4];
		uint8_t bv[32];
	};
} mm_256;

typedef struct {
	mm_256 x;
	mm_256 y;
	mm_256 z;
} mm256_point_t;

extern void gf2_add(mm_256* a, mm_256* b, mm_256* r);
extern void gf2_mul(mm_256* a, mm_256* b, mm_256* r1, mm_256* r2);
extern void gf2_mod(mm_256* a1, mm_256* a2, mm_256* r);
extern void gf2_sqr(mm_256* a, mm_256* r1, mm_256* r2);
extern void gf2_mod_mul(mm_256* a, mm_256* b, mm_256* r);
extern void gf2_mod_sqr(mm_256* a, mm_256* r);
extern void gf2m_inv(mm_256* a, mm_256 *r);
extern void gf2m_inv_asm(mm_256* a, mm_256 *r);

extern void gf2_point_dbl(mm256_point_t* pa, mm256_point_t* pr, int a, int b);
extern void gf2_point_add(mm256_point_t* pa, mm256_point_t* pb, mm256_point_t* pr, int a, int b);
extern void gf2_point_mul(mm256_point_t* p, mm_256* k, mm256_point_t* q, int a, int b);
extern void gf2_point_mul_with_preset_key(mm256_point_t* p, mm256_point_t* q, int a, int b);

#endif
