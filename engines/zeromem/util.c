#include <stdlib.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/objects.h>
#include "util.h"

unsigned int sqr_table[1 << 16];

void print_mm_256(mm_256* m){
	/* printf("(%lu, %lu, %lu, %lu)", m->iv[3], m->iv[2], m->iv[1], m->iv[0]); */
  BIGNUM *bn = BN_new();
  mm256_to_bn(m, bn);
  printf("%s", BN_bn2hex(bn));
}

void init_sqr_table(){
	unsigned int i, j;
	unsigned int t;
	unsigned int n;
	for(i = 0; i < sizeof(sqr_table) / sizeof(sqr_table[0]); i++){
		t = 0;
		j = i;
		n = 16;
		while(n-- > 0){
			t = t << 2;
			t |= ((j >> n) & 0x1);
		}
		sqr_table[i] = t;
	}
}

void ec_point_init(ec_point_t *P) {
	P->X = BN_new();
	P->Y = BN_new();
	P->Z = BN_new();	
}

void ec_point_free(ec_point_t *P){
	OPENSSL_free(P->X);
	OPENSSL_free(P->Y);
	OPENSSL_free(P->Z);
}

void bn_to_mm256(const BIGNUM* bn, mm_256* m){
	memset(m, 0, sizeof(mm_256));
	assert(bn->top <= 4);
	int i;
	
	for(i = 0; i < bn->top; i++){
		m->iv[i] = bn->d[i];
	}
}

void mm256_to_bn(const mm_256* m, BIGNUM* bn){
	BN_zero(bn);
	int i = 4;
	while(i-- > 0){
		BN_lshift(bn, bn, 64);
		BN_add_word(bn, m->iv[i]);
	}
}

void bn_point_to_mm_point(const ec_point_t* src, mm256_point_t* dst){
	bn_to_mm256(src->X, &dst->x);
	bn_to_mm256(src->Y, &dst->y);
	bn_to_mm256(src->Z, &dst->z);
}

void EC_POINT_to_mm_point(const ec_point_st* src, mm256_point_t* dst)
{
	bn_to_mm256(&src->X, &dst->x);
	bn_to_mm256(&src->Y, &dst->y);
	bn_to_mm256(&src->Z, &dst->z);
}

void mm_point_to_EC_POINT(const mm256_point_t* src, ec_point_st* dst)
{
	mm256_to_bn(&(src->x), &dst->X);
	mm256_to_bn(&(src->y), &dst->Y);
	mm256_to_bn(&(src->z), &dst->Z);
}

void mm_point_to_bn_point(const mm256_point_t* src, ec_point_t* dst){
	mm256_to_bn(&(src->x), dst->X);
	mm256_to_bn(&(src->y), dst->Y);
	mm256_to_bn(&(src->z), dst->Z);
}

int cmp_mm_256_with_bn(mm_256* a, BIGNUM* bn){
	mm_256 b;
	bn_to_mm256(bn, &b);
	return memcmp(a, &b, sizeof(mm_256));
}

int cmp_mm_point_with_bn_point(mm256_point_t* a, ec_point_t* b){
	mm256_point_t t;
	bn_point_to_mm_point(b, &t);
	return memcmp(a, &t, sizeof(mm256_point_t));
}

void print_bn_point(ec_point_t* p){
	char *px, *py, *pz;
	px = BN_bn2str(p->X);
	py = BN_bn2str(p->Y);
	pz = BN_bn2str(p->Z);
	printf("(%s: %s: %s)", px, py, pz);
	OPENSSL_free(px);
	OPENSSL_free(py);
	OPENSSL_free(pz);
}

void print_EC_POINT(ec_point_st*p)
{
	char *px, *py, *pz;

	if(p->X.d)
      px = BN_bn2str(&p->X);
    else
      px = "";
    if(p->Y.d)
      py = BN_bn2str(&p->Y);
    else
      py = "";
    if(p->Z.d)
      pz = BN_bn2str(&p->Z);
    else
      pz = "";
    
	printf("(%s: %s: %s)", px, py, pz);

    if(p->X.d)
      OPENSSL_free(px);
	if(p->Y.d)
      OPENSSL_free(py);
	if(p->Z.d)
      OPENSSL_free(pz);
}

void print_mm_point(mm256_point_t* p){
	ec_point_t t;
	ec_point_init(&t);
	mm_point_to_bn_point(p, &t);
	print_bn_point(&t);
	ec_point_free(&t);
}

void print_affine_bn_point(ec_point_t* p){
	char *px, *py;
	px = BN_bn2str(p->X);
	py = BN_bn2str(p->Y);
	printf("(%s, %s)", px, py);
	OPENSSL_free(px);
	OPENSSL_free(py);
}

void print_affine_mm_point(mm256_point_t* p){
	ec_point_t t;
	ec_point_init(&t);
	mm_point_to_bn_point(p, &t);
	print_affine_bn_point(&t);
	ec_point_free(&t);
}

void printHex(uint8_t* str, uint32_t len){
	uint32_t i;
	for(i = 0; i < len; i++){
		printf("%02x", str[i]);
	}
}

void save_ymm_group(uint8_t* buf){
	__asm__("vmovdqu %ymm0, (%rdi)\n\t"
			"vmovdqu %ymm1, 32(%rdi)\n\t"
			"vmovdqu %ymm2, 64(%rdi)\n\t"
			"vmovdqu %ymm3, 96(%rdi)\n\t"
			"vmovdqu %ymm4, 128(%rdi)\n\t"
			"vmovdqu %ymm5, 160(%rdi)\n\t"
			"vmovdqu %ymm6, 192(%rdi)\n\t"
			"vmovdqu %ymm7, 224(%rdi)\n\t"
			"vmovdqu %ymm8, 256(%rdi)\n\t"
			"vmovdqu %ymm9, 288(%rdi)\n\t"
			"vmovdqu %ymm10, 320(%rdi)\n\t"
			"vmovdqu %ymm11, 352(%rdi)\n\t"
			"vmovdqu %ymm12, 384(%rdi)\n\t"
			"vmovdqu %ymm13, 416(%rdi)\n\t"
			"vmovdqu %ymm14, 448(%rdi)\n\t"
			"vmovdqu %ymm15, 480(%rdi)\n\t"
		   );
	__asm__("" ::: "memory");
}

void load_ymm_group(uint8_t* buf){
	__asm__("vmovdqu (%rdi), %ymm0\n\t"
			"vmovdqu 32(%rdi), %ymm1\n\t"
			"vmovdqu 64(%rdi), %ymm2\n\t"
			"vmovdqu 96(%rdi), %ymm3\n\t"
			"vmovdqu 128(%rdi), %ymm4\n\t"
			"vmovdqu 160(%rdi), %ymm5\n\t"
			"vmovdqu 192(%rdi), %ymm6\n\t"
			"vmovdqu 224(%rdi), %ymm7\n\t"
			"vmovdqu 256(%rdi), %ymm8\n\t"
			"vmovdqu 288(%rdi), %ymm9\n\t"
			"vmovdqu 320(%rdi), %ymm10\n\t"
			"vmovdqu 352(%rdi), %ymm11\n\t"
			"vmovdqu 384(%rdi), %ymm12\n\t"
			"vmovdqu 416(%rdi), %ymm13\n\t"
			"vmovdqu 448(%rdi), %ymm14\n\t"
			"vmovdqu 480(%rdi), %ymm15\n\t"
		   );
	__asm__("" ::: "memory");
}

void dummy_print(const char* format, ...){
}
