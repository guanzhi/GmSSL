

#include <openssl/sm4.h>
#include "internal/rotate.h"
#include "modes_lcl.h"
#include "sms4_lcl.h"

# include <immintrin.h>

# define GET_BLKS(x0, x1, x2, x3, in)					\
	t0 = _mm256_i32gather_epi32((int *)(in+4*0), vindex_4i, 4);	\
	t1 = _mm256_i32gather_epi32((int *)(in+4*1), vindex_4i, 4);	\
	t2 = _mm256_i32gather_epi32((int *)(in+4*2), vindex_4i, 4);	\
	t3 = _mm256_i32gather_epi32((int *)(in+4*3), vindex_4i, 4);	\
	x0 = _mm256_shuffle_epi8(t0, vindex_swap);			\
	x1 = _mm256_shuffle_epi8(t1, vindex_swap);			\
	x2 = _mm256_shuffle_epi8(t2, vindex_swap);			\
	x3 = _mm256_shuffle_epi8(t3, vindex_swap)


# define PUT_BLKS(out, x0, x1, x2, x3)					\
	t0 = _mm256_shuffle_epi8(x0, vindex_swap);			\
	t1 = _mm256_shuffle_epi8(x1, vindex_swap);			\
	t2 = _mm256_shuffle_epi8(x2, vindex_swap);			\
	t3 = _mm256_shuffle_epi8(x3, vindex_swap);			\
	_mm256_storeu_si256((__m256i *)(out+32*0), t0);			\
	_mm256_storeu_si256((__m256i *)(out+32*1), t1);			\
	_mm256_storeu_si256((__m256i *)(out+32*2), t2);			\
	_mm256_storeu_si256((__m256i *)(out+32*3), t3);			\
	x0 = _mm256_i32gather_epi32((int *)(out+8*0), vindex_read, 4);	\
	x1 = _mm256_i32gather_epi32((int *)(out+8*1), vindex_read, 4);	\
	x2 = _mm256_i32gather_epi32((int *)(out+8*2), vindex_read, 4);	\
	x3 = _mm256_i32gather_epi32((int *)(out+8*3), vindex_read, 4);	\
	_mm256_storeu_si256((__m256i *)(out+32*0), x0);			\
	_mm256_storeu_si256((__m256i *)(out+32*1), x1);			\
	_mm256_storeu_si256((__m256i *)(out+32*2), x2);			\
	_mm256_storeu_si256((__m256i *)(out+32*3), x3)

# define _mm256_rotl_epi32(a, i)	_mm256_xor_si256(			\
	_mm256_slli_epi32(a, i), _mm256_srli_epi32(a, 32 - i))

# define INDEX_MASK_TBOX 0xff

# define ROUND_TBOX(x0, x1, x2, x3, x4, i)				\
	t0 = _mm256_set1_epi32(*(rk + i));				\
	t1 = _mm256_xor_si256(x1, x2);					\
	t2 = _mm256_xor_si256(x3, t0);					\
	x4 = _mm256_xor_si256(t1, t2);					\
	t0 = _mm256_and_si256(x4, vindex_mask);				\
	t0 = _mm256_i32gather_epi32((int *)SMS4_T, t0, 4);		\
	t0 = _mm256_rotl_epi32(t0, 8);					\
	x4 = _mm256_srli_epi32(x4, 8);					\
	x0 = _mm256_xor_si256(x0, t0);					\
	t0 = _mm256_and_si256(x4, vindex_mask);				\
	t0 = _mm256_i32gather_epi32((int *)SMS4_T, t0, 4);		\
	t0 = _mm256_rotl_epi32(t0, 16);					\
	x4 = _mm256_srli_epi32(x4, 8);					\
	x0 = _mm256_xor_si256(x0, t0);					\
	t0 = _mm256_and_si256(x4, vindex_mask);				\
	t0 = _mm256_i32gather_epi32((int *)SMS4_T, t0, 4);		\
	t0 = _mm256_rotl_epi32(t0, 24);					\
	x4 = _mm256_srli_epi32(x4, 8);					\
	x0 = _mm256_xor_si256(x0, t0);					\
	t1 = _mm256_i32gather_epi32((int *)SMS4_T, x4, 4);		\
	x4 = _mm256_xor_si256(x0, t1)

# define INDEX_MASK_DBOX 0xffff

# define ROUND_DBOX(x0, x1, x2, x3, x4, i)				\
	t0 = _mm256_set1_epi32(*(rk + i));				\
	t1 = _mm256_xor_si256(x1, x2);					\
	t2 = _mm256_xor_si256(x3, t0);					\
	x4 = _mm256_xor_si256(t1, t2);					\
	t0 = _mm256_srli_epi32(x4, 16);					\
	t1 = _mm256_i32gather_epi32((int *)SMS4_D, t0, 4);		\
	t2 = _mm256_and_si256(x4, vindex_mask);				\
	t3 = _mm256_i32gather_epi32((int *)SMS4_D, t2, 4);		\
	t0 = _mm256_rotl_epi32(t3, 16);					\
	x4 = _mm256_xor_si256(x0, t1);					\
	x4 = _mm256_xor_si256(x4, t0)

# define ROUND ROUND_TBOX
# define INDEX_MASK INDEX_MASK_TBOX



// 这个函数是否要做成完全独立的呢？
void sm4_avx2_ecb_encrypt_blocks(const unsigned char *in, unsigned char *out,
	size_t blocks, const sms4_key_t *key)
{
	const int *rk = (int *)key->rk;
	__m256i x0, x1, x2, x3, x4;
	__m256i t0, t1, t2, t3;
	__m256i vindex_4i = _mm256_setr_epi32(0,4,8,12,16,20,24,28);
	__m256i vindex_mask = _mm256_set1_epi32(INDEX_MASK);
	__m256i vindex_read = _mm256_setr_epi32(0,8,16,24,1,9,17,25);
	__m256i vindex_swap = _mm256_setr_epi8(
		3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12,
		3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12
	);

	while (blocks >= 8) {

		// read 8 blocks
		t0 = _mm256_i32gather_epi32((int *)(in+4*0), vindex_4i, 4);
		t1 = _mm256_i32gather_epi32((int *)(in+4*1), vindex_4i, 4);
		t2 = _mm256_i32gather_epi32((int *)(in+4*2), vindex_4i, 4);
		t3 = _mm256_i32gather_epi32((int *)(in+4*3), vindex_4i, 4);
		x0 = _mm256_shuffle_epi8(t0, vindex_swap);
		x1 = _mm256_shuffle_epi8(t1, vindex_swap);
		x2 = _mm256_shuffle_epi8(t2, vindex_swap);
		x3 = _mm256_shuffle_epi8(t3, vindex_swap);


		// 这里还是循环好了

		ROUNDS(x0, x1, x2, x3, x4);


		PUT_BLKS(out, x0, x4, x3, x2);
		in += 128;
		out += 128;
		blocks -= 8;
	}
}


// 这个应该还是比较有效果的
void sms4_avx2_ctr32_encrypt_blocks(const unsigned char *in, unsigned char *out,
	size_t blocks, const sms4_key_t *key, const unsigned char iv[16])
{
	const int *rk = (int *)key->rk;
	__m256i x0, x1, x2, x3, x4;
	__m256i t0, t1, t2, t3;
	__m256i vindex_4i = _mm256_setr_epi32(0,4,8,12,16,20,24,28);
	__m256i vindex_mask = _mm256_set1_epi32(INDEX_MASK);
	__m256i vindex_read = _mm256_setr_epi32(0,8,16,24,1,9,17,25);
	__m256i vindex_swap = _mm256_setr_epi8(
		3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12,
		3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12
	);
	__m256i incr = _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7);
	int c0 = (int)GETU32(iv     );
	int c1 = (int)GETU32(iv +  4);
	int c2 = (int)GETU32(iv +  8);
	int c3 = (int)GETU32(iv + 12);

	while (blocks >= 8) {
		x0 = _mm256_set1_epi32(c0);
		x1 = _mm256_set1_epi32(c1);
		x2 = _mm256_set1_epi32(c2);
		x3 = _mm256_set1_epi32(c3);
		x3 = _mm256_add_epi32(x3, incr);
		ROUNDS(x0, x1, x2, x3, x4);
		GET_BLKS(t0, t1, t2, t3, in);
		x0 = _mm256_xor_si256(x0, t0);
		x4 = _mm256_xor_si256(x4, t1);
		x3 = _mm256_xor_si256(x3, t2);
		x2 = _mm256_xor_si256(x2, t3);
		PUT_BLKS(out, x0, x4, x3, x2);
		c3 += 8;
		in += 128;
		out += 128;
		blocks -= 8;
	}

	if (blocks) {
		unsigned char ctr[16];
		memcpy(ctr, iv, 12);
		PUTU32(ctr + 12, c3);
		sms4_ctr32_encrypt_blocks(in, out, blocks, key, ctr);
	}
}
