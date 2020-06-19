#include <stdio.h>
#include <string.h>
#include <x86intrin.h>
#include <immintrin.h>

# define GETU32(p)			\
	((unsigned int)(p)[0] << 24 |	\
	 (unsigned int)(p)[1] << 16 |	\
	 (unsigned int)(p)[2] <<  8 |	\
	 (unsigned int)(p)[3])

# define ROL32(X,n)			\
	(((X) << (n)) | (((X) & 0xffffffff) >> (32-(n))))


# define P1(X)	\
	((X) ^ ROL32((X), 15) ^ ROL32((X), 23))

# define _mm_rotl_epi32(X, i)	_mm_xor_si128(		\
	_mm_slli_epi32((X), i), _mm_srli_epi32((X), 32 - i))


# define P1_128(X)				\
	T = _mm_rotl_epi32((X), (23-15));		\
	T = _mm_xor_si128(T, (X));		\
	T = _mm_rotl_epi32(T, 15);		\
	X = _mm_xor_si128((X), T)

/*
# define GETU128(p)							\
	_mm_setr_epi32(							\
		*((unsigned int *)(((unsigned char *)(p)) + 0)),	\
		*((unsigned int *)(((unsigned char *)(p)) + 4)),	\
		*((unsigned int *)(((unsigned char *)(p)) + 8)),	\
		*((unsigned int *)(((unsigned char *)(p)) + 12)))
*/

# define GETU128(p)			\
	_mm_loadu_si128((__m128i *)(p))

/*
 * _mm_lddqu_si128	SSE3	<pmmintrin.h> faster when data crosses a cache line boundary
 * _mm_load_si128	SSE2	<emmintrin.h>
 * _mm_loadu_si128	SSE2	<emmintrin.h> no aligned mem
 * _mm_loadu_si32	SSE2	<immintrin.h> load u32 to lower 32-bit of xmm
 * _mm_loadl_epi64	SSE2	<emmintrin.h> load u64 to lower 64-bit of xmm
 * _mm_loadu_si64	SSE	<immintrin.h> load unaligned u64 to lower 64-bit of xmm
 */

static void print_words(unsigned int W[68])
{
	int i;
	for (i = 0; i < 68; i++) {
		printf("%08x ", W[i]);
		if (i % 4 == 3)
			printf("\n");
	}
	printf("\n");
}

static void expand(unsigned int W[68], const unsigned char data[64])
{
	int j;
	unsigned int X;
	unsigned int T;

	for (j = 0; j < 16; j++)
		W[j] = GETU32(data + j*4);

	for (; j < 68; j++) {
		W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROL32(W[j - 3], 15))
			^ ROL32(W[j - 13], 7) ^ W[j - 6];
	}
}


static void print_mm(const char *s, __m128i X) {
	unsigned int buf[4];
	int i;

	_mm_store_si128((__m128i *)buf, X);

	printf("%s = ", s);
	for (i = 0; i < 4; i++) {
		printf("%08x ", buf[i]);
	}
	printf("\n");
}

static __m128i V;
static __m128i M;
static __m128i M2;

static void expand_simd(unsigned int W[68], const unsigned char data[64])
{
	__m128i X, T, R;
	int j;
	const uint32_t *p = (uint32_t *)data;

	for (j = 0; j < 16; j += sizeof(X)/sizeof(W[0])) {
		X = _mm_loadu_si128((__m128i *)(data + j * 4));
		X = _mm_shuffle_epi8(X, V);
		_mm_storeu_si128((__m128i *)(W + j), X);
	}

	for (j = 16; j < 68; j += 4) {
		/* X = (W[j - 3], W[j - 2], W[j - 1], 0) */
		X = _mm_loadu_si128((__m128i *)(W + j - 3));
		X = _mm_andnot_si128(M, X);

		X = _mm_rotl_epi32(X, 15);
		T = _mm_loadu_si128((__m128i *)(W + j - 9));
		X = _mm_xor_si128(X, T);
		T = _mm_loadu_si128((__m128i *)(W + j - 16));
		X = _mm_xor_si128(X, T);

		/* P1() */
		T = _mm_rotl_epi32(X, (23 - 15));
		T = _mm_xor_si128(T, X);
		T = _mm_rotl_epi32(T, 15);
		X = _mm_xor_si128(X, T);

		T = _mm_loadu_si128((__m128i *)(W + j - 13));
		T = _mm_rotl_epi32(T, 7);
		X = _mm_xor_si128(X, T);
		T = _mm_loadu_si128((__m128i *)(W + j - 6));
		X = _mm_xor_si128(X, T);

		/* W[j + 3] ^= P1(ROL32(W[j + 1], 15)) */
		R = _mm_shuffle_epi32(X, 0);
		R = _mm_and_si128(R, M);
		T = _mm_rotl_epi32(R, 15);
		T = _mm_xor_si128(T, R);
		T = _mm_rotl_epi32(T, 9);
		R = _mm_xor_si128(R, T);
		R = _mm_rotl_epi32(R, 6);
		X = _mm_xor_si128(X, R);

		_mm_storeu_si128((__m128i *)(W + j), X);
	}
}

void test()
{
	unsigned char block[64] __attribute__((aligned(0x10))) = {0};
	unsigned int W1[68] __attribute__((aligned(0x10))) = {0};
	unsigned int W2[68] __attribute__((aligned(0x10))) = {0};
	int i;

	for (i = 0; i < 64; i++)
		block[i] = i;


	printf("W1 = %08x\n", &W1[0]);
	printf("W2 = %08x\n", &W2[0]);



	expand(W1, block);





	expand_simd(W2, block);


	for (i = 0; i < 68; i++) {
		printf("%08x ", W1[i]);
		if (i % 4 == 3) printf("\n");
	}
	printf("\n");


	for (i = 0; i < 68; i++) {
		printf("%08x ", W2[i]);
		if (i % 4 == 3) printf("\n");
	}
	printf("\n");


	for (i = 0; i < 68; i++) {
		if (W1[i] != W2[i]) {
			printf("failed on %d\n" , i);
			printf("%08x\n", W1[i]);
			printf("%08x\n", W2[i]);
		}
	}
}

int main(int argc, char **argv)
{
	unsigned char block[64] __attribute__((aligned(0x10))) = {0};
	unsigned int W[68] __attribute__((aligned(0x10))) = {0};
	int i;

	V = _mm_setr_epi8(3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12);
	M = _mm_setr_epi32(0, 0, 0, 0xffffffff);


	for (i = 0; i < 64; i++)
		block[i] = i;


	/*
	for (i = 0; i < 1000000; i++) {
		expand(W, block);
	}
	*/

	/*
	for (i = 0; i < 1000000; i++) {
	expand_simd(W, block);
	}
	*/


	test();

	return 0;
}
