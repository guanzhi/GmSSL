#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/aes.h>
#include <sys/time.h>
#include "ec.h"
#include "aes_tight.h"
#include "util.h"
#include "sys_ec2m.h"
#include "ec2m_kern.h"

#include "test.h"

/*
 * list all embedded elliptic curves in openssl:
 * # openssl ecparam -list_curves
 */
#define curve_sect163k1		"sect163k1"
#define curve_sect163r1		"sect163r1"
#define curve_sect233k1		"sect233k1"
#define curve_sect233r1		"sect233r1"

/* Lopez-Dahab coordinates */
#define __LD__

/* Affine Coordinates */
#define __AFFINE__

const int sz_buf = 1024;
const int cntUS = 1000000;

BN_CTX *ctx;
EC_GROUP *ec_group;
const EC_POINT *G;
static BIGNUM *p = NULL;
static BIGNUM *a = NULL;
static BIGNUM *b = NULL;
static BIGNUM *x = NULL;
static BIGNUM *y = NULL;
static BIGNUM *n = NULL;
static BIGNUM *h = NULL;
static int a_is_one = 0;
static int b_is_one = 0;

int initDomainParameters(int argc, char** argv){
	ctx = BN_CTX_new();
	ec_group = EC_GROUP_new_by_curve_name(OBJ_sn2nid("sect163k1"));
	p = BN_new();
	a = BN_new();
	b = BN_new();
	x = BN_new();
	y = BN_new();
	n = BN_new();
	h = BN_new();

	assert(EC_GROUP_get_curve_GF2m(ec_group, p, a, b, NULL));
	assert(EC_GROUP_get_order(ec_group, n, NULL));
	assert(EC_GROUP_get_cofactor(ec_group, h, NULL));
	G = EC_GROUP_get0_generator(ec_group);
	assert(G);
	assert(EC_POINT_get_affine_coordinates_GF2m(ec_group, G, x, y, NULL));

	if (BN_is_one(a))
		a_is_one = 1;
	if (BN_is_one(b))
		b_is_one = 1;

	init_sqr_table();
	return 1;
}

void domain_parameters_print() {
	assert(p && a && b && x && y && n && h);

	printf("p = 0x %s\n", BN_bn2str(p));
	printf("a = 0x %s\n", BN_bn2str(a));
	printf("b = 0x %s\n", BN_bn2str(b));
	printf("x = 0x %s\n", BN_bn2str(x));
	printf("y = 0x %s\n", BN_bn2str(y));
	printf("n = 0x %s\n", BN_bn2str(n));
	printf("h = 0x %s\n", BN_bn2str(h));
}

void ec_point_set_infinity(ec_point_t *P) {
	BN_one(P->X);
	BN_zero(P->Y);
	BN_zero(P->Z);
}

void ec_point_set_affine_xy(ec_point_t *P, const BIGNUM *ax, const BIGNUM *ay) {
	BN_copy(P->X, ax);
	BN_copy(P->Y, ay);
	BN_one(P->Z);
}

void ec_point_ld_to_affine(ec_point_t *P) {
}


/* in Lopez-Dahab co-ordinates
 * the point at infinity (oo) is (1: 0: 0)
 * and -(X: Y: Z) is (X: X+Y: Z)
 */ 
int ec_point_is_at_infinity(const ec_point_t __LD__ *P) {
	assert(P->X && P->Y && P->Z);
	if (BN_is_one(P->X) && BN_is_zero(P->Y) && BN_is_zero(P->Z))
		return 1;
	return 0;
}

void ec_point_copy(ec_point_t *R, const ec_point_t *P) {
	BN_copy(R->X, P->X);
	BN_copy(R->Y, P->Y);
	BN_copy(R->Z, P->Z);
}

/*
 * Algorithm 3.24 in "Guide to Elliptic Curve Cryptography"
 * P = (X1: Y1: Z1)
 * R = 2P = (X3: Y3: Z3)
 */
void ec_point_double(ec_point_t __LD__ *R, const ec_point_t __LD__ *P) {
	int r;
	BN_CTX *ctx = BN_CTX_new();
	const BIGNUM *X1 = P->X;
	const BIGNUM *Y1 = P->Y;
	const BIGNUM *Z1 = P->Z;
	      BIGNUM *X3 = R->X;
	      BIGNUM *Y3 = R->Y;
	      BIGNUM *Z3 = R->Z;
	      BIGNUM *T1 = BN_new();
	      BIGNUM *T2 = BN_new();

	debug(" 1. if P == oo, return P. ");
	if (ec_point_is_at_infinity(P)) {
		debug("P == oo\n");
		ec_point_copy(R, P);
		return;
	} else {
		debug("P != oo\n");
	}

	debug(" 2. T1 = Z1^2");
	r = BN_GF2m_mod_sqr(T1, Z1, p, ctx);
	assert(r);
	debug(" = %s\n", BN_bn2str(T1));

	debug(" 3. T2 = X1^2");
	r = BN_GF2m_mod_sqr(T2, X1, p, ctx);
	assert(r);
	debug(" = %s\n", BN_bn2str(T2));

	debug(" 4. Z3 = T1 * T2");
	r = BN_GF2m_mod_mul(Z3, T1, T2, p, ctx);
	assert(r);
	debug(" = %s\n", BN_bn2str(Z3));

	debug(" 5. X3 = T2^2");
	r = BN_GF2m_mod_sqr(X3, T2, p, ctx);
	assert(r);
	debug(" = %s\n", BN_bn2str(X3));

	debug(" 6. T1 = T1^2");
	r = BN_GF2m_mod_sqr(T1, T1, p, ctx);
	assert(r);
	debug(" = %s\n", BN_bn2str(T1));
	
	debug(" 7. T2 = T1 * b");
	if (b_is_one)
		BN_copy(T2, T1);
	else
		r = BN_GF2m_mod_mul(T2, T1, b, p, ctx);
	assert(r);
	debug(" = %s\n", BN_bn2str(T2));

	debug(" 8. X3 = X3 + T2");
	r = BN_GF2m_add(X3, X3, T2);
	assert(r);
	debug(" = %s\n", BN_bn2str(X3));
	
	debug(" 9. T1 = Y1^2");
	r = BN_GF2m_mod_sqr(T1, Y1, p, ctx);
	assert(r);
	debug(" = %s\n", BN_bn2str(T1));
	
	debug("10. if a==1, T1 = T1 + Z3, ");
	if (a_is_one) {
		debug("a == 1, T1 = T1 + Z3");
		r = BN_GF2m_add(T1, T1, Z3);
		assert(r);
		debug(" = %s\n", BN_bn2str(T1));
	} else {
		debug("a != 1, do nothing\n");
	}

	debug("11. T1 = T1 + T2");
	r = BN_GF2m_add(T1, T1, T2);
	assert(r);
	debug(" = %s\n", BN_bn2str(T1));

	debug("12. Y3 = X3 * T1");
	r = BN_GF2m_mod_mul(Y3, X3, T1, p, ctx);
	assert(r);
	debug(" = %s\n", BN_bn2str(X3));

	debug("13. T1 = T2 * Z3");
	r = BN_GF2m_mod_mul(T1, T2, Z3, p, ctx);
	assert(r);
	debug(" = %s\n", BN_bn2str(T1));
	
	debug("14. Y3 = Y3 + T1");
	r = BN_GF2m_add(Y3, Y3, T1);
	assert(r);
	debug(" = %s\n", BN_bn2str(Y3));

	debug("15. return (X3: Y3: Z3) = (%s: %s: %s)\n", BN_bn2str(X3), BN_bn2str(Y3), BN_bn2str(Z3));
	return;
}

void ec_point_add(ec_point_t __LD__ *R, const ec_point_t __LD__ *P, const ec_point_t __AFFINE__ *Q) {
	int r;
	BN_CTX *ctx = BN_CTX_new();
	const BIGNUM *X1 = P->X;
	const BIGNUM *Y1 = P->Y;
	const BIGNUM *Z1 = P->Z;
	const BIGNUM *x2 = Q->X;
	const BIGNUM *y2 = Q->Y;
	      BIGNUM *X3 = R->X;
	      BIGNUM *Y3 = R->Y;
	      BIGNUM *Z3 = R->Z;
	      BIGNUM *T1 = BN_new();
	      BIGNUM *T2 = BN_new();
	      BIGNUM *T3 = BN_new();
	
	debug(" 1. if Q == oo, return P. Q should not be oo\n");
	
	debug(" 2. if P == oo, return Q. ");
	if (ec_point_is_at_infinity(P)) {
		debug(" P == oo, return Q\n");
		ec_point_copy(R, Q);
		return;
	} else {
		debug(" P != oo\n");
	}

	debug(" 3. T1 = Z1 * x2");
	r = BN_GF2m_mod_mul(T1, Z1, x2, p, ctx);
	assert(r);
	debug(" = %s\n", BN_bn2str(T1));
	
	debug(" 4. T2 = Z1^2");
	r = BN_GF2m_mod_sqr(T2, Z1, p, ctx);
	assert(r);
	debug(" = %s\n", BN_bn2str(T2));	

	debug(" 5. X3 = X1 + T1");
	r = BN_GF2m_add(X3, X1, T1);
	assert(r);
	debug(" = %s\n", BN_bn2str(X3));
	
	debug(" 6. T1 = Z1 * X3");
	r = BN_GF2m_mod_mul(T1, Z1, X3, p, ctx);
	assert(r);
	debug(" = %s\n", BN_bn2str(T1));

	debug(" 7. T3 = T2 * y2");
	r = BN_GF2m_mod_mul(T3, T2, y2, p, ctx);
	assert(r);
	debug(" = %s\n", BN_bn2str(T3));	

	debug(" 8. Y3 = Y1 + T3");
	r = BN_GF2m_add(Y3, Y1, T3);
	assert(r);
	debug(" = %s\n", BN_bn2str(Y3));
	
	/* 9. if X3 == 0,
		if Y3 == 0, (X3: Y3: Z3) = 2(x2: y2: 1)
		else return oo
	 */
	debug(" 9. if X3 == 0 { if Y3== 0, return 2(x2: y2: 1) } else return oo\n");
	if (BN_is_zero(X3)) {
		debug("X3 == 0\n");
		if (BN_is_zero(Y3)) {
			debug("Y3 == 0\n");
			ec_point_double(R, P);
			return;
		}
	}
	 
	 
	debug("10. Z3 = T1^2");
	r = BN_GF2m_mod_sqr(Z3, T1, p, ctx);
	assert(r);
	debug(" = %s\n", BN_bn2str(Z3));
	
	debug("11. T3 = T1 * Y3");
	r = BN_GF2m_mod_mul(T3, T1, Y3, p, ctx);
	debug(" = %s\n", BN_bn2str(T3));
	
	debug("12. if a==1, T1 = T1 + T2\n");
	if (a_is_one) {
		debug("a == 1, T1 = T1 + T2");
		r = BN_GF2m_add(T1, T1, T2);
		debug(" = %s\n", BN_bn2str(T1));
	}
	
	debug("13. T2 = X3^2");
	r = BN_GF2m_mod_sqr(T2, X3, p, ctx);
	assert(r);
	debug(" = %s\n", BN_bn2str(T2));

	
	debug("14. X3 = T2 * T1");
	r = BN_GF2m_mod_mul(X3, T2, T1, p, ctx);	
	assert(r);
	debug(" = %s\n", BN_bn2str(X3));
	
	debug("15. T2 = Y3^2");
	r = BN_GF2m_mod_sqr(T2, Y3, p, ctx);
	assert(r);
	debug(" = %s\n", BN_bn2str(T2));
	
	debug("16. X3 = X3 + T2");
	r = BN_GF2m_add(X3, X3, T2);
	assert(r);
	debug(" = %s\n", BN_bn2str(X3));
	
	debug("17. X3 = X3 + T3");
	r = BN_GF2m_add(X3, X3, T3);
	assert(r);
	debug(" = %s\n", BN_bn2str(X3));
	
	debug("18. T2 = x2 * Z3");
	r = BN_GF2m_mod_mul(T2, x2, Z3, p, ctx);
	assert(r);
	debug(" = %s\n", BN_bn2str(T2));
	
	debug("19. T2 = T2 + X3");
	r = BN_GF2m_add(T2, T2, X3);
	assert(r);
	debug(" = %s\n", BN_bn2str(T2));
	
	debug("20. T1 = Z3^2");
	r = BN_GF2m_mod_sqr(T1, Z3, p, ctx);
	assert(r);
	debug(" = %s\n", BN_bn2str(T1));
	
	debug("21. T3 = T3 + Z3");
	r = BN_GF2m_add(T3, T3, Z3);
	assert(r);
	debug(" = %s\n", BN_bn2str(T3));
	
	debug("22. Y3 = T3 * T2");
	r = BN_GF2m_mod_mul(Y3, T3, T2, p, ctx);
	assert(r);
	debug(" = %s\n", BN_bn2str(Y3));
	
	debug("23. T2 = x2 + y2");
	r = BN_GF2m_add(T2, x2, y2);
	assert(r);
	debug(" = %s\n", BN_bn2str(T2));
	
	debug("24. T3 = T1 * T2");
	r = BN_GF2m_mod_mul(T3, T1, T2, p, ctx);
	assert(r);
	debug(" = %s\n", BN_bn2str(T3));
	
	debug("25. Y3 = Y3 + T3");
	r = BN_GF2m_add(Y3, Y3, T3);
	assert(r);
	debug(" = %s\n", BN_bn2str(Y3));
	
	debug("26. return (X3: Y3: Z3) = (%s: %s: %s)\n", BN_bn2str(X3), BN_bn2str(Y3), BN_bn2str(Z3));
	return;
}

void ec_point_multiply(ec_point_t __LD__ *R, const ec_point_t __AFFINE__ *P, const BIGNUM* K){
	const int t = 163;
	int i;
	int b;
	ec_point_t Q;
	debug("1. Q = infinity\n");
	ec_point_init(&Q);
	BN_set_word(Q.X, 1);
	BN_set_word(Q.Y, 0);
	BN_set_word(Q.Z, 0);

	debug("2. for i from t - 1 downto 0 do\n");
	for(i = t - 1; i >= 0; i--){
		b = BN_is_bit_set(K, i);
		if(b){
		//	printf("k_%d = %d\n", i, b);
		}
		debug("2.1 Q = 2Q\n");
		ec_point_double(R, &Q);
		ec_point_copy(&Q, R);

		debug("2.2 if ki = 1 then Q = Q + P\n");
		if(b == 1){
			ec_point_add(R, &Q, P);
			ec_point_copy(&Q, R);
		}
	}

	debug("3. return Q\n");
	ec_point_copy(R, &Q);
}

int testFieldArithmetic(){
	mm_256 ma, mb, mr;
	char* pa, *pb, *pr;
	BIGNUM* ta = BN_new();
	BIGNUM* tb = BN_new();
	BIGNUM* tr = BN_new();

	int passed = 0;
	int failed = 0;
	printf("test arithmetic operations on gf2m:\n");

	assert(BN_rand_range(ta, n));
	assert(BN_rand_range(tb, n));

	// addition
	BN_GF2m_add(tr, ta, tb);
	pa = BN_bn2hex(ta);
	pb = BN_bn2hex(tb);
	pr = BN_bn2hex(tr);
	printf("0x%s + 0x%s = 0x%s ... ", pa, pb, pr);
	OPENSSL_free(pa);
	OPENSSL_free(pb);
	OPENSSL_free(pr);
	
	bn_to_mm256(ta, &ma);
	bn_to_mm256(tb, &mb);
	gf2_add(&ma, &mb, &mr);
	if(cmp_mm_256_with_bn(&mr, tr) == 0){
		passed ++;
		printf("passed!\n");
	} else {
		failed ++;
		mm256_to_bn(&mr, tr);
		pr = BN_bn2hex(tr);
		printf("failed! got %s\n", pr);
		OPENSSL_free(pr);
	}

	// multiplication
	BN_GF2m_mod_mul(tr, ta, tb, p, ctx);
	pa = BN_bn2hex(ta);
	pb = BN_bn2hex(tb);
	pr = BN_bn2hex(tr);
	printf("0x%s * 0x%s = 0x%s ... ", pa, pb, pr);
	OPENSSL_free(pa);
	OPENSSL_free(pb);
	OPENSSL_free(pr);

	bn_to_mm256(ta, &ma);
	bn_to_mm256(tb, &mb);
	gf2_mod_mul(&ma, &mb, &mr);
	if(cmp_mm_256_with_bn(&mr, tr) == 0){
		passed ++;
		printf("passed!\n");
	} else {
		failed ++;
		mm256_to_bn(&mr, tr);
		pr = BN_bn2hex(tr);
		printf("failed! got 0x%s\n", pr);
		OPENSSL_free(pr);
	}

	// square mod

	BN_GF2m_mod_sqr(tr, ta, p, ctx);
	pa = BN_bn2hex(ta);
	pr = BN_bn2hex(tr);
	printf("0x%s ^ 2 = 0x%s ... ", pa, pr);
	OPENSSL_free(pa);
	OPENSSL_free(pr);

	bn_to_mm256(ta, &ma);
	gf2_mod_sqr(&ma, &mr);
	if(cmp_mm_256_with_bn(&mr, tr) == 0){
		passed ++;
		printf("passed!\n");
	} else {
		failed ++;
		mm256_to_bn(&mr, tr);
		pr = BN_bn2hex(tr);
		printf("failed! got 0x%s\n", pr);
		OPENSSL_free(pr);
	}

	mm_256 mrt;
	gf2_sqr(&ma, &mr, &mrt);
	mm256_to_bn(&mr, tr);
	pr = BN_bn2hex(tr);
	mm256_to_bn(&mrt, ta);
	pa = BN_bn2hex(ta);
	printf("sqr: (%s, %s)\n", pa, pr);
	OPENSSL_free(pr);
	OPENSSL_free(pa);

	/* ma.iv[0] = 1; */
	/* ma.iv[1] = 2; */
	/* ma.iv[2] = 3; */
	/* mb.iv[0] = 1; */
	/* mb.iv[1] = 1; */
	/* mb.iv[2] = 1; */

	/* gf2_mul(&ma, &mb, &mr, &mrt); */
	/* mm256_to_bn(&mr, tr); */
	/* pr = BN_bn2hex(tr); */
	/* mm256_to_bn(&mrt, ta); */
	/* pa = BN_bn2hex(ta); */
	/* printf("mul: (%s, %s)\n", pa, pr); */
	/* OPENSSL_free(pr); */
	/* OPENSSL_free(pa); */

	bn_to_mm256(ta, &ma);
	gf2m_inv_asm(&ma, &mr);
	mm256_to_bn(&mr, tr);
	pa = BN_bn2hex(ta);
	pr = BN_bn2hex(tr);
	printf("inv: %s, %s\n", pa, pr);
	OPENSSL_free(pr);
	OPENSSL_free(pa);

	bn_to_mm256(ta, &ma);
	gf2m_inv(&ma, &mr);
	mm256_to_bn(&mr, tr);
	pa = BN_bn2hex(ta);
	pr = BN_bn2hex(tr);
	printf("inv: %s, %s\n", pa, pr);
	OPENSSL_free(pr);
	OPENSSL_free(pa);

	mb = mr;
	gf2_mod_mul(&ma, &mb, &mr);
	mm256_to_bn(&ma, ta);
	mm256_to_bn(&mb, tb);
	mm256_to_bn(&mr, tr);	
	pa = BN_bn2hex(ta);
	pb = BN_bn2hex(tb);
	pr = BN_bn2hex(tr);
	printf("0x%s * 0x%s = 0x%s ... ", pa, pb, pr);
	OPENSSL_free(pa);
	OPENSSL_free(pb);
	OPENSSL_free(pr);
	
	
	// summary
	printf("%d/%d test(s) passed.\n", passed, (passed + failed));

	return failed;
}

int testAES(){
	const int sz_buf = 1024;
	const int sz_ymm_group = 512;
	int passed = 0, failed = 0;
	uint8_t key[SIZE_AES_KEY_256] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
	uint8_t pt[SIZE_AES_BLOCK] = {'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 'a', ' ', 't', 'e', 's', 't', '!', 0x0};
	uint8_t ct[SIZE_AES_BLOCK];
	AES_KEY ssl_key;
	uint8_t ssl_ct[sz_buf];
	uint8_t buf1[sz_buf], buf2[sz_buf];
	int i;

	// aes 128
	printf("AES128:\n");
	printf("plaintext: ");
	printHex(pt, SIZE_AES_BLOCK);
	printf("\n");
	// openssl
	assert(AES_set_encrypt_key(key, 128, &ssl_key) == 0);
	AES_encrypt(pt, ssl_ct, &ssl_key);
	printf("ciphertext by openssl: ");
	printHex(ssl_ct, SIZE_AES_BLOCK);
	printf("\n");

	// tight aes
	memcpy(ct, pt, SIZE_AES_BLOCK);
	tight_aes_128_set_key(key);
	tight_aes_128_enc(ct);
	printf("ciphertext by tight aes 128: ");
	printHex(ct, SIZE_AES_BLOCK);
	printf("\n");

	if(memcmp(ssl_ct, ct, SIZE_AES_BLOCK) == 0){
		passed++;
		printf("passed!\n");
	} else {
		failed++;
		printf("failed!\n");
	}

	// decrypt by tight aes
	tight_aes_128_set_key(key);
	//tight_aes_enc(ct);
	tight_aes_128_dec(ct);
	printf("plain by tight aes 128: ");
	printHex(ct, SIZE_AES_BLOCK);
	printf("\n");

	if(memcmp(pt, ct, SIZE_AES_BLOCK) == 0){
		passed++;
		printf("passed!\n");
	} else {
		failed++;
		printf("failed!\n");
	}

	// aes 256
	printf("AES256:\n");
	printf("plaintext: ");
	printHex(pt, SIZE_AES_BLOCK);
	printf("\n");
	// openssl
	assert(AES_set_encrypt_key(key, 256, &ssl_key) == 0);
	AES_encrypt(pt, ssl_ct, &ssl_key);
	printf("ciphertext by openssl: ");
	printHex(ssl_ct, SIZE_AES_BLOCK);
	printf("\n");

	// tight aes
	memcpy(ct, pt, SIZE_AES_BLOCK);
	tight_aes_256_set_key(key);
	tight_aes_256_enc(ct);
	printf("ciphertext by tight aes 256: ");
	printHex(ct, SIZE_AES_BLOCK);
	printf("\n");

	if(memcmp(ssl_ct, ct, SIZE_AES_BLOCK) == 0){
		passed++;
		printf("passed!\n");
	} else {
		failed++;
		printf("failed!\n");
	}

	// decrypt by tight aes
	tight_aes_256_set_key(key);
	//memcpy(ct, pt, sizeof(pt));
	//tight_aes_enc(ct);
	tight_aes_256_dec(ct);
	printf("plaintext by tight aes 256: ");
	printHex(ct, SIZE_AES_BLOCK);
	printf("\n");

	if(memcmp(pt, ct, SIZE_AES_BLOCK) == 0){
		passed++;
		printf("passed!\n");
	} else {
		failed++;
		printf("failed!\n");
	}

	// test encrypt ymm group
	printf("encrypt ymm group:\n");
	memset(buf1, 0, sz_buf);
	memset(buf2, 0, sz_buf);
	memset(ssl_ct, 0, sz_buf);
	for(i = 0; i < sz_ymm_group; i++)
		buf1[i] = rand() & 0xff;
	tight_aes_256_set_key(key);
	load_ymm_group(buf1);
	aes_256_enc_ymm_group(buf2);
	printf("plaintext in ymm group:\n");
	for(i = 0; i < 16; i++){
		printHex(buf1 + i * 32, 32);
		printf("\n");
	}
	for(i = 0; i < 32; i++){
		AES_encrypt(buf1 + i * 16, ssl_ct + i * 16, &ssl_key);
	}
	if(memcmp(ssl_ct, buf2, sz_ymm_group) == 0){
		passed++;
		printf("passed!\n");
	} else {
		failed++;
		printf("failed!\n");
		for(i = 0; i < 16; i++){
			printf("ymm%d\n", i);
			printHex(buf2 + i * 32, 32);
			printf("\n");
			printHex(ssl_ct + i * 32, 32);
			printf("\n");
		}
	}

	// test decrypt ymm group
	printf("decrypt ymm group:\n");
	tight_aes_256_set_key(key);
	aes_256_dec_ymm_group(ssl_ct);
	save_ymm_group(buf2);
	if(memcmp(buf1, buf2, sz_ymm_group) == 0){
		passed++;
		printf("passed!\n");
	} else {
		failed++;
		printf("failed!\n");
		for(i = 0; i < 16; i++){
			printf("ymm%d\n", i);
			printHex(buf1 + i * 32, 32);
			printf("\n");
			printHex(buf2 + i * 32, 32);
			printf("\n");
		}
	}

	printf("%d/%d test(s) passed.\n", passed, (passed + failed));

	return failed;
}

struct ec_method_st {
    /* Various method flags */
    int flags;
    /* used by EC_METHOD_get_field_type: */
    int field_type; /* a NID */

    /* used by EC_GROUP_new, EC_GROUP_free, EC_GROUP_clear_free, EC_GROUP_copy: */
    int (*group_init)(EC_GROUP *); 
    void (*group_finish)(EC_GROUP *); 
    void (*group_clear_finish)(EC_GROUP *); 
    int (*group_copy)(EC_GROUP *, const EC_GROUP *); 

    /* used by EC_GROUP_set_curve_GFp, EC_GROUP_get_curve_GFp, */
    /* EC_GROUP_set_curve_GF2m, and EC_GROUP_get_curve_GF2m: */
    int (*group_set_curve)(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *); 
    int (*group_get_curve)(const EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *); 

    /* used by EC_GROUP_get_degree: */
    int (*group_get_degree)(const EC_GROUP *); 

    /* used by EC_GROUP_check: */
    int (*group_check_discriminant)(const EC_GROUP *, BN_CTX *); 
/* used by EC_POINT_new, EC_POINT_free, EC_POINT_clear_free, EC_POINT_copy: */
    int (*point_init)(EC_POINT *); 
    void (*point_finish)(EC_POINT *); 
    void (*point_clear_finish)(EC_POINT *); 
    int (*point_copy)(EC_POINT *, const EC_POINT *); 

    /* used by EC_POINT_set_to_infinity,
     * EC_POINT_set_Jprojective_coordinates_GFp,
     * EC_POINT_get_Jprojective_coordinates_GFp,
     * EC_POINT_set_affine_coordinates_GFp,     ..._GF2m,
     * EC_POINT_get_affine_coordinates_GFp,     ..._GF2m,
     * EC_POINT_set_compressed_coordinates_GFp, ..._GF2m:
     */
    int (*point_set_to_infinity)(const EC_GROUP *, EC_POINT *);
    int (*point_set_Jprojective_coordinates_GFp)(const EC_GROUP *, EC_POINT *,
        const BIGNUM *x, const BIGNUM *y, const BIGNUM *z, BN_CTX *);
    int (*point_get_Jprojective_coordinates_GFp)(const EC_GROUP *, const EC_POINT *,
        BIGNUM *x, BIGNUM *y, BIGNUM *z, BN_CTX *);
    int (*point_set_affine_coordinates)(const EC_GROUP *, EC_POINT *,
        const BIGNUM *x, const BIGNUM *y, BN_CTX *);
    int (*point_get_affine_coordinates)(const EC_GROUP *, const EC_POINT *,
        BIGNUM *x, BIGNUM *y, BN_CTX *);
    int (*point_set_compressed_coordinates)(const EC_GROUP *, EC_POINT *,
        const BIGNUM *x, int y_bit, BN_CTX *);

    /* used by EC_POINT_point2oct, EC_POINT_oct2point: */
size_t (*point2oct)(const EC_GROUP *, const EC_POINT *, point_conversion_form_t form,
            unsigned char *buf, size_t len, BN_CTX *);
    int (*oct2point)(const EC_GROUP *, EC_POINT *,
            const unsigned char *buf, size_t len, BN_CTX *);

    /* used by EC_POINT_add, EC_POINT_dbl, ECP_POINT_invert: */
    int (*add)(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *);
    int (*dbl)(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *);
    int (*invert)(const EC_GROUP *, EC_POINT *, BN_CTX *);

    /* used by EC_POINT_is_at_infinity, EC_POINT_is_on_curve, EC_POINT_cmp: */
    int (*is_at_infinity)(const EC_GROUP *, const EC_POINT *);
    int (*is_on_curve)(const EC_GROUP *, const EC_POINT *, BN_CTX *);
    int (*point_cmp)(const EC_GROUP *, const EC_POINT *a, const EC_POINT *b, BN_CTX *);

    /* used by EC_POINT_make_affine, EC_POINTs_make_affine: */
    int (*make_affine)(const EC_GROUP *, EC_POINT *, BN_CTX *);
    int (*points_make_affine)(const EC_GROUP *, size_t num, EC_POINT *[], BN_CTX *);

    /* used by EC_POINTs_mul, EC_POINT_mul, EC_POINT_precompute_mult, EC_POINT_have_precompute_mult
     * (default implementations are used if the 'mul' pointer is 0): */
    int (*mul)(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
        size_t num, const EC_POINT *points[], const BIGNUM *scalars[], BN_CTX *);
    int (*precompute_mult)(EC_GROUP *group, BN_CTX *);
    int (*have_precompute_mult)(const EC_GROUP *group);
    

    /* internal functions */
    
    /* 'field_mul', 'field_sqr', and 'field_div' can be used by 'add' and 'dbl' so that
     * the same implementations of point operations can be used with different
     * optimized implementations of expensive field operations: */
    int (*field_mul)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
    int (*field_sqr)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);
    int (*field_div)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
    
    int (*field_encode)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *); /* e.g. to Montgomery */
    int (*field_decode)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *); /* e.g. from Montgomery */
    int (*field_set_to_one)(const EC_GROUP *, BIGNUM *r, BN_CTX *);
} /* EC_METHOD */;

typedef struct ec_extra_data_st {
    struct ec_extra_data_st *next;
    void *data;
    void *(*dup_func)(void *);
    void (*free_func)(void *);
    void (*clear_free_func)(void *);
} EC_EXTRA_DATA; /* used in EC_GROUP */

struct ec_group_st {
    const EC_METHOD *meth;

    EC_POINT *generator; /* optional */
    BIGNUM order, cofactor;

    int curve_name;/* optional NID for named curve */
    int asn1_flag; /* flag to control the asn1 encoding */
    point_conversion_form_t asn1_form;

    unsigned char *seed; /* optional seed for parameters (appears in ASN1) */
    size_t seed_len;

    EC_EXTRA_DATA *extra_data; /* linked list */

    /* The following members are handled by the method functions,
     * even if they appear generic */

    BIGNUM field; /* Field specification.
                   * For curves over GF(p), this is the modulus;
                   * for curves over GF(2^m), this is the 
                   * irreducible polynomial defining the field.
                   */

    int poly[6]; /* Field specification for curves over GF(2^m).
                  * The irreducible f(t) is then of the form:
                  *     t^poly[0] + t^poly[1] + ... + t^poly[k]
                  * where m = poly[0] > poly[1] > ... > poly[k] = 0.
                  * The array is terminated with poly[k+1]=-1.
                  * All elliptic curve irreducibles have at most 5
                  * non-zero terms.
                  */
    BIGNUM a, b; /* Curve coefficients.
                  * (Here the assumption is that BIGNUMs can be used
                  * or abused for all kinds of fields, not just GF(p).)
                  * For characteristic  > 3,  the curve is defined
                  * by a Weierstrass equation of the form
                  *     y^2 = x^3 + a*x + b.
                  * For characteristic  2,  the curve is defined by
                  * an equation of the form
                  *     y^2 + x*y = x^3 + a*x^2 + b.
                  */

    int a_is_minus3; /* enable optimized point arithmetics for special case */

    void *field_data1; /* method-specific (e.g., Montgomery structure) */
    void *field_data2; /* method-specific */
    int (*field_mod_func)(BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *); /* method-specific */
} /* EC_GROUP */;

static int gf2m_Mdouble(const EC_GROUP *group, BIGNUM *x, BIGNUM *z, BN_CTX *ctx)
    {   
    BIGNUM *t1;
    int ret = 0;
    
    /* Since Mdouble is static we can guarantee that ctx != NULL. */
    BN_CTX_start(ctx);
    t1 = BN_CTX_get(ctx);
    if (t1 == NULL) goto err;

    if (!group->meth->field_sqr(group, x, x, ctx)) goto err;
    if (!group->meth->field_sqr(group, t1, z, ctx)) goto err;
    if (!group->meth->field_mul(group, z, x, t1, ctx)) goto err;
    if (!group->meth->field_sqr(group, x, x, ctx)) goto err;
    if (!group->meth->field_sqr(group, t1, t1, ctx)) goto err;
    if (!group->meth->field_mul(group, t1, &group->b, t1, ctx)) goto err;
    if (!BN_GF2m_add(x, x, t1)) goto err;

    ret = 1;

 err:
    BN_CTX_end(ctx);
    return ret;
    }

static int gf2m_Madd(const EC_GROUP *group, const BIGNUM *x, BIGNUM *x1, BIGNUM *z1,
    const BIGNUM *x2, const BIGNUM *z2, BN_CTX *ctx)
    {
    BIGNUM *t1, *t2;
    int ret = 0;

    /* Since Madd is static we can guarantee that ctx != NULL. */
    BN_CTX_start(ctx);
    t1 = BN_CTX_get(ctx);
    t2 = BN_CTX_get(ctx);
    if (t2 == NULL) goto err;

    if (!BN_copy(t1, x)) goto err;
    if (!group->meth->field_mul(group, x1, x1, z2, ctx)) goto err;
    if (!group->meth->field_mul(group, z1, z1, x2, ctx)) goto err;
    if (!group->meth->field_mul(group, t2, x1, z1, ctx)) goto err;
    if (!BN_GF2m_add(z1, z1, x1)) goto err;
    if (!group->meth->field_sqr(group, z1, z1, ctx)) goto err;
    if (!group->meth->field_mul(group, x1, z1, t1, ctx)) goto err;
    if (!BN_GF2m_add(x1, x1, t2)) goto err;

    ret = 1;

 err:
    BN_CTX_end(ctx);
    return ret;
    }

int benchmark_EC2() {
	const int cntTest = 1000;

	int i;
	struct timeval ts, te;
	long td;

	BIGNUM* bnsrc1[cntTest];
	BIGNUM* bnsrc2[cntTest];
	BIGNUM* bndst;
	mm_256 mmsrc1[cntTest];
	mm_256 mmsrc2[cntTest];
	mm_256 mmdst;

	ec_point_t epsrc[cntTest], epdst;
	BIGNUM *bnk[cntTest];
	mm256_point_t mpsrc[cntTest], mpdst;
	mm_256 mk[cntTest];

	int r;
	int nid;
	
	EC_KEY *key;
	const BIGNUM* rkey;
	const EC_GROUP* group;
	const EC_POINT* ukey;
	const EC_POINT* G;
	EC_POINT* br;

	ctx = BN_CTX_new();

	nid = OBJ_sn2nid(SN_sect163k1);
	
	// generate the key
	key = EC_KEY_new_by_curve_name(nid);
	assert(key != NULL);
	r = EC_KEY_generate_key(key);
	assert(r == 1);

	group = EC_KEY_get0_group(key);
	// get generator
	G = EC_GROUP_get0_generator(group);
	// get private key
	rkey = EC_KEY_get0_private_key(key);
	ukey = EC_KEY_get0_public_key(key);
	br = EC_POINT_new(group);

	// 1. generate $cntTest test cases
	bndst = BN_new();
	ec_point_init(&epdst);
	for(i = 0; i < cntTest; i++){
		bnsrc1[i] = BN_new();
		bnsrc2[i] = BN_new();
		assert(BN_rand_range(bnsrc1[i], n));
		assert(BN_rand_range(bnsrc2[i], n));
		bn_to_mm256(bnsrc1[i], &mmsrc1[i]);
		bn_to_mm256(bnsrc2[i], &mmsrc2[i]);

		bnk[i] = BN_new();
		ec_point_init(&epsrc[i]);
		assert(BN_rand_range(epsrc[i].X, n));
		assert(BN_rand_range(epsrc[i].Y, n));
		assert(BN_rand_range(epsrc[i].Z, n));
		assert(BN_rand_range(bnk[i], n));
		
		bn_point_to_mm_point(&epsrc[i], mpsrc + i);
		bn_to_mm256(bnk[i], mk + i);
	}
	// do addition / multiplication / square for $cntTest times
	gettimeofday(&ts, NULL);
	for(i = 0; i < cntTest; i++){
		BN_GF2m_add(bndst, bnsrc1[i], bnsrc2[i]);
	}
	gettimeofday(&te, NULL);
	td = cntUS * (te.tv_sec - ts.tv_sec) + (te.tv_usec - ts.tv_usec);
	printf("bignum addition: ");
	printf("%d cases, %lfs used, %lfus for each cases\n", cntTest, (double)td / cntUS, (double)td / cntTest);

	gettimeofday(&ts, NULL);
	for(i = 0; i < cntTest; i++){
		gf2_add(&mmsrc1[i], &mmsrc2[i], &mmdst);
	}
	gettimeofday(&te, NULL);
	td = cntUS * (te.tv_sec - ts.tv_sec) + (te.tv_usec - ts.tv_usec);
	printf("secure addition: ");
	printf("%d cases, %lfs used, %lfus for each cases\n", cntTest, (double)td / cntUS, (double)td / cntTest);

	gettimeofday(&ts, NULL);
	for(i = 0; i < cntTest; i++){
		BN_GF2m_mod_mul_arr(bndst, bnsrc1[i], bnsrc2[i], group->poly, ctx);
	}
	gettimeofday(&te, NULL);
	td = cntUS * (te.tv_sec - ts.tv_sec) + (te.tv_usec - ts.tv_usec);
	printf("bignum multiplication: ");
	printf("%d cases, %lfs used, %lfus for each cases\n", cntTest, (double)td / cntUS, (double)td / cntTest);
	
	gettimeofday(&ts, NULL);
	for(i = 0; i < cntTest; i++){
		gf2_mod_mul(&mmsrc1[i], &mmsrc2[i], &mmdst);
	}
	gettimeofday(&te, NULL);
	td = cntUS * (te.tv_sec - ts.tv_sec) + (te.tv_usec - ts.tv_usec);
	printf("secure multiplication: ");
	printf("%d cases, %lfs used, %lfus for each cases\n", cntTest, (double)td / cntUS, (double)td / cntTest);

	mm_256 mmt;
	gettimeofday(&ts, NULL);
	for(i = 0; i < cntTest; i++){
		gf2_mul(&mmsrc1[i], &mmsrc2[i], &mmdst, &mmt);
	}
	gettimeofday(&te, NULL);
	td = cntUS * (te.tv_sec - ts.tv_sec) + (te.tv_usec - ts.tv_usec);
	printf("secure multiplication only: ");
	printf("%d cases, %lfs used, %lfus for each cases\n", cntTest, (double)td / cntUS, (double)td / cntTest);

	gettimeofday(&ts, NULL);
	for(i = 0; i < cntTest; i++){
		BN_GF2m_mod_sqr_arr(bndst, bnsrc1[i], group->poly, ctx);
	}
	gettimeofday(&te, NULL);
	td = cntUS * (te.tv_sec - ts.tv_sec) + (te.tv_usec - ts.tv_usec);
	printf("bignum square: ");
	printf("%d cases, %lfs used, %lfus for each cases\n", cntTest, (double)td / cntUS, (double)td / cntTest);
	
	gettimeofday(&ts, NULL);
	for(i = 0; i < cntTest; i++){
		gf2_mod_sqr(&mmsrc1[i], &mmdst);
		//gf2_sqr(&mmsrc1[i], &mmdst, &t);
	}
	gettimeofday(&te, NULL);
	td = cntUS * (te.tv_sec - ts.tv_sec) + (te.tv_usec - ts.tv_usec);
	printf("secure squre: ");
	printf("%d cases, %lfs used, %lfus for each cases\n", cntTest, (double)td / cntUS, (double)td / cntTest);

	gettimeofday(&ts, NULL);
	for(i = 0; i < cntTest; i++){
		BN_GF2m_mod_inv(bndst, bnsrc1[i], p, ctx);
	}
	gettimeofday(&te, NULL);
	td = cntUS * (te.tv_sec - ts.tv_sec) + (te.tv_usec - ts.tv_usec);
	printf("bignum inv: ");
	printf("%d cases, %lfs used, %lfus for each cases\n", cntTest, (double)td / cntUS, (double)td / cntTest);

	gettimeofday(&ts, NULL);
	for(i = 0; i < cntTest; i++){
		gf2m_inv(&mmsrc1[i], &mmdst);
		/* gf2_mod_sqr(&mmsrc1[i], &mmdst); */
		//gf2_sqr(&mmsrc1[i], &mmdst, &t);
	}
	gettimeofday(&te, NULL);
	td = cntUS * (te.tv_sec - ts.tv_sec) + (te.tv_usec - ts.tv_usec);
	printf("secure inv: ");
	printf("%d cases, %lfs used, %lfus for each cases\n", cntTest, (double)td / cntUS, (double)td / cntTest);
	
	gettimeofday(&ts, NULL);
	for(i = 0; i < cntTest; i++){
		gf2m_inv_asm(&mmsrc1[i], &mmdst);
		/* gf2_mod_sqr(&mmsrc1[i], &mmdst); */
		//gf2_sqr(&mmsrc1[i], &mmdst, &t);
	}
	gettimeofday(&te, NULL);
	td = cntUS * (te.tv_sec - ts.tv_sec) + (te.tv_usec - ts.tv_usec);
	printf("secure inv asm: ");
	printf("%d cases, %lfs used, %lfus for each cases\n", cntTest, (double)td / cntUS, (double)td / cntTest);

	BIGNUM* x1, *z1, * x2, *z2;
	x1 = BN_CTX_get(ctx);
	z1 = BN_CTX_get(ctx);
	x2 = BN_CTX_get(ctx);
	z2 = BN_CTX_get(ctx);

	BN_rand(x1, EC_GROUP_get_degree(group), 0, 1);
	BN_rand(z1, EC_GROUP_get_degree(group), 0, 1);
	BN_rand(x2, EC_GROUP_get_degree(group), 0, 1);
	BN_rand(z2, EC_GROUP_get_degree(group), 0, 1);

	gettimeofday(&ts, NULL);
	// openssl point multiplication
	for(i = 0; i < cntTest; i++){
		gf2m_Mdouble(group, x1, z1, ctx);
	}
	gettimeofday(&te, NULL);
	td = cntUS * (te.tv_sec - ts.tv_sec) + (te.tv_usec - ts.tv_usec);
	printf("openssl mont point dbl: ");
	printf("%d cases, %lfs used, %lfus for each cases\n", cntTest, (double)td / cntUS, (double)td / cntTest);

	gettimeofday(&ts, NULL);
	// openssl point multiplication
	for(i = 0; i < cntTest; i++){
		gf2m_Madd(group, rkey, x1, z1, x2, z2, ctx);
	}
	gettimeofday(&te, NULL);
	td = cntUS * (te.tv_sec - ts.tv_sec) + (te.tv_usec - ts.tv_usec);
	printf("openssl mont point add: ");
	printf("%d cases, %lfs used, %lfus for each cases\n", cntTest, (double)td / cntUS, (double)td / cntTest);

	gettimeofday(&ts, NULL);
	// openssl point multiplication
	for(i = 0; i < cntTest; i++){
		EC_POINT_add(group, br, G, ukey, ctx);
	}
	gettimeofday(&te, NULL);
	td = cntUS * (te.tv_sec - ts.tv_sec) + (te.tv_usec - ts.tv_usec);
	printf("openssl point add: ");
	printf("%d cases, %lfs used, %lfus for each cases\n", cntTest, (double)td / cntUS, (double)td / cntTest);

	gettimeofday(&ts, NULL);
	for(i = 0; i < cntTest; i++){
		gf2_point_add(mpsrc + i, mpsrc + (i + 1) % cntTest, &mpdst, 1, 1);
	}
	gettimeofday(&te, NULL);
	td = cntUS * (te.tv_sec - ts.tv_sec) + (te.tv_usec - ts.tv_usec);
	printf("secure point addition: ");
	printf("%d cases, %lfs used, %lfus for each cases\n", cntTest, (double)td / cntUS, (double)td / cntTest);

		gettimeofday(&ts, NULL);
	// openssl point multiplication
	for(i = 0; i < cntTest; i++){
		EC_POINT_dbl(group, br, G, ctx);
	}
	gettimeofday(&te, NULL);
	td = cntUS * (te.tv_sec - ts.tv_sec) + (te.tv_usec - ts.tv_usec);
	printf("openssl point doubling: ");
	printf("%d cases, %lfs used, %lfus for each cases\n", cntTest, (double)td / cntUS, (double)td / cntTest);

	gettimeofday(&ts, NULL);
	for(i = 0; i < cntTest; i++){
		gf2_point_dbl(mpsrc + i, &mpdst, 1, 1);
	}
	gettimeofday(&te, NULL);
	td = cntUS * (te.tv_sec - ts.tv_sec) + (te.tv_usec - ts.tv_usec);
	printf("secure point doubling: ");
	printf("%d cases, %lfs used, %lfus for each cases\n", cntTest, (double)td / cntUS, (double)td / cntTest);

	
	gettimeofday(&ts, NULL);
	// openssl point multiplication
	for(i = 0; i < cntTest; i++){
		EC_POINT_mul(group, br, NULL, G, rkey, ctx);
	}
	gettimeofday(&te, NULL);
	td = cntUS * (te.tv_sec - ts.tv_sec) + (te.tv_usec - ts.tv_usec);
	printf("openssl point mul: ");
	printf("%d cases, %lfs used, %lfus for each cases\n", cntTest, (double)td / cntUS, (double)td / cntTest);
	

	gettimeofday(&ts, NULL);
	for(i = 0; i < cntTest; i++){
		gf2_point_mul(mpsrc + i, mk + i, &mpdst, 1, 1);
		//gf2_point_dbl(mp + i, mr + i, 1, 1);
	}
	gettimeofday(&te, NULL);
	td = cntUS * (te.tv_sec - ts.tv_sec) + (te.tv_usec - ts.tv_usec);
	printf("secure point multiplication: ");
	printf("%d cases, %lfs used, %lfus for each cases\n", cntTest, (double)td / cntUS, (double)td / cntTest);


	ec2m_kern_init();
	ec2m_import_key(&mk[0]);

	gettimeofday(&ts, NULL);
	
	for(i = 0; i < cntTest; i++){
		ec2m_private_operation(mpsrc + i, &mpdst);
	}
	gettimeofday(&te, NULL);
	td = cntUS * (te.tv_sec - ts.tv_sec) + (te.tv_usec - ts.tv_usec);
	printf("kernel point multiplication: ");
	printf("%d cases, %lfs used, %lfus for each cases\n", cntTest, (double)td / cntUS, (double)td / cntTest);
	ec2m_kern_clean();

	return 0;
}

int testPointArithmetic(){
	int passed = 0, failed = 0;
	BIGNUM* K;

	ec_point_t P, Q, R, T;
	mm256_point_t mp, mq, mr;
	mm_256 mk;
	domain_parameters_print();
	
	ec_point_init(&P);
	ec_point_init(&Q);
	ec_point_init(&R);
	ec_point_init(&T);

	// point double 
	// special cases
	// P = infinity
	BN_set_word(P.X, 1);
	bn_point_to_mm_point(&P, &mp);
	ec_point_double(&R, &P);
	gf2_point_dbl(&mp, &mr, 1, 1);

	print_bn_point(&P);
	printf(" * 2 = ");
	print_bn_point(&R);
	if(cmp_mm_point_with_bn_point(&mr, &R) == 0){
		passed++;
		printf(" ... passed!\n");
	} else {
		failed++;
		printf(" ... failed! got ");
		print_mm_point(&mr);
		printf("\n");
	}

	// a general case
	ec_point_set_affine_xy(&P, x, y);
	//BN_rand_range(P.Z, n);
	bn_point_to_mm_point(&P, &mp);

	ec_point_double(&R, &P);
	
	gf2_point_dbl(&mp, &mr, 1, 1);

	print_bn_point(&P);
	printf(" * 2 = ");
	print_bn_point(&R);
	if(cmp_mm_point_with_bn_point(&mr, &R) == 0){
		passed++;
		printf(" ... passed!\n");
	} else {
		failed++;
		printf(" ... failed! got ");
		print_mm_point(&mr);
		printf("\n");
	}
	// double again
	ec_point_copy(&P, &R);
	bn_point_to_mm_point(&P, &mp);

	ec_point_double(&R, &P);
	
	gf2_point_dbl(&mp, &mr, 1, 1);

	print_bn_point(&P);
	printf(" * 2 = ");
	print_bn_point(&R);
	if(cmp_mm_point_with_bn_point(&mr, &R) == 0){
		passed++;
		printf(" ... passed!\n");
	} else {
		failed++;
		printf(" ... failed! got ");
		print_mm_point(&mr);
		printf("\n");
	}
	
	// point add
	
	ec_point_copy(&T, &R);
	// special cases
	// P = infinity
	BN_set_word(P.X, 1);
	BN_set_word(P.Y, 0);
	BN_set_word(P.Z, 0);
	ec_point_copy(&Q, &T);
	BN_set_word(Q.Z, 1);
	bn_point_to_mm_point(&P, &mp);
	bn_point_to_mm_point(&Q, &mq);
	ec_point_add(&R, &P, &Q);
	gf2_point_add(&mp, &mq, &mr, 1, 1);

	print_bn_point(&P);
	printf(" + ");
	print_bn_point(&Q);
	printf(" = ");
	print_bn_point(&R);
	if(cmp_mm_point_with_bn_point(&mr, &R) == 0){
		passed++;
		printf(" ... passed!\n");
	} else {
		failed++;
		printf(" ... failed! got ");
		print_mm_point(&mr);
		printf("\n");
	}

	// a general case
	ec_point_copy(&P, &T);
	ec_point_set_affine_xy(&Q, x, y);
	bn_point_to_mm_point(&P, &mp);
	bn_point_to_mm_point(&Q, &mq);
	ec_point_add(&R, &P, &Q);
	gf2_point_add(&mp, &mq, &mr, BN_get_word(a), BN_get_word(b));

	print_bn_point(&P);
	printf(" + ");
	print_affine_bn_point(&Q);
	printf(" = ");
	print_bn_point(&R);
	if(cmp_mm_point_with_bn_point(&mr, &R) == 0){
		passed++;
		printf(" ... passed!\n");
	} else {
		failed++;
		printf(" ... failed! got ");
		print_mm_point(&mr);
		printf("\n");
	}

	// point multiply
	ec_point_set_affine_xy(&P, x, y);
	bn_point_to_mm_point(&P, &mp);
	K = BN_new();
	BN_rand_range(K, n);
	bn_to_mm256(K, &mk);

	ec_point_multiply(&R, &P, K);

	gf2_point_mul(&mp, &mk, &mr, BN_get_word(a), BN_get_word(b));

	print_bn_point(&P);
	printf(" * ");
	printf("%s", BN_bn2str(K));
	printf(" = ");
	print_bn_point(&R);
	if(cmp_mm_point_with_bn_point(&mr, &R) == 0){
		passed++;
		printf(" ... passed!\n");
	} else {
		failed++;
		printf(" ... failed! got ");
		print_mm_point(&mr);
		printf("\n");
	}

	// point multiply with key preset
	__asm__ __volatile__ ("vmovdqu %0, %%ymm15" : : "m"(mk));
	gf2_point_mul_with_preset_key(&mp, &mr, BN_get_word(a), BN_get_word(b));

	print_bn_point(&P);
	printf(" * ");
	printf("%s", BN_bn2str(K));
	printf(" = ");
	print_bn_point(&R);
	if(cmp_mm_point_with_bn_point(&mr, &R) == 0){
		passed++;
		printf(" ... passed!\n");
	} else {
		failed++;
		printf(" ... failed! got ");
		print_mm_point(&mr);
		printf("\n");
	}

	ec2m_kern_init();
	
	ec2m_import_key(&mk);
	ec2m_private_operation(&mp, &mr);
	print_bn_point(&P);
	printf(" * ");
	printf("%s", BN_bn2str(K));
	printf(" = ");
	print_bn_point(&R);
	if(cmp_mm_point_with_bn_point(&mr, &R) == 0){
		passed++;
		printf(" ... passed!\n");
	} else {
		failed++;
		printf(" ... failed! got ");
		print_mm_point(&mr);
		printf("\n");
	}
	ec2m_kern_clean();

	printf("%d/%d test(s) passed.\n", passed, (passed + failed));
	
	return failed;
}

int testKernelEc2m() {
	int r;
	int rid;
	ec_point_t P, R;
	mm256_point_t mp, mr;
	BIGNUM* tk = BN_new();
	mm_256 mk;
	BN_rand_range(tk, n);
	bn_to_mm256(tk, &mk);

	ec_point_init(&P);
	ec_point_init(&R);
	ec_point_set_affine_xy(&P, x, y);
	bn_point_to_mm_point(&P, &mp);

	printf("alloc ec2m resource... ");
	rid = sys_ec2m_alloc();
	printf(" got %d\n", rid);
	if(rid < 0)
		return 1;

	r = sys_ec2m_setkey(rid, &mk, BN_get_word(a), BN_get_word(b));
	printf("setkey: %d\n", r);

	printf("encrypt: %d\n", r);
	// point multiply
	ec_point_set_affine_xy(&P, x, y);
	ec_point_multiply(&R, &P, tk);

	sys_ec2m_encrypt(rid, &mp, &mr);

	print_bn_point(&P);
	printf(" * ");
	printf("%s", BN_bn2str(tk));
	printf(" = ");
	print_bn_point(&R);
	if(cmp_mm_point_with_bn_point(&mr, &R) == 0){
		printf(" ... passed!\n");
	} else {
		printf(" ... failed! got ");
		print_mm_point(&mr);
		printf("\n");
	}

	r = sys_ec2m_free(rid);
	printf("free: %d\n", r);
	return 0;
}

int testMisc(){
	int passed = 0, failed = 0;
	BIGNUM* K;

	ec_point_t P, Q, R, T;
	mm256_point_t mp, mr;
	mm_256 mk;
	domain_parameters_print();
	
	ec_point_init(&P);
	ec_point_init(&Q);
	ec_point_init(&R);
	ec_point_init(&T);

	/*
	// point double 
	// a general case
	ec_point_set_affine_xy(&P, x, y);
	BN_rand_range(P.Z, n);
	BN_set_word(P.Z, 4);
	bn_point_to_mm_point(&P, &mp);

	ec_point_double(&R, &P);
	
	gf2_point_dbl(&mp, &mr, 1, 1);

	print_bn_point(&P);
	printf(" * 2 = ");
	print_bn_point(&R);
	if(cmp_mm_point_with_bn_point(&mr, &R) == 0){
		passed++;
		printf(" ... passed!\n");
	} else {
		failed++;
		printf(" ... failed! got ");
		print_mm_point(&mr);
		printf("\n");
	}
	
	// point add
	ec_point_copy(&T, &R);
	// special cases
	// P = infinity
	BN_set_word(P.X, 1);
	BN_set_word(P.Y, 0);
	BN_set_word(P.Z, 0);
	ec_point_copy(&Q, &T);
	BN_set_word(Q.Z, 1);
	bn_point_to_mm_point(&P, &mp);
	bn_point_to_mm_point(&Q, &mq);
	ec_point_add(&R, &P, &Q);
	gf2_point_add(&mp, &mq, &mr, 1, 1);

	print_bn_point(&P);
	printf(" + ");
	print_bn_point(&Q);
	printf(" = ");
	print_bn_point(&R);
	if(cmp_mm_point_with_bn_point(&mr, &R) == 0){
		passed++;
		printf(" ... passed!\n");
	} else {
		failed++;
		printf(" ... failed! got ");
		print_mm_point(&mr);
		printf("\n");
	}
	*/

	// point multiply
	ec_point_set_affine_xy(&P, x, y);
	bn_point_to_mm_point(&P, &mp);
	K = BN_new();
	BN_rand_range(K, n);
	//K->d[0] = 3;
	//K->d[2] = 2;
	bn_to_mm256(K, &mk);

	ec_point_multiply(&R, &P, K);

	gf2_point_mul(&mp, &mk, &mr, BN_get_word(a), BN_get_word(b));

	print_bn_point(&P);
	printf(" * ");
	printf("%s", BN_bn2str(K));
	printf(" = ");
	print_bn_point(&R);
	if(cmp_mm_point_with_bn_point(&mr, &R) == 0){
		passed++;
		printf(" ... passed!\n");
	} else {
		failed++;
		printf(" ... failed! got ");
		print_mm_point(&mr);
		printf("\n");
	}
	
	return failed;
}

int benchmark_cycles(){
	mm_256 ma, mb, mr;
	const int cases = 1000;
	unsigned long hi_s, lo_s, hi_e, lo_e, s, e;
	unsigned long td[cases];
	unsigned long t_base, t_min, t_sum, t_avg;
	int i;
	const char* item;

	// calculate the bases
	for(i = 0; i < cases; i++){
		rdtsc_begin(hi_s, lo_s);
		rdtsc_end(hi_e, lo_e);
		s = (hi_s << 32) | lo_s;
		e = (hi_e << 32) | lo_e;
		td[i] = e - s;
	}
	
	item = "base";
	t_min = td[0];
	t_sum = 0;
	for(i = 0; i < cases; i++){
		if(t_min > td[i]){
			t_min = td[i];
		}
		t_sum += td[i];
	}
	t_avg = t_sum / cases;
	t_base = t_min;
#ifdef KERN
	printk(KERN_INFO"base: %lu\n", t_min);
#else
	printf("%s: %lu, %lu, %lu\n", item, t_min,  t_sum, t_avg);
#endif

	gf2_add(&ma, &mb, &mr);
	for(i = 0; i < cases; i++){
		rdtsc_begin(hi_s, lo_s);
		gf2_add(&ma, &mb, &mr);
		rdtsc_end(hi_e, lo_e);
		s = (hi_s << 32) | lo_s;
		e = (hi_e << 32) | lo_e;
		td[i] = e - s;
	}

	item = "add";
	t_sum = 0;
	t_min = td[0];
	for(i = 0; i < cases; i++){
		if(t_min > td[i]){
			t_min = td[i];
		}
		t_sum += td[i];
	}
	t_avg = t_sum / cases;
#ifdef KERN
	printk(KERN_INFO "add: %lu, %lu\n", t_min, t_min - t_base);
#else
	printf("%s: %lu, %lu, %lu, %lu\n", item, t_min, t_min - t_base, t_sum, t_avg);
#endif

	for(i = 0; i < cases; i++){
		rdtsc_begin(hi_s, lo_s);
		gf2_mod_mul(&ma, &mb, &mr);
		rdtsc_end(hi_e, lo_e);
		s = (hi_s << 32) | lo_s;
		e = (hi_e << 32) | lo_e;
		td[i] = e - s;
	}

	item = "mul";
	t_sum = 0;
	t_min = td[0];
	for(i = 0; i < cases; i++){
		if(t_min > td[i]){
			t_min = td[i];
		}
		t_sum += td[i];
	}
	t_avg = t_sum / cases;
#ifdef KERN
	printk(KERN_INFO "add: %lu, %lu\n", t_min, t_min - t_base);
#else
	printf("%s: %lu, %lu, %lu, %lu\n", item, t_min, t_min - t_base, t_sum, t_avg);
#endif

	for(i = 0; i < cases; i++){
		rdtsc_begin(hi_s, lo_s);
		gf2_mod_sqr(&ma, &mr);
		rdtsc_end(hi_e, lo_e);
		s = (hi_s << 32) | lo_s;
		e = (hi_e << 32) | lo_e;
		td[i] = e - s;
	}
	item = "sqr";
	t_sum = 0;
	t_min = td[0];
	for(i = 0; i < cases; i++){
		if(t_min > td[i]){
			t_min = td[i];
		}
		t_sum += td[i];
	}
	t_avg = t_sum / cases;
#ifdef KERN
	printk(KERN_INFO "add: %lu, %lu\n", t_min, t_min - t_base);
#else
	printf("%s: %lu, %lu, %lu, %lu\n", item, t_min, t_min - t_base, t_sum, t_avg);
#endif
	return 0;
}
