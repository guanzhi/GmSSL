#include <stdio.h>
#include <assert.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include "kernel_test.h"
#include "ec.h"
#include "ec2m_kern.h"
#include "util.h"


#define _NR_sse_switch 312

struct ec_point_st {
	const EC_METHOD *meth;

	/* All members except 'meth' are handled by the method functions,
	 * even if they appear generic */

	BIGNUM X;
	BIGNUM Y;
	BIGNUM Z; /* Jacobian projective coordinates:
	           * (X, Y, Z)  represents  (X/Z^2, Y/Z^3)  if  Z != 0 */
	int Z_is_one; /* enable optimized point arithmetics for special case */
} /* EC_POINT */;

int testSSE(){
	// try perform an simple packed add operation
	mm_256 a, b, c;

	syscall(_NR_sse_switch, 0);
	
	a.iv[0] = 0;
	a.iv[1] = 1;
	b.iv[0] = 2;
	b.iv[1] = 3;
	__asm__ __volatile__ ("vmovdqu %0, %%ymm0" : : "m"(a));
	__asm__ __volatile__ ("vmovdqu %0, %%ymm1" : : "m"(b));
	__asm__ __volatile__ ("vaddpd %ymm0, %ymm1, %ymm1");
	__asm__ __volatile__ ("vmovdqu %%ymm1, %0" : "=m"(c) :);
	printf("%ld, %ld\n", c.iv[0], c.iv[1]);

	//syscall(_NR_sse_switch, 0);

	return 1;
}

void print_num(mm_256* m) 
{
	int i;
	int nonzero = 0;
	
	for (i = sizeof(mm_256) - 1; i >= 0; i--) {
		if (!nonzero){
			if (m->bv[i] != 0)
				nonzero = 1;
			else
				continue;
		}
		printf("%02x", m->bv[i]);
	}
	if (!nonzero)
		printf("0");
}


void print_point(mm256_point_t* p) 
{
	print_num(&p->x);
	printf(", ");
	print_num(&p->y);
	printf(", ");
	print_num(&p->z);
}

void print_ec_point(EC_POINT* p)
{
	printf("(");
	BN_print_fp(stdout, &p->X);
	printf(":");
	BN_print_fp(stdout, &p->Y);
	printf(":");
	BN_print_fp(stdout, &p->Z);
	printf(")");
}



int testAPI()
{
	int r;
	int nid;
	EC_KEY *key;
	BIO *bio_out;
	const BIGNUM* rkey;
	const EC_GROUP* group;
	const EC_POINT* ukey;
	const EC_POINT* G, *pr;
	BIGNUM* x, *y;
	
	BN_CTX* ctx;
	mm_256 mkey;
	mm256_point_t mp, mq;
	mm_256 z_;
	

	init_sqr_table();
	

	ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	x = BN_CTX_get(ctx);
	y = BN_CTX_get(ctx);	
	
	// open stdout as bio
	bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

	// get curve nid
	/* nid = EC_curve_nist2nid("sect163k1"); */
	nid = OBJ_sn2nid(SN_sect163k1);
	
	// generate the key
	key = EC_KEY_new_by_curve_name(nid);
	assert(key != NULL);
	r = EC_KEY_generate_key(key);
	assert(r == 1);

	// print key
	EC_KEY_print(bio_out, key, 0);
	// get group
	group = EC_KEY_get0_group(key);
	// get generator
	G = EC_GROUP_get0_generator(group);
	// get private key
	rkey = EC_KEY_get0_private_key(key);
	memset(&mkey, 0, sizeof(mkey));
	memcpy(&mkey, rkey->d, rkey->top * sizeof(rkey->d[0]));
	print_num(&mkey);
	printf("\n");
	
	// get the public key
	ukey = EC_KEY_get0_public_key(key);

	// init api
	r = ec2m_kern_init();
	assert(r == 0);
	printf("ec2m init done.\n");
	

	// import the private key
	r = ec2m_import_key(&mkey);
	assert(r == 0);

	// calculate r=G*k
	// r should be equal to the public key
	EC_POINT_get_affine_coordinates_GF2m(group, G, x, y, ctx);
	memset(&mq, 0, sizeof(mq));
	memset(&mp, 0, sizeof(mp));
	memcpy(&mp.x, x->d, sizeof(x->d[0]) * x->top);
	memcpy(&mp.y, y->d, sizeof(y->d[0]) * y->top);
	mp.z.iv[0] = 1;
	
	bn_expand2(x, 3);
	bn_expand2(y, 3);
	
	gf2_point_mul(&mp, &mkey, &mq, 1, 1);
	print_mm_point(&mq);
	printf("\n");

	r = ec2m_private_operation(&mp, &mq);
	assert(r == 0);
	
	print_mm_point(&mq);
	printf("\n");

	/* printf("inv(z): "); */
	/* gf2m_inv(&mq.z, &z_); */
	/* print_num(&z_); */
	/* printf("\n"); */

	/* gf2_mod_mul(&mq.x, &z_, &mq.x); */
	/* gf2_mod_mul(&mq.y, &z_, &mq.y); */
	/* gf2_mod_mul(&mq.z, &z_, &mq.z);	 */
	/* print_mm_point(&mq); */
	/* printf("\n"); */

	pr = EC_POINT_new(group);
	EC_POINT_mul(group, pr, NULL, G, rkey, ctx);
	print_ec_point(pr);
	printf("\n");
	EC_POINT_get_affine_coordinates_GF2m(group, pr, x, y, ctx);	
	
	
	ec2m_kern_clean();

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	

	return 0;
	
}


int main()
{
	testSSE();
	testAPI();
	
	return 0;
	
}
