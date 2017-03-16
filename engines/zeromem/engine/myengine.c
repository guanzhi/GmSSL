#include <stdio.h>
#include <string.h>
#include <openssl/ecdh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include "myengine.h"
#include "../ec.h"
#include "../util.h"

int get_affine(const EC_GROUP* group, const EC_POINT* point, BIGNUM* x, BIGNUM* y, BN_CTX *ctx){
	int ret = 0;
	if(EC_POINT_is_at_infinity(group, point)){
		return 0;
	}
	if(x == NULL || y == NULL)
		return 0;
	if(BN_cmp(&point->Z, BN_value_one()) == 0){
		if(!BN_copy(x, &point->X) || !BN_copy(y, &point->Y))
			return 0;
		BN_set_negative(x, 0);
		BN_set_negative(y, 0);
	} else {
		BIGNUM* z = BN_new();
		if(!BN_GF2m_mod_inv(z, &point->Z, &group->field, ctx)){
			printf("could not get the inv\n");
			return 0;
		}
		if(!BN_GF2m_mod_mul(x, &point->X, z, &group->field, ctx)){
			return 0;
		}
		if(!BN_GF2m_mod_sqr(z, z, &group->field, ctx)){
			return 0;
		}
		if(!BN_GF2m_mod_mul(y, &point->Y, z, &group->field, ctx)){
			return 0;
		}
	}
	return 1;
}

static int my_ecdh_compute_key(void *out, size_t outlen, const EC_POINT *pub_key,
                               EC_KEY *ecdh, void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen))
{
  BN_CTX *ctx;
  EC_POINT *tmp=NULL;
  BIGNUM *x=NULL, *y=NULL;
  const BIGNUM *priv_key;
  const EC_GROUP* group;
  int ret= -1;
  size_t buflen, len;
  unsigned char *buf=NULL;
  mm256_point_t mPK;
  mm_256 mUK;
  mm256_point_t mR;
  
  group = EC_KEY_get0_group(ecdh);
  printf("curve_name: %d, field type: %d, degree: %d, a: %x, b: %x\n", EC_GROUP_get_curve_name(group), EC_METHOD_get_field_type(EC_GROUP_method_of(group)), EC_GROUP_get_degree(group), BN_get_word(&group->a), BN_get_word(&group->b));
    
  // compute with the syscall only when the filetype is NID_X9_62_characteristic_two_field and the degree is 163
  if (!(
        EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_characteristic_two_field
        && EC_GROUP_get_degree(group) == 163
        )) 
    {
      ECDH_METHOD* temp = ECDH_get_default_method();
      return temp->compute_key(out, len, pub_key, ecdh, KDF);        
    }
    
  if (outlen > INT_MAX)
    {
      ECDHerr(ECDH_F_ECDH_COMPUTE_KEY,ERR_R_MALLOC_FAILURE); /* sort of, anyway */
      return -1;
    }

  if ((ctx = BN_CTX_new()) == NULL) goto err;
  BN_CTX_start(ctx);
  x = BN_CTX_get(ctx);
  y = BN_CTX_get(ctx);

  priv_key = EC_KEY_get0_private_key(ecdh);
  if (priv_key == NULL)
    {
      ECDHerr(ECDH_F_ECDH_COMPUTE_KEY,ECDH_R_NO_PRIVATE_VALUE);
      goto err;
    }

  if ((tmp=EC_POINT_new(group)) == NULL)
    {
      ECDHerr(ECDH_F_ECDH_COMPUTE_KEY,ERR_R_MALLOC_FAILURE);
      goto err;
    }

  bn_to_mm256(priv_key, &mUK);
  
  printf("%s\n", BN_bn2hex(priv_key));
  
  print_mm_256(&mUK);
  printf("\n");
  
  EC_POINT_to_mm_point(pub_key, &mPK);

  print_EC_POINT(pub_key);
  printf("\n");
  print_mm_point(&mPK);
  printf("\n");

  init_sqr_table();
  
  gf2_point_mul(&mPK, &mUK, &mR, BN_get_word(&group->a), BN_get_word(&group->b));
  print_mm_point(&mR);
  printf("\n");
      
  if (!EC_POINT_mul(group, tmp, NULL, pub_key, priv_key, ctx))
    {
      ECDHerr(ECDH_F_ECDH_COMPUTE_KEY,ECDH_R_POINT_ARITHMETIC_FAILURE);
      goto err;
    }
  print_EC_POINT(tmp);
  printf("\n");
  
  		
  if (!get_affine(group, tmp, x, y, ctx)) 
    {
      ECDHerr(ECDH_F_ECDH_COMPUTE_KEY,ECDH_R_POINT_ARITHMETIC_FAILURE);
      goto err;
    }

  buflen = (EC_GROUP_get_degree(group) + 7)/8;
  len = BN_num_bytes(x);
  if (len > buflen)
    {
      ECDHerr(ECDH_F_ECDH_COMPUTE_KEY,ERR_R_INTERNAL_ERROR);
      goto err;
    }
  if ((buf = OPENSSL_malloc(buflen)) == NULL)
    {
      ECDHerr(ECDH_F_ECDH_COMPUTE_KEY,ERR_R_MALLOC_FAILURE);
      goto err;
    }
	
  memset(buf, 0, buflen - len);
  if (len != (size_t)BN_bn2bin(x, buf + buflen - len))
    {
      ECDHerr(ECDH_F_ECDH_COMPUTE_KEY,ERR_R_BN_LIB);
      goto err;
    }

  if (KDF != 0)
    {
      if (KDF(buf, buflen, out, &outlen) == NULL)
        {
          ECDHerr(ECDH_F_ECDH_COMPUTE_KEY,ECDH_R_KDF_FAILED);
          goto err;
        }
      ret = outlen;
    }
  else
    {
      /* no KDF, just copy as much as we can */
      if (outlen > buflen)
        outlen = buflen;
      memcpy(out, buf, outlen);
      ret = outlen;
    }
  printf("ECC compute key done!\n");	
 err:
  if (tmp) EC_POINT_free(tmp);
  if (ctx) BN_CTX_end(ctx);
  if (ctx) BN_CTX_free(ctx);
  if (buf) OPENSSL_free(buf);
  return(ret);


  /* if(1){ */
  /*   ECDH_METHOD* temp = ECDH_get_default_method(); */
  /*   return temp->compute_key(out, len, pub_key, ecdh, KDF); */
  /* } */
  /* return 1; */
}

/****************************************************************************
 *			Functions to handle the engine									*
*****************************************************************************/

static int bind_my(ENGINE *e)
{
	//const RSA_METHOD *meth1;
	if(!ENGINE_set_id(e, engine_my_id)
		|| !ENGINE_set_name(e, engine_my_name)
		|| !ENGINE_set_ECDH(e, &my_ecdh)
		//|| !ENGINE_set_ciphers(e, my_ciphers)
		//|| !ENGINE_set_digests(e, my_digests)
		|| !ENGINE_set_destroy_function(e, my_destroy)
		|| !ENGINE_set_init_function(e, my_init)
		|| !ENGINE_set_finish_function(e, my_finish)
		/* || !ENGINE_set_ctrl_function(e, my_ctrl) */
		/* || !ENGINE_set_cmd_defns(e, my_cmd_defns) */)
		return 0;
	return 1;
	}


#ifdef ENGINE_DYNAMIC_SUPPORT
static int bind_helper(ENGINE *e, const char *id)
{
	if(id && (strcmp(id, engine_my_id) != 0))
		return 0;
	if(!bind_my(e))
		return 0;
	return 1;
}       
IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
#else
static ENGINE *engine_my(void)
{
	ENGINE *ret = ENGINE_new();
	if(!ret)
		return NULL;
	if(!bind_my(ret))
	{
		ENGINE_free(ret);
		return NULL;
	}
	return ret;
}

void ENGINE_load_myengine(void)
{
	/* Copied from eng_[openssl|dyn].c */
	ENGINE *toadd = engine_my();
	if(!toadd) return;
	ENGINE_add(toadd);
	ENGINE_free(toadd);
	ERR_clear_error();
}
#endif


static int my_init(ENGINE *e)
{
	printf("my_init\n");
	return 1;
}


static int my_finish(ENGINE *e)
{
	printf("my_finih\n");	
	return 1;
}


static int my_destroy(ENGINE *e)
{
	printf("my_destroy\n");
	return 1;
}
