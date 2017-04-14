//test.c
#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/engine.h>

static void display_engine_list()
{
	ENGINE *h;
	int loop;
	
	h = ENGINE_get_first();
	loop = 0;
	printf("listing available engine types\n");
	while(h)
	{
		printf("engine %i, id = \"%s\", name = \"%s\"\n",
			loop++, ENGINE_get_id(h), ENGINE_get_name(h));
		h = ENGINE_get_next(h);
	}
	printf("end of list\n");
	/* ENGINE_get_first() increases the struct_ref counter, so we 
	must call ENGINE_free() to decrease it again */
	ENGINE_free(h);
}


void test()
{
	ENGINE *e = NULL;
	int rv;
	unsigned char buf[1024];
	EVP_PKEY *evpKey;

	EC_KEY *key;
	EC_POINT *pubkey;
	EC_GROUP *group;
	EC_builtin_curve    *curves;
	int crv_len;
	char shareKey1[10240],shareKey2[10240];
	int ret,nid,size,i,sig_len;
	int len1,len2;

	crv_len = EC_get_builtin_curves(NULL, 0);
	curves = (EC_builtin_curve *)malloc(sizeof(EC_builtin_curve) * crv_len);
	EC_get_builtin_curves(curves, crv_len);
    nid = NID_sect163k1;
	group=EC_GROUP_new_by_curve_name(nid);

	key=EC_KEY_new();
	ret=EC_KEY_set_group(key,group);
	ret=EC_KEY_generate_key(key);
	ret=EC_KEY_check_key(key);
	pubkey = EC_KEY_get0_public_key(key);

	ENGINE_load_myengine();
	display_engine_list();
	
	len1=ECDH_compute_key(shareKey1, 10240, pubkey, key, NULL);
	e = ENGINE_by_id("111");
	printf("get myengine engine OK.name:%s\n",ENGINE_get_name(e));
	ENGINE_register_ECDH(e);
	//rv = ENGINE_set_default(e,ENGINE_METHOD_ALL);


	len2=ECDH_compute_key(shareKey2, 10240, pubkey, key, NULL);

	printf("len: %d, %d\n", len1, len2);
	if(len1!=len2)
	{
		printf("err: %d, %d\n", len1, len2);
	}
	else
	{
		ret=memcmp(shareKey1,shareKey2,len1);
		if(ret==0)
		{
			printf("right\n");
		}
		else
			printf("wrong\n");
	}
	printf("test ok!\n");
	/*ENGINE_register_RSA(e);
	rv = ENGINE_set_default(e,ENGINE_METHOD_ALL);
	evpKey = EVP_PKEY_new();
	rsa = RSA_generate_key(1024,RSA_F4,NULL,NULL);
	rv = EVP_PKEY_set1_RSA(evpKey,rsa);
	rv = EVP_PKEY_encrypt(buf,buf,128,evpKey);
*/	
/*	rv = ENGINE_finish(e);
	
	rv = ENGINE_free(e);
	printf("test end.\n");
	return;*/
	}

int main()
{
	test();
	return 0;
}


