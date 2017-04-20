#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/dso.h>
#include <openssl/engine.h>
#include <openssl/ui.h>
#include <openssl/rand.h>
#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#endif
#include <openssl/bn.h>
#include <openssl/ecdh.h>
#include "ec2m_kern.h"

struct ecdh_method 
{
	const char *name;
	int (*compute_key)(void *key, size_t outlen, const EC_POINT *pub_key, EC_KEY *ecdh,
					   void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));
	int flags;
	char *app_data;
};


#ifndef OPENSSL_NO_HW

/* the header file of vender */
//#include "hwdevice.h"

/* Constants used when creating the ENGINE */
static const char *engine_hwdev_id = "cba_ecdh";
static const char *engine_hwdev_name = "cold boot resistant ECDH";
#ifndef OPENSSL_NO_DYNAMIC_ENGINE 
/* Compatibility hack, the dynamic library uses this form in the path */
static const char *engine_hwdev_id_alt = "cba_ecdh";
#endif

static int compute_key(void *out, size_t outlen,
	const EC_POINT *pub_key, EC_KEY *ecdh,
	void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen))
{
	const EC_GROUP* group;
	int ret;

	group = EC_KEY_get0_group(ecdh);

	// only use our solution if the curve name is SECT163K1
	if (EC_GROUP_get_curve_name(group) == NID_sect163k1) {
		const BIGNUM* rkey;
		BN_CTX *ctx;
		BIGNUM* x, *y;
		mm256_point_t p, q;
		mm_256 mkey;
		int r;

		ctx = BN_CTX_new();
		BN_CTX_start(ctx);

		x = BN_CTX_get(ctx);
		y = BN_CTX_get(ctx);

		rkey = EC_KEY_get0_private_key(ecdh);
		memset(&mkey, 0, sizeof(mkey));
		memcpy(&mkey, rkey->d, sizeof(rkey->d[0]) * rkey->top);
		ec2m_import_key(&mkey);

		r = EC_POINT_get_affine_coordinates_GF2m(group, pub_key, x, y, ctx);
		memset(&p, 0, sizeof(p));
		memcpy(&p.x, x->d, sizeof(x->d[0]) * x->top);
		memcpy(&p.y, y->d, sizeof(y->d[0]) * y->top);
		p.z.iv[0] = 1;

		r = ec2m_private_operation(&p, &q);
		if (r < 0) {
			fprintf(stderr, "invalid result: %d\n", r);
		}

		int xlen = (163 + 7) / 8; 
		if (KDF != 0)
		{
			if (KDF(&q.x, xlen, out, &outlen) == NULL)
			{
				return -1;
			}
			ret = outlen;
		}
		else
		{
			/* no KDF, just copy as much as we can */
			if (outlen > xlen)
				outlen = xlen;
			memcpy(out, &q.x, outlen);
			ret = outlen;
		}

		BN_CTX_end(ctx);
		BN_CTX_free(ctx);

	} else {
		// use the default method
		const ECDH_METHOD* meth = ECDH_OpenSSL();
		return meth->compute_key(out, outlen, pub_key, ecdh, KDF);
	}

	return ret;
}

static ECDH_METHOD ecdh_meth = {
	"CBA resistant ECDH method",
	compute_key,
	0,
	NULL
};

static int hwdev_destroy(ENGINE *e)
{
    fprintf(stderr, "arrive at hwdev_destroy\n");
    return 1;
}

static int hwdev_init(ENGINE *e)
{
    fprintf(stderr, "arrive at hwdev_init\n");
	ec2m_kern_init();
    return 1;
}

static int hwdev_finish(ENGINE *e)
{
    fprintf(stderr, "arrive at hwdev_finish\n");
	ec2m_kern_clean();
    return 1;
}

/* The definitions for control commands specific to this engine */
#define HWDEV_CMD_INIT  (ENGINE_CMD_BASE)
#define HWDEV_CMD_EXIT  (ENGINE_CMD_BASE + 1)
#define HWDEV_CMD_TEST  (ENGINE_CMD_BASE + 2)
static const ENGINE_CMD_DEFN hwdev_cmd_defns[] = {
	{HWDEV_CMD_INIT,
		"INIT",
		"init the hardware device before using",
		ENGINE_CMD_FLAG_STRING}, /* may be the password */
	{HWDEV_CMD_EXIT,
		"EXIT",
		"exit the hardware device after using",
		ENGINE_CMD_FLAG_NO_INPUT},
	{HWDEV_CMD_TEST,
		"TEST",
		"run the test case of the hardware device",
		ENGINE_CMD_FLAG_NUMERIC}, /* may be the number of test case */
	{0, NULL, NULL, 0}
	};

/* This internal function is used by ENGINE_chil() and possibly by the
 * "dynamic" ENGINE support too */
static int hwdev_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
	int to_return = 1;

	switch(cmd) {
	case HWDEV_CMD_INIT:
        fprintf(stderr, "arrive at HWDEV_CMD_INIT, password: %s\n", 
                (const char *)p);
        break;
	case HWDEV_CMD_EXIT:
        fprintf(stderr, "arrive at HWDEV_CMD_EXIT, no parameters\n");
		break;
	case HWDEV_CMD_TEST:
        fprintf(stderr, "arrive at HWDEV_CMD_TEST, case id: %ld\n",
                i);
		break;
	/* The command isn't understood by this engine */
	default:
		to_return = 0;
		break;
	}

	return to_return;
}

static EVP_PKEY *hwdev_load_privkey(ENGINE *eng, const char *key_id,
	UI_METHOD *ui_method, void *callback_data)
{
    fprintf(stderr, "arrive at hwdev_load_privkey\n");
	EVP_PKEY *res = NULL;

	return res;
}

static EVP_PKEY *hwdev_load_pubkey(ENGINE *eng, const char *key_id,
	UI_METHOD *ui_method, void *callback_data)
{
    fprintf(stderr, "arrive at hwdev_load_pubkey\n");
	EVP_PKEY *res = NULL;

	return res;
}

static int bind_helper(ENGINE *e)
{
    fprintf(stderr, "arrive at bind_helper\n");
	if(!ENGINE_set_id(e, engine_hwdev_id) ||
	   !ENGINE_set_name(e, engine_hwdev_name) ||
	   !ENGINE_set_ECDH(e, &ecdh_meth) ||
	   !ENGINE_set_destroy_function(e, hwdev_destroy) ||
	   !ENGINE_set_init_function(e, hwdev_init) ||
	   !ENGINE_set_finish_function(e, hwdev_finish) ||
	   !ENGINE_set_ctrl_function(e, hwdev_ctrl) ||
	   !ENGINE_set_load_privkey_function(e, hwdev_load_privkey) ||
	   !ENGINE_set_load_pubkey_function(e, hwdev_load_pubkey) ||
	   !ENGINE_set_cmd_defns(e, hwdev_cmd_defns))
		return 0;

	return 1;
}

static ENGINE *engine_hwdev(void)
{
    fprintf(stderr, "arrive at engine_test\n");
	ENGINE *ret = ENGINE_new();
	if(!ret) {
		return NULL;
    }

	if(!bind_helper(ret)) {
		ENGINE_free(ret);
		return NULL;
    }

	return ret;
}

void ENGINE_load_test(void)
{
    fprintf(stderr, "arrive at ENGINE_load_test\n");
	/* Copied from eng_[openssl|dyn].c */
	ENGINE *toadd = engine_hwdev();
	if(!toadd) return;
	ENGINE_add(toadd);
	ENGINE_free(toadd);
	ERR_clear_error();
}
//#endif


/* This stuff is needed if this ENGINE is being compiled into a self-contained
 * shared-library. */	   
#ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_fn(ENGINE *e, const char *id)
{
    fprintf(stderr, "arrive at bind_fn\n");
	if(id && (strcmp(id, engine_hwdev_id) != 0) &&
			(strcmp(id, engine_hwdev_id_alt) != 0))
		return 0;
	if(!bind_helper(e))
		return 0;
	return 1;
} 
IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
#endif /* OPENSSL_NO_DYNAMIC_ENGINE */

#endif /* !OPENSSL_NO_HW */
