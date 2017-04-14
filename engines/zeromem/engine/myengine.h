#define INT_MAX 32767

#include <openssl/ec.h>
typedef struct ec_extra_data_st {
    struct ec_extra_data_st *next;
    void *data;
    void *(*dup_func)(void *);
    void (*free_func)(void *);
    void (*clear_free_func)(void *);
} EC_EXTRA_DATA;

typedef struct ec_key_st {
    int version;

    EC_GROUP *group;

    EC_POINT *pub_key;
    BIGNUM   *priv_key;

    unsigned int enc_flag;
    point_conversion_form_t conv_form;

    int     references;
    int flags;

    EC_EXTRA_DATA *method_data;
} EC_KEY;
static const char *engine_my_id = "111";
static const char *engine_my_name = "myengine";


/****************************************************************************
 *			Functions to handle the engine									*
 ***************************************************************************/
static int my_destroy(ENGINE *e);
static int my_init(ENGINE *e);
static int my_finish(ENGINE *e);


/****************************************************************************
 *			Engine commands													*
*****************************************************************************/
static const ENGINE_CMD_DEFN my_cmd_defns[] = 
{
	{0, NULL, NULL, 0}
};

static int my_ecdh_compute_key(void *out, size_t len, const EC_POINT *pub_key,
EC_KEY *ecdh, void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));

/* 
some definations missing in openssl header files public accessible
*/

struct ec_point_st {
	const EC_METHOD *meth;

	/* All members except 'meth' are handled by the method functions,
	 *      * even if they appear generic */

	BIGNUM X;
	BIGNUM Y;
	BIGNUM Z; /* Jacobian projective coordinates:
			   * (X, Y, Z)  represents  (X/Z^2, Y/Z^3)  if  Z != 0 */
	int Z_is_one; /* enable optimized point arithmetics for special case */
} /* EC_POINT */;

typedef struct ec_point_st EC_POINT;

struct ec_group_st {
	const EC_METHOD *meth;

	EC_POINT *generator; /* optional */
	BIGNUM order, cofactor;

	int curve_name;/* optional NID for named curve */
	int asn1_flag; /* flag to control the asn1 encoding */
	point_conversion_form_t asn1_form;

	unsigned char *seed; /* optional seed for parameters (appears in ASN1) */
	size_t seed_len;

	struct EC_EXTRA_DATA *extra_data; /* linked list */

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
	int (*field_mod_func)(BIGNUM *, const BIGNUM *, const BIGNUM *,	BN_CTX *); /* method-specific */
} /* EC_GROUP */;

struct ec_key_st {
	int version;

	EC_GROUP *group;

	EC_POINT *pub_key;
	BIGNUM	 *priv_key;

	unsigned int enc_flag;
	point_conversion_form_t conv_form;

	int 	references;
	int	flags;

	struct EC_EXTRA_DATA *method_data;
} /* EC_KEY */;


struct ecdh_method 
	{
	const char *name;
	int (*compute_key)(void *key, size_t outlen, const EC_POINT *pub_key, EC_KEY *ecdh,void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));
#if 0
	int (*init)(EC_KEY *eckey);
	int (*finish)(EC_KEY *eckey);
#endif
	int flags;
	char *app_data;
	};

static ECDH_METHOD my_ecdh = {
	"myengine",
	my_ecdh_compute_key,
#if 0
	NULL, /* init     */
	NULL, /* finish   */
#endif
	0,    /* flags    */
	NULL  /* app_data */
};

/****************************************************************************
 *			Symetric cipher and digest function registrars					*
*****************************************************************************/

static int my_ciphers(ENGINE *e, const EVP_CIPHER **cipher,const int **nids, int nid);

static int my_digests(ENGINE *e, const EVP_MD **digest,const int **nids, int nid);


static int my_cipher_nids[] ={ NID_des_cbc, NID_des_ede3_cbc, NID_desx_cbc, 0 };
static int my_digest_nids[] ={ NID_md2, NID_md5, 0 };

/*__declspec(dllexport)*/ void ENGINE_load_myengine(void);

