/*
 * Support for ZHAOXIN GMI (GuoMi Instruction)
 * Written by Yun Shen (yunshen@via-alliance.com) and
 * Kai Li <kelvinkli@via-alliance.com>
 */

/* ====================================================================
 * Copyright (c) 1999-2016 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
 /* ====================================================================
 * Copyright 2016 Shanghai Zhaoxin Semiconductor Co., Ltd. ALL RIGHTS RESERVED.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/modes.h>
#include "../crypto/evp/evp_locl.h"

/* gmi sm3 header */
# define SM3_LONG unsigned int

# define SM3_LBLOCK      16
# define SM3_CBLOCK      (SM3_LBLOCK*4)/* SHA treats input data as a
                                        * contiguous array of 32 bit wide
                                        * big-endian values. */
# define SM3_LAST_BLOCK  (SM3_CBLOCK-8)
# define SM3_DIGEST_LENGTH 32

typedef struct SM3state_st {
    SM3_LONG h[8];
    SM3_LONG Nl, Nh;
    SM3_LONG data[SM3_LBLOCK];
    unsigned int num, md_len;
} SM3_CTX;

/* gmi sm4 header */
# define SM4_ENCRYPT     1
# define SM4_DECRYPT     0

/*
 * Because array size can't be a const in C, the following two are macros.
 * Both sizes are in bytes.
 */
#define SM4_BLOCK_SIZE 16

#define SM4_KEY_SIZE    16

/* This should be a hidden type, but EVP requires that the size be known */
struct sm4_key_st {
# ifdef SM4_LONG
    unsigned long rd_key[32];
# else
    unsigned int rd_key[32];
# endif
};
typedef struct sm4_key_st SM4_KEY;


#define NID_sm3WithRSAEncryption	NID_sm3
#define NID_sm4_ecb	NID_sms4_ecb
#define NID_sm4_cbc	NID_sms4_cbc
#define NID_sm4_cfb	NID_sms4_cfb8
#define NID_sm4_ofb	NID_sms4_ofb128
#define NID_sm4_ctr	NID_sms4_ctr


#include "../crypto/include/internal/evp_int.h"

#ifndef OPENSSL_NO_HW
# ifndef OPENSSL_NO_HW_GMI

/* Attempt to have a single source for both 0.9.7 and 0.9.8 :-) */
#  if (OPENSSL_VERSION_NUMBER >= 0x00908000L)
#   ifndef OPENSSL_NO_DYNAMIC_ENGINE
#    define DYNAMIC_ENGINE
#   endif
#  elif (OPENSSL_VERSION_NUMBER >= 0x00907000L)
#   ifdef ENGINE_DYNAMIC_SUPPORT
#    define DYNAMIC_ENGINE
#   endif
#  else
#   error "Only OpenSSL >= 0.9.7 is supported"
#  endif

/*
 * ZHAOXIN GMI is available *ONLY* on some x86 CPUs. Not only that it
 * doesn't exist elsewhere, but it even can't be compiled on other platforms!
 */

#  undef COMPILE_HW_GMI
#  if !defined(I386_ONLY) && !defined(OPENSSL_NO_ASM)
#   if    defined(__i386__) || defined(__i386) ||    \
        defined(__x86_64__) || defined(__x86_64) || \
        defined(_M_IX86) || defined(_M_AMD64) || defined(_M_X64) || \
        defined(__INTEL__)
#    define COMPILE_HW_GMI
#    ifdef OPENSSL_NO_DYNAMIC_ENGINE
static ENGINE *ENGINE_gmi(void);
#    endif
#   endif
#  endif

#  ifdef OPENSSL_NO_DYNAMIC_ENGINE
void engine_load_gmi_int(void);
void engine_load_gmi_int(void)
{
/* On non-x86 CPUs it just returns. */
#   ifdef COMPILE_HW_GMI
    ENGINE *toadd = ENGINE_gmi();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
#   endif
}

#  endif

#  ifdef COMPILE_HW_GMI

/* Function for ENGINE detection and control */
static int gmi_available(void);
static int gmi_init(ENGINE *e);


/* Cipher Stuff */
static int gmi_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                           const int **nids, int nid);

static int gmi_digests(ENGINE *e, const EVP_MD **digest,
                          const int **nids, int nid);

/* Engine names */
static const char *gmi_id = "gmi";
static char gmi_name[100];

/* Available features */
static int gmi_use_ccs = 0; /* CCS */

/* ===== Engine "management" functions ===== */

/* Prepare the ENGINE structure for registration */
static int gmi_bind_helper(ENGINE *e)
{
    /* Check available features */
    gmi_available();

    /* Generate a nice engine name with available features */
    BIO_snprintf(gmi_name, sizeof(gmi_name),
                 "ZX GMI (%s)",
                 gmi_use_ccs ? "CCS" : "no-CCS");

    /* Register everything or return with an error */
    if (!ENGINE_set_id(e, gmi_id) ||
        !ENGINE_set_name(e, gmi_name) ||
        !ENGINE_set_init_function(e, gmi_init) ||
        (gmi_use_ccs && !ENGINE_set_ciphers(e, gmi_ciphers)) ||
		(gmi_use_ccs && !ENGINE_set_digests(e, gmi_digests))) {

		   return 0;
    }

    /* Everything looks good */
    return 1;
}

#   ifdef OPENSSL_NO_DYNAMIC_ENGINE
/* Constructor */
static ENGINE *ENGINE_gmi(void)
{
    ENGINE *eng = ENGINE_new();

    if (eng == NULL) {
        return NULL;
    }

    if (!gmi_bind_helper(eng)) {
        ENGINE_free(eng);
        return NULL;
    }

    return eng;
}
#   endif

/* Check availability of the engine */
static int gmi_init(ENGINE *e)
{
    return (gmi_use_ccs);
}

/*
 * This stuff is needed if this ENGINE is being compiled into a
 * self-contained shared-library.
 */
#   ifdef DYNAMIC_ENGINE
static int gmi_bind_fn(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, gmi_id) != 0)) {
        return 0;
    }

    if (!gmi_bind_helper(e)) {
        return 0;
    }

    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(gmi_bind_fn)
#   endif                       /* DYNAMIC_ENGINE */


/* ===== Here comes the "real" engine ===== */

#define CCS_ENCRYPT_FUNC_SM4     0x10

#define CCS_ENCRYPT_MODE_ECB     0x1
#define CCS_ENCRYPT_MODE_CBC     0x2
#define CCS_ENCRYPT_MODE_CFB     0x4
#define CCS_ENCRYPT_MODE_OFB     0x8
#define CCS_ENCRYPT_MODE_CTR     0x10
/*
 * Here we store the status information relevant to the current context.
 */
/*
 * BIG FAT WARNING: Inline assembler in GMI_XCRYPT_ASM() depends on
 * the order of items in this structure.  Don't blindly modify, reorder,
 * etc!
 */
struct gmi_cipher_data {
    unsigned char iv[SM4_BLOCK_SIZE]; /* Initialization vector */
    union {
        unsigned int pad[4];
        struct {
            int encdec:1;
            int func:5;
            int mode:5;
            int digest:1;
        } b;
    } cword;                    /* Control word */
    SM4_KEY ks;                 /* Encryption key */
};

/* Interface to assembler module */
unsigned int zx_gmi_capability();
void gmi_sm3_oneshot(void *ctx, const void *inp, size_t len);
void gmi_sm3_blocks(void *ctx, const void *inp, size_t len);
void gmi_reload_key();
void gmi_verify_context(struct gmi_cipher_data *ctx);

void gmi_sm4_block(void *out, const void *inp,
                       struct gmi_cipher_data *ctx);
int gmi_ecb_encrypt(void *out, const void *inp,
                        struct gmi_cipher_data *ctx, size_t len);
int gmi_cbc_encrypt(void *out, const void *inp,
                        struct gmi_cipher_data *ctx, size_t len);
int gmi_ctr32_encrypt(void *out, const void *inp,
                          struct gmi_cipher_data *ctx, size_t len);

/*
 * Load supported features of the CPU to see if the PadLock is available.
 */
static int gmi_available(void)
{
    int zx_gmi_use_ccs = 0;
    //unsigned int edx; //original code
    unsigned int edx = 0;

    /* Fill up some flags */
    gmi_use_ccs = ((edx & (0x3 << 4)) == (0x3 << 4));

    edx = zx_gmi_capability();
    zx_gmi_use_ccs = ((edx & (0x3 << 6)) == (0x3 << 6));

    gmi_use_ccs = gmi_use_ccs | zx_gmi_use_ccs;

    return gmi_use_ccs;
}

#define SM3_MAKE_STRING(c, s) do {    \
        unsigned long ll;               \
        unsigned int  nn;               \
        for (nn=0;nn<SM3_DIGEST_LENGTH/4;nn++)       \
        {   ll=(c)->h[nn]; (void)HOST_l2c(ll,(s));   }  \
                         \
        } while (0)

#define HOST_l2c(l,c)        ({ unsigned int r=(l);                  \
                                   asm ("bswapl %0":"=r"(r):"0"(r));    \
                                   *((unsigned int *)(c))=r; (c)+=4; r; })

static int gmi_sm3_init(EVP_MD_CTX *ctx)
{
    BIO *b = BIO_new_fp(stdout, BIO_NOCLOSE|BIO_FP_TEXT);
    BIO_printf(b, "%s\n", __FUNCTION__);

    SM3_CTX *c = (SM3_CTX *)EVP_MD_CTX_md_data(ctx);

    /* set the IV in Big-Endian */
    c->h[0]=0x6f168073UL;
   	c->h[1]=0xb9b21449UL;
   	c->h[2]=0xd7422417UL;
   	c->h[3]=0x00068adaUL;
   	c->h[4]=0xbc306fa9UL;
   	c->h[5]=0xaa383116UL;
   	c->h[6]=0x4dee8de3UL;
   	c->h[7]=0x4e0efbb0UL;

    c->md_len = SM3_DIGEST_LENGTH;

    c->num = 0; //



    BIO_free(b);
    return 1;
}

static int gmi_sm3_update(EVP_MD_CTX *ctx, const void *data_, size_t len)
{

    const unsigned char *data = data_;
    unsigned char *p;
    SM3_LONG l;
    size_t n;
    SM3_CTX *c = (SM3_CTX *)EVP_MD_CTX_md_data(ctx);

    if (len == 0)
        return 1;

    l = (c->Nl + (((SM3_LONG) len) << 3)) & 0xffffffffUL;

    if (l < c->Nl)              /* overflow */
        c->Nh++;
    c->Nh += (SM3_LONG) (len >> 29); /* might cause compiler warning on
                                       * 16-bit */
    c->Nl = l;

    n = c->num;
    if (n != 0) {
        p = (unsigned char *)c->data;

        if (len >= SM3_CBLOCK || len + n >= SM3_CBLOCK) {
            memcpy(p + n, data, SM3_CBLOCK - n);
            gmi_sm3_blocks(c->h, p, 1);
            n = SM3_CBLOCK - n;
            data += n;
            len -= n;
            c->num = 0;
            memset(p, 0, SM3_CBLOCK); /* keep it zeroed */
        } else {
            memcpy(p + n, data, len);
            c->num += (unsigned int)len;
            return 1;
        }
    }

    n = len / SM3_CBLOCK;
    if (n > 0) {
        gmi_sm3_blocks(c->h, data, n);
        n *= SM3_CBLOCK;
        data += n;
        len -= n;
    }

    if (len != 0) {
        p = (unsigned char *)c->data;
        c->num = (unsigned int)len;
        memcpy(p, data, len);
}

    return 1;
}

static int gmi_sm3_final(EVP_MD_CTX *ctx, unsigned char *md)
{

    SM3_CTX *c = (SM3_CTX *)EVP_MD_CTX_md_data(ctx);
    unsigned char *p = (unsigned char *)c->data;
    size_t n = c->num;

    p[n] = 0x80;                /* there is always room for one */
    n++;

    if (n > (SM3_CBLOCK - 8)) {
        memset(p + n, 0, SM3_CBLOCK - n);
        n = 0;
        gmi_sm3_blocks(c->h, p, 1);
    }
    memset(p + n, 0, SM3_CBLOCK - 8 - n);

    p += SM3_CBLOCK - 8;

    (void)HOST_l2c(c->Nh, p);
    (void)HOST_l2c(c->Nl, p);

    p -= SM3_CBLOCK;
    gmi_sm3_blocks(c->h, p, 1);

    c->num = 0;
    memset(p, 0, SM3_CBLOCK);

    memcpy(md, c->h, c->md_len);

    return 1;
}

/* List of supported ciphers. */
static const int gmi_digest_nids[] = {
    NID_sm3,
    0
};

static const EVP_MD digest_sm3= {
    NID_sm3,
    NID_sm3WithRSAEncryption,
    SM3_DIGEST_LENGTH,
    EVP_MD_FLAG_DIGALGID_ABSENT,
    gmi_sm3_init,
    gmi_sm3_update,
    gmi_sm3_final,
    NULL,
    NULL,
    SM3_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SM3_CTX),
};


static int gmi_digests(ENGINE *e, const EVP_MD **digest,
                          const int **nids, int nid)
{
    int ok = 1;
    if (!digest) {
        /* We are returning a list of supported nids */
        *nids = gmi_digest_nids;
        return (sizeof(gmi_digest_nids) -
                1) / sizeof(gmi_digest_nids[0]);
    }
    /* We are being asked for a specific digest */
    switch (nid) {
    case NID_sm3:
        *digest = &digest_sm3;
        break;
    default:
        ok = 0;
        *digest = NULL;
        break;
    }
    return ok;
}


/* ======== GX6 ===================== */
#   define NEAREST_ALIGNED(ptr) ( (unsigned char *)(ptr) +         \
        ( (0x10 - ((size_t)(ptr) & 0x0F)) & 0x0F )      )
#   define ALIGNED_CIPHER_DATA(ctx) ((struct gmi_cipher_data *)\
        NEAREST_ALIGNED(EVP_CIPHER_CTX_get_cipher_data(ctx)))

/* Prepare the encryption key for PadLock usage */
static int
gmi_sm4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                     const unsigned char *iv, int enc)
{
    struct gmi_cipher_data *cdata;
    unsigned long mode = EVP_CIPHER_CTX_mode(ctx);


    if (key == NULL)
        return 0;               /* ERROR */

    cdata = ALIGNED_CIPHER_DATA(ctx);
    memset(cdata, 0, sizeof(*cdata));

    /* Prepare Control word. */
    if (mode == EVP_CIPH_OFB_MODE || mode == EVP_CIPH_CTR_MODE)
        cdata->cword.b.encdec = 0;
    else
        cdata->cword.b.encdec = (ctx->encrypt == 0);

    cdata->cword.b.func = CCS_ENCRYPT_FUNC_SM4;
    cdata->cword.b.mode = 1<<(mode-1);;
    cdata->cword.b.digest = 0;

    if(iv != NULL)
    {
        memcpy(cdata->iv, iv, SM4_BLOCK_SIZE);
    }

    memcpy(cdata->ks.rd_key, key, SM4_KEY_SIZE);


    /*
     * This is done to cover for cases when user reuses the
     * context for new key. The catch is that if we don't do
     * this, gmi_eas_cipher might proceed with old key...
     */
    gmi_reload_key();

    return 1;
}

void gmi_sm4_encrypt(unsigned char *out, const unsigned char *in, struct gmi_cipher_data *ctx, size_t len);
void gmi_sm4_ecb_enc(unsigned char *in, unsigned char *out, unsigned char *key);

static int
gmi_sm4_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out_arg,
                   const unsigned char *in_arg, size_t nbytes)
{
    struct gmi_cipher_data *cdata = ALIGNED_CIPHER_DATA(ctx);

    gmi_sm4_encrypt(out_arg, in_arg, cdata, nbytes);

    return 1;
}

static int
gmi_sm4_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out_arg,
                   const unsigned char *in_arg, size_t nbytes)
{
	struct gmi_cipher_data *cdata = ALIGNED_CIPHER_DATA(ctx);

    memcpy(cdata->iv, ctx->iv, SM4_BLOCK_SIZE);

    gmi_sm4_encrypt(out_arg, in_arg, cdata, nbytes);

    memcpy(ctx->iv, cdata->iv, SM4_BLOCK_SIZE);

    return 1;
}

#if 0
static int
gmi_sm4_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out_arg,
                   const unsigned char *in_arg, size_t nbytes)
{
    struct gmi_cipher_data *cdata = ALIGNED_CIPHER_DATA(ctx);
    unsigned int num = ctx->num;

    CRYPTO_ctr128_encrypt(in_arg, out_arg, nbytes,
                                cdata->ks.rd_key, ctx->iv, ctx->buf, &num,
                                (block128_f) gmi_sm4_ecb_enc);

    ctx->num = (size_t)num;
    return 1;
}
#endif
#if 1
static int
gmi_sm4_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out_arg,
                   const unsigned char *in_arg, size_t nbytes)
{
    struct gmi_cipher_data *cdata = ALIGNED_CIPHER_DATA(ctx);
    unsigned int num = ctx->num;
    memcpy(cdata->iv, ctx->iv, SM4_BLOCK_SIZE);
    gmi_sm4_encrypt(out_arg, in_arg, cdata, nbytes);
    ctx->num = (size_t)num;
    return 1;
}
#endif

static int
gmi_sm4_cfb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out_arg,
                   const unsigned char *in_arg, size_t nbytes)
{
#if 0
	struct gmi_cipher_data *cdata = ALIGNED_CIPHER_DATA(ctx);
    CRYPTO_cfb128_encrypt(in_arg, out_arg, nbytes, cdata->ks.rd_key,
    		              ctx->iv, &ctx->num, ctx->encrypt,
    		              (block128_f)gmi_sm4_ecb_enc);
#else
    struct gmi_cipher_data *cdata = ALIGNED_CIPHER_DATA(ctx);

        memcpy(cdata->iv, ctx->iv, SM4_BLOCK_SIZE);


        gmi_sm4_encrypt(out_arg, in_arg, cdata, nbytes);

        memcpy(ctx->iv, cdata->iv, SM4_BLOCK_SIZE);

#endif
        return 1;
}

static int
gmi_sm4_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out_arg,
                   const unsigned char *in_arg, size_t nbytes)
{
#if 0
    struct gmi_cipher_data *cdata = ALIGNED_CIPHER_DATA(ctx);
    CRYPTO_ofb128_encrypt(in_arg, out_arg, nbytes,cdata->ks.rd_key,
    		              ctx->iv, &ctx->num, (block128_f) gmi_sm4_ecb_enc);
#else
    struct gmi_cipher_data *cdata = ALIGNED_CIPHER_DATA(ctx);
    memcpy(cdata->iv, ctx->iv, SM4_BLOCK_SIZE);
    gmi_sm4_encrypt(out_arg, in_arg, cdata, nbytes);
    memcpy(ctx->iv, cdata->iv, SM4_BLOCK_SIZE);
#endif
	return 1;
}

#define EVP_SM4_CIPHER_block_size_ECB       SM4_BLOCK_SIZE
#define EVP_SM4_CIPHER_block_size_CBC       SM4_BLOCK_SIZE
#define EVP_SM4_CIPHER_block_size_OFB       1
#define EVP_SM4_CIPHER_block_size_CFB       1
#define EVP_SM4_CIPHER_block_size_CTR       1
/*
 * Declaring so many ciphers by hand would be a pain. Instead introduce a bit
 * of preprocessor magic :-)
 */

#   define DECLARE_SM4_EVP(lmode,umode)      \
static EVP_CIPHER *_hidden_sm4_##lmode = NULL; \
static const EVP_CIPHER *gmi_sm4_##lmode(void) \
{                                                                       \
    if (_hidden_sm4_##lmode == NULL                           \
        && ((_hidden_sm4_##lmode =                            \
             EVP_CIPHER_meth_new(NID_sm4_##lmode,             \
                                 EVP_SM4_CIPHER_block_size_##umode,         \
                                 SM4_KEY_SIZE)) == NULL         \
            || !EVP_CIPHER_meth_set_iv_length(_hidden_sm4_##lmode, \
                                              SM4_BLOCK_SIZE)           \
            || !EVP_CIPHER_meth_set_flags(_hidden_sm4_##lmode, \
                                          0 | EVP_CIPH_##umode##_MODE)  \
            || !EVP_CIPHER_meth_set_init(_hidden_sm4_##lmode, \
                                         gmi_sm4_init_key)          \
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_sm4_##lmode, \
                                              gmi_sm4_##lmode##_cipher) \
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_sm4_##lmode, \
                                                  sizeof(struct gmi_cipher_data) + 16) \
            || !EVP_CIPHER_meth_set_set_asn1_params(_hidden_sm4_##lmode, \
                                                    EVP_CIPHER_set_asn1_iv) \
            || !EVP_CIPHER_meth_set_get_asn1_params(_hidden_sm4_##lmode, \
                                                    EVP_CIPHER_get_asn1_iv))) { \
        EVP_CIPHER_meth_free(_hidden_sm4_##lmode);            \
        _hidden_sm4_##lmode = NULL;                           \
    }                                                                   \
    return _hidden_sm4_##lmode;                               \
}

DECLARE_SM4_EVP(ecb, ECB);
DECLARE_SM4_EVP(cbc, CBC);
DECLARE_SM4_EVP(ctr, CTR);
DECLARE_SM4_EVP(cfb, CFB);
DECLARE_SM4_EVP(ofb, OFB);

/* List of supported ciphers. */
static const int gmi_cipher_nids[] = {
    NID_sm4_ecb,
    NID_sm4_cbc,
    NID_sm4_cfb,
    NID_sm4_ofb,
    NID_sm4_ctr,
    0
};


static int gmi_cipher_nids_num = (sizeof(gmi_cipher_nids) /
                                      sizeof(gmi_cipher_nids[0]));

static int
gmi_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids,
                int nid)
{
    /* No specific cipher => return a list of supported nids ... */
    if (!cipher) {
        *nids = gmi_cipher_nids;
        return gmi_cipher_nids_num;
    }

    /* ... or the requested "cipher" otherwise */
    switch (nid) {
    case NID_sm4_ecb:
        *cipher = gmi_sm4_ecb();
        break;
    case NID_sm4_cbc:
        *cipher = gmi_sm4_cbc();
        break;
    case NID_sm4_cfb:
        *cipher = gmi_sm4_cfb();
        break;
    case NID_sm4_ofb:
        *cipher = gmi_sm4_ofb();
        break;
    case NID_sm4_ctr:
        *cipher = gmi_sm4_ctr();
        break;
    default:
        /* Sorry, we don't support this NID */
        *cipher = NULL;
        return 0;
    }

    return 1;
}

#  endif                        /* COMPILE_HW_GMI */
# endif                         /* !OPENSSL_NO_HW_GMI */
#endif                          /* !OPENSSL_NO_HW */

#if defined(OPENSSL_NO_HW) || defined(OPENSSL_NO_HW_GMI) \
        || !defined(COMPILE_HW_GMI)
# ifndef OPENSSL_NO_DYNAMIC_ENGINE
OPENSSL_EXPORT
    int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns);
OPENSSL_EXPORT
    int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns)
{
    return 0;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
# endif
#endif
