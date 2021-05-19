/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <gmssl/opensslconf.h>

#include "internal/err_int.h"
#include <gmssl/asn1.h>
#include <gmssl/bn.h>
#ifndef OPENSSL_NO_EC
# include <gmssl/ec.h>
#endif
#include <gmssl/buffer.h>
#include <gmssl/bio.h>
#ifndef OPENSSL_NO_COMP
# include <gmssl/comp.h>
#endif
#ifndef OPENSSL_NO_RSA
# include <gmssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DH
# include <gmssl/dh.h>
#endif
#ifndef OPENSSL_NO_DSA
# include <gmssl/dsa.h>
#endif
#include <gmssl/evp.h>
#include <gmssl/objects.h>
#include <gmssl/pem2.h>
#include <gmssl/x509.h>
#include <gmssl/x509v3.h>
#include <gmssl/conf.h>
#include <gmssl/pkcs12.h>
#include <gmssl/rand.h>
#include "internal/dso.h"
#ifndef OPENSSL_NO_ENGINE
# include <gmssl/engine.h>
#endif
#ifndef OPENSSL_NO_UI
# include <gmssl/ui.h>
#endif
#ifndef OPENSSL_NO_OCSP
# include <gmssl/ocsp.h>
#endif
#include <gmssl/err.h>
#ifdef OPENSSL_FIPS
# include <gmssl/fips.h>
#endif
#ifndef OPENSSL_NO_TS
# include <gmssl/ts.h>
#endif
#ifndef OPENSSL_NO_CMS
# include <gmssl/cms.h>
#endif
#ifndef OPENSSL_NO_CT
# include <gmssl/ct.h>
#endif
#ifndef OPENSSL_NO_ASYNC
# include <gmssl/async.h>
#endif
#include <gmssl/kdf.h>
#include <gmssl/kdf2.h>
#ifndef OPENSSL_NO_PAILLIER
# include <gmssl/paillier.h>
#endif
#ifndef OPENSSL_NO_OTP
# include <gmssl/otp.h>
#endif
#ifndef OPENSSL_NO_GMAPI
# include <gmssl/gmapi.h>
#endif
#ifndef OPENSSL_NO_SM2
# include <gmssl/sm2.h>
#endif
#ifndef OPENSSL_NO_SM9
# include <gmssl/sm9.h>
#endif
#ifndef OPENSSL_NO_SDF
# include <gmssl/gmsdf.h>
#endif
#ifndef OPENSSL_NO_SKF
# include <gmssl/gmskf.h>
#endif


int err_load_crypto_strings_int(void)
{
    if (
#ifdef OPENSSL_FIPS
        FIPS_set_error_callbacks(ERR_put_error, ERR_add_error_vdata) == 0 ||
#endif
#ifndef OPENSSL_NO_ERR
        ERR_load_ERR_strings() == 0 ||    /* include error strings for SYSerr */
        ERR_load_BN_strings() == 0 ||
# ifndef OPENSSL_NO_RSA
        ERR_load_RSA_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_DH
        ERR_load_DH_strings() == 0 ||
# endif
        ERR_load_EVP_strings() == 0 ||
        ERR_load_BUF_strings() == 0 ||
        ERR_load_OBJ_strings() == 0 ||
        ERR_load_PEM_strings() == 0 ||
# ifndef OPENSSL_NO_DSA
        ERR_load_DSA_strings() == 0 ||
# endif
        ERR_load_X509_strings() == 0 ||
        ERR_load_ASN1_strings() == 0 ||
        ERR_load_CONF_strings() == 0 ||
        ERR_load_CRYPTO_strings() == 0 ||
# ifndef OPENSSL_NO_COMP
        ERR_load_COMP_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_EC
        ERR_load_EC_strings() == 0 ||
# endif
        /* skip ERR_load_SSL_strings() because it is not in this library */
        ERR_load_BIO_strings() == 0 ||
        ERR_load_PKCS7_strings() == 0 ||
        ERR_load_X509V3_strings() == 0 ||
# ifndef OPENSSL_NO_PKCS12
        ERR_load_PKCS12_strings() == 0 ||
# endif
        ERR_load_RAND_strings() == 0 ||
        ERR_load_DSO_strings() == 0 ||
# ifndef OPENSSL_NO_TS
        ERR_load_TS_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_ENGINE
        ERR_load_ENGINE_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_OCSP
        ERR_load_OCSP_strings() == 0 ||
# endif
#ifndef OPENSSL_NO_UI
        ERR_load_UI_strings() == 0 ||
#endif
# ifdef OPENSSL_FIPS
        ERR_load_FIPS_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_CMS
        ERR_load_CMS_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_CT
        ERR_load_CT_strings() == 0 ||
# endif
        ERR_load_ASYNC_strings() == 0 ||
# ifndef OPENSSL_NO_KDF2
        ERR_load_KDF2_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_PAILLIER
        ERR_load_PAILLIER_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_OTP
        ERR_load_OTP_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_GMAPI
        ERR_load_GMAPI_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_SM2
        ERR_load_SM2_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_SM9
        ERR_load_SM9_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_SDF
        ERR_load_SDF_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_SKF
        ERR_load_SKF_strings() == 0 ||
# endif
#endif
        ERR_load_KDF_strings() == 0)
        return 0;

    return 1;
}
