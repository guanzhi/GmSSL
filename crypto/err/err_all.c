/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/err_int.h"
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/comp.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem2.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/conf.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include "internal/dso.h"
#include <openssl/engine.h>
#include <openssl/ui.h>
#include <openssl/ocsp.h>
#include <openssl/err.h>
#ifdef OPENSSL_FIPS
# include <openssl/fips.h>
#endif
#include <openssl/ts.h>
#include <openssl/cms.h>
#include <openssl/ct.h>
#include <openssl/async.h>
#include <openssl/kdf.h>
#include <openssl/kdf2.h>
#include <openssl/ffx.h>
#include <openssl/paillier.h>
#include <openssl/cpk.h>
#include <openssl/otp.h>
#include <openssl/gmapi.h>
#include <openssl/bfibe.h>
#include <openssl/bb1ibe.h>
#include <openssl/sm2.h>
#include <openssl/sm9.h>
#include <openssl/gmsaf.h>
#include <openssl/gmsdf.h>
#include <openssl/gmskf.h>
#include <openssl/gmsof.h>
#ifndef OPENSSL_NO_BASE58
#include <openssl/base58.h>
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
        ERR_load_PKCS12_strings() == 0 ||
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
# ifndef OPENSSL_NO_FFX
        ERR_load_FFX_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_PAILLIER
        ERR_load_PAILLIER_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_CPK
        ERR_load_CPK_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_OTP
        ERR_load_OTP_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_GMAPI
        ERR_load_GMAPI_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_BFIBE
        ERR_load_BFIBE_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_BB1IBE
        ERR_load_BB1IBE_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_SM2
        ERR_load_SM2_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_SM9
        ERR_load_SM9_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_SAF
        ERR_load_SAF_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_SDF
        ERR_load_SDF_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_SKF
        ERR_load_SKF_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_SOF
        ERR_load_SOF_strings() == 0 ||
# endif
# ifndef OPENSSL_NO_BASE58
        ERR_load_BASE58_strings() == 0 ||
# endif
#endif
        ERR_load_KDF_strings() == 0)
        return 0;

    return 1;
}
