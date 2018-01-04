/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <time.h>
#include "internal/cryptlib.h"
#include <openssl/opensslconf.h>
#include "internal/rand.h"

#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif

#ifdef OPENSSL_FIPS
# include <openssl/fips.h>
# include <openssl/fips_rand.h>
#endif

#ifndef OPENSSL_NO_ENGINE
/* non-NULL if default_RAND_meth is ENGINE-provided */
static ENGINE *funct_ref = NULL;
#endif
static const RAND_METHOD *default_RAND_meth = NULL;

int RAND_set_rand_method(const RAND_METHOD *meth)
{
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(funct_ref);
    funct_ref = NULL;
#endif
    default_RAND_meth = meth;
    return 1;
}

const RAND_METHOD *RAND_get_rand_method(void)
{
    if (!default_RAND_meth) {
#ifndef OPENSSL_NO_ENGINE
        ENGINE *e = ENGINE_get_default_RAND();
        if (e) {
            default_RAND_meth = ENGINE_get_RAND(e);
            if (default_RAND_meth == NULL) {
                ENGINE_finish(e);
                e = NULL;
            }
        }
        if (e)
            funct_ref = e;
        else
#endif
            default_RAND_meth = RAND_OpenSSL();
    }
    return default_RAND_meth;
}

#ifndef OPENSSL_NO_ENGINE
int RAND_set_rand_engine(ENGINE *engine)
{
    const RAND_METHOD *tmp_meth = NULL;
    if (engine) {
        if (!ENGINE_init(engine))
            return 0;
        tmp_meth = ENGINE_get_RAND(engine);
        if (tmp_meth == NULL) {
            ENGINE_finish(engine);
            return 0;
        }
    }
    /* This function releases any prior ENGINE so call it first */
    RAND_set_rand_method(tmp_meth);
    funct_ref = engine;
    return 1;
}
#endif

void rand_cleanup_int(void)
{
    const RAND_METHOD *meth = RAND_get_rand_method();
    if (meth && meth->cleanup)
        meth->cleanup();
    RAND_set_rand_method(NULL);
}

void RAND_seed(const void *buf, int num)
{
    const RAND_METHOD *meth = RAND_get_rand_method();
    if (meth && meth->seed)
        meth->seed(buf, num);
}

void RAND_add(const void *buf, int num, double entropy)
{
    const RAND_METHOD *meth = RAND_get_rand_method();
    if (meth && meth->add)
        meth->add(buf, num, entropy);
}

int RAND_bytes(unsigned char *buf, int num)
{
    const RAND_METHOD *meth = RAND_get_rand_method();
    if (meth && meth->bytes)
        return meth->bytes(buf, num);
    return (-1);
}

#if OPENSSL_API_COMPAT < 0x10100000L
int RAND_pseudo_bytes(unsigned char *buf, int num)
{
    const RAND_METHOD *meth = RAND_get_rand_method();
    if (meth && meth->pseudorand)
        return meth->pseudorand(buf, num);
    return (-1);
}
#endif

int RAND_status(void)
{
    const RAND_METHOD *meth = RAND_get_rand_method();
    if (meth && meth->status)
        return meth->status();
    return 0;
}
