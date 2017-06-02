/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apps.h"
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#ifndef OPENSSL_NO_MD2
# include <openssl/md2.h>
#endif
#ifndef OPENSSL_NO_RC4
# include <openssl/rc4.h>
#endif
#ifndef OPENSSL_NO_DES
# include <openssl/des.h>
#endif
#ifndef OPENSSL_NO_IDEA
# include <openssl/idea.h>
#endif
#ifndef OPENSSL_NO_BF
# include <openssl/blowfish.h>
#endif

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_B, OPT_D, OPT_E, OPT_F, OPT_O, OPT_P, OPT_V, OPT_A
} OPTION_CHOICE;

OPTIONS version_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"a", OPT_A, '-', "Show all data"},
    {"b", OPT_B, '-', "Show build date"},
    {"d", OPT_D, '-', "Show configuration directory"},
    {"e", OPT_E, '-', "Show engines directory"},
    {"f", OPT_F, '-', "Show compiler flags used"},
    {"o", OPT_O, '-', "Show some internal datatype options"},
    {"p", OPT_P, '-', "Show target build platform"},
    {"v", OPT_V, '-', "Show library version"},
    {NULL}
};

int version_main(int argc, char **argv)
{
    int ret = 1, dirty = 0;
    int cflags = 0, version = 0, date = 0, options = 0, platform = 0, dir = 0;
    int engdir = 0;
    char *prog;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, version_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(version_options);
            ret = 0;
            goto end;
        case OPT_B:
            dirty = date = 1;
            break;
        case OPT_D:
            dirty = dir = 1;
            break;
        case OPT_E:
            dirty = engdir = 1;
            break;
        case OPT_F:
            dirty = cflags = 1;
            break;
        case OPT_O:
            dirty = options = 1;
            break;
        case OPT_P:
            dirty = platform = 1;
            break;
        case OPT_V:
            dirty = version = 1;
            break;
        case OPT_A:
            cflags = version = date = platform = dir = engdir = 1;
            break;
        }
    }
    if (!dirty)
        version = 1;

    if (version) {
        if (OpenSSL_version_num() == OPENSSL_VERSION_NUMBER) {
            printf("%s\n", OpenSSL_version(OPENSSL_VERSION));
        } else {
            printf("%s (Library: %s)\n",
                   OPENSSL_VERSION_TEXT, OpenSSL_version(OPENSSL_VERSION));
        }
    }
    if (date)
        printf("%s\n", OpenSSL_version(OPENSSL_BUILT_ON));
    if (platform)
        printf("%s\n", OpenSSL_version(OPENSSL_PLATFORM));
    if (options) {
        printf("options:  ");
        printf("%s ", BN_options());
#ifndef OPENSSL_NO_MD2
        printf("%s ", MD2_options());
#endif
#ifndef OPENSSL_NO_RC4
        printf("%s ", RC4_options());
#endif
#ifndef OPENSSL_NO_DES
        printf("%s ", DES_options());
#endif
#ifndef OPENSSL_NO_IDEA
        printf("%s ", IDEA_options());
#endif
#ifndef OPENSSL_NO_BF
        printf("%s ", BF_options());
#endif
        printf("\n");
    }
    if (cflags)
        printf("%s\n", OpenSSL_version(OPENSSL_CFLAGS));
    if (dir)
        printf("%s\n", OpenSSL_version(OPENSSL_DIR));
    if (engdir)
        printf("%s\n", OpenSSL_version(OPENSSL_ENGINES_DIR));
    ret = 0;
 end:
    return (ret);
}
