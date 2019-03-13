/* ====================================================================
 * Copyright (c) 2014 - 2018 The GmSSL Project.  All rights reserved.
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
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */
/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#ifdef OPENSSL_NO_SM2
NON_EMPTY_TRANSLATION_UNIT
#else

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/evp.h>
# include <openssl/pem.h>
# include <openssl/sm2.h>
# include <openssl/objects.h>
# include "../crypto/ec/ec_lcl.h"
# include "apps.h"

static OPT_PAIR conv_forms[] = {
    {"compressed", POINT_CONVERSION_COMPRESSED},
    {"uncompressed", POINT_CONVERSION_UNCOMPRESSED},
    {"hybrid", POINT_CONVERSION_HYBRID},
    {NULL}
};

static OPT_PAIR param_enc[] = {
    {"named_curve", OPENSSL_EC_NAMED_CURVE},
    {"explicit", 0},
    {NULL}
};

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_OUTFORM, OPT_ENGINE, OPT_IN, OPT_OUT,
    OPT_NOOUT, OPT_TEXT, OPT_PARAM_OUT, OPT_PUBIN, OPT_PUBOUT,
    OPT_PASSIN, OPT_PASSOUT, OPT_PARAM_ENC, OPT_CONV_FORM, OPT_CIPHER,
    OPT_NO_PUBLIC, OPT_CHECK, OPT_CONFIG,
    OPT_GENKEY, OPT_RAND, OPT_ID, OPT_GENZID
} OPTION_CHOICE;

OPTIONS sm2_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"in", OPT_IN, 's', "Input file"},
    {"inform", OPT_INFORM, 'f', "Input format - DER or PEM"},
    {"out", OPT_OUT, '>', "Output file"},
    {"outform", OPT_OUTFORM, 'F', "Output format - DER or PEM"},
    {"noout", OPT_NOOUT, '-', "Don't print key out"},
    {"text", OPT_TEXT, '-', "Print the key"},
    {"param_out", OPT_PARAM_OUT, '-', "Print 'sm2p256v1' elliptic curve parameters"},
    {"pubin", OPT_PUBIN, '-', "Expect a public key in input file"},
    {"pubout", OPT_PUBOUT, '-', "Output public key, not private"},
    {"no_public", OPT_NO_PUBLIC, '-', "exclude public key from private key"},
    {"check", OPT_CHECK, '-', "check key consistency"},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    {"passout", OPT_PASSOUT, 's', "Output file pass phrase source"},
    {"param_enc", OPT_PARAM_ENC, 's',
     "Specifies the way the ec parameters are encoded"},
    {"conv_form", OPT_CONV_FORM, 's', "Specifies the point conversion form "},
    {"genkey", OPT_GENKEY, '-', "Generate sm2 key"},
    {"rand", OPT_RAND, 's', "Files to use for random number input"},
    {"id", OPT_ID, 's', "SM2 key owner's identity"},
    {"genzid", OPT_GENZID, '-', "Generate SM2 Z value from public key and identity"},
    {"", OPT_CIPHER, '-', "Any supported cipher"},
# ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
    {"config", OPT_CONFIG, 's', "A config file"},
# endif
    {NULL}
};

int sm2_main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    ENGINE *e = NULL;
    EC_KEY *eckey = NULL;
    const EC_GROUP *group;
    const EVP_CIPHER *enc = EVP_sms4_cbc();
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
    char *infile = NULL, *outfile = NULL, *prog;
    char *passin = NULL, *passout = NULL, *passinarg = NULL, *passoutarg = NULL;
    OPTION_CHOICE o;
    int asn1_flag = OPENSSL_EC_NAMED_CURVE, new_form = 0, new_asn1_flag = 0;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, text = 0, noout = 0;
    int pubin = 0, pubout = 0, param_out = 0, i, ret = 1, private = 0;
    int no_public = 0, check = 0;
    CONF *conf = NULL;
    char *configfile = default_config_file;
    int genkey = 0, need_rand = 0;
    char *inrand = NULL;
    int genzid = 0;
    char *id = NULL;

    prog = opt_init(argc, argv, sm2_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(sm2_options);
            ret = 0;
            goto end;
        case OPT_INFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &informat))
                goto opthelp;
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
                goto opthelp;
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_NOOUT:
            noout = 1;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_PARAM_OUT:
            param_out = 1;
            break;
        case OPT_PUBIN:
            pubin = 1;
            break;
        case OPT_PUBOUT:
            pubout = 1;
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_PASSOUT:
            passoutarg = opt_arg();
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_CIPHER:
            if (!opt_cipher(opt_unknown(), &enc))
                goto opthelp;
            break;
        case OPT_CONV_FORM:
            if (!opt_pair(opt_arg(), conv_forms, &i))
                goto opthelp;
            new_form = 1;
            form = i;
            break;
        case OPT_PARAM_ENC:
            if (!opt_pair(opt_arg(), param_enc, &i))
                goto opthelp;
            new_asn1_flag = 1;
            asn1_flag = i;
            break;
        case OPT_NO_PUBLIC:
            no_public = 1;
            break;
        case OPT_CHECK:
            check = 1;
            break;
        case OPT_CONFIG:
            configfile = opt_arg();
            break;
        case OPT_GENKEY:
            genkey = need_rand = 1;
            break;
        case OPT_RAND:
            inrand = opt_arg();
            need_rand = 1;
            break;
        case OPT_ID:
            id = opt_arg();
            break;
        case OPT_GENZID:
            genzid = 1;
            break;
        }
    }
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    BIO_printf(bio_err, "Using configuration from %s\n", configfile);

    if ((conf = app_load_config(configfile)) == NULL)
        goto end;
    if (configfile != default_config_file && !app_load_modules(conf))
        goto end;

    private = param_out || pubin || pubout ? 0 : 1;
    if (text && !pubin)
        private = 1;

    if (!app_passwd(passinarg, passoutarg, &passin, &passout)) {
        BIO_printf(bio_err, "Error getting passwords\n");
        goto end;
    }

    if (informat != FORMAT_ENGINE) {
        in = bio_open_default(infile, 'r', informat);
        if (in == NULL)
            goto end;
    }

    if (need_rand) {
        app_RAND_load_file(NULL, (inrand != NULL));
        if (inrand != NULL)
            BIO_printf(bio_err, "%ld semi-random bytes loaded\n",
                       app_RAND_load_files(inrand));
    }


    if (genkey) {
        BIO_printf(bio_err, "generate SM2 key\n");
        if (!(eckey = EC_KEY_new_by_curve_name(NID_sm2p256v1))) {
            goto end;
        }
        assert(need_rand);
        if (!EC_KEY_generate_key(eckey)) {
            BIO_printf(bio_err, "unable to generate key\n");
            EC_KEY_free(eckey);
            ERR_print_errors(bio_err);
            goto end;
        }
    } else {
        BIO_printf(bio_err, "read SM2 key\n");
        if (informat == FORMAT_ASN1) {
            if (pubin)
                eckey = d2i_EC_PUBKEY_bio(in, NULL);
            else
                eckey = d2i_ECPrivateKey_bio(in, NULL);
        } else if (informat == FORMAT_TEXT) {
            unsigned char buf[256] = {0};
            unsigned char *key = NULL;
            long keylen;
            if (!(eckey = EC_KEY_new_by_curve_name(NID_sm2p256v1))) {
                ERR_print_errors(bio_err);
                goto end;
            }
            if (BIO_read(in, buf, sizeof(buf) - 1) <= 0) {
                ERR_print_errors(bio_err);
                OPENSSL_cleanse(buf, sizeof(buf));
                goto end;
            }
            if (!(key = OPENSSL_hexstr2buf((char *)buf, &keylen))) {
                ERR_print_errors(bio_err);
                OPENSSL_cleanse(buf, sizeof(buf));
                goto end;
            }
            OPENSSL_cleanse(buf, sizeof(buf));
            if (keylen != 32) {
                BIO_printf(bio_err, "Invalid private key in hex format\n");
		BIO_printf(bio_err, "Key length is %ld, not 32 byte\n", keylen);
                OPENSSL_cleanse(key, keylen);
                goto end;
            }
            if (!EC_KEY_oct2priv(eckey, key, keylen)) {
                ERR_print_errors(bio_err);
                OPENSSL_cleanse(key, keylen);
                goto end;
            }
            OPENSSL_cleanse(key, keylen);

            if (eckey->group->meth->keygenpub == NULL
                || eckey->group->meth->keygenpub(eckey) == 0) {
                BIO_printf(bio_err, "Generate public key from private key failed\n");
                ERR_print_errors(bio_err);
                goto end;
            }

        } else if (informat == FORMAT_ENGINE) {
            EVP_PKEY *pkey;
            if (pubin)
                pkey = load_pubkey(infile, informat , 1, passin, e, "Public Key");
            else
                pkey = load_key(infile, informat, 1, passin, e, "Private Key");
            if (pkey != NULL) {
                eckey = EVP_PKEY_get1_EC_KEY(pkey);
                EVP_PKEY_free(pkey);
            }
        } else {
            if (pubin)
                eckey = PEM_read_bio_EC_PUBKEY(in, NULL, NULL, NULL);
            else
                eckey = PEM_read_bio_ECPrivateKey(in, NULL, NULL, passin);
        }
        if (eckey == NULL) {
            BIO_printf(bio_err, "unable to load Key\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        if (!EC_KEY_is_sm2p256v1(eckey)) {
            BIO_printf(bio_err, "curve is not sm2p256v1\n");
            goto end;
        }
    }

    out = bio_open_owner(outfile, outformat, private);
    if (out == NULL)
        goto end;

    group = EC_KEY_get0_group(eckey);

    if (new_form)
        EC_KEY_set_conv_form(eckey, form);

    if (new_asn1_flag)
        EC_KEY_set_asn1_flag(eckey, asn1_flag);

    if (no_public)
        EC_KEY_set_enc_flags(eckey, EC_PKEY_NO_PUBKEY);

    if (text) {
        assert(pubin || private);
        if (!EC_KEY_print(out, eckey, 0)) {
            perror(outfile);
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (check) {
        if (EC_KEY_check_key(eckey) == 1) {
                if (EC_KEY_is_sm2p256v1(eckey)) {
                    BIO_printf(bio_err, "SM2 Key valid.\n");
                } else {
                    BIO_printf(bio_err, "Not SM2 Key.\n");
                }
        } else {
            BIO_printf(bio_err, "EC Key Invalid!\n");
            ERR_print_errors(bio_err);
        }
    }

    if (genzid) {
        unsigned char z[64];
        size_t zlen = sizeof(z);
        if (!id) {
            id = SM2_DEFAULT_ID;
            BIO_printf(bio_err, "use default identity '%s'\n", id);
        }
        if (!SM2_compute_id_digest(EVP_sm3(), id, strlen(id), z, &zlen, eckey)) {
            goto end;
        }
        BIO_printf(out, "id: %s\n", id);
        BIO_puts(out, "Z:\n");
	ASN1_buf_print(out, z, zlen, 4);


        BIO_printf(out, "\n");
    }

    if (noout) {
        ret = 0;
        goto end;
    }

    BIO_printf(bio_err, "writing SM2 key\n");
    if (outformat == FORMAT_ASN1) {
        if (param_out)
            i = i2d_ECPKParameters_bio(out, group);
        else if (pubin || pubout)
            i = i2d_EC_PUBKEY_bio(out, eckey);
        else {
            assert(private);
            i = i2d_ECPrivateKey_bio(out, eckey);
        }
    } else {
        if (param_out)
            i = PEM_write_bio_ECPKParameters(out, group);
        else if (pubin || pubout)
            i = PEM_write_bio_EC_PUBKEY(out, eckey);
        else {
            assert(private);
            //FIXME: use PKCS#8				
            i = PEM_write_bio_ECPrivateKey(out, eckey, enc,
                                           NULL, 0, NULL, passout);

        }
    }

    if (!i) {
        BIO_printf(bio_err, "unable to write private key\n");
        ERR_print_errors(bio_err);
    } else
        ret = 0;

 end:
    BIO_free(in);
    BIO_free_all(out);
    EC_KEY_free(eckey);
    release_engine(e);
    OPENSSL_free(passin);
    OPENSSL_free(passout);
    NCONF_free(conf);
    return (ret);
}

#endif
