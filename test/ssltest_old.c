/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECC cipher suite support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

/* Or gethostname won't be declared properly on Linux and GNU platforms. */
#ifndef _BSD_SOURCE
# define _BSD_SOURCE 1
#endif
#ifndef _DEFAULT_SOURCE
# define _DEFAULT_SOURCE 1
#endif

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define USE_SOCKETS
#include "e_os.h"

#ifdef OPENSSL_SYS_VMS
/*
 * Or isascii won't be declared properly on VMS (at least with DECompHP C).
 */
# define _XOPEN_SOURCE 500
#endif

#include <ctype.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
# include <openssl/dsa.h>
#endif
#ifndef OPENSSL_NO_DH
# include <openssl/dh.h>
#endif
#ifndef OPENSSL_NO_SRP
# include <openssl/srp.h>
#endif
#include <openssl/bn.h>
#ifndef OPENSSL_NO_CT
# include <openssl/ct.h>
#endif

/*
 * Or gethostname won't be declared properly
 * on Compaq platforms (at least with DEC C).
 * Do not try to put it earlier, or IPv6 includes
 * get screwed...
 */
#define _XOPEN_SOURCE_EXTENDED  1

#ifdef OPENSSL_SYS_WINDOWS
# include <winsock.h>
#else
# include OPENSSL_UNISTD
#endif

static SSL_CTX *s_ctx = NULL;
static SSL_CTX *s_ctx2 = NULL;

/*
 * There is really no standard for this, so let's assign something
 * only for this test
 */
#define COMP_ZLIB       1

static int verify_callback(int ok, X509_STORE_CTX *ctx);
static int app_verify_callback(X509_STORE_CTX *ctx, void *arg);
#define APP_CALLBACK_STRING "Test Callback Argument"
struct app_verify_arg {
    char *string;
    int app_verify;
};

#ifndef OPENSSL_NO_DH
static DH *get_dh512(void);
static DH *get_dh1024(void);
static DH *get_dh1024dsa(void);
#endif

static char *psk_key = NULL;    /* by default PSK is not used */
#ifndef OPENSSL_NO_PSK
static unsigned int psk_client_callback(SSL *ssl, const char *hint,
                                        char *identity,
                                        unsigned int max_identity_len,
                                        unsigned char *psk,
                                        unsigned int max_psk_len);
static unsigned int psk_server_callback(SSL *ssl, const char *identity,
                                        unsigned char *psk,
                                        unsigned int max_psk_len);
#endif

#ifndef OPENSSL_NO_SRP
/* SRP client */
/* This is a context that we pass to all callbacks */
typedef struct srp_client_arg_st {
    char *srppassin;
    char *srplogin;
} SRP_CLIENT_ARG;

# define PWD_STRLEN 1024

static char *ssl_give_srp_client_pwd_cb(SSL *s, void *arg)
{
    SRP_CLIENT_ARG *srp_client_arg = (SRP_CLIENT_ARG *)arg;
    return OPENSSL_strdup((char *)srp_client_arg->srppassin);
}

/* SRP server */
/* This is a context that we pass to SRP server callbacks */
typedef struct srp_server_arg_st {
    char *expected_user;
    char *pass;
} SRP_SERVER_ARG;

static int ssl_srp_server_param_cb(SSL *s, int *ad, void *arg)
{
    SRP_SERVER_ARG *p = (SRP_SERVER_ARG *)arg;

    if (strcmp(p->expected_user, SSL_get_srp_username(s)) != 0) {
        fprintf(stderr, "User %s doesn't exist\n", SSL_get_srp_username(s));
        return SSL3_AL_FATAL;
    }
    if (SSL_set_srp_server_param_pw(s, p->expected_user, p->pass, "1024") < 0) {
        *ad = SSL_AD_INTERNAL_ERROR;
        return SSL3_AL_FATAL;
    }
    return SSL_ERROR_NONE;
}
#endif

static BIO *bio_err = NULL;
static BIO *bio_stdout = NULL;

#ifndef OPENSSL_NO_NEXTPROTONEG
/* Note that this code assumes that this is only a one element list: */
static const char NEXT_PROTO_STRING[] = "\x09testproto";
static int npn_client = 0;
static int npn_server = 0;
static int npn_server_reject = 0;

static int cb_client_npn(SSL *s, unsigned char **out, unsigned char *outlen,
                         const unsigned char *in, unsigned int inlen,
                         void *arg)
{
    /*
     * This callback only returns the protocol string, rather than a length
     * prefixed set. We assume that NEXT_PROTO_STRING is a one element list
     * and remove the first byte to chop off the length prefix.
     */
    *out = (unsigned char *)NEXT_PROTO_STRING + 1;
    *outlen = sizeof(NEXT_PROTO_STRING) - 2;
    return SSL_TLSEXT_ERR_OK;
}

static int cb_server_npn(SSL *s, const unsigned char **data,
                         unsigned int *len, void *arg)
{
    *data = (const unsigned char *)NEXT_PROTO_STRING;
    *len = sizeof(NEXT_PROTO_STRING) - 1;
    return SSL_TLSEXT_ERR_OK;
}

static int cb_server_rejects_npn(SSL *s, const unsigned char **data,
                                 unsigned int *len, void *arg)
{
    return SSL_TLSEXT_ERR_NOACK;
}

static int verify_npn(SSL *client, SSL *server)
{
    const unsigned char *client_s;
    unsigned client_len;
    const unsigned char *server_s;
    unsigned server_len;

    SSL_get0_next_proto_negotiated(client, &client_s, &client_len);
    SSL_get0_next_proto_negotiated(server, &server_s, &server_len);

    if (client_len) {
        BIO_printf(bio_stdout, "Client NPN: ");
        BIO_write(bio_stdout, client_s, client_len);
        BIO_printf(bio_stdout, "\n");
    }

    if (server_len) {
        BIO_printf(bio_stdout, "Server NPN: ");
        BIO_write(bio_stdout, server_s, server_len);
        BIO_printf(bio_stdout, "\n");
    }

    /*
     * If an NPN string was returned, it must be the protocol that we
     * expected to negotiate.
     */
    if (client_len && (client_len != sizeof(NEXT_PROTO_STRING) - 2 ||
                       memcmp(client_s, NEXT_PROTO_STRING + 1, client_len)))
        return -1;
    if (server_len && (server_len != sizeof(NEXT_PROTO_STRING) - 2 ||
                       memcmp(server_s, NEXT_PROTO_STRING + 1, server_len)))
        return -1;

    if (!npn_client && client_len)
        return -1;
    if (!npn_server && server_len)
        return -1;
    if (npn_server_reject && server_len)
        return -1;
    if (npn_client && npn_server && (!client_len || !server_len))
        return -1;

    return 0;
}
#endif

static const char *alpn_client;
static char *alpn_server;
static char *alpn_server2;
static const char *alpn_expected;
static unsigned char *alpn_selected;
static const char *server_min_proto;
static const char *server_max_proto;
static const char *client_min_proto;
static const char *client_max_proto;
static const char *should_negotiate;
static const char *sn_client;
static const char *sn_server1;
static const char *sn_server2;
static int sn_expect = 0;
static const char *server_sess_out;
static const char *server_sess_in;
static const char *client_sess_out;
static const char *client_sess_in;
static SSL_SESSION *server_sess;
static SSL_SESSION *client_sess;

static int servername_cb(SSL *s, int *ad, void *arg)
{
    const char *servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
    if (sn_server2 == NULL) {
        BIO_printf(bio_stdout, "Servername 2 is NULL\n");
        return SSL_TLSEXT_ERR_NOACK;
    }

    if (servername) {
        if (s_ctx2 != NULL && sn_server2 != NULL &&
            !strcasecmp(servername, sn_server2)) {
            BIO_printf(bio_stdout, "Switching server context.\n");
            SSL_set_SSL_CTX(s, s_ctx2);
        }
    }
    return SSL_TLSEXT_ERR_OK;
}
static int verify_servername(SSL *client, SSL *server)
{
    /* just need to see if sn_context is what we expect */
    SSL_CTX* ctx = SSL_get_SSL_CTX(server);
    if (sn_expect == 0)
        return 0;
    if (sn_expect == 1 && ctx == s_ctx)
        return 0;
    if (sn_expect == 2 && ctx == s_ctx2)
        return 0;
    BIO_printf(bio_stdout, "Servername: expected context %d\n", sn_expect);
    if (ctx == s_ctx2)
        BIO_printf(bio_stdout, "Servername: context is 2\n");
    else if (ctx == s_ctx)
        BIO_printf(bio_stdout, "Servername: context is 1\n");
    else
        BIO_printf(bio_stdout, "Servername: context is unknown\n");
    return -1;
}


/*-
 * next_protos_parse parses a comma separated list of strings into a string
 * in a format suitable for passing to SSL_CTX_set_next_protos_advertised.
 *   outlen: (output) set to the length of the resulting buffer on success.
 *   err: (maybe NULL) on failure, an error message line is written to this BIO.
 *   in: a NUL terminated string like "abc,def,ghi"
 *
 *   returns: a malloced buffer or NULL on failure.
 */
static unsigned char *next_protos_parse(size_t *outlen,
                                        const char *in)
{
    size_t len;
    unsigned char *out;
    size_t i, start = 0;

    len = strlen(in);
    if (len >= 65535)
        return NULL;

    out = OPENSSL_malloc(strlen(in) + 1);
    if (!out)
        return NULL;

    for (i = 0; i <= len; ++i) {
        if (i == len || in[i] == ',') {
            if (i - start > 255) {
                OPENSSL_free(out);
                return NULL;
            }
            out[start] = i - start;
            start = i + 1;
        } else
            out[i + 1] = in[i];
    }

    *outlen = len + 1;
    return out;
}

static int cb_server_alpn(SSL *s, const unsigned char **out,
                          unsigned char *outlen, const unsigned char *in,
                          unsigned int inlen, void *arg)
{
    unsigned char *protos;
    size_t protos_len;
    char* alpn_str = arg;

    protos = next_protos_parse(&protos_len, alpn_str);
    if (protos == NULL) {
        fprintf(stderr, "failed to parser ALPN server protocol string: %s\n",
                alpn_str);
        abort();
    }

    if (SSL_select_next_proto
        ((unsigned char **)out, outlen, protos, protos_len, in,
         inlen) != OPENSSL_NPN_NEGOTIATED) {
        OPENSSL_free(protos);
        return SSL_TLSEXT_ERR_NOACK;
    }

    /*
     * Make a copy of the selected protocol which will be freed in
     * verify_alpn.
     */
    alpn_selected = OPENSSL_malloc(*outlen);
    memcpy(alpn_selected, *out, *outlen);
    *out = alpn_selected;

    OPENSSL_free(protos);
    return SSL_TLSEXT_ERR_OK;
}

static int verify_alpn(SSL *client, SSL *server)
{
    const unsigned char *client_proto, *server_proto;
    unsigned int client_proto_len = 0, server_proto_len = 0;
    SSL_get0_alpn_selected(client, &client_proto, &client_proto_len);
    SSL_get0_alpn_selected(server, &server_proto, &server_proto_len);

    OPENSSL_free(alpn_selected);
    alpn_selected = NULL;

    if (client_proto_len != server_proto_len) {
        BIO_printf(bio_stdout, "ALPN selected protocols differ!\n");
        goto err;
    }

    if (client_proto != NULL &&
        memcmp(client_proto, server_proto, client_proto_len) != 0) {
        BIO_printf(bio_stdout, "ALPN selected protocols differ!\n");
        goto err;
    }

    if (client_proto_len > 0 && alpn_expected == NULL) {
        BIO_printf(bio_stdout, "ALPN unexpectedly negotiated\n");
        goto err;
    }

    if (alpn_expected != NULL &&
        (client_proto_len != strlen(alpn_expected) ||
         memcmp(client_proto, alpn_expected, client_proto_len) != 0)) {
        BIO_printf(bio_stdout,
                   "ALPN selected protocols not equal to expected protocol: %s\n",
                   alpn_expected);
        goto err;
    }

    return 0;

 err:
    BIO_printf(bio_stdout, "ALPN results: client: '");
    BIO_write(bio_stdout, client_proto, client_proto_len);
    BIO_printf(bio_stdout, "', server: '");
    BIO_write(bio_stdout, server_proto, server_proto_len);
    BIO_printf(bio_stdout, "'\n");
    BIO_printf(bio_stdout, "ALPN configured: client: '%s', server: '",
                   alpn_client);
    if (SSL_get_SSL_CTX(server) == s_ctx2) {
        BIO_printf(bio_stdout, "%s'\n",
                   alpn_server2);
    } else {
        BIO_printf(bio_stdout, "%s'\n",
                   alpn_server);
    }
    return -1;
}

/*
 * WARNING : below extension types are *NOT* IETF assigned, and could
 * conflict if these types are reassigned and handled specially by OpenSSL
 * in the future
 */
#define TACK_EXT_TYPE 62208
#define CUSTOM_EXT_TYPE_0 1000
#define CUSTOM_EXT_TYPE_1 1001
#define CUSTOM_EXT_TYPE_2 1002
#define CUSTOM_EXT_TYPE_3 1003

static const char custom_ext_cli_string[] = "abc";
static const char custom_ext_srv_string[] = "defg";

/* These set from cmdline */
static char *serverinfo_file = NULL;
static int serverinfo_sct = 0;
static int serverinfo_tack = 0;

/* These set based on extension callbacks */
static int serverinfo_sct_seen = 0;
static int serverinfo_tack_seen = 0;
static int serverinfo_other_seen = 0;

/* This set from cmdline */
static int custom_ext = 0;

/* This set based on extension callbacks */
static int custom_ext_error = 0;

static int serverinfo_cli_parse_cb(SSL *s, unsigned int ext_type,
                                   const unsigned char *in, size_t inlen,
                                   int *al, void *arg)
{
    if (ext_type == TLSEXT_TYPE_signed_certificate_timestamp)
        serverinfo_sct_seen++;
    else if (ext_type == TACK_EXT_TYPE)
        serverinfo_tack_seen++;
    else
        serverinfo_other_seen++;
    return 1;
}

static int verify_serverinfo()
{
    if (serverinfo_sct != serverinfo_sct_seen)
        return -1;
    if (serverinfo_tack != serverinfo_tack_seen)
        return -1;
    if (serverinfo_other_seen)
        return -1;
    return 0;
}

/*-
 * Four test cases for custom extensions:
 * 0 - no ClientHello extension or ServerHello response
 * 1 - ClientHello with "abc", no response
 * 2 - ClientHello with "abc", empty response
 * 3 - ClientHello with "abc", "defg" response
 */

static int custom_ext_0_cli_add_cb(SSL *s, unsigned int ext_type,
                                   const unsigned char **out,
                                   size_t *outlen, int *al, void *arg)
{
    if (ext_type != CUSTOM_EXT_TYPE_0)
        custom_ext_error = 1;
    return 0;                   /* Don't send an extension */
}

static int custom_ext_0_cli_parse_cb(SSL *s, unsigned int ext_type,
                                     const unsigned char *in,
                                     size_t inlen, int *al, void *arg)
{
    return 1;
}

static int custom_ext_1_cli_add_cb(SSL *s, unsigned int ext_type,
                                   const unsigned char **out,
                                   size_t *outlen, int *al, void *arg)
{
    if (ext_type != CUSTOM_EXT_TYPE_1)
        custom_ext_error = 1;
    *out = (const unsigned char *)custom_ext_cli_string;
    *outlen = strlen(custom_ext_cli_string);
    return 1;                   /* Send "abc" */
}

static int custom_ext_1_cli_parse_cb(SSL *s, unsigned int ext_type,
                                     const unsigned char *in,
                                     size_t inlen, int *al, void *arg)
{
    return 1;
}

static int custom_ext_2_cli_add_cb(SSL *s, unsigned int ext_type,
                                   const unsigned char **out,
                                   size_t *outlen, int *al, void *arg)
{
    if (ext_type != CUSTOM_EXT_TYPE_2)
        custom_ext_error = 1;
    *out = (const unsigned char *)custom_ext_cli_string;
    *outlen = strlen(custom_ext_cli_string);
    return 1;                   /* Send "abc" */
}

static int custom_ext_2_cli_parse_cb(SSL *s, unsigned int ext_type,
                                     const unsigned char *in,
                                     size_t inlen, int *al, void *arg)
{
    if (ext_type != CUSTOM_EXT_TYPE_2)
        custom_ext_error = 1;
    if (inlen != 0)
        custom_ext_error = 1;   /* Should be empty response */
    return 1;
}

static int custom_ext_3_cli_add_cb(SSL *s, unsigned int ext_type,
                                   const unsigned char **out,
                                   size_t *outlen, int *al, void *arg)
{
    if (ext_type != CUSTOM_EXT_TYPE_3)
        custom_ext_error = 1;
    *out = (const unsigned char *)custom_ext_cli_string;
    *outlen = strlen(custom_ext_cli_string);
    return 1;                   /* Send "abc" */
}

static int custom_ext_3_cli_parse_cb(SSL *s, unsigned int ext_type,
                                     const unsigned char *in,
                                     size_t inlen, int *al, void *arg)
{
    if (ext_type != CUSTOM_EXT_TYPE_3)
        custom_ext_error = 1;
    if (inlen != strlen(custom_ext_srv_string))
        custom_ext_error = 1;
    if (memcmp(custom_ext_srv_string, in, inlen) != 0)
        custom_ext_error = 1;   /* Check for "defg" */
    return 1;
}

/*
 * custom_ext_0_cli_add_cb returns 0 - the server won't receive a callback
 * for this extension
 */
static int custom_ext_0_srv_parse_cb(SSL *s, unsigned int ext_type,
                                     const unsigned char *in,
                                     size_t inlen, int *al, void *arg)
{
    custom_ext_error = 1;
    return 1;
}

/* 'add' callbacks are only called if the 'parse' callback is called */
static int custom_ext_0_srv_add_cb(SSL *s, unsigned int ext_type,
                                   const unsigned char **out,
                                   size_t *outlen, int *al, void *arg)
{
    /* Error: should not have been called */
    custom_ext_error = 1;
    return 0;                   /* Don't send an extension */
}

static int custom_ext_1_srv_parse_cb(SSL *s, unsigned int ext_type,
                                     const unsigned char *in,
                                     size_t inlen, int *al, void *arg)
{
    if (ext_type != CUSTOM_EXT_TYPE_1)
        custom_ext_error = 1;
    /* Check for "abc" */
    if (inlen != strlen(custom_ext_cli_string))
        custom_ext_error = 1;
    if (memcmp(in, custom_ext_cli_string, inlen) != 0)
        custom_ext_error = 1;
    return 1;
}

static int custom_ext_1_srv_add_cb(SSL *s, unsigned int ext_type,
                                   const unsigned char **out,
                                   size_t *outlen, int *al, void *arg)
{
    return 0;                   /* Don't send an extension */
}

static int custom_ext_2_srv_parse_cb(SSL *s, unsigned int ext_type,
                                     const unsigned char *in,
                                     size_t inlen, int *al, void *arg)
{
    if (ext_type != CUSTOM_EXT_TYPE_2)
        custom_ext_error = 1;
    /* Check for "abc" */
    if (inlen != strlen(custom_ext_cli_string))
        custom_ext_error = 1;
    if (memcmp(in, custom_ext_cli_string, inlen) != 0)
        custom_ext_error = 1;
    return 1;
}

static int custom_ext_2_srv_add_cb(SSL *s, unsigned int ext_type,
                                   const unsigned char **out,
                                   size_t *outlen, int *al, void *arg)
{
    *out = NULL;
    *outlen = 0;
    return 1;                   /* Send empty extension */
}

static int custom_ext_3_srv_parse_cb(SSL *s, unsigned int ext_type,
                                     const unsigned char *in,
                                     size_t inlen, int *al, void *arg)
{
    if (ext_type != CUSTOM_EXT_TYPE_3)
        custom_ext_error = 1;
    /* Check for "abc" */
    if (inlen != strlen(custom_ext_cli_string))
        custom_ext_error = 1;
    if (memcmp(in, custom_ext_cli_string, inlen) != 0)
        custom_ext_error = 1;
    return 1;
}

static int custom_ext_3_srv_add_cb(SSL *s, unsigned int ext_type,
                                   const unsigned char **out,
                                   size_t *outlen, int *al, void *arg)
{
    *out = (const unsigned char *)custom_ext_srv_string;
    *outlen = strlen(custom_ext_srv_string);
    return 1;                   /* Send "defg" */
}

static char *cipher = NULL;
static int verbose = 0;
static int debug = 0;
static const char rnd_seed[] =
    "string to make the random number generator think it has entropy";

int doit_localhost(SSL *s_ssl, SSL *c_ssl, int family,
                   long bytes, clock_t *s_time, clock_t *c_time);
int doit_biopair(SSL *s_ssl, SSL *c_ssl, long bytes, clock_t *s_time,
                 clock_t *c_time);
int doit(SSL *s_ssl, SSL *c_ssl, long bytes);

static void sv_usage(void)
{
    fprintf(stderr, "usage: ssltest [args ...]\n");
    fprintf(stderr, "\n");
#ifdef OPENSSL_FIPS
    fprintf(stderr, "-F             - run test in FIPS mode\n");
#endif
    fprintf(stderr, " -server_auth  - check server certificate\n");
    fprintf(stderr, " -client_auth  - do client authentication\n");
    fprintf(stderr, " -v            - more output\n");
    fprintf(stderr, " -d            - debug output\n");
    fprintf(stderr, " -reuse        - use session-id reuse\n");
    fprintf(stderr, " -num <val>    - number of connections to perform\n");
    fprintf(stderr,
            " -bytes <val>  - number of bytes to swap between client/server\n");
#ifndef OPENSSL_NO_DH
    fprintf(stderr,
            " -dhe512       - use 512 bit key for DHE (to test failure)\n");
    fprintf(stderr,
            " -dhe1024      - use 1024 bit key (safe prime) for DHE (default, no-op)\n");
    fprintf(stderr,
            " -dhe1024dsa   - use 1024 bit key (with 160-bit subprime) for DHE\n");
    fprintf(stderr, " -no_dhe       - disable DHE\n");
#endif
#ifndef OPENSSL_NO_EC
    fprintf(stderr, " -no_ecdhe     - disable ECDHE\nTODO(openssl-team): no_ecdhe was broken by auto ecdh. Make this work again.\n");
#endif
#ifndef OPENSSL_NO_PSK
    fprintf(stderr, " -psk arg      - PSK in hex (without 0x)\n");
#endif
#ifndef OPENSSL_NO_SRP
    fprintf(stderr, " -srpuser user - SRP username to use\n");
    fprintf(stderr, " -srppass arg  - password for 'user'\n");
#endif
#ifndef OPENSSL_NO_SSL3
    fprintf(stderr, " -ssl3         - use SSLv3\n");
#endif
#ifndef OPENSSL_NO_TLS1
    fprintf(stderr, " -tls1         - use TLSv1\n");
#endif
#ifndef OPENSSL_NO_DTLS
    fprintf(stderr, " -dtls         - use DTLS\n");
#ifndef OPENSSL_NO_DTLS1
    fprintf(stderr, " -dtls1        - use DTLSv1\n");
#endif
#ifndef OPENSSL_NO_DTLS1_2
    fprintf(stderr, " -dtls12       - use DTLSv1.2\n");
#endif
#endif
    fprintf(stderr, " -CApath arg   - PEM format directory of CA's\n");
    fprintf(stderr, " -CAfile arg   - PEM format file of CA's\n");
    fprintf(stderr, " -cert arg     - Server certificate file\n");
    fprintf(stderr,
            " -key arg      - Server key file (default: same as -cert)\n");
    fprintf(stderr, " -c_cert arg   - Client certificate file\n");
    fprintf(stderr,
            " -c_key arg    - Client key file (default: same as -c_cert)\n");
    fprintf(stderr, " -cipher arg   - The cipher list\n");
    fprintf(stderr, " -bio_pair     - Use BIO pairs\n");
    fprintf(stderr, " -ipv4         - Use IPv4 connection on localhost\n");
    fprintf(stderr, " -ipv6         - Use IPv6 connection on localhost\n");
    fprintf(stderr, " -f            - Test even cases that can't work\n");
    fprintf(stderr,
            " -time         - measure processor time used by client and server\n");
    fprintf(stderr, " -zlib         - use zlib compression\n");
#ifndef OPENSSL_NO_NEXTPROTONEG
    fprintf(stderr, " -npn_client - have client side offer NPN\n");
    fprintf(stderr, " -npn_server - have server side offer NPN\n");
    fprintf(stderr, " -npn_server_reject - have server reject NPN\n");
#endif
    fprintf(stderr, " -serverinfo_file file - have server use this file\n");
    fprintf(stderr, " -serverinfo_sct  - have client offer and expect SCT\n");
    fprintf(stderr,
            " -serverinfo_tack - have client offer and expect TACK\n");
    fprintf(stderr,
            " -custom_ext - try various custom extension callbacks\n");
    fprintf(stderr, " -alpn_client <string> - have client side offer ALPN\n");
    fprintf(stderr, " -alpn_server <string> - have server side offer ALPN\n");
    fprintf(stderr, " -alpn_server1 <string> - alias for -alpn_server\n");
    fprintf(stderr, " -alpn_server2 <string> - have server side context 2 offer ALPN\n");
    fprintf(stderr,
            " -alpn_expected <string> - the ALPN protocol that should be negotiated\n");
    fprintf(stderr, " -server_min_proto <string> - Minimum version the server should support\n");
    fprintf(stderr, " -server_max_proto <string> - Maximum version the server should support\n");
    fprintf(stderr, " -client_min_proto <string> - Minimum version the client should support\n");
    fprintf(stderr, " -client_max_proto <string> - Maximum version the client should support\n");
    fprintf(stderr, " -should_negotiate <string> - The version that should be negotiated, fail-client or fail-server\n");
#ifndef OPENSSL_NO_CT
    fprintf(stderr, " -noct         - no certificate transparency\n");
    fprintf(stderr, " -requestct    - request certificate transparency\n");
    fprintf(stderr, " -requirect    - require certificate transparency\n");
#endif
    fprintf(stderr, " -sn_client <string>  - have client request this servername\n");
    fprintf(stderr, " -sn_server1 <string> - have server context 1 respond to this servername\n");
    fprintf(stderr, " -sn_server2 <string> - have server context 2 respond to this servername\n");
    fprintf(stderr, " -sn_expect1          - expected server 1\n");
    fprintf(stderr, " -sn_expect2          - expected server 2\n");
    fprintf(stderr, " -server_sess_out <file>    - Save the server session to a file\n");
    fprintf(stderr, " -server_sess_in <file>     - Read the server session from a file\n");
    fprintf(stderr, " -client_sess_out <file>    - Save the client session to a file\n");
    fprintf(stderr, " -client_sess_in <file>     - Read the client session from a file\n");
    fprintf(stderr, " -should_reuse <number>     - The expected state of reusing the session\n");
    fprintf(stderr, " -no_ticket    - do not issue TLS session ticket\n");
}

static void print_key_details(BIO *out, EVP_PKEY *key)
{
    int keyid = EVP_PKEY_id(key);
#ifndef OPENSSL_NO_EC
    if (keyid == EVP_PKEY_EC) {
        EC_KEY *ec = EVP_PKEY_get1_EC_KEY(key);
        int nid;
        const char *cname;
        nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec));
        EC_KEY_free(ec);
        cname = EC_curve_nid2nist(nid);
        if (!cname)
            cname = OBJ_nid2sn(nid);
        BIO_printf(out, "%d bits EC (%s)", EVP_PKEY_bits(key), cname);
    } else
#endif
    {
        const char *algname;
        switch (keyid) {
        case EVP_PKEY_RSA:
            algname = "RSA";
            break;
        case EVP_PKEY_DSA:
            algname = "DSA";
            break;
        case EVP_PKEY_DH:
            algname = "DH";
            break;
        default:
            algname = OBJ_nid2sn(keyid);
            break;
        }
        BIO_printf(out, "%d bits %s", EVP_PKEY_bits(key), algname);
    }
}

static void print_details(SSL *c_ssl, const char *prefix)
{
    const SSL_CIPHER *ciph;
    int mdnid;
    X509 *cert;
    EVP_PKEY *pkey;

    ciph = SSL_get_current_cipher(c_ssl);
    BIO_printf(bio_stdout, "%s%s, cipher %s %s",
               prefix,
               SSL_get_version(c_ssl),
               SSL_CIPHER_get_version(ciph), SSL_CIPHER_get_name(ciph));
    cert = SSL_get_peer_certificate(c_ssl);
    if (cert != NULL) {
        EVP_PKEY* pubkey = X509_get0_pubkey(cert);

        if (pubkey != NULL) {
            BIO_puts(bio_stdout, ", ");
            print_key_details(bio_stdout, pubkey);
        }
        X509_free(cert);
    }
    if (SSL_get_server_tmp_key(c_ssl, &pkey)) {
        BIO_puts(bio_stdout, ", temp key: ");
        print_key_details(bio_stdout, pkey);
        EVP_PKEY_free(pkey);
    }
    if (SSL_get_peer_signature_nid(c_ssl, &mdnid))
        BIO_printf(bio_stdout, ", digest=%s", OBJ_nid2sn(mdnid));
    BIO_printf(bio_stdout, "\n");
}

/*
 * protocol_from_string - converts a protocol version string to a number
 *
 * Returns -1 on failure or the version on success
 */
static int protocol_from_string(const char *value)
{
    struct protocol_versions {
        const char *name;
        int version;
    };
    static const struct protocol_versions versions[] = {
        {"ssl3", SSL3_VERSION},
        {"tls1", TLS1_VERSION},
        {"tls1.1", TLS1_1_VERSION},
        {"tls1.2", TLS1_2_VERSION},
        {"dtls1", DTLS1_VERSION},
        {"dtls1.2", DTLS1_2_VERSION}};
    size_t i;
    size_t n = OSSL_NELEM(versions);

    for (i = 0; i < n; i++)
        if (strcmp(versions[i].name, value) == 0)
            return versions[i].version;
    return -1;
}

static SSL_SESSION *read_session(const char *filename)
{
    SSL_SESSION *sess;
    BIO *f = BIO_new_file(filename, "r");

    if (f == NULL) {
        BIO_printf(bio_err, "Can't open session file %s\n", filename);
        ERR_print_errors(bio_err);
        return NULL;
    }
    sess = PEM_read_bio_SSL_SESSION(f, NULL, 0, NULL);
    if (sess == NULL) {
        BIO_printf(bio_err, "Can't parse session file %s\n", filename);
        ERR_print_errors(bio_err);
    }
    BIO_free(f);
    return sess;
}

static int write_session(const char *filename, SSL_SESSION *sess)
{
    BIO *f = BIO_new_file(filename, "w");

    if (sess == NULL) {
        BIO_printf(bio_err, "No session information\n");
        return 0;
    }
    if (f == NULL) {
        BIO_printf(bio_err, "Can't open session file %s\n", filename);
        ERR_print_errors(bio_err);
        return 0;
    }
    PEM_write_bio_SSL_SESSION(f, sess);
    BIO_free(f);
    return 1;
}

/*
 * set_protocol_version - Sets protocol version minimum or maximum
 *
 * Returns 0 on failure and 1 on success
 */
static int set_protocol_version(const char *version, SSL *ssl, int setting)
{
    if (version != NULL) {
        int ver = protocol_from_string(version);
        if (ver < 0) {
            BIO_printf(bio_err, "Error parsing: %s\n", version);
            return 0;
        }
        return SSL_ctrl(ssl, setting, ver, NULL);
    }
    return 1;
}

int main(int argc, char *argv[])
{
    const char *CApath = NULL, *CAfile = NULL;
    int badop = 0;
    enum { BIO_MEM, BIO_PAIR, BIO_IPV4, BIO_IPV6 } bio_type = BIO_MEM;
    int force = 0;
    int dtls1 = 0, dtls12 = 0, dtls = 0, tls1 = 0, ssl3 = 0, ret = 1;
    int client_auth = 0;
    int server_auth = 0, i;
    struct app_verify_arg app_verify_arg =
        { APP_CALLBACK_STRING, 0 };
    char *p;
    SSL_CTX *c_ctx = NULL;
    const SSL_METHOD *meth = NULL;
    SSL *c_ssl, *s_ssl;
    int number = 1, reuse = 0;
    int should_reuse = -1;
    int no_ticket = 0;
    long bytes = 256L;
#ifndef OPENSSL_NO_DH
    DH *dh;
    int dhe512 = 0, dhe1024dsa = 0;
#endif
#ifndef OPENSSL_NO_SRP
    /* client */
    SRP_CLIENT_ARG srp_client_arg = { NULL, NULL };
    /* server */
    SRP_SERVER_ARG srp_server_arg = { NULL, NULL };
#endif
    int no_dhe = 0;
    int no_psk = 0;
    int print_time = 0;
    clock_t s_time = 0, c_time = 0;
#ifndef OPENSSL_NO_COMP
    int n, comp = 0;
    COMP_METHOD *cm = NULL;
    STACK_OF(SSL_COMP) *ssl_comp_methods = NULL;
#endif
#ifdef OPENSSL_FIPS
    int fips_mode = 0;
#endif
    int no_protocol;
    int min_version = 0, max_version = 0;
#ifndef OPENSSL_NO_CT
    /*
     * Disable CT validation by default, because it will interfere with
     * anything using custom extension handlers to deal with SCT extensions.
     */
    int ct_validation = 0;
#endif
    SSL_CONF_CTX *s_cctx = NULL, *c_cctx = NULL, *s_cctx2 = NULL;
    STACK_OF(OPENSSL_STRING) *conf_args = NULL;
    char *arg = NULL, *argn = NULL;

    verbose = 0;
    debug = 0;
    cipher = 0;

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    p = getenv("OPENSSL_DEBUG_MEMORY");
    if (p != NULL && strcmp(p, "on") == 0)
        CRYPTO_set_mem_debug(1);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    RAND_seed(rnd_seed, sizeof rnd_seed);

    bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);

    s_cctx = SSL_CONF_CTX_new();
    s_cctx2 = SSL_CONF_CTX_new();
    c_cctx = SSL_CONF_CTX_new();

    if (!s_cctx || !c_cctx || !s_cctx2) {
        ERR_print_errors(bio_err);
        goto end;
    }

    SSL_CONF_CTX_set_flags(s_cctx,
                           SSL_CONF_FLAG_CMDLINE | SSL_CONF_FLAG_SERVER |
                           SSL_CONF_FLAG_CERTIFICATE |
                           SSL_CONF_FLAG_REQUIRE_PRIVATE);
    SSL_CONF_CTX_set_flags(s_cctx2,
                           SSL_CONF_FLAG_CMDLINE | SSL_CONF_FLAG_SERVER |
                           SSL_CONF_FLAG_CERTIFICATE |
                           SSL_CONF_FLAG_REQUIRE_PRIVATE);
    if (!SSL_CONF_CTX_set1_prefix(s_cctx, "-s_")) {
        ERR_print_errors(bio_err);
        goto end;
    }
    if (!SSL_CONF_CTX_set1_prefix(s_cctx2, "-s_")) {
        ERR_print_errors(bio_err);
        goto end;
    }

    SSL_CONF_CTX_set_flags(c_cctx,
                           SSL_CONF_FLAG_CMDLINE | SSL_CONF_FLAG_CLIENT |
                           SSL_CONF_FLAG_CERTIFICATE |
                           SSL_CONF_FLAG_REQUIRE_PRIVATE);
    if (!SSL_CONF_CTX_set1_prefix(c_cctx, "-c_")) {
        ERR_print_errors(bio_err);
        goto end;
    }

    argc--;
    argv++;

    while (argc >= 1) {
        if (strcmp(*argv, "-F") == 0) {
#ifdef OPENSSL_FIPS
            fips_mode = 1;
#else
            fprintf(stderr,
                    "not compiled with FIPS support, so exiting without running.\n");
            EXIT(0);
#endif
        } else if (strcmp(*argv, "-server_auth") == 0)
            server_auth = 1;
        else if (strcmp(*argv, "-client_auth") == 0)
            client_auth = 1;
        else if (strcmp(*argv, "-v") == 0)
            verbose = 1;
        else if (strcmp(*argv, "-d") == 0)
            debug = 1;
        else if (strcmp(*argv, "-reuse") == 0)
            reuse = 1;
        else if (strcmp(*argv, "-dhe512") == 0) {
#ifndef OPENSSL_NO_DH
            dhe512 = 1;
#else
            fprintf(stderr,
                    "ignoring -dhe512, since I'm compiled without DH\n");
#endif
        } else if (strcmp(*argv, "-dhe1024dsa") == 0) {
#ifndef OPENSSL_NO_DH
            dhe1024dsa = 1;
#else
            fprintf(stderr,
                    "ignoring -dhe1024dsa, since I'm compiled without DH\n");
#endif
        } else if (strcmp(*argv, "-no_dhe") == 0)
            no_dhe = 1;
        else if (strcmp(*argv, "-no_ecdhe") == 0)
            /* obsolete */;
        else if (strcmp(*argv, "-psk") == 0) {
            if (--argc < 1)
                goto bad;
            psk_key = *(++argv);
#ifndef OPENSSL_NO_PSK
            if (strspn(psk_key, "abcdefABCDEF1234567890") != strlen(psk_key)) {
                BIO_printf(bio_err, "Not a hex number '%s'\n", *argv);
                goto bad;
            }
#else
            no_psk = 1;
#endif
        }
#ifndef OPENSSL_NO_SRP
        else if (strcmp(*argv, "-srpuser") == 0) {
            if (--argc < 1)
                goto bad;
            srp_server_arg.expected_user = srp_client_arg.srplogin =
                *(++argv);
            min_version = TLS1_VERSION;
        } else if (strcmp(*argv, "-srppass") == 0) {
            if (--argc < 1)
                goto bad;
            srp_server_arg.pass = srp_client_arg.srppassin = *(++argv);
            min_version = TLS1_VERSION;
        }
#endif
        else if (strcmp(*argv, "-tls1") == 0) {
            tls1 = 1;
        } else if (strcmp(*argv, "-ssl3") == 0) {
            ssl3 = 1;
        } else if (strcmp(*argv, "-dtls1") == 0) {
            dtls1 = 1;
        } else if (strcmp(*argv, "-dtls12") == 0) {
            dtls12 = 1;
        } else if (strcmp(*argv, "-dtls") == 0) {
            dtls = 1;
        } else if (strncmp(*argv, "-num", 4) == 0) {
            if (--argc < 1)
                goto bad;
            number = atoi(*(++argv));
            if (number == 0)
                number = 1;
        } else if (strcmp(*argv, "-bytes") == 0) {
            if (--argc < 1)
                goto bad;
            bytes = atol(*(++argv));
            if (bytes == 0L)
                bytes = 1L;
            i = strlen(argv[0]);
            if (argv[0][i - 1] == 'k')
                bytes *= 1024L;
            if (argv[0][i - 1] == 'm')
                bytes *= 1024L * 1024L;
        } else if (strcmp(*argv, "-cipher") == 0) {
            if (--argc < 1)
                goto bad;
            cipher = *(++argv);
        } else if (strcmp(*argv, "-CApath") == 0) {
            if (--argc < 1)
                goto bad;
            CApath = *(++argv);
        } else if (strcmp(*argv, "-CAfile") == 0) {
            if (--argc < 1)
                goto bad;
            CAfile = *(++argv);
        } else if (strcmp(*argv, "-bio_pair") == 0) {
            bio_type = BIO_PAIR;
        }
#ifndef OPENSSL_NO_SOCK
        else if (strcmp(*argv, "-ipv4") == 0) {
            bio_type = BIO_IPV4;
        } else if (strcmp(*argv, "-ipv6") == 0) {
            bio_type = BIO_IPV6;
        }
#endif
        else if (strcmp(*argv, "-f") == 0) {
            force = 1;
        } else if (strcmp(*argv, "-time") == 0) {
            print_time = 1;
        }
#ifndef OPENSSL_NO_CT
        else if (strcmp(*argv, "-noct") == 0) {
            ct_validation = 0;
        }
        else if (strcmp(*argv, "-ct") == 0) {
            ct_validation = 1;
        }
#endif
#ifndef OPENSSL_NO_COMP
        else if (strcmp(*argv, "-zlib") == 0) {
            comp = COMP_ZLIB;
        }
#endif
        else if (strcmp(*argv, "-app_verify") == 0) {
            app_verify_arg.app_verify = 1;
        }
#ifndef OPENSSL_NO_NEXTPROTONEG
          else if (strcmp(*argv, "-npn_client") == 0) {
            npn_client = 1;
        } else if (strcmp(*argv, "-npn_server") == 0) {
            npn_server = 1;
        } else if (strcmp(*argv, "-npn_server_reject") == 0) {
            npn_server_reject = 1;
        }
#endif
        else if (strcmp(*argv, "-serverinfo_sct") == 0) {
            serverinfo_sct = 1;
        } else if (strcmp(*argv, "-serverinfo_tack") == 0) {
            serverinfo_tack = 1;
        } else if (strcmp(*argv, "-serverinfo_file") == 0) {
            if (--argc < 1)
                goto bad;
            serverinfo_file = *(++argv);
        } else if (strcmp(*argv, "-custom_ext") == 0) {
            custom_ext = 1;
        } else if (strcmp(*argv, "-alpn_client") == 0) {
            if (--argc < 1)
                goto bad;
            alpn_client = *(++argv);
        } else if (strcmp(*argv, "-alpn_server") == 0 ||
                   strcmp(*argv, "-alpn_server1") == 0) {
            if (--argc < 1)
                goto bad;
            alpn_server = *(++argv);
        } else if (strcmp(*argv, "-alpn_server2") == 0) {
            if (--argc < 1)
                goto bad;
            alpn_server2 = *(++argv);
        } else if (strcmp(*argv, "-alpn_expected") == 0) {
            if (--argc < 1)
                goto bad;
            alpn_expected = *(++argv);
        } else if (strcmp(*argv, "-server_min_proto") == 0) {
            if (--argc < 1)
                goto bad;
            server_min_proto = *(++argv);
        } else if (strcmp(*argv, "-server_max_proto") == 0) {
            if (--argc < 1)
                goto bad;
            server_max_proto = *(++argv);
        } else if (strcmp(*argv, "-client_min_proto") == 0) {
            if (--argc < 1)
                goto bad;
            client_min_proto = *(++argv);
        } else if (strcmp(*argv, "-client_max_proto") == 0) {
            if (--argc < 1)
                goto bad;
            client_max_proto = *(++argv);
        } else if (strcmp(*argv, "-should_negotiate") == 0) {
            if (--argc < 1)
                goto bad;
            should_negotiate = *(++argv);
        } else if (strcmp(*argv, "-sn_client") == 0) {
            if (--argc < 1)
                goto bad;
            sn_client = *(++argv);
        } else if (strcmp(*argv, "-sn_server1") == 0) {
            if (--argc < 1)
                goto bad;
            sn_server1 = *(++argv);
        } else if (strcmp(*argv, "-sn_server2") == 0) {
            if (--argc < 1)
                goto bad;
            sn_server2 = *(++argv);
        } else if (strcmp(*argv, "-sn_expect1") == 0) {
            sn_expect = 1;
        } else if (strcmp(*argv, "-sn_expect2") == 0) {
            sn_expect = 2;
        } else if (strcmp(*argv, "-server_sess_out") == 0) {
            if (--argc < 1)
                goto bad;
            server_sess_out = *(++argv);
        } else if (strcmp(*argv, "-server_sess_in") == 0) {
            if (--argc < 1)
                goto bad;
            server_sess_in = *(++argv);
        } else if (strcmp(*argv, "-client_sess_out") == 0) {
            if (--argc < 1)
                goto bad;
            client_sess_out = *(++argv);
        } else if (strcmp(*argv, "-client_sess_in") == 0) {
            if (--argc < 1)
                goto bad;
            client_sess_in = *(++argv);
        } else if (strcmp(*argv, "-should_reuse") == 0) {
            if (--argc < 1)
                goto bad;
            should_reuse = !!atoi(*(++argv));
        } else if (strcmp(*argv, "-no_ticket") == 0) {
            no_ticket = 1;
        } else {
            int rv;
            arg = argv[0];
            argn = argv[1];
            /* Try to process command using SSL_CONF */
            rv = SSL_CONF_cmd_argv(c_cctx, &argc, &argv);
            /* If not processed try server */
            if (rv == 0)
                rv = SSL_CONF_cmd_argv(s_cctx, &argc, &argv);
            /* Recognised: store it for later use */
            if (rv > 0) {
                if (rv == 1)
                    argn = NULL;
                if (!conf_args) {
                    conf_args = sk_OPENSSL_STRING_new_null();
                    if (!conf_args)
                        goto end;
                }
                if (!sk_OPENSSL_STRING_push(conf_args, arg))
                    goto end;
                if (!sk_OPENSSL_STRING_push(conf_args, argn))
                    goto end;
                continue;
            }
            if (rv == -3)
                BIO_printf(bio_err, "Missing argument for %s\n", arg);
            else if (rv < 0)
                BIO_printf(bio_err, "Error with command %s\n", arg);
            else if (rv == 0)
                BIO_printf(bio_err, "unknown option %s\n", arg);
            badop = 1;
            break;
        }
        argc--;
        argv++;
    }
    if (badop) {
 bad:
        sv_usage();
        goto end;
    }

    if (ssl3 + tls1 + dtls + dtls1 + dtls12 > 1) {
        fprintf(stderr, "At most one of -ssl3, -tls1, -dtls, -dtls1 or -dtls12 should "
                "be requested.\n");
        EXIT(1);
    }

#ifdef OPENSSL_NO_SSL3
    if (ssl3)
        no_protocol = 1;
    else
#endif
#ifdef OPENSSL_NO_TLS1
    if (tls1)
        no_protocol = 1;
    else
#endif
#if defined(OPENSSL_NO_DTLS) || defined(OPENSSL_NO_DTLS1)
    if (dtls1)
        no_protocol = 1;
    else
#endif
#if defined(OPENSSL_NO_DTLS) || defined(OPENSSL_NO_DTLS1_2)
    if (dtls12)
        no_protocol = 1;
    else
#endif
        no_protocol = 0;

    /*
     * Testing was requested for a compiled-out protocol (e.g. SSLv3).
     * Ideally, we would error out, but the generic test wrapper can't know
     * when to expect failure. So we do nothing and return success.
     */
    if (no_protocol) {
        fprintf(stderr, "Testing was requested for a disabled protocol. "
                "Skipping tests.\n");
        ret = 0;
        goto end;
    }

    if (!ssl3 && !tls1 && !dtls && !dtls1 && !dtls12 && number > 1 && !reuse && !force) {
        fprintf(stderr, "This case cannot work.  Use -f to perform "
                "the test anyway (and\n-d to see what happens), "
                "or add one of -ssl3, -tls1, -dtls, -dtls1, -dtls12, -reuse\n"
                "to avoid protocol mismatch.\n");
        EXIT(1);
    }
#ifdef OPENSSL_FIPS
    if (fips_mode) {
        if (!FIPS_mode_set(1)) {
            ERR_print_errors(bio_err);
            EXIT(1);
        } else
            fprintf(stderr, "*** IN FIPS MODE ***\n");
    }
#endif

    if (print_time) {
        if (bio_type != BIO_PAIR) {
            fprintf(stderr, "Using BIO pair (-bio_pair)\n");
            bio_type = BIO_PAIR;
        }
        if (number < 50 && !force)
            fprintf(stderr,
                    "Warning: For accurate timings, use more connections (e.g. -num 1000)\n");
    }

/*      if (cipher == NULL) cipher=getenv("SSL_CIPHER"); */

#ifndef OPENSSL_NO_COMP
    if (comp == COMP_ZLIB)
        cm = COMP_zlib();
    if (cm != NULL) {
        if (COMP_get_type(cm) != NID_undef) {
            if (SSL_COMP_add_compression_method(comp, cm) != 0) {
                fprintf(stderr, "Failed to add compression method\n");
                ERR_print_errors_fp(stderr);
            }
        } else {
            fprintf(stderr,
                    "Warning: %s compression not supported\n",
                    comp == COMP_ZLIB ? "zlib" : "unknown");
            ERR_print_errors_fp(stderr);
        }
    }
    ssl_comp_methods = SSL_COMP_get_compression_methods();
    n = sk_SSL_COMP_num(ssl_comp_methods);
    if (n) {
        int j;
        printf("Available compression methods:");
        for (j = 0; j < n; j++) {
            SSL_COMP *c = sk_SSL_COMP_value(ssl_comp_methods, j);
            printf("  %s:%d", SSL_COMP_get0_name(c), SSL_COMP_get_id(c));
        }
        printf("\n");
    }
#endif

#ifndef OPENSSL_NO_TLS
    meth = TLS_method();
    if (ssl3) {
        min_version = SSL3_VERSION;
        max_version = SSL3_VERSION;
    } else if (tls1) {
        min_version = TLS1_VERSION;
        max_version = TLS1_VERSION;
    }
#endif
#ifndef OPENSSL_NO_DTLS
    if (dtls || dtls1 || dtls12)
        meth = DTLS_method();
    if (dtls1) {
        min_version = DTLS1_VERSION;
        max_version = DTLS1_VERSION;
    } else if (dtls12) {
        min_version = DTLS1_2_VERSION;
        max_version = DTLS1_2_VERSION;
    }
#endif

    c_ctx = SSL_CTX_new(meth);
    s_ctx = SSL_CTX_new(meth);
    s_ctx2 = SSL_CTX_new(meth); /* no SSL_CTX_dup! */
    if ((c_ctx == NULL) || (s_ctx == NULL) || (s_ctx2 == NULL)) {
        ERR_print_errors(bio_err);
        goto end;
    }
    /*
     * Since we will use low security ciphersuites and keys for testing set
     * security level to zero by default. Tests can override this by adding
     * "@SECLEVEL=n" to the cipher string.
     */
    SSL_CTX_set_security_level(c_ctx, 0);
    SSL_CTX_set_security_level(s_ctx, 0);
    SSL_CTX_set_security_level(s_ctx2, 0);

    if (no_ticket) {
        SSL_CTX_set_options(c_ctx, SSL_OP_NO_TICKET);
        SSL_CTX_set_options(s_ctx, SSL_OP_NO_TICKET);
    }

    if (SSL_CTX_set_min_proto_version(c_ctx, min_version) == 0)
        goto end;
    if (SSL_CTX_set_max_proto_version(c_ctx, max_version) == 0)
        goto end;
    if (SSL_CTX_set_min_proto_version(s_ctx, min_version) == 0)
        goto end;
    if (SSL_CTX_set_max_proto_version(s_ctx, max_version) == 0)
        goto end;

    if (cipher != NULL) {
        if (!SSL_CTX_set_cipher_list(c_ctx, cipher)
            || !SSL_CTX_set_cipher_list(s_ctx, cipher)
            || !SSL_CTX_set_cipher_list(s_ctx2, cipher)) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

#ifndef OPENSSL_NO_CT
    if (ct_validation &&
        !SSL_CTX_enable_ct(c_ctx, SSL_CT_VALIDATION_STRICT)) {
        ERR_print_errors(bio_err);
        goto end;
    }
#endif

    /* Process SSL_CONF arguments */
    SSL_CONF_CTX_set_ssl_ctx(c_cctx, c_ctx);
    SSL_CONF_CTX_set_ssl_ctx(s_cctx, s_ctx);
    SSL_CONF_CTX_set_ssl_ctx(s_cctx2, s_ctx2);

    for (i = 0; i < sk_OPENSSL_STRING_num(conf_args); i += 2) {
        int rv;
        arg = sk_OPENSSL_STRING_value(conf_args, i);
        argn = sk_OPENSSL_STRING_value(conf_args, i + 1);
        rv = SSL_CONF_cmd(c_cctx, arg, argn);
        /* If not recognised use server context */
        if (rv == -2) {
            rv = SSL_CONF_cmd(s_cctx2, arg, argn);
            if (rv > 0)
                rv = SSL_CONF_cmd(s_cctx, arg, argn);
        }
        if (rv <= 0) {
            BIO_printf(bio_err, "Error processing %s %s\n",
                       arg, argn ? argn : "");
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (!SSL_CONF_CTX_finish(s_cctx) || !SSL_CONF_CTX_finish(c_cctx) || !SSL_CONF_CTX_finish(s_cctx2)) {
        BIO_puts(bio_err, "Error finishing context\n");
        ERR_print_errors(bio_err);
        goto end;
    }
#ifndef OPENSSL_NO_DH
    if (!no_dhe) {
        if (dhe1024dsa) {
            dh = get_dh1024dsa();
        } else if (dhe512)
            dh = get_dh512();
        else
            dh = get_dh1024();
        SSL_CTX_set_tmp_dh(s_ctx, dh);
        SSL_CTX_set_tmp_dh(s_ctx2, dh);
        DH_free(dh);
    }
#else
    (void)no_dhe;
#endif

    if ((!SSL_CTX_load_verify_locations(s_ctx, CAfile, CApath)) ||
        (!SSL_CTX_set_default_verify_paths(s_ctx)) ||
        (!SSL_CTX_load_verify_locations(s_ctx2, CAfile, CApath)) ||
        (!SSL_CTX_set_default_verify_paths(s_ctx2)) ||
        (!SSL_CTX_load_verify_locations(c_ctx, CAfile, CApath)) ||
        (!SSL_CTX_set_default_verify_paths(c_ctx))) {
        /* fprintf(stderr,"SSL_load_verify_locations\n"); */
        ERR_print_errors(bio_err);
        /* goto end; */
    }

#ifndef OPENSSL_NO_CT
    if (!SSL_CTX_set_default_ctlog_list_file(s_ctx) ||
        !SSL_CTX_set_default_ctlog_list_file(s_ctx2) ||
        !SSL_CTX_set_default_ctlog_list_file(c_ctx)) {
        ERR_print_errors(bio_err);
    }
#endif

    if (client_auth) {
        printf("client authentication\n");
        SSL_CTX_set_verify(s_ctx,
                           SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                           verify_callback);
        SSL_CTX_set_verify(s_ctx2,
                           SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                           verify_callback);
        SSL_CTX_set_cert_verify_callback(s_ctx, app_verify_callback,
                                         &app_verify_arg);
        SSL_CTX_set_cert_verify_callback(s_ctx2, app_verify_callback,
                                         &app_verify_arg);
    }
    if (server_auth) {
        printf("server authentication\n");
        SSL_CTX_set_verify(c_ctx, SSL_VERIFY_PEER, verify_callback);
        SSL_CTX_set_cert_verify_callback(c_ctx, app_verify_callback,
                                         &app_verify_arg);
    }

    {
        int session_id_context = 0;
        if (!SSL_CTX_set_session_id_context(s_ctx, (void *)&session_id_context,
                                            sizeof session_id_context) ||
            !SSL_CTX_set_session_id_context(s_ctx2, (void *)&session_id_context,
                                            sizeof session_id_context)) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    /* Use PSK only if PSK key is given */
    if (psk_key != NULL) {
        /*
         * no_psk is used to avoid putting psk command to openssl tool
         */
        if (no_psk) {
            /*
             * if PSK is not compiled in and psk key is given, do nothing and
             * exit successfully
             */
            ret = 0;
            goto end;
        }
#ifndef OPENSSL_NO_PSK
        SSL_CTX_set_psk_client_callback(c_ctx, psk_client_callback);
        SSL_CTX_set_psk_server_callback(s_ctx, psk_server_callback);
        SSL_CTX_set_psk_server_callback(s_ctx2, psk_server_callback);
        if (debug)
            BIO_printf(bio_err, "setting PSK identity hint to s_ctx\n");
        if (!SSL_CTX_use_psk_identity_hint(s_ctx, "ctx server identity_hint") ||
            !SSL_CTX_use_psk_identity_hint(s_ctx2, "ctx server identity_hint")) {
            BIO_printf(bio_err, "error setting PSK identity hint to s_ctx\n");
            ERR_print_errors(bio_err);
            goto end;
        }
#endif
    }
#ifndef OPENSSL_NO_SRP
    if (srp_client_arg.srplogin) {
        if (!SSL_CTX_set_srp_username(c_ctx, srp_client_arg.srplogin)) {
            BIO_printf(bio_err, "Unable to set SRP username\n");
            goto end;
        }
        SSL_CTX_set_srp_cb_arg(c_ctx, &srp_client_arg);
        SSL_CTX_set_srp_client_pwd_callback(c_ctx,
                                            ssl_give_srp_client_pwd_cb);
        /*
         * SSL_CTX_set_srp_strength(c_ctx, srp_client_arg.strength);
         */
    }

    if (srp_server_arg.expected_user != NULL) {
        SSL_CTX_set_verify(s_ctx, SSL_VERIFY_NONE, verify_callback);
        SSL_CTX_set_verify(s_ctx2, SSL_VERIFY_NONE, verify_callback);
        SSL_CTX_set_srp_cb_arg(s_ctx, &srp_server_arg);
        SSL_CTX_set_srp_cb_arg(s_ctx2, &srp_server_arg);
        SSL_CTX_set_srp_username_callback(s_ctx, ssl_srp_server_param_cb);
        SSL_CTX_set_srp_username_callback(s_ctx2, ssl_srp_server_param_cb);
    }
#endif

#ifndef OPENSSL_NO_NEXTPROTONEG
    if (npn_client) {
        SSL_CTX_set_next_proto_select_cb(c_ctx, cb_client_npn, NULL);
    }
    if (npn_server) {
        if (npn_server_reject) {
            BIO_printf(bio_err,
                       "Can't have both -npn_server and -npn_server_reject\n");
            goto end;
        }
        SSL_CTX_set_next_protos_advertised_cb(s_ctx, cb_server_npn, NULL);
        SSL_CTX_set_next_protos_advertised_cb(s_ctx2, cb_server_npn, NULL);
    }
    if (npn_server_reject) {
        SSL_CTX_set_next_protos_advertised_cb(s_ctx, cb_server_rejects_npn,
                                              NULL);
        SSL_CTX_set_next_protos_advertised_cb(s_ctx2, cb_server_rejects_npn,
                                              NULL);
    }
#endif

    if (serverinfo_sct) {
        if (!SSL_CTX_add_client_custom_ext(c_ctx,
                TLSEXT_TYPE_signed_certificate_timestamp,
                NULL, NULL, NULL,
                serverinfo_cli_parse_cb, NULL)) {
            BIO_printf(bio_err, "Error adding SCT extension\n");
            goto end;
        }
    }
    if (serverinfo_tack) {
        if (!SSL_CTX_add_client_custom_ext(c_ctx, TACK_EXT_TYPE,
                                      NULL, NULL, NULL,
                                      serverinfo_cli_parse_cb, NULL)) {
            BIO_printf(bio_err, "Error adding TACK extension\n");
            goto end;
        }
    }
    if (serverinfo_file)
        if (!SSL_CTX_use_serverinfo_file(s_ctx, serverinfo_file) ||
            !SSL_CTX_use_serverinfo_file(s_ctx2, serverinfo_file)) {
            BIO_printf(bio_err, "missing serverinfo file\n");
            goto end;
        }

    if (custom_ext) {
        if (!SSL_CTX_add_client_custom_ext(c_ctx, CUSTOM_EXT_TYPE_0,
                                      custom_ext_0_cli_add_cb,
                                      NULL, NULL,
                                      custom_ext_0_cli_parse_cb, NULL)
            || !SSL_CTX_add_client_custom_ext(c_ctx, CUSTOM_EXT_TYPE_1,
                                      custom_ext_1_cli_add_cb,
                                      NULL, NULL,
                                      custom_ext_1_cli_parse_cb, NULL)
            || !SSL_CTX_add_client_custom_ext(c_ctx, CUSTOM_EXT_TYPE_2,
                                      custom_ext_2_cli_add_cb,
                                      NULL, NULL,
                                      custom_ext_2_cli_parse_cb, NULL)
            || !SSL_CTX_add_client_custom_ext(c_ctx, CUSTOM_EXT_TYPE_3,
                                      custom_ext_3_cli_add_cb,
                                      NULL, NULL,
                                      custom_ext_3_cli_parse_cb, NULL)
            || !SSL_CTX_add_server_custom_ext(s_ctx, CUSTOM_EXT_TYPE_0,
                                      custom_ext_0_srv_add_cb,
                                      NULL, NULL,
                                      custom_ext_0_srv_parse_cb, NULL)
            || !SSL_CTX_add_server_custom_ext(s_ctx2, CUSTOM_EXT_TYPE_0,
                                      custom_ext_0_srv_add_cb,
                                      NULL, NULL,
                                      custom_ext_0_srv_parse_cb, NULL)
            || !SSL_CTX_add_server_custom_ext(s_ctx, CUSTOM_EXT_TYPE_1,
                                      custom_ext_1_srv_add_cb,
                                      NULL, NULL,
                                      custom_ext_1_srv_parse_cb, NULL)
            || !SSL_CTX_add_server_custom_ext(s_ctx2, CUSTOM_EXT_TYPE_1,
                                      custom_ext_1_srv_add_cb,
                                      NULL, NULL,
                                      custom_ext_1_srv_parse_cb, NULL)
            || !SSL_CTX_add_server_custom_ext(s_ctx, CUSTOM_EXT_TYPE_2,
                                      custom_ext_2_srv_add_cb,
                                      NULL, NULL,
                                      custom_ext_2_srv_parse_cb, NULL)
            || !SSL_CTX_add_server_custom_ext(s_ctx2, CUSTOM_EXT_TYPE_2,
                                      custom_ext_2_srv_add_cb,
                                      NULL, NULL,
                                      custom_ext_2_srv_parse_cb, NULL)
            || !SSL_CTX_add_server_custom_ext(s_ctx, CUSTOM_EXT_TYPE_3,
                                      custom_ext_3_srv_add_cb,
                                      NULL, NULL,
                                      custom_ext_3_srv_parse_cb, NULL)
            || !SSL_CTX_add_server_custom_ext(s_ctx2, CUSTOM_EXT_TYPE_3,
                                      custom_ext_3_srv_add_cb,
                                      NULL, NULL,
                                      custom_ext_3_srv_parse_cb, NULL)) {
            BIO_printf(bio_err, "Error setting custom extensions\n");
            goto end;
        }
    }

    if (alpn_server)
        SSL_CTX_set_alpn_select_cb(s_ctx, cb_server_alpn, alpn_server);
    if (alpn_server2)
        SSL_CTX_set_alpn_select_cb(s_ctx2, cb_server_alpn, alpn_server2);

    if (alpn_client) {
        size_t alpn_len;
        unsigned char *alpn = next_protos_parse(&alpn_len, alpn_client);

        if (alpn == NULL) {
            BIO_printf(bio_err, "Error parsing -alpn_client argument\n");
            goto end;
        }
        /* Returns 0 on success!! */
        if (SSL_CTX_set_alpn_protos(c_ctx, alpn, alpn_len)) {
            BIO_printf(bio_err, "Error setting ALPN\n");
            OPENSSL_free(alpn);
            goto end;
        }
        OPENSSL_free(alpn);
    }

    if (server_sess_in != NULL) {
        server_sess = read_session(server_sess_in);
        if (server_sess == NULL)
            goto end;
    }
    if (client_sess_in != NULL) {
        client_sess = read_session(client_sess_in);
        if (client_sess == NULL)
            goto end;
    }

    if (server_sess_out != NULL || server_sess_in != NULL) {
        char *keys;
        long size;

        /* Use a fixed key so that we can decrypt the ticket. */
        size = SSL_CTX_set_tlsext_ticket_keys(s_ctx, NULL, 0);
        keys = OPENSSL_zalloc(size);
        SSL_CTX_set_tlsext_ticket_keys(s_ctx, keys, size);
        OPENSSL_free(keys);
    }

    if (sn_server1 != NULL || sn_server2 != NULL)
        SSL_CTX_set_tlsext_servername_callback(s_ctx, servername_cb);

    c_ssl = SSL_new(c_ctx);
    s_ssl = SSL_new(s_ctx);

    if (sn_client)
        SSL_set_tlsext_host_name(c_ssl, sn_client);

    if (!set_protocol_version(server_min_proto, s_ssl, SSL_CTRL_SET_MIN_PROTO_VERSION))
        goto end;
    if (!set_protocol_version(server_max_proto, s_ssl, SSL_CTRL_SET_MAX_PROTO_VERSION))
        goto end;
    if (!set_protocol_version(client_min_proto, c_ssl, SSL_CTRL_SET_MIN_PROTO_VERSION))
        goto end;
    if (!set_protocol_version(client_max_proto, c_ssl, SSL_CTRL_SET_MAX_PROTO_VERSION))
        goto end;

    if (server_sess) {
        if (SSL_CTX_add_session(s_ctx, server_sess) == 0) {
            BIO_printf(bio_err, "Can't add server session\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    BIO_printf(bio_stdout, "Doing handshakes=%d bytes=%ld\n", number, bytes);
    for (i = 0; i < number; i++) {
        if (!reuse) {
            if (!SSL_set_session(c_ssl, NULL)) {
                BIO_printf(bio_err, "Failed to set session\n");
                goto end;
            }
        }
        if (client_sess_in != NULL) {
            if (SSL_set_session(c_ssl, client_sess) == 0) {
                BIO_printf(bio_err, "Can't set client session\n");
                ERR_print_errors(bio_err);
                goto end;
            }
        }
        switch (bio_type) {
        case BIO_MEM:
            ret = doit(s_ssl, c_ssl, bytes);
            break;
        case BIO_PAIR:
            ret = doit_biopair(s_ssl, c_ssl, bytes, &s_time, &c_time);
            break;
#ifndef OPENSSL_NO_SOCK
        case BIO_IPV4:
            ret = doit_localhost(s_ssl, c_ssl, BIO_FAMILY_IPV4,
                                 bytes, &s_time, &c_time);
            break;
        case BIO_IPV6:
            ret = doit_localhost(s_ssl, c_ssl, BIO_FAMILY_IPV6,
                                 bytes, &s_time, &c_time);
            break;
#else
        case BIO_IPV4:
        case BIO_IPV6:
            ret = 1;
            goto err;
#endif
        }
        if (ret)  break;
    }

    if (should_negotiate && ret == 0 &&
        strcmp(should_negotiate, "fail-server") != 0 &&
        strcmp(should_negotiate, "fail-client") != 0) {
        int version = protocol_from_string(should_negotiate);
        if (version < 0) {
            BIO_printf(bio_err, "Error parsing: %s\n", should_negotiate);
            ret = 1;
            goto err;
        }
        if (SSL_version(c_ssl) != version) {
            BIO_printf(bio_err, "Unxpected version negotiated. "
                "Expected: %s, got %s\n", should_negotiate, SSL_get_version(c_ssl));
            ret = 1;
            goto err;
        }
    }

    if (should_reuse != -1) {
        if (SSL_session_reused(s_ssl) != should_reuse ||
            SSL_session_reused(c_ssl) != should_reuse) {
            BIO_printf(bio_err, "Unexpected session reuse state. "
                "Expected: %d, server: %d, client: %d\n", should_reuse,
                SSL_session_reused(s_ssl), SSL_session_reused(c_ssl));
            ret = 1;
            goto err;
        }
    }

    if (server_sess_out != NULL) {
        if (write_session(server_sess_out, SSL_get_session(s_ssl)) == 0) {
            ret = 1;
            goto err;
        }
    }
    if (client_sess_out != NULL) {
        if (write_session(client_sess_out, SSL_get_session(c_ssl)) == 0) {
            ret = 1;
            goto err;
        }
    }

    if (!verbose) {
        print_details(c_ssl, "");
    }
    if (print_time) {
#ifdef CLOCKS_PER_SEC
        /*
         * "To determine the time in seconds, the value returned by the clock
         * function should be divided by the value of the macro
         * CLOCKS_PER_SEC." -- ISO/IEC 9899
         */
        BIO_printf(bio_stdout, "Approximate total server time: %6.2f s\n"
                   "Approximate total client time: %6.2f s\n",
                   (double)s_time / CLOCKS_PER_SEC,
                   (double)c_time / CLOCKS_PER_SEC);
#else
        BIO_printf(bio_stdout,
                   "Approximate total server time: %6.2f units\n"
                   "Approximate total client time: %6.2f units\n",
                   (double)s_time, (double)c_time);
#endif
    }

 err:
    SSL_free(s_ssl);
    SSL_free(c_ssl);

 end:
    SSL_CTX_free(s_ctx);
    SSL_CTX_free(s_ctx2);
    SSL_CTX_free(c_ctx);
    SSL_CONF_CTX_free(s_cctx);
    SSL_CONF_CTX_free(s_cctx2);
    SSL_CONF_CTX_free(c_cctx);
    sk_OPENSSL_STRING_free(conf_args);

    BIO_free(bio_stdout);

    SSL_SESSION_free(server_sess);
    SSL_SESSION_free(client_sess);

#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (CRYPTO_mem_leaks(bio_err) <= 0)
        ret = 1;
#endif
    BIO_free(bio_err);
    EXIT(ret);
}

#ifndef OPENSSL_NO_SOCK
int doit_localhost(SSL *s_ssl, SSL *c_ssl, int family, long count,
                   clock_t *s_time, clock_t *c_time)
{
    long cw_num = count, cr_num = count, sw_num = count, sr_num = count;
    BIO *s_ssl_bio = NULL, *c_ssl_bio = NULL;
    BIO *acpt = NULL, *server = NULL, *client = NULL;
    char addr_str[40];
    int ret = 1;
    int err_in_client = 0;
    int err_in_server = 0;

    acpt = BIO_new_accept("0");
    if (acpt == NULL)
        goto err;
    BIO_set_accept_ip_family(acpt, family);
    BIO_set_bind_mode(acpt, BIO_SOCK_NONBLOCK | BIO_SOCK_REUSEADDR);
    if (BIO_do_accept(acpt) <= 0)
        goto err;

    BIO_snprintf(addr_str, sizeof(addr_str), ":%s", BIO_get_accept_port(acpt));

    client = BIO_new_connect(addr_str);
    BIO_set_conn_ip_family(client, family);
    if (!client)
        goto err;

    if (BIO_set_nbio(client, 1) <= 0)
        goto err;
    if (BIO_set_nbio(acpt, 1) <= 0)
        goto err;

    {
        int st_connect = 0, st_accept = 0;

        while(!st_connect || !st_accept) {
            if (!st_connect) {
                if (BIO_do_connect(client) <= 0) {
                    if (!BIO_should_retry(client))
                        goto err;
                } else {
                    st_connect = 1;
                }
            }
            if (!st_accept) {
                if (BIO_do_accept(acpt) <= 0) {
                    if (!BIO_should_retry(acpt))
                        goto err;
                } else {
                    st_accept = 1;
                }
            }
        }
    }
    /* We're not interested in accepting further connects */
    server = BIO_pop(acpt);
    BIO_free_all(acpt);
    acpt = NULL;

    s_ssl_bio = BIO_new(BIO_f_ssl());
    if (!s_ssl_bio)
        goto err;

    c_ssl_bio = BIO_new(BIO_f_ssl());
    if (!c_ssl_bio)
        goto err;

    SSL_set_connect_state(c_ssl);
    SSL_set_bio(c_ssl, client, client);
    (void)BIO_set_ssl(c_ssl_bio, c_ssl, BIO_NOCLOSE);

    SSL_set_accept_state(s_ssl);
    SSL_set_bio(s_ssl, server, server);
    (void)BIO_set_ssl(s_ssl_bio, s_ssl, BIO_NOCLOSE);

    do {
        /*-
         * c_ssl_bio:          SSL filter BIO
         *
         * client:             I/O for SSL library
         *
         *
         * server:             I/O for SSL library
         *
         * s_ssl_bio:          SSL filter BIO
         */

        /*
         * We have non-blocking behaviour throughout this test program, but
         * can be sure that there is *some* progress in each iteration; so we
         * don't have to worry about ..._SHOULD_READ or ..._SHOULD_WRITE --
         * we just try everything in each iteration
         */

        {
            /* CLIENT */

            char cbuf[1024 * 8];
            int i, r;
            clock_t c_clock = clock();

            memset(cbuf, 0, sizeof(cbuf));

            if (debug)
                if (SSL_in_init(c_ssl))
                    printf("client waiting in SSL_connect - %s\n",
                           SSL_state_string_long(c_ssl));

            if (cw_num > 0) {
                /* Write to server. */

                if (cw_num > (long)sizeof cbuf)
                    i = sizeof cbuf;
                else
                    i = (int)cw_num;
                r = BIO_write(c_ssl_bio, cbuf, i);
                if (r < 0) {
                    if (!BIO_should_retry(c_ssl_bio)) {
                        fprintf(stderr, "ERROR in CLIENT\n");
                        err_in_client = 1;
                        goto err;
                    }
                    /*
                     * BIO_should_retry(...) can just be ignored here. The
                     * library expects us to call BIO_write with the same
                     * arguments again, and that's what we will do in the
                     * next iteration.
                     */
                } else if (r == 0) {
                    fprintf(stderr, "SSL CLIENT STARTUP FAILED\n");
                    goto err;
                } else {
                    if (debug)
                        printf("client wrote %d\n", r);
                    cw_num -= r;
                }
            }

            if (cr_num > 0) {
                /* Read from server. */

                r = BIO_read(c_ssl_bio, cbuf, sizeof(cbuf));
                if (r < 0) {
                    if (!BIO_should_retry(c_ssl_bio)) {
                        fprintf(stderr, "ERROR in CLIENT\n");
                        err_in_client = 1;
                        goto err;
                    }
                    /*
                     * Again, "BIO_should_retry" can be ignored.
                     */
                } else if (r == 0) {
                    fprintf(stderr, "SSL CLIENT STARTUP FAILED\n");
                    goto err;
                } else {
                    if (debug)
                        printf("client read %d\n", r);
                    cr_num -= r;
                }
            }

            /*
             * c_time and s_time increments will typically be very small
             * (depending on machine speed and clock tick intervals), but
             * sampling over a large number of connections should result in
             * fairly accurate figures.  We cannot guarantee a lot, however
             * -- if each connection lasts for exactly one clock tick, it
             * will be counted only for the client or only for the server or
             * even not at all.
             */
            *c_time += (clock() - c_clock);
        }

        {
            /* SERVER */

            char sbuf[1024 * 8];
            int i, r;
            clock_t s_clock = clock();

            memset(sbuf, 0, sizeof(sbuf));

            if (debug)
                if (SSL_in_init(s_ssl))
                    printf("server waiting in SSL_accept - %s\n",
                           SSL_state_string_long(s_ssl));

            if (sw_num > 0) {
                /* Write to client. */

                if (sw_num > (long)sizeof sbuf)
                    i = sizeof sbuf;
                else
                    i = (int)sw_num;
                r = BIO_write(s_ssl_bio, sbuf, i);
                if (r < 0) {
                    if (!BIO_should_retry(s_ssl_bio)) {
                        fprintf(stderr, "ERROR in SERVER\n");
                        err_in_server = 1;
                        goto err;
                    }
                    /* Ignore "BIO_should_retry". */
                } else if (r == 0) {
                    fprintf(stderr, "SSL SERVER STARTUP FAILED\n");
                    goto err;
                } else {
                    if (debug)
                        printf("server wrote %d\n", r);
                    sw_num -= r;
                }
            }

            if (sr_num > 0) {
                /* Read from client. */

                r = BIO_read(s_ssl_bio, sbuf, sizeof(sbuf));
                if (r < 0) {
                    if (!BIO_should_retry(s_ssl_bio)) {
                        fprintf(stderr, "ERROR in SERVER\n");
                        err_in_server = 1;
                        goto err;
                    }
                    /* blah, blah */
                } else if (r == 0) {
                    fprintf(stderr, "SSL SERVER STARTUP FAILED\n");
                    goto err;
                } else {
                    if (debug)
                        printf("server read %d\n", r);
                    sr_num -= r;
                }
            }

            *s_time += (clock() - s_clock);
        }
    }
    while (cw_num > 0 || cr_num > 0 || sw_num > 0 || sr_num > 0);

    if (verbose)
        print_details(c_ssl, "DONE via TCP connect: ");
# ifndef OPENSSL_NO_NEXTPROTONEG
    if (verify_npn(c_ssl, s_ssl) < 0) {
        ret = 1;
        goto end;
    }
# endif
    if (verify_serverinfo() < 0) {
        fprintf(stderr, "Server info verify error\n");
        ret = 1;
        goto err;
    }
    if (verify_alpn(c_ssl, s_ssl) < 0) {
        ret = 1;
        goto err;
    }
    if (verify_servername(c_ssl, s_ssl) < 0) {
        ret = 1;
        goto err;
    }

    if (custom_ext_error) {
        fprintf(stderr, "Custom extension error\n");
        ret = 1;
        goto err;
    }

# ifndef OPENSSL_NO_NEXTPROTONEG
 end:
# endif
    ret = 0;

 err:
    ERR_print_errors(bio_err);

    BIO_free_all(acpt);
    BIO_free(server);
    BIO_free(client);
    BIO_free(s_ssl_bio);
    BIO_free(c_ssl_bio);

    if (should_negotiate != NULL && strcmp(should_negotiate, "fail-client") == 0)
        ret = (err_in_client != 0) ? 0 : 1;
    else if (should_negotiate != NULL && strcmp(should_negotiate, "fail-server") == 0)
        ret = (err_in_server != 0) ? 0 : 1;

    return ret;
}
#endif

int doit_biopair(SSL *s_ssl, SSL *c_ssl, long count,
                 clock_t *s_time, clock_t *c_time)
{
    long cw_num = count, cr_num = count, sw_num = count, sr_num = count;
    BIO *s_ssl_bio = NULL, *c_ssl_bio = NULL;
    BIO *server = NULL, *server_io = NULL, *client = NULL, *client_io = NULL;
    int ret = 1;
    int err_in_client = 0;
    int err_in_server = 0;

    size_t bufsiz = 256;        /* small buffer for testing */

    if (!BIO_new_bio_pair(&server, bufsiz, &server_io, bufsiz))
        goto err;
    if (!BIO_new_bio_pair(&client, bufsiz, &client_io, bufsiz))
        goto err;

    s_ssl_bio = BIO_new(BIO_f_ssl());
    if (!s_ssl_bio)
        goto err;

    c_ssl_bio = BIO_new(BIO_f_ssl());
    if (!c_ssl_bio)
        goto err;

    SSL_set_connect_state(c_ssl);
    SSL_set_bio(c_ssl, client, client);
    (void)BIO_set_ssl(c_ssl_bio, c_ssl, BIO_NOCLOSE);

    SSL_set_accept_state(s_ssl);
    SSL_set_bio(s_ssl, server, server);
    (void)BIO_set_ssl(s_ssl_bio, s_ssl, BIO_NOCLOSE);

    do {
        /*-
         * c_ssl_bio:          SSL filter BIO
         *
         * client:             pseudo-I/O for SSL library
         *
         * client_io:          client's SSL communication; usually to be
         *                     relayed over some I/O facility, but in this
         *                     test program, we're the server, too:
         *
         * server_io:          server's SSL communication
         *
         * server:             pseudo-I/O for SSL library
         *
         * s_ssl_bio:          SSL filter BIO
         *
         * The client and the server each employ a "BIO pair":
         * client + client_io, server + server_io.
         * BIO pairs are symmetric.  A BIO pair behaves similar
         * to a non-blocking socketpair (but both endpoints must
         * be handled by the same thread).
         * [Here we could connect client and server to the ends
         * of a single BIO pair, but then this code would be less
         * suitable as an example for BIO pairs in general.]
         *
         * Useful functions for querying the state of BIO pair endpoints:
         *
         * BIO_ctrl_pending(bio)              number of bytes we can read now
         * BIO_ctrl_get_read_request(bio)     number of bytes needed to fulfil
         *                                      other side's read attempt
         * BIO_ctrl_get_write_guarantee(bio)   number of bytes we can write now
         *
         * ..._read_request is never more than ..._write_guarantee;
         * it depends on the application which one you should use.
         */

        /*
         * We have non-blocking behaviour throughout this test program, but
         * can be sure that there is *some* progress in each iteration; so we
         * don't have to worry about ..._SHOULD_READ or ..._SHOULD_WRITE --
         * we just try everything in each iteration
         */

        {
            /* CLIENT */

            char cbuf[1024 * 8];
            int i, r;
            clock_t c_clock = clock();

            memset(cbuf, 0, sizeof(cbuf));

            if (debug)
                if (SSL_in_init(c_ssl))
                    printf("client waiting in SSL_connect - %s\n",
                           SSL_state_string_long(c_ssl));

            if (cw_num > 0) {
                /* Write to server. */

                if (cw_num > (long)sizeof cbuf)
                    i = sizeof cbuf;
                else
                    i = (int)cw_num;
                r = BIO_write(c_ssl_bio, cbuf, i);
                if (r < 0) {
                    if (!BIO_should_retry(c_ssl_bio)) {
                        fprintf(stderr, "ERROR in CLIENT\n");
                        err_in_client = 1;
                        goto err;
                    }
                    /*
                     * BIO_should_retry(...) can just be ignored here. The
                     * library expects us to call BIO_write with the same
                     * arguments again, and that's what we will do in the
                     * next iteration.
                     */
                } else if (r == 0) {
                    fprintf(stderr, "SSL CLIENT STARTUP FAILED\n");
                    goto err;
                } else {
                    if (debug)
                        printf("client wrote %d\n", r);
                    cw_num -= r;
                }
            }

            if (cr_num > 0) {
                /* Read from server. */

                r = BIO_read(c_ssl_bio, cbuf, sizeof(cbuf));
                if (r < 0) {
                    if (!BIO_should_retry(c_ssl_bio)) {
                        fprintf(stderr, "ERROR in CLIENT\n");
                        err_in_client = 1;
                        goto err;
                    }
                    /*
                     * Again, "BIO_should_retry" can be ignored.
                     */
                } else if (r == 0) {
                    fprintf(stderr, "SSL CLIENT STARTUP FAILED\n");
                    goto err;
                } else {
                    if (debug)
                        printf("client read %d\n", r);
                    cr_num -= r;
                }
            }

            /*
             * c_time and s_time increments will typically be very small
             * (depending on machine speed and clock tick intervals), but
             * sampling over a large number of connections should result in
             * fairly accurate figures.  We cannot guarantee a lot, however
             * -- if each connection lasts for exactly one clock tick, it
             * will be counted only for the client or only for the server or
             * even not at all.
             */
            *c_time += (clock() - c_clock);
        }

        {
            /* SERVER */

            char sbuf[1024 * 8];
            int i, r;
            clock_t s_clock = clock();

            memset(sbuf, 0, sizeof(sbuf));

            if (debug)
                if (SSL_in_init(s_ssl))
                    printf("server waiting in SSL_accept - %s\n",
                           SSL_state_string_long(s_ssl));

            if (sw_num > 0) {
                /* Write to client. */

                if (sw_num > (long)sizeof sbuf)
                    i = sizeof sbuf;
                else
                    i = (int)sw_num;
                r = BIO_write(s_ssl_bio, sbuf, i);
                if (r < 0) {
                    if (!BIO_should_retry(s_ssl_bio)) {
                        fprintf(stderr, "ERROR in SERVER\n");
                        err_in_server = 1;
                        goto err;
                    }
                    /* Ignore "BIO_should_retry". */
                } else if (r == 0) {
                    fprintf(stderr, "SSL SERVER STARTUP FAILED\n");
                    goto err;
                } else {
                    if (debug)
                        printf("server wrote %d\n", r);
                    sw_num -= r;
                }
            }

            if (sr_num > 0) {
                /* Read from client. */

                r = BIO_read(s_ssl_bio, sbuf, sizeof(sbuf));
                if (r < 0) {
                    if (!BIO_should_retry(s_ssl_bio)) {
                        fprintf(stderr, "ERROR in SERVER\n");
                        err_in_server = 1;
                        goto err;
                    }
                    /* blah, blah */
                } else if (r == 0) {
                    fprintf(stderr, "SSL SERVER STARTUP FAILED\n");
                    goto err;
                } else {
                    if (debug)
                        printf("server read %d\n", r);
                    sr_num -= r;
                }
            }

            *s_time += (clock() - s_clock);
        }

        {
            /* "I/O" BETWEEN CLIENT AND SERVER. */

            size_t r1, r2;
            BIO *io1 = server_io, *io2 = client_io;
            /*
             * we use the non-copying interface for io1 and the standard
             * BIO_write/BIO_read interface for io2
             */

            static int prev_progress = 1;
            int progress = 0;

            /* io1 to io2 */
            do {
                size_t num;
                int r;

                r1 = BIO_ctrl_pending(io1);
                r2 = BIO_ctrl_get_write_guarantee(io2);

                num = r1;
                if (r2 < num)
                    num = r2;
                if (num) {
                    char *dataptr;

                    if (INT_MAX < num) /* yeah, right */
                        num = INT_MAX;

                    r = BIO_nread(io1, &dataptr, (int)num);
                    assert(r > 0);
                    assert(r <= (int)num);
                    /*
                     * possibly r < num (non-contiguous data)
                     */
                    num = r;
                    r = BIO_write(io2, dataptr, (int)num);
                    if (r != (int)num) { /* can't happen */
                        fprintf(stderr, "ERROR: BIO_write could not write "
                                "BIO_ctrl_get_write_guarantee() bytes");
                        goto err;
                    }
                    progress = 1;

                    if (debug)
                        printf((io1 == client_io) ?
                               "C->S relaying: %d bytes\n" :
                               "S->C relaying: %d bytes\n", (int)num);
                }
            }
            while (r1 && r2);

            /* io2 to io1 */
            {
                size_t num;
                int r;

                r1 = BIO_ctrl_pending(io2);
                r2 = BIO_ctrl_get_read_request(io1);
                /*
                 * here we could use ..._get_write_guarantee instead of
                 * ..._get_read_request, but by using the latter we test
                 * restartability of the SSL implementation more thoroughly
                 */
                num = r1;
                if (r2 < num)
                    num = r2;
                if (num) {
                    char *dataptr;

                    if (INT_MAX < num)
                        num = INT_MAX;

                    if (num > 1)
                        --num;  /* test restartability even more thoroughly */

                    r = BIO_nwrite0(io1, &dataptr);
                    assert(r > 0);
                    if (r < (int)num)
                        num = r;
                    r = BIO_read(io2, dataptr, (int)num);
                    if (r != (int)num) { /* can't happen */
                        fprintf(stderr, "ERROR: BIO_read could not read "
                                "BIO_ctrl_pending() bytes");
                        goto err;
                    }
                    progress = 1;
                    r = BIO_nwrite(io1, &dataptr, (int)num);
                    if (r != (int)num) { /* can't happen */
                        fprintf(stderr, "ERROR: BIO_nwrite() did not accept "
                                "BIO_nwrite0() bytes");
                        goto err;
                    }

                    if (debug)
                        printf((io2 == client_io) ?
                               "C->S relaying: %d bytes\n" :
                               "S->C relaying: %d bytes\n", (int)num);
                }
            }                   /* no loop, BIO_ctrl_get_read_request now
                                 * returns 0 anyway */

            if (!progress && !prev_progress)
                if (cw_num > 0 || cr_num > 0 || sw_num > 0 || sr_num > 0) {
                    fprintf(stderr, "ERROR: got stuck\n");
                    fprintf(stderr, " ERROR.\n");
                    goto err;
                }
            prev_progress = progress;
        }
    }
    while (cw_num > 0 || cr_num > 0 || sw_num > 0 || sr_num > 0);

    if (verbose)
        print_details(c_ssl, "DONE via BIO pair: ");
#ifndef OPENSSL_NO_NEXTPROTONEG
    if (verify_npn(c_ssl, s_ssl) < 0) {
        ret = 1;
        goto end;
    }
#endif
    if (verify_serverinfo() < 0) {
        fprintf(stderr, "Server info verify error\n");
        ret = 1;
        goto err;
    }
    if (verify_alpn(c_ssl, s_ssl) < 0) {
        ret = 1;
        goto err;
    }
    if (verify_servername(c_ssl, s_ssl) < 0) {
        ret = 1;
        goto err;
    }

    if (custom_ext_error) {
        fprintf(stderr, "Custom extension error\n");
        ret = 1;
        goto err;
    }

#ifndef OPENSSL_NO_NEXTPROTONEG
 end:
#endif
    ret = 0;

 err:
    ERR_print_errors(bio_err);

    BIO_free(server);
    BIO_free(server_io);
    BIO_free(client);
    BIO_free(client_io);
    BIO_free(s_ssl_bio);
    BIO_free(c_ssl_bio);

    if (should_negotiate != NULL && strcmp(should_negotiate, "fail-client") == 0)
        ret = (err_in_client != 0) ? 0 : 1;
    else if (should_negotiate != NULL && strcmp(should_negotiate, "fail-server") == 0)
        ret = (err_in_server != 0) ? 0 : 1;

    return ret;
}

#define W_READ  1
#define W_WRITE 2
#define C_DONE  1
#define S_DONE  2

int doit(SSL *s_ssl, SSL *c_ssl, long count)
{
    char *cbuf = NULL, *sbuf = NULL;
    long bufsiz;
    long cw_num = count, cr_num = count;
    long sw_num = count, sr_num = count;
    int ret = 1;
    BIO *c_to_s = NULL;
    BIO *s_to_c = NULL;
    BIO *c_bio = NULL;
    BIO *s_bio = NULL;
    int c_r, c_w, s_r, s_w;
    int i, j;
    int done = 0;
    int c_write, s_write;
    int do_server = 0, do_client = 0;
    int max_frag = 5 * 1024;
    int err_in_client = 0;
    int err_in_server = 0;

    bufsiz = count > 40 * 1024 ? 40 * 1024 : count;

    if ((cbuf = OPENSSL_zalloc(bufsiz)) == NULL)
        goto err;
    if ((sbuf = OPENSSL_zalloc(bufsiz)) == NULL)
        goto err;

    c_to_s = BIO_new(BIO_s_mem());
    s_to_c = BIO_new(BIO_s_mem());
    if ((s_to_c == NULL) || (c_to_s == NULL)) {
        ERR_print_errors(bio_err);
        goto err;
    }

    c_bio = BIO_new(BIO_f_ssl());
    s_bio = BIO_new(BIO_f_ssl());
    if ((c_bio == NULL) || (s_bio == NULL)) {
        ERR_print_errors(bio_err);
        goto err;
    }

    SSL_set_connect_state(c_ssl);
    SSL_set_bio(c_ssl, s_to_c, c_to_s);
    SSL_set_max_send_fragment(c_ssl, max_frag);
    BIO_set_ssl(c_bio, c_ssl, BIO_NOCLOSE);

    /*
     * We've just given our ref to these BIOs to c_ssl. We need another one to
     * give to s_ssl
     */
    if (!BIO_up_ref(c_to_s)) {
        /* c_to_s and s_to_c will get freed when we free c_ssl */
        c_to_s = NULL;
        s_to_c = NULL;
        goto err;
    }
    if (!BIO_up_ref(s_to_c)) {
        /* s_to_c will get freed when we free c_ssl */
        s_to_c = NULL;
        goto err;
    }

    SSL_set_accept_state(s_ssl);
    SSL_set_bio(s_ssl, c_to_s, s_to_c);

    /* We've used up all our refs to these now */
    c_to_s = NULL;
    s_to_c = NULL;

    SSL_set_max_send_fragment(s_ssl, max_frag);
    BIO_set_ssl(s_bio, s_ssl, BIO_NOCLOSE);

    c_r = 0;
    s_r = 1;
    c_w = 1;
    s_w = 0;
    c_write = 1, s_write = 0;

    /* We can always do writes */
    for (;;) {
        do_server = 0;
        do_client = 0;

        i = (int)BIO_pending(s_bio);
        if ((i && s_r) || s_w)
            do_server = 1;

        i = (int)BIO_pending(c_bio);
        if ((i && c_r) || c_w)
            do_client = 1;

        if (do_server && debug) {
            if (SSL_in_init(s_ssl))
                printf("server waiting in SSL_accept - %s\n",
                       SSL_state_string_long(s_ssl));
/*-
            else if (s_write)
                printf("server:SSL_write()\n");
            else
                printf("server:SSL_read()\n"); */
        }

        if (do_client && debug) {
            if (SSL_in_init(c_ssl))
                printf("client waiting in SSL_connect - %s\n",
                       SSL_state_string_long(c_ssl));
/*-
            else if (c_write)
                printf("client:SSL_write()\n");
            else
                printf("client:SSL_read()\n"); */
        }

        if (!do_client && !do_server) {
            fprintf(stdout, "ERROR IN STARTUP\n");
            ERR_print_errors(bio_err);
            goto err;
        }
        if (do_client && !(done & C_DONE)) {
            if (c_write) {
                j = (cw_num > bufsiz) ? (int)bufsiz : (int)cw_num;
                i = BIO_write(c_bio, cbuf, j);
                if (i < 0) {
                    c_r = 0;
                    c_w = 0;
                    if (BIO_should_retry(c_bio)) {
                        if (BIO_should_read(c_bio))
                            c_r = 1;
                        if (BIO_should_write(c_bio))
                            c_w = 1;
                    } else {
                        fprintf(stderr, "ERROR in CLIENT\n");
                        err_in_client = 1;
                        ERR_print_errors(bio_err);
                        goto err;
                    }
                } else if (i == 0) {
                    fprintf(stderr, "SSL CLIENT STARTUP FAILED\n");
                    goto err;
                } else {
                    if (debug)
                        printf("client wrote %d\n", i);
                    /* ok */
                    s_r = 1;
                    c_write = 0;
                    cw_num -= i;
                    if (max_frag > 1029)
                        SSL_set_max_send_fragment(c_ssl, max_frag -= 5);
                }
            } else {
                i = BIO_read(c_bio, cbuf, bufsiz);
                if (i < 0) {
                    c_r = 0;
                    c_w = 0;
                    if (BIO_should_retry(c_bio)) {
                        if (BIO_should_read(c_bio))
                            c_r = 1;
                        if (BIO_should_write(c_bio))
                            c_w = 1;
                    } else {
                        fprintf(stderr, "ERROR in CLIENT\n");
                        err_in_client = 1;
                        ERR_print_errors(bio_err);
                        goto err;
                    }
                } else if (i == 0) {
                    fprintf(stderr, "SSL CLIENT STARTUP FAILED\n");
                    goto err;
                } else {
                    if (debug)
                        printf("client read %d\n", i);
                    cr_num -= i;
                    if (sw_num > 0) {
                        s_write = 1;
                        s_w = 1;
                    }
                    if (cr_num <= 0) {
                        s_write = 1;
                        s_w = 1;
                        done = S_DONE | C_DONE;
                    }
                }
            }
        }

        if (do_server && !(done & S_DONE)) {
            if (!s_write) {
                i = BIO_read(s_bio, sbuf, bufsiz);
                if (i < 0) {
                    s_r = 0;
                    s_w = 0;
                    if (BIO_should_retry(s_bio)) {
                        if (BIO_should_read(s_bio))
                            s_r = 1;
                        if (BIO_should_write(s_bio))
                            s_w = 1;
                    } else {
                        fprintf(stderr, "ERROR in SERVER\n");
                        err_in_server = 1;
                        ERR_print_errors(bio_err);
                        goto err;
                    }
                } else if (i == 0) {
                    ERR_print_errors(bio_err);
                    fprintf(stderr,
                            "SSL SERVER STARTUP FAILED in SSL_read\n");
                    goto err;
                } else {
                    if (debug)
                        printf("server read %d\n", i);
                    sr_num -= i;
                    if (cw_num > 0) {
                        c_write = 1;
                        c_w = 1;
                    }
                    if (sr_num <= 0) {
                        s_write = 1;
                        s_w = 1;
                        c_write = 0;
                    }
                }
            } else {
                j = (sw_num > bufsiz) ? (int)bufsiz : (int)sw_num;
                i = BIO_write(s_bio, sbuf, j);
                if (i < 0) {
                    s_r = 0;
                    s_w = 0;
                    if (BIO_should_retry(s_bio)) {
                        if (BIO_should_read(s_bio))
                            s_r = 1;
                        if (BIO_should_write(s_bio))
                            s_w = 1;
                    } else {
                        fprintf(stderr, "ERROR in SERVER\n");
                        err_in_server = 1;
                        ERR_print_errors(bio_err);
                        goto err;
                    }
                } else if (i == 0) {
                    ERR_print_errors(bio_err);
                    fprintf(stderr,
                            "SSL SERVER STARTUP FAILED in SSL_write\n");
                    goto err;
                } else {
                    if (debug)
                        printf("server wrote %d\n", i);
                    sw_num -= i;
                    s_write = 0;
                    c_r = 1;
                    if (sw_num <= 0)
                        done |= S_DONE;
                    if (max_frag > 1029)
                        SSL_set_max_send_fragment(s_ssl, max_frag -= 5);
                }
            }
        }

        if ((done & S_DONE) && (done & C_DONE))
            break;
    }

    if (verbose)
        print_details(c_ssl, "DONE: ");
#ifndef OPENSSL_NO_NEXTPROTONEG
    if (verify_npn(c_ssl, s_ssl) < 0) {
        ret = 1;
        goto err;
    }
#endif
    if (verify_serverinfo() < 0) {
        fprintf(stderr, "Server info verify error\n");
        ret = 1;
        goto err;
    }
    if (custom_ext_error) {
        fprintf(stderr, "Custom extension error\n");
        ret = 1;
        goto err;
    }
    ret = 0;
 err:
    BIO_free(c_to_s);
    BIO_free(s_to_c);
    BIO_free_all(c_bio);
    BIO_free_all(s_bio);
    OPENSSL_free(cbuf);
    OPENSSL_free(sbuf);

    if (should_negotiate != NULL && strcmp(should_negotiate, "fail-client") == 0)
        ret = (err_in_client != 0) ? 0 : 1;
    else if (should_negotiate != NULL && strcmp(should_negotiate, "fail-server") == 0)
        ret = (err_in_server != 0) ? 0 : 1;

    return (ret);
}

static int verify_callback(int ok, X509_STORE_CTX *ctx)
{
    char *s, buf[256];

    s = X509_NAME_oneline(X509_get_subject_name(X509_STORE_CTX_get_current_cert(ctx)),
                          buf, sizeof buf);
    if (s != NULL) {
        if (ok)
            printf("depth=%d %s\n", X509_STORE_CTX_get_error_depth(ctx), buf);
        else {
            fprintf(stderr, "depth=%d error=%d %s\n",
                    X509_STORE_CTX_get_error_depth(ctx),
                    X509_STORE_CTX_get_error(ctx), buf);
        }
    }

    if (ok == 0) {
        int i = X509_STORE_CTX_get_error(ctx);

        switch (i) {
        default:
            fprintf(stderr, "Error string: %s\n",
                    X509_verify_cert_error_string(i));
            break;
        case X509_V_ERR_CERT_NOT_YET_VALID:
        case X509_V_ERR_CERT_HAS_EXPIRED:
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            ok = 1;
            break;
        }
    }

    return (ok);
}

static int app_verify_callback(X509_STORE_CTX *ctx, void *arg)
{
    int ok = 1;
    struct app_verify_arg *cb_arg = arg;

    if (cb_arg->app_verify) {
        char *s = NULL, buf[256];
        X509 *c = X509_STORE_CTX_get0_cert(ctx);

        printf("In app_verify_callback, allowing cert. ");
        printf("Arg is: %s\n", cb_arg->string);
        printf("Finished printing do we have a context? 0x%p a cert? 0x%p\n",
                (void *)ctx, (void *)c);
        if (c)
            s = X509_NAME_oneline(X509_get_subject_name(c), buf, 256);
        if (s != NULL) {
            printf("cert depth=%d %s\n",
                    X509_STORE_CTX_get_error_depth(ctx), buf);
        }
        return (1);
    }

    ok = X509_verify_cert(ctx);

    return (ok);
}

#ifndef OPENSSL_NO_DH
/*-
 * These DH parameters have been generated as follows:
 *    $ openssl dhparam -C -noout 512
 *    $ openssl dhparam -C -noout 1024
 *    $ openssl dhparam -C -noout -dsaparam 1024
 * (The third function has been renamed to avoid name conflicts.)
 */
static DH *get_dh512()
{
    static unsigned char dh512_p[] = {
        0xCB, 0xC8, 0xE1, 0x86, 0xD0, 0x1F, 0x94, 0x17, 0xA6, 0x99, 0xF0,
        0xC6,
        0x1F, 0x0D, 0xAC, 0xB6, 0x25, 0x3E, 0x06, 0x39, 0xCA, 0x72, 0x04,
        0xB0,
        0x6E, 0xDA, 0xC0, 0x61, 0xE6, 0x7A, 0x77, 0x25, 0xE8, 0x3B, 0xB9,
        0x5F,
        0x9A, 0xB6, 0xB5, 0xFE, 0x99, 0x0B, 0xA1, 0x93, 0x4E, 0x35, 0x33,
        0xB8,
        0xE1, 0xF1, 0x13, 0x4F, 0x59, 0x1A, 0xD2, 0x57, 0xC0, 0x26, 0x21,
        0x33,
        0x02, 0xC5, 0xAE, 0x23,
    };
    static unsigned char dh512_g[] = {
        0x02,
    };
    DH *dh;
    BIGNUM *p, *g;

    if ((dh = DH_new()) == NULL)
        return (NULL);
    p = BN_bin2bn(dh512_p, sizeof(dh512_p), NULL);
    g = BN_bin2bn(dh512_g, sizeof(dh512_g), NULL);
    if ((p == NULL) || (g == NULL) || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return (NULL);
    }
    return (dh);
}

static DH *get_dh1024()
{
    static unsigned char dh1024_p[] = {
        0xF8, 0x81, 0x89, 0x7D, 0x14, 0x24, 0xC5, 0xD1, 0xE6, 0xF7, 0xBF,
        0x3A,
        0xE4, 0x90, 0xF4, 0xFC, 0x73, 0xFB, 0x34, 0xB5, 0xFA, 0x4C, 0x56,
        0xA2,
        0xEA, 0xA7, 0xE9, 0xC0, 0xC0, 0xCE, 0x89, 0xE1, 0xFA, 0x63, 0x3F,
        0xB0,
        0x6B, 0x32, 0x66, 0xF1, 0xD1, 0x7B, 0xB0, 0x00, 0x8F, 0xCA, 0x87,
        0xC2,
        0xAE, 0x98, 0x89, 0x26, 0x17, 0xC2, 0x05, 0xD2, 0xEC, 0x08, 0xD0,
        0x8C,
        0xFF, 0x17, 0x52, 0x8C, 0xC5, 0x07, 0x93, 0x03, 0xB1, 0xF6, 0x2F,
        0xB8,
        0x1C, 0x52, 0x47, 0x27, 0x1B, 0xDB, 0xD1, 0x8D, 0x9D, 0x69, 0x1D,
        0x52,
        0x4B, 0x32, 0x81, 0xAA, 0x7F, 0x00, 0xC8, 0xDC, 0xE6, 0xD9, 0xCC,
        0xC1,
        0x11, 0x2D, 0x37, 0x34, 0x6C, 0xEA, 0x02, 0x97, 0x4B, 0x0E, 0xBB,
        0xB1,
        0x71, 0x33, 0x09, 0x15, 0xFD, 0xDD, 0x23, 0x87, 0x07, 0x5E, 0x89,
        0xAB,
        0x6B, 0x7C, 0x5F, 0xEC, 0xA6, 0x24, 0xDC, 0x53,
    };
    static unsigned char dh1024_g[] = {
        0x02,
    };
    DH *dh;
    BIGNUM *p, *g;

    if ((dh = DH_new()) == NULL)
        return (NULL);
    p = BN_bin2bn(dh1024_p, sizeof(dh1024_p), NULL);
    g = BN_bin2bn(dh1024_g, sizeof(dh1024_g), NULL);
    if ((p == NULL) || (g == NULL) || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return (NULL);
    }
    return (dh);
}

static DH *get_dh1024dsa()
{
    static unsigned char dh1024_p[] = {
        0xC8, 0x00, 0xF7, 0x08, 0x07, 0x89, 0x4D, 0x90, 0x53, 0xF3, 0xD5,
        0x00,
        0x21, 0x1B, 0xF7, 0x31, 0xA6, 0xA2, 0xDA, 0x23, 0x9A, 0xC7, 0x87,
        0x19,
        0x3B, 0x47, 0xB6, 0x8C, 0x04, 0x6F, 0xFF, 0xC6, 0x9B, 0xB8, 0x65,
        0xD2,
        0xC2, 0x5F, 0x31, 0x83, 0x4A, 0xA7, 0x5F, 0x2F, 0x88, 0x38, 0xB6,
        0x55,
        0xCF, 0xD9, 0x87, 0x6D, 0x6F, 0x9F, 0xDA, 0xAC, 0xA6, 0x48, 0xAF,
        0xFC,
        0x33, 0x84, 0x37, 0x5B, 0x82, 0x4A, 0x31, 0x5D, 0xE7, 0xBD, 0x52,
        0x97,
        0xA1, 0x77, 0xBF, 0x10, 0x9E, 0x37, 0xEA, 0x64, 0xFA, 0xCA, 0x28,
        0x8D,
        0x9D, 0x3B, 0xD2, 0x6E, 0x09, 0x5C, 0x68, 0xC7, 0x45, 0x90, 0xFD,
        0xBB,
        0x70, 0xC9, 0x3A, 0xBB, 0xDF, 0xD4, 0x21, 0x0F, 0xC4, 0x6A, 0x3C,
        0xF6,
        0x61, 0xCF, 0x3F, 0xD6, 0x13, 0xF1, 0x5F, 0xBC, 0xCF, 0xBC, 0x26,
        0x9E,
        0xBC, 0x0B, 0xBD, 0xAB, 0x5D, 0xC9, 0x54, 0x39,
    };
    static unsigned char dh1024_g[] = {
        0x3B, 0x40, 0x86, 0xE7, 0xF3, 0x6C, 0xDE, 0x67, 0x1C, 0xCC, 0x80,
        0x05,
        0x5A, 0xDF, 0xFE, 0xBD, 0x20, 0x27, 0x74, 0x6C, 0x24, 0xC9, 0x03,
        0xF3,
        0xE1, 0x8D, 0xC3, 0x7D, 0x98, 0x27, 0x40, 0x08, 0xB8, 0x8C, 0x6A,
        0xE9,
        0xBB, 0x1A, 0x3A, 0xD6, 0x86, 0x83, 0x5E, 0x72, 0x41, 0xCE, 0x85,
        0x3C,
        0xD2, 0xB3, 0xFC, 0x13, 0xCE, 0x37, 0x81, 0x9E, 0x4C, 0x1C, 0x7B,
        0x65,
        0xD3, 0xE6, 0xA6, 0x00, 0xF5, 0x5A, 0x95, 0x43, 0x5E, 0x81, 0xCF,
        0x60,
        0xA2, 0x23, 0xFC, 0x36, 0xA7, 0x5D, 0x7A, 0x4C, 0x06, 0x91, 0x6E,
        0xF6,
        0x57, 0xEE, 0x36, 0xCB, 0x06, 0xEA, 0xF5, 0x3D, 0x95, 0x49, 0xCB,
        0xA7,
        0xDD, 0x81, 0xDF, 0x80, 0x09, 0x4A, 0x97, 0x4D, 0xA8, 0x22, 0x72,
        0xA1,
        0x7F, 0xC4, 0x70, 0x56, 0x70, 0xE8, 0x20, 0x10, 0x18, 0x8F, 0x2E,
        0x60,
        0x07, 0xE7, 0x68, 0x1A, 0x82, 0x5D, 0x32, 0xA2,
    };
    DH *dh;
    BIGNUM *p, *g;

    if ((dh = DH_new()) == NULL)
        return (NULL);
    p = BN_bin2bn(dh1024_p, sizeof(dh1024_p), NULL);
    g = BN_bin2bn(dh1024_g, sizeof(dh1024_g), NULL);
    if ((p == NULL) || (g == NULL) || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return (NULL);
    }
    DH_set_length(dh, 160);
    return (dh);
}
#endif

#ifndef OPENSSL_NO_PSK
/* convert the PSK key (psk_key) in ascii to binary (psk) */
static int psk_key2bn(const char *pskkey, unsigned char *psk,
                      unsigned int max_psk_len)
{
    int ret;
    BIGNUM *bn = NULL;

    ret = BN_hex2bn(&bn, pskkey);
    if (!ret) {
        BIO_printf(bio_err, "Could not convert PSK key '%s' to BIGNUM\n",
                   pskkey);
        BN_free(bn);
        return 0;
    }
    if (BN_num_bytes(bn) > (int)max_psk_len) {
        BIO_printf(bio_err,
                   "psk buffer of callback is too small (%d) for key (%d)\n",
                   max_psk_len, BN_num_bytes(bn));
        BN_free(bn);
        return 0;
    }
    ret = BN_bn2bin(bn, psk);
    BN_free(bn);
    return ret;
}

static unsigned int psk_client_callback(SSL *ssl, const char *hint,
                                        char *identity,
                                        unsigned int max_identity_len,
                                        unsigned char *psk,
                                        unsigned int max_psk_len)
{
    int ret;
    unsigned int psk_len = 0;

    ret = BIO_snprintf(identity, max_identity_len, "Client_identity");
    if (ret < 0)
        goto out_err;
    if (debug)
        fprintf(stderr, "client: created identity '%s' len=%d\n", identity,
                ret);
    ret = psk_key2bn(psk_key, psk, max_psk_len);
    if (ret < 0)
        goto out_err;
    psk_len = ret;
 out_err:
    return psk_len;
}

static unsigned int psk_server_callback(SSL *ssl, const char *identity,
                                        unsigned char *psk,
                                        unsigned int max_psk_len)
{
    unsigned int psk_len = 0;

    if (strcmp(identity, "Client_identity") != 0) {
        BIO_printf(bio_err, "server: PSK error: client identity not found\n");
        return 0;
    }
    psk_len = psk_key2bn(psk_key, psk, max_psk_len);
    return psk_len;
}
#endif
