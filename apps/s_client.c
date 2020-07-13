/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/e_os2.h>

#ifndef OPENSSL_NO_SOCK

/*
 * With IPv6, it looks like Digital has mixed up the proper order of
 * recursive header file inclusion, resulting in the compiler complaining
 * that u_int isn't defined, but only if _POSIX_C_SOURCE is defined, which is
 * needed to have fileno() declared correctly...  So let's define u_int
 */
#if defined(OPENSSL_SYS_VMS_DECC) && !defined(__U_INT)
# define __U_INT
typedef unsigned int u_int;
#endif

#define USE_SOCKETS
#include "apps.h"
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ocsp.h>
#include <openssl/bn.h>
#include <openssl/async.h>
#ifndef OPENSSL_NO_SRP
# include <openssl/srp.h>
#endif
#ifndef OPENSSL_NO_CT
# include <openssl/ct.h>
#endif
#include "s_apps.h"
#include "timeouts.h"

#if defined(__has_feature)
# if __has_feature(memory_sanitizer)
#  include <sanitizer/msan_interface.h>
# endif
#endif

#undef BUFSIZZ
#define BUFSIZZ 1024*8
#define S_CLIENT_IRC_READ_TIMEOUT 8

static char *prog;
static int c_debug = 0;
static int c_showcerts = 0;
static char *keymatexportlabel = NULL;
static int keymatexportlen = 20;
static BIO *bio_c_out = NULL;
static int c_quiet = 0;

static void print_stuff(BIO *berr, SSL *con, int full);
#ifndef OPENSSL_NO_OCSP
static int ocsp_resp_cb(SSL *s, void *arg);
#endif

static int saved_errno;

static void save_errno(void)
{
    saved_errno = errno;
    errno = 0;
}

static int restore_errno(void)
{
    int ret = errno;
    errno = saved_errno;
    return ret;
}

static void do_ssl_shutdown(SSL *ssl)
{
    int ret;

    do {
        /* We only do unidirectional shutdown */
        ret = SSL_shutdown(ssl);
        if (ret < 0) {
            switch (SSL_get_error(ssl, ret)) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_ASYNC:
            case SSL_ERROR_WANT_ASYNC_JOB:
                /* We just do busy waiting. Nothing clever */
                continue;
            }
            ret = 0;
        }
    } while (ret < 0);
}

#ifndef OPENSSL_NO_PSK
/* Default PSK identity and key */
static char *psk_identity = "Client_identity";
/*
 * char *psk_key=NULL; by default PSK is not used
 */

static unsigned int psk_client_cb(SSL *ssl, const char *hint, char *identity,
                                  unsigned int max_identity_len,
                                  unsigned char *psk,
                                  unsigned int max_psk_len)
{
    int ret;
    long key_len;
    unsigned char *key;

    if (c_debug)
        BIO_printf(bio_c_out, "psk_client_cb\n");
    if (!hint) {
        /* no ServerKeyExchange message */
        if (c_debug)
            BIO_printf(bio_c_out,
                       "NULL received PSK identity hint, continuing anyway\n");
    } else if (c_debug)
        BIO_printf(bio_c_out, "Received PSK identity hint '%s'\n", hint);

    /*
     * lookup PSK identity and PSK key based on the given identity hint here
     */
    ret = BIO_snprintf(identity, max_identity_len, "%s", psk_identity);
    if (ret < 0 || (unsigned int)ret > max_identity_len)
        goto out_err;
    if (c_debug)
        BIO_printf(bio_c_out, "created identity '%s' len=%d\n", identity,
                   ret);

    /* convert the PSK key to binary */
    key = OPENSSL_hexstr2buf(psk_key, &key_len);
    if (key == NULL) {
        BIO_printf(bio_err, "Could not convert PSK key '%s' to buffer\n",
                   psk_key);
        return 0;
    }
    if (key_len > max_psk_len) {
        BIO_printf(bio_err,
                   "psk buffer of callback is too small (%d) for key (%ld)\n",
                   max_psk_len, key_len);
        OPENSSL_free(key);
        return 0;
    }

    memcpy(psk, key, key_len);
    OPENSSL_free(key);

    if (c_debug)
        BIO_printf(bio_c_out, "created PSK len=%ld\n", key_len);

    return key_len;
 out_err:
    if (c_debug)
        BIO_printf(bio_err, "Error in PSK client callback\n");
    return 0;
}
#endif

/* This is a context that we pass to callbacks */
typedef struct tlsextctx_st {
    BIO *biodebug;
    int ack;
} tlsextctx;

static int ssl_servername_cb(SSL *s, int *ad, void *arg)
{
    tlsextctx *p = (tlsextctx *) arg;
    const char *hn = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
    if (SSL_get_servername_type(s) != -1)
        p->ack = !SSL_session_reused(s) && hn != NULL;
    else
        BIO_printf(bio_err, "Can't use SSL_get_servername\n");

    return SSL_TLSEXT_ERR_OK;
}

#ifndef OPENSSL_NO_SRP

/* This is a context that we pass to all callbacks */
typedef struct srp_arg_st {
    char *srppassin;
    char *srplogin;
    int msg;                    /* copy from c_msg */
    int debug;                  /* copy from c_debug */
    int amp;                    /* allow more groups */
    int strength;               /* minimal size for N */
} SRP_ARG;

# define SRP_NUMBER_ITERATIONS_FOR_PRIME 64

static int srp_Verify_N_and_g(const BIGNUM *N, const BIGNUM *g)
{
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BIGNUM *r = BN_new();
    int ret =
        g != NULL && N != NULL && bn_ctx != NULL && BN_is_odd(N) &&
        BN_is_prime_ex(N, SRP_NUMBER_ITERATIONS_FOR_PRIME, bn_ctx, NULL) == 1 &&
        p != NULL && BN_rshift1(p, N) &&
        /* p = (N-1)/2 */
        BN_is_prime_ex(p, SRP_NUMBER_ITERATIONS_FOR_PRIME, bn_ctx, NULL) == 1 &&
        r != NULL &&
        /* verify g^((N-1)/2) == -1 (mod N) */
        BN_mod_exp(r, g, p, N, bn_ctx) &&
        BN_add_word(r, 1) && BN_cmp(r, N) == 0;

    BN_free(r);
    BN_free(p);
    BN_CTX_free(bn_ctx);
    return ret;
}

/*-
 * This callback is used here for two purposes:
 * - extended debugging
 * - making some primality tests for unknown groups
 * The callback is only called for a non default group.
 *
 * An application does not need the call back at all if
 * only the standard groups are used.  In real life situations,
 * client and server already share well known groups,
 * thus there is no need to verify them.
 * Furthermore, in case that a server actually proposes a group that
 * is not one of those defined in RFC 5054, it is more appropriate
 * to add the group to a static list and then compare since
 * primality tests are rather cpu consuming.
 */

static int ssl_srp_verify_param_cb(SSL *s, void *arg)
{
    SRP_ARG *srp_arg = (SRP_ARG *)arg;
    BIGNUM *N = NULL, *g = NULL;

    if (((N = SSL_get_srp_N(s)) == NULL) || ((g = SSL_get_srp_g(s)) == NULL))
        return 0;
    if (srp_arg->debug || srp_arg->msg || srp_arg->amp == 1) {
        BIO_printf(bio_err, "SRP parameters:\n");
        BIO_printf(bio_err, "\tN=");
        BN_print(bio_err, N);
        BIO_printf(bio_err, "\n\tg=");
        BN_print(bio_err, g);
        BIO_printf(bio_err, "\n");
    }

    if (SRP_check_known_gN_param(g, N))
        return 1;

    if (srp_arg->amp == 1) {
        if (srp_arg->debug)
            BIO_printf(bio_err,
                       "SRP param N and g are not known params, going to check deeper.\n");

        /*
         * The srp_moregroups is a real debugging feature. Implementors
         * should rather add the value to the known ones. The minimal size
         * has already been tested.
         */
        if (BN_num_bits(g) <= BN_BITS && srp_Verify_N_and_g(N, g))
            return 1;
    }
    BIO_printf(bio_err, "SRP param N and g rejected.\n");
    return 0;
}

# define PWD_STRLEN 1024

static char *ssl_give_srp_client_pwd_cb(SSL *s, void *arg)
{
    SRP_ARG *srp_arg = (SRP_ARG *)arg;
    char *pass = app_malloc(PWD_STRLEN + 1, "SRP password buffer");
    PW_CB_DATA cb_tmp;
    int l;

    cb_tmp.password = (char *)srp_arg->srppassin;
    cb_tmp.prompt_info = "SRP user";
    if ((l = password_callback(pass, PWD_STRLEN, 0, &cb_tmp)) < 0) {
        BIO_printf(bio_err, "Can't read Password\n");
        OPENSSL_free(pass);
        return NULL;
    }
    *(pass + l) = '\0';

    return pass;
}

#endif

static char *srtp_profiles = NULL;

#ifndef OPENSSL_NO_NEXTPROTONEG
/* This the context that we pass to next_proto_cb */
typedef struct tlsextnextprotoctx_st {
    unsigned char *data;
    size_t len;
    int status;
} tlsextnextprotoctx;

static tlsextnextprotoctx next_proto;

static int next_proto_cb(SSL *s, unsigned char **out, unsigned char *outlen,
                         const unsigned char *in, unsigned int inlen,
                         void *arg)
{
    tlsextnextprotoctx *ctx = arg;

    if (!c_quiet) {
        /* We can assume that |in| is syntactically valid. */
        unsigned i;
        BIO_printf(bio_c_out, "Protocols advertised by server: ");
        for (i = 0; i < inlen;) {
            if (i)
                BIO_write(bio_c_out, ", ", 2);
            BIO_write(bio_c_out, &in[i + 1], in[i]);
            i += in[i] + 1;
        }
        BIO_write(bio_c_out, "\n", 1);
    }

    ctx->status =
        SSL_select_next_proto(out, outlen, in, inlen, ctx->data, ctx->len);
    return SSL_TLSEXT_ERR_OK;
}
#endif                         /* ndef OPENSSL_NO_NEXTPROTONEG */

static int serverinfo_cli_parse_cb(SSL *s, unsigned int ext_type,
                                   const unsigned char *in, size_t inlen,
                                   int *al, void *arg)
{
    char pem_name[100];
    unsigned char ext_buf[4 + 65536];

    /* Reconstruct the type/len fields prior to extension data */
    ext_buf[0] = ext_type >> 8;
    ext_buf[1] = ext_type & 0xFF;
    ext_buf[2] = inlen >> 8;
    ext_buf[3] = inlen & 0xFF;
    memcpy(ext_buf + 4, in, inlen);

    BIO_snprintf(pem_name, sizeof(pem_name), "SERVERINFO FOR EXTENSION %d",
                 ext_type);
    PEM_write_bio(bio_c_out, pem_name, "", ext_buf, 4 + inlen);
    return 1;
}

/*
 * Hex decoder that tolerates optional whitespace.  Returns number of bytes
 * produced, advances inptr to end of input string.
 */
static ossl_ssize_t hexdecode(const char **inptr, void *result)
{
    unsigned char **out = (unsigned char **)result;
    const char *in = *inptr;
    unsigned char *ret = app_malloc(strlen(in) / 2, "hexdecode");
    unsigned char *cp = ret;
    uint8_t byte;
    int nibble = 0;

    if (ret == NULL)
        return -1;

    for (byte = 0; *in; ++in) {
        int x;

        if (isspace(_UC(*in)))
            continue;
        x = OPENSSL_hexchar2int(*in);
        if (x < 0) {
            OPENSSL_free(ret);
            return 0;
        }
        byte |= (char)x;
        if ((nibble ^= 1) == 0) {
            *cp++ = byte;
            byte = 0;
        } else {
            byte <<= 4;
        }
    }
    if (nibble != 0) {
        OPENSSL_free(ret);
        return 0;
    }
    *inptr = in;

    return cp - (*out = ret);
}

/*
 * Decode unsigned 0..255, returns 1 on success, <= 0 on failure. Advances
 * inptr to next field skipping leading whitespace.
 */
static ossl_ssize_t checked_uint8(const char **inptr, void *out)
{
    uint8_t *result = (uint8_t *)out;
    const char *in = *inptr;
    char *endp;
    long v;
    int e;

    save_errno();
    v = strtol(in, &endp, 10);
    e = restore_errno();

    if (((v == LONG_MIN || v == LONG_MAX) && e == ERANGE) ||
        endp == in || !isspace(_UC(*endp)) ||
        v != (*result = (uint8_t) v)) {
        return -1;
    }
    for (in = endp; isspace(_UC(*in)); ++in)
        continue;

    *inptr = in;
    return 1;
}

struct tlsa_field {
    void *var;
    const char *name;
    ossl_ssize_t (*parser)(const char **, void *);
};

static int tlsa_import_rr(SSL *con, const char *rrdata)
{
    /* Not necessary to re-init these values; the "parsers" do that. */
    static uint8_t usage;
    static uint8_t selector;
    static uint8_t mtype;
    static unsigned char *data;
    static struct tlsa_field tlsa_fields[] = {
        { &usage, "usage", checked_uint8 },
        { &selector, "selector", checked_uint8 },
        { &mtype, "mtype", checked_uint8 },
        { &data, "data", hexdecode },
        { NULL, }
    };
    struct tlsa_field *f;
    int ret;
    const char *cp = rrdata;
    ossl_ssize_t len = 0;

    for (f = tlsa_fields; f->var; ++f) {
        /* Returns number of bytes produced, advances cp to next field */
        if ((len = f->parser(&cp, f->var)) <= 0) {
            BIO_printf(bio_err, "%s: warning: bad TLSA %s field in: %s\n",
                       prog, f->name, rrdata);
            return 0;
        }
    }
    /* The data field is last, so len is its length */
    ret = SSL_dane_tlsa_add(con, usage, selector, mtype, data, len);
    OPENSSL_free(data);

    if (ret == 0) {
        ERR_print_errors(bio_err);
        BIO_printf(bio_err, "%s: warning: unusable TLSA rrdata: %s\n",
                   prog, rrdata);
        return 0;
    }
    if (ret < 0) {
        ERR_print_errors(bio_err);
        BIO_printf(bio_err, "%s: warning: error loading TLSA rrdata: %s\n",
                   prog, rrdata);
        return 0;
    }
    return ret;
}

static int tlsa_import_rrset(SSL *con, STACK_OF(OPENSSL_STRING) *rrset)
{
    int num = sk_OPENSSL_STRING_num(rrset);
    int count = 0;
    int i;

    for (i = 0; i < num; ++i) {
        char *rrdata = sk_OPENSSL_STRING_value(rrset, i);
        if (tlsa_import_rr(con, rrdata) > 0)
            ++count;
    }
    return count > 0;
}

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_4, OPT_6, OPT_HOST, OPT_PORT, OPT_CONNECT, OPT_UNIX,
    OPT_XMPPHOST, OPT_VERIFY,
    OPT_CERT, OPT_CRL, OPT_CRL_DOWNLOAD, OPT_SESS_OUT, OPT_SESS_IN,
    OPT_CERTFORM, OPT_CRLFORM, OPT_DCERTFORM, OPT_DCERT, OPT_DKEYFORM,
    OPT_DKEY, OPT_VERIFY_RET_ERROR, OPT_VERIFY_QUIET,
    OPT_BRIEF, OPT_PREXIT, OPT_CRLF, OPT_QUIET, OPT_NBIO,
    OPT_SSL_CLIENT_ENGINE, OPT_RAND, OPT_IGN_EOF, OPT_NO_IGN_EOF,
    OPT_DEBUG, OPT_TLSEXTDEBUG, OPT_STATUS, OPT_WDEBUG,
    OPT_MSG, OPT_MSGFILE, OPT_ENGINE, OPT_TRACE, OPT_SECURITY_DEBUG,
    OPT_SECURITY_DEBUG_VERBOSE, OPT_SHOWCERTS, OPT_NBIO_TEST, OPT_STATE,
#ifndef OPENSSL_NO_PSK
    OPT_PSK_IDENTITY, OPT_PSK,
#endif
#ifndef OPENSSL_NO_SRP
    OPT_SRPUSER, OPT_SRPPASS, OPT_SRP_STRENGTH, OPT_SRP_LATEUSER,
    OPT_SRP_MOREGROUPS,
#endif
    OPT_SSL3, OPT_CONFIG, OPT_SSL_CONFIG,
    OPT_TLS1_2, OPT_TLS1_1, OPT_TLS1, OPT_DTLS, OPT_DTLS1,
    OPT_GMTLS,
    OPT_DTLS1_2, OPT_TIMEOUT, OPT_MTU, OPT_KEYFORM, OPT_PASS,
    OPT_CERT_CHAIN, OPT_CAPATH, OPT_NOCAPATH, OPT_CHAINCAPATH,
        OPT_VERIFYCAPATH,
    OPT_KEY, OPT_RECONNECT, OPT_BUILD_CHAIN, OPT_CAFILE, OPT_NOCAFILE,
    OPT_CHAINCAFILE, OPT_VERIFYCAFILE, OPT_NEXTPROTONEG, OPT_ALPN,
    OPT_SERVERINFO, OPT_STARTTLS, OPT_SERVERNAME,
    OPT_USE_SRTP, OPT_KEYMATEXPORT, OPT_KEYMATEXPORTLEN, OPT_SMTPHOST,
    OPT_ASYNC, OPT_SPLIT_SEND_FRAG, OPT_MAX_PIPELINES, OPT_READ_BUF,
    OPT_V_ENUM,
    OPT_X_ENUM,
    OPT_S_ENUM,
    OPT_FALLBACKSCSV, OPT_NOCMDS, OPT_PROXY, OPT_DANE_TLSA_DOMAIN,
#ifndef OPENSSL_NO_CT
    OPT_CT, OPT_NOCT, OPT_CTLOG_FILE,
#endif
    OPT_DANE_TLSA_RRDATA, OPT_DANE_EE_NO_NAME
} OPTION_CHOICE;

OPTIONS s_client_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"host", OPT_HOST, 's', "Use -connect instead"},
    {"port", OPT_PORT, 'p', "Use -connect instead"},
    {"connect", OPT_CONNECT, 's',
     "TCP/IP where to connect (default is :" PORT ")"},
    {"proxy", OPT_PROXY, 's',
     "Connect to via specified proxy to the real server"},
#ifdef AF_UNIX
    {"unix", OPT_UNIX, 's', "Connect over the specified Unix-domain socket"},
#endif
    {"4", OPT_4, '-', "Use IPv4 only"},
#ifdef AF_INET6
    {"6", OPT_6, '-', "Use IPv6 only"},
#endif
    {"verify", OPT_VERIFY, 'p', "Turn on peer certificate verification"},
    {"cert", OPT_CERT, '<', "Certificate file to use, PEM format assumed"},
    {"certform", OPT_CERTFORM, 'F',
     "Certificate format (PEM or DER) PEM default"},
    {"key", OPT_KEY, 's', "Private key file to use, if not in -cert file"},
    {"keyform", OPT_KEYFORM, 'E', "Key format (PEM, DER or engine) PEM default"},
    {"pass", OPT_PASS, 's', "Private key file pass phrase source"},
    {"dcert", OPT_DCERT, '<', "Second certificate file to use (usually for DSA)"},
    {"dcertform", OPT_DCERTFORM, 'F', "Second certificate format (PEM or DER) PEM default"},
    {"dkey", OPT_DKEY, 's', "Second private key file to use (usually for DSA)"},
    {"dkeyform", OPT_DKEYFORM, 'F', "Second key format (PEM, DER or ENGINE) PEM default"},
    {"CApath", OPT_CAPATH, '/', "PEM format directory of CA's"},
    {"CAfile", OPT_CAFILE, '<', "PEM format file of CA's"},
    {"no-CAfile", OPT_NOCAFILE, '-',
     "Do not load the default certificates file"},
    {"no-CApath", OPT_NOCAPATH, '-',
     "Do not load certificates from the default certificates directory"},
    {"dane_tlsa_domain", OPT_DANE_TLSA_DOMAIN, 's', "DANE TLSA base domain"},
    {"dane_tlsa_rrdata", OPT_DANE_TLSA_RRDATA, 's',
     "DANE TLSA rrdata presentation form"},
    {"dane_ee_no_namechecks", OPT_DANE_EE_NO_NAME, '-',
     "Disable name checks when matching DANE-EE(3) TLSA records"},
    {"reconnect", OPT_RECONNECT, '-',
     "Drop and re-make the connection with the same Session-ID"},
    {"showcerts", OPT_SHOWCERTS, '-', "Show all certificates in the chain"},
    {"debug", OPT_DEBUG, '-', "Extra output"},
    {"msg", OPT_MSG, '-', "Show protocol messages"},
    {"msgfile", OPT_MSGFILE, '>',
     "File to send output of -msg or -trace, instead of stdout"},
    {"nbio_test", OPT_NBIO_TEST, '-', "More ssl protocol testing"},
    {"state", OPT_STATE, '-', "Print the ssl states"},
    {"crlf", OPT_CRLF, '-', "Convert LF from terminal into CRLF"},
    {"quiet", OPT_QUIET, '-', "No s_client output"},
    {"ign_eof", OPT_IGN_EOF, '-', "Ignore input eof (default when -quiet)"},
    {"no_ign_eof", OPT_NO_IGN_EOF, '-', "Don't ignore input eof"},
    {"starttls", OPT_STARTTLS, 's',
     "Use the appropriate STARTTLS command before starting TLS"},
    {"xmpphost", OPT_XMPPHOST, 's',
     "Host to use with \"-starttls xmpp[-server]\""},
    {"rand", OPT_RAND, 's',
     "Load the file(s) into the random number generator"},
    {"sess_out", OPT_SESS_OUT, '>', "File to write SSL session to"},
    {"sess_in", OPT_SESS_IN, '<', "File to read SSL session from"},
    {"use_srtp", OPT_USE_SRTP, 's',
     "Offer SRTP key management with a colon-separated profile list"},
    {"keymatexport", OPT_KEYMATEXPORT, 's',
     "Export keying material using label"},
    {"keymatexportlen", OPT_KEYMATEXPORTLEN, 'p',
     "Export len bytes of keying material (default 20)"},
    {"fallback_scsv", OPT_FALLBACKSCSV, '-', "Send the fallback SCSV"},
    {"name", OPT_SMTPHOST, 's', "Hostname to use for \"-starttls smtp\""},
    {"CRL", OPT_CRL, '<', "CRL file to use"},
    {"crl_download", OPT_CRL_DOWNLOAD, '-', "Download CRL from distribution points"},
    {"CRLform", OPT_CRLFORM, 'F', "CRL format (PEM or DER) PEM is default"},
    {"verify_return_error", OPT_VERIFY_RET_ERROR, '-',
     "Close connection on verification error"},
    {"verify_quiet", OPT_VERIFY_QUIET, '-', "Restrict verify output to errors"},
    {"brief", OPT_BRIEF, '-',
     "Restrict output to brief summary of connection parameters"},
    {"prexit", OPT_PREXIT, '-',
     "Print session information when the program exits"},
    {"security_debug", OPT_SECURITY_DEBUG, '-',
     "Enable security debug messages"},
    {"security_debug_verbose", OPT_SECURITY_DEBUG_VERBOSE, '-',
     "Output more security debug output"},
    {"cert_chain", OPT_CERT_CHAIN, '<',
     "Certificate chain file (in PEM format)"},
    {"chainCApath", OPT_CHAINCAPATH, '/',
     "Use dir as certificate store path to build CA certificate chain"},
    {"verifyCApath", OPT_VERIFYCAPATH, '/',
     "Use dir as certificate store path to verify CA certificate"},
    {"build_chain", OPT_BUILD_CHAIN, '-', "Build certificate chain"},
    {"chainCAfile", OPT_CHAINCAFILE, '<',
     "CA file for certificate chain (PEM format)"},
    {"verifyCAfile", OPT_VERIFYCAFILE, '<',
     "CA file for certificate verification (PEM format)"},
    {"nocommands", OPT_NOCMDS, '-', "Do not use interactive command letters"},
    {"servername", OPT_SERVERNAME, 's',
     "Set TLS extension servername in ClientHello"},
    {"tlsextdebug", OPT_TLSEXTDEBUG, '-',
     "Hex dump of all TLS extensions received"},
#ifndef OPENSSL_NO_OCSP
    {"status", OPT_STATUS, '-', "Request certificate status from server"},
#endif
    {"serverinfo", OPT_SERVERINFO, 's',
     "types  Send empty ClientHello extensions (comma-separated numbers)"},
    {"alpn", OPT_ALPN, 's',
     "Enable ALPN extension, considering named protocols supported (comma-separated list)"},
    {"async", OPT_ASYNC, '-', "Support asynchronous operation"},
    {"config", OPT_CONFIG, 's', "Use configuration file"},
    {"ssl_config", OPT_SSL_CONFIG, 's', "Use specified configuration section"},
    {"split_send_frag", OPT_SPLIT_SEND_FRAG, 'n',
     "Size used to split data for encrypt pipelines"},
    {"max_pipelines", OPT_MAX_PIPELINES, 'n',
     "Maximum number of encrypt/decrypt pipelines to be used"},
    {"read_buf", OPT_READ_BUF, 'n',
     "Default read buffer size to be used for connections"},
    OPT_S_OPTIONS,
    OPT_V_OPTIONS,
    OPT_X_OPTIONS,
#ifndef OPENSSL_NO_SSL3
    {"ssl3", OPT_SSL3, '-', "Just use SSLv3"},
#endif
#ifndef OPENSSL_NO_TLS1
    {"tls1", OPT_TLS1, '-', "Just use TLSv1"},
#endif
#ifndef OPENSSL_NO_TLS1_1
    {"tls1_1", OPT_TLS1_1, '-', "Just use TLSv1.1"},
#endif
#ifndef OPENSSL_NO_TLS1_2
    {"tls1_2", OPT_TLS1_2, '-', "Just use TLSv1.2"},
#endif
#ifndef OPENSSL_NO_DTLS
    {"dtls", OPT_DTLS, '-', "Use any version of DTLS"},
    {"timeout", OPT_TIMEOUT, '-',
     "Enable send/receive timeout on DTLS connections"},
    {"mtu", OPT_MTU, 'p', "Set the link layer MTU"},
#endif
#ifndef OPENSSL_NO_DTLS1
    {"dtls1", OPT_DTLS1, '-', "Just use DTLSv1"},
#endif
#ifndef OPENSSL_NO_DTLS1_2
    {"dtls1_2", OPT_DTLS1_2, '-', "Just use DTLSv1.2"},
#endif
#ifndef OPENSSL_NO_GMTLS
    {"gmtls", OPT_GMTLS, '-', "Just use GMTLS"},
#endif
#ifndef OPENSSL_NO_SSL_TRACE
    {"trace", OPT_TRACE, '-', "Show trace output of protocol messages"},
#endif
#ifdef WATT32
    {"wdebug", OPT_WDEBUG, '-', "WATT-32 tcp debugging"},
#endif
    {"nbio", OPT_NBIO, '-', "Use non-blocking IO"},
#ifndef OPENSSL_NO_PSK
    {"psk_identity", OPT_PSK_IDENTITY, 's', "PSK identity"},
    {"psk", OPT_PSK, 's', "PSK in hex (without 0x)"},
#endif
#ifndef OPENSSL_NO_SRP
    {"srpuser", OPT_SRPUSER, 's', "SRP authentication for 'user'"},
    {"srppass", OPT_SRPPASS, 's', "Password for 'user'"},
    {"srp_lateuser", OPT_SRP_LATEUSER, '-',
     "SRP username into second ClientHello message"},
    {"srp_moregroups", OPT_SRP_MOREGROUPS, '-',
     "Tolerate other than the known g N values."},
    {"srp_strength", OPT_SRP_STRENGTH, 'p', "Minimal length in bits for N"},
#endif
#ifndef OPENSSL_NO_NEXTPROTONEG
    {"nextprotoneg", OPT_NEXTPROTONEG, 's',
     "Enable NPN extension, considering named protocols supported (comma-separated list)"},
#endif
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
    {"ssl_client_engine", OPT_SSL_CLIENT_ENGINE, 's',
     "Specify engine to be used for client certificate operations"},
#endif
#ifndef OPENSSL_NO_CT
    {"ct", OPT_CT, '-', "Request and parse SCTs (also enables OCSP stapsection)"},
    {"noct", OPT_NOCT, '-', "Do not request or parse SCTs (default)"},
    {"ctlogfile", OPT_CTLOG_FILE, '<', "CT log list CONF file"},
#endif
    {NULL, OPT_EOF, 0x00, NULL}
};

typedef enum PROTOCOL_choice {
    PROTO_OFF,
    PROTO_SMTP,
    PROTO_POP3,
    PROTO_IMAP,
    PROTO_FTP,
    PROTO_TELNET,
    PROTO_XMPP,
    PROTO_XMPP_SERVER,
    PROTO_CONNECT,
    PROTO_IRC
} PROTOCOL_CHOICE;

static const OPT_PAIR services[] = {
    {"smtp", PROTO_SMTP},
    {"pop3", PROTO_POP3},
    {"imap", PROTO_IMAP},
    {"ftp", PROTO_FTP},
    {"xmpp", PROTO_XMPP},
    {"xmpp-server", PROTO_XMPP_SERVER},
    {"telnet", PROTO_TELNET},
    {"irc", PROTO_IRC},
    {NULL, 0}
};

#define IS_INET_FLAG(o) \
 (o == OPT_4 || o == OPT_6 || o == OPT_HOST || o == OPT_PORT || o == OPT_CONNECT)
#define IS_UNIX_FLAG(o) (o == OPT_UNIX)

#define IS_PROT_FLAG(o) \
 (o == OPT_SSL3 || o == OPT_TLS1 || o == OPT_TLS1_1 || o == OPT_TLS1_2 \
  || o == OPT_GMTLS \
  || o == OPT_DTLS || o == OPT_DTLS1 || o == OPT_DTLS1_2)

/* Free |*dest| and optionally set it to a copy of |source|. */
static void freeandcopy(char **dest, const char *source)
{
    OPENSSL_free(*dest);
    *dest = NULL;
    if (source != NULL)
        *dest = OPENSSL_strdup(source);
}

int s_client_main(int argc, char **argv)
{
    BIO *sbio;
    EVP_PKEY *key = NULL, *dkey = NULL;
    SSL *con = NULL;
    SSL_CTX *ctx = NULL;
    STACK_OF(X509) *chain = NULL, *dchain = NULL;
    X509 *cert = NULL, *dcert = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    SSL_EXCERT *exc = NULL;
    SSL_CONF_CTX *cctx = NULL;
    STACK_OF(OPENSSL_STRING) *ssl_args = NULL;
    char *dane_tlsa_domain = NULL;
    STACK_OF(OPENSSL_STRING) *dane_tlsa_rrset = NULL;
    int dane_ee_no_name = 0;
    STACK_OF(X509_CRL) *crls = NULL;
    const SSL_METHOD *meth = TLS_client_method();
    const char *CApath = NULL, *CAfile = NULL;
    char *cbuf = NULL, *sbuf = NULL;
    char *mbuf = NULL, *proxystr = NULL, *connectstr = NULL;
    char *cert_file = NULL, *key_file = NULL, *chain_file = NULL;
    char *dcert_file = NULL, *dkey_file = NULL, *dchain_file = NULL;
    char *chCApath = NULL, *chCAfile = NULL, *host = NULL;
    char *port = OPENSSL_strdup(PORT);
    char *inrand = NULL;
    char *passarg = NULL, *pass = NULL, *vfyCApath = NULL, *vfyCAfile = NULL;
    char *dpassarg = NULL, *dpass = NULL;
    char *sess_in = NULL, *sess_out = NULL, *crl_file = NULL, *p;
    char *xmpphost = NULL;
    const char *ehlo = "mail.example.com";
    struct timeval timeout, *timeoutp;
    fd_set readfds, writefds;
    int noCApath = 0, noCAfile = 0;
    int build_chain = 0, cbuf_len, cbuf_off, cert_format = FORMAT_PEM;
    int key_format = FORMAT_PEM, crlf = 0, full_log = 1, mbuf_len = 0;
    int dcert_format = FORMAT_PEM, dkey_format = FORMAT_PEM;
    int prexit = 0;
    int sdebug = 0;
    int reconnect = 0, verify = SSL_VERIFY_NONE, vpmtouched = 0;
    int ret = 1, in_init = 1, i, nbio_test = 0, s = -1, k, width, state = 0;
    int sbuf_len, sbuf_off, cmdletters = 1;
    int socket_family = AF_UNSPEC, socket_type = SOCK_STREAM;
    int starttls_proto = PROTO_OFF, crl_format = FORMAT_PEM, crl_download = 0;
    int write_tty, read_tty, write_ssl, read_ssl, tty_on, ssl_pending;
#if !defined(OPENSSL_SYS_WINDOWS) && !defined(OPENSSL_SYS_MSDOS)
    int at_eof = 0;
#endif
    int read_buf_len = 0;
    int fallback_scsv = 0;
    long randamt = 0;
    OPTION_CHOICE o;
#ifndef OPENSSL_NO_DTLS
    int enable_timeouts = 0;
    long socket_mtu = 0;
#endif
#ifndef OPENSSL_NO_ENGINE
    ENGINE *ssl_client_engine = NULL;
#endif
    ENGINE *e = NULL;
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS)
    struct timeval tv;
#endif
    char *servername = NULL;
    const char *alpn_in = NULL;
    tlsextctx tlsextcbp = { NULL, 0 };
    CONF *conf = NULL;
    const char *configfile = default_config_file;
    const char *ssl_config = NULL;
#define MAX_SI_TYPES 100
    unsigned short serverinfo_types[MAX_SI_TYPES];
    int serverinfo_count = 0, start = 0, len;
#ifndef OPENSSL_NO_NEXTPROTONEG
    const char *next_proto_neg_in = NULL;
#endif
#ifndef OPENSSL_NO_SRP
    char *srppass = NULL;
    int srp_lateuser = 0;
    SRP_ARG srp_arg = { NULL, NULL, 0, 0, 0, 1024 };
#endif
#ifndef OPENSSL_NO_CT
    char *ctlog_file = NULL;
    int ct_validation = 0;
#endif
    int min_version = 0, max_version = 0, prot_opt = 0, no_prot_opt = 0;
    int async = 0;
    unsigned int split_send_fragment = 0;
    unsigned int max_pipelines = 0;
    enum { use_inet, use_unix, use_unknown } connect_type = use_unknown;
    int count4or6 = 0;
    int c_nbio = 0, c_msg = 0, c_ign_eof = 0, c_brief = 0;
    int c_tlsextdebug = 0;
#ifndef OPENSSL_NO_OCSP
    int c_status_req = 0;
#endif
    BIO *bio_c_msg = NULL;

    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
/* Known false-positive of MemorySanitizer. */
#if defined(__has_feature)
# if __has_feature(memory_sanitizer)
    __msan_unpoison(&readfds, sizeof(readfds));
    __msan_unpoison(&writefds, sizeof(writefds));
# endif
#endif

    prog = opt_progname(argv[0]);
    c_quiet = 0;
    c_debug = 0;
    c_showcerts = 0;
    c_nbio = 0;
    vpm = X509_VERIFY_PARAM_new();
    cctx = SSL_CONF_CTX_new();

    if (vpm == NULL || cctx == NULL) {
        BIO_printf(bio_err, "%s: out of memory\n", prog);
        goto end;
    }

    cbuf = app_malloc(BUFSIZZ, "cbuf");
    sbuf = app_malloc(BUFSIZZ, "sbuf");
    mbuf = app_malloc(BUFSIZZ, "mbuf");

    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CLIENT | SSL_CONF_FLAG_CMDLINE);

    prog = opt_init(argc, argv, s_client_options);
    while ((o = opt_next()) != OPT_EOF) {
        /* Check for intermixing flags. */
        if (connect_type == use_unix && IS_INET_FLAG(o)) {
            BIO_printf(bio_err,
                       "%s: Intermixed protocol flags (unix and internet domains)\n",
                       prog);
            goto end;
        }
        if (connect_type == use_inet && IS_UNIX_FLAG(o)) {
            BIO_printf(bio_err,
                       "%s: Intermixed protocol flags (internet and unix domains)\n",
                       prog);
            goto end;
        }

        if (IS_PROT_FLAG(o) && ++prot_opt > 1) {
            BIO_printf(bio_err, "Cannot supply multiple protocol flags\n");
            goto end;
        }
        if (IS_NO_PROT_FLAG(o))
            no_prot_opt++;
        if (prot_opt == 1 && no_prot_opt) {
            BIO_printf(bio_err,
                       "Cannot supply both a protocol flag and '-no_<prot>'\n");
            goto end;
        }

        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(s_client_options);
            ret = 0;
            goto end;
        case OPT_4:
            connect_type = use_inet;
            socket_family = AF_INET;
            count4or6++;
            break;
#ifdef AF_INET6
        case OPT_6:
            connect_type = use_inet;
            socket_family = AF_INET6;
            count4or6++;
            break;
#endif
        case OPT_HOST:
            connect_type = use_inet;
            freeandcopy(&host, opt_arg());
            break;
        case OPT_PORT:
            connect_type = use_inet;
            freeandcopy(&port, opt_arg());
            break;
        case OPT_CONNECT:
            connect_type = use_inet;
            freeandcopy(&connectstr, opt_arg());
            break;
        case OPT_PROXY:
            proxystr = opt_arg();
            starttls_proto = PROTO_CONNECT;
            break;
#ifdef AF_UNIX
        case OPT_UNIX:
            connect_type = use_unix;
            socket_family = AF_UNIX;
            freeandcopy(&host, opt_arg());
            break;
#endif
        case OPT_XMPPHOST:
            xmpphost = opt_arg();
            break;
        case OPT_SMTPHOST:
            ehlo = opt_arg();
            break;
        case OPT_VERIFY:
            verify = SSL_VERIFY_PEER;
            verify_args.depth = atoi(opt_arg());
            if (!c_quiet)
                BIO_printf(bio_err, "verify depth is %d\n", verify_args.depth);
            break;
        case OPT_CERT:
            cert_file = opt_arg();
            break;
        case OPT_CRL:
            crl_file = opt_arg();
            break;
        case OPT_CRL_DOWNLOAD:
            crl_download = 1;
            break;
        case OPT_SESS_OUT:
            sess_out = opt_arg();
            break;
        case OPT_SESS_IN:
            sess_in = opt_arg();
            break;
        case OPT_CERTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &cert_format))
                goto opthelp;
            break;
        case OPT_CRLFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &crl_format))
                goto opthelp;
            break;
        case OPT_DCERTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &dcert_format))
                goto opthelp;
            break;
        case OPT_DCERT:
            dcert_file = opt_arg();
            break;
        case OPT_DKEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &dkey_format))
                goto opthelp;
            break;
        case OPT_DKEY:
            dkey_file = opt_arg();
            break;
        case OPT_VERIFY_RET_ERROR:
            verify_args.return_error = 1;
            break;
        case OPT_VERIFY_QUIET:
            verify_args.quiet = 1;
            break;
        case OPT_BRIEF:
            c_brief = verify_args.quiet = c_quiet = 1;
            break;
        case OPT_S_CASES:
            if (ssl_args == NULL)
                ssl_args = sk_OPENSSL_STRING_new_null();
            if (ssl_args == NULL
                || !sk_OPENSSL_STRING_push(ssl_args, opt_flag())
                || !sk_OPENSSL_STRING_push(ssl_args, opt_arg())) {
                BIO_printf(bio_err, "%s: Memory allocation failure\n", prog);
                goto end;
            }
            break;
        case OPT_V_CASES:
            if (!opt_verify(o, vpm))
                goto end;
            vpmtouched++;
            break;
        case OPT_X_CASES:
            if (!args_excert(o, &exc))
                goto end;
            break;
        case OPT_PREXIT:
            prexit = 1;
            break;
        case OPT_CRLF:
            crlf = 1;
            break;
        case OPT_QUIET:
            c_quiet = c_ign_eof = 1;
            break;
        case OPT_NBIO:
            c_nbio = 1;
            break;
        case OPT_NOCMDS:
            cmdletters = 0;
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 1);
            break;
        case OPT_SSL_CLIENT_ENGINE:
#ifndef OPENSSL_NO_ENGINE
            ssl_client_engine = ENGINE_by_id(opt_arg());
            if (ssl_client_engine == NULL) {
                BIO_printf(bio_err, "Error getting client auth engine\n");
                goto opthelp;
            }
#endif
            break;
        case OPT_RAND:
            inrand = opt_arg();
            break;
        case OPT_IGN_EOF:
            c_ign_eof = 1;
            break;
        case OPT_NO_IGN_EOF:
            c_ign_eof = 0;
            break;
        case OPT_DEBUG:
            c_debug = 1;
            break;
        case OPT_TLSEXTDEBUG:
            c_tlsextdebug = 1;
            break;
        case OPT_STATUS:
#ifndef OPENSSL_NO_OCSP
            c_status_req = 1;
#endif
            break;
        case OPT_WDEBUG:
#ifdef WATT32
            dbug_init();
#endif
            break;
        case OPT_MSG:
            c_msg = 1;
            break;
        case OPT_MSGFILE:
            bio_c_msg = BIO_new_file(opt_arg(), "w");
            break;
        case OPT_TRACE:
#ifndef OPENSSL_NO_SSL_TRACE
            c_msg = 2;
#endif
            break;
        case OPT_SECURITY_DEBUG:
            sdebug = 1;
            break;
        case OPT_SECURITY_DEBUG_VERBOSE:
            sdebug = 2;
            break;
        case OPT_SHOWCERTS:
            c_showcerts = 1;
            break;
        case OPT_NBIO_TEST:
            nbio_test = 1;
            break;
        case OPT_STATE:
            state = 1;
            break;
#ifndef OPENSSL_NO_PSK
        case OPT_PSK_IDENTITY:
            psk_identity = opt_arg();
            break;
        case OPT_PSK:
            for (p = psk_key = opt_arg(); *p; p++) {
                if (isxdigit(_UC(*p)))
                    continue;
                BIO_printf(bio_err, "Not a hex number '%s'\n", psk_key);
                goto end;
            }
            break;
#endif
#ifndef OPENSSL_NO_SRP
        case OPT_SRPUSER:
            srp_arg.srplogin = opt_arg();
            if (min_version < TLS1_VERSION)
                min_version = TLS1_VERSION;
            break;
        case OPT_SRPPASS:
            srppass = opt_arg();
            if (min_version < TLS1_VERSION)
                min_version = TLS1_VERSION;
            break;
        case OPT_SRP_STRENGTH:
            srp_arg.strength = atoi(opt_arg());
            BIO_printf(bio_err, "SRP minimal length for N is %d\n",
                       srp_arg.strength);
            if (min_version < TLS1_VERSION)
                min_version = TLS1_VERSION;
            break;
        case OPT_SRP_LATEUSER:
            srp_lateuser = 1;
            if (min_version < TLS1_VERSION)
                min_version = TLS1_VERSION;
            break;
        case OPT_SRP_MOREGROUPS:
            srp_arg.amp = 1;
            if (min_version < TLS1_VERSION)
                min_version = TLS1_VERSION;
            break;
#endif
        case OPT_CONFIG:
            configfile = opt_arg();
            break;
        case OPT_SSL_CONFIG:
            ssl_config = opt_arg();
            break;
        case OPT_SSL3:
            min_version = SSL3_VERSION;
            max_version = SSL3_VERSION;
            break;
        case OPT_TLS1_2:
            min_version = TLS1_2_VERSION;
            max_version = TLS1_2_VERSION;
            break;
        case OPT_TLS1_1:
            min_version = TLS1_1_VERSION;
            max_version = TLS1_1_VERSION;
            break;
        case OPT_TLS1:
            min_version = TLS1_VERSION;
            max_version = TLS1_VERSION;
            break;
        case OPT_DTLS:
#ifndef OPENSSL_NO_DTLS
            meth = DTLS_client_method();
            socket_type = SOCK_DGRAM;
#endif
            break;
        case OPT_DTLS1:
#ifndef OPENSSL_NO_DTLS1
            meth = DTLS_client_method();
            min_version = DTLS1_VERSION;
            max_version = DTLS1_VERSION;
            socket_type = SOCK_DGRAM;
#endif
            break;
        case OPT_DTLS1_2:
#ifndef OPENSSL_NO_DTLS1_2
            meth = DTLS_client_method();
            min_version = DTLS1_2_VERSION;
            max_version = DTLS1_2_VERSION;
            socket_type = SOCK_DGRAM;
#endif
            break;
        case OPT_GMTLS:
#ifndef OPENSSL_NO_GMTLS
            meth = GMTLS_client_method();
            //min_version = GMTLS_VERSION;
            //max_version = GMTLS_VERSION;
#endif
            break;
       case OPT_TIMEOUT:
#ifndef OPENSSL_NO_DTLS
            enable_timeouts = 1;
#endif
            break;
        case OPT_MTU:
#ifndef OPENSSL_NO_DTLS
            socket_mtu = atol(opt_arg());
#endif
            break;
        case OPT_FALLBACKSCSV:
            fallback_scsv = 1;
            break;
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PDE, &key_format))
                goto opthelp;
            break;
        case OPT_PASS:
            passarg = opt_arg();
            break;
        case OPT_CERT_CHAIN:
            chain_file = opt_arg();
            break;
        case OPT_KEY:
            key_file = opt_arg();
            break;
        case OPT_RECONNECT:
            reconnect = 5;
            break;
        case OPT_CAPATH:
            CApath = opt_arg();
            break;
        case OPT_NOCAPATH:
            noCApath = 1;
            break;
        case OPT_CHAINCAPATH:
            chCApath = opt_arg();
            break;
        case OPT_VERIFYCAPATH:
            vfyCApath = opt_arg();
            break;
        case OPT_BUILD_CHAIN:
            build_chain = 1;
            break;
        case OPT_CAFILE:
            CAfile = opt_arg();
            break;
        case OPT_NOCAFILE:
            noCAfile = 1;
            break;
#ifndef OPENSSL_NO_CT
        case OPT_NOCT:
            ct_validation = 0;
            break;
        case OPT_CT:
            ct_validation = 1;
            break;
        case OPT_CTLOG_FILE:
            ctlog_file = opt_arg();
            break;
#endif
        case OPT_CHAINCAFILE:
            chCAfile = opt_arg();
            break;
        case OPT_VERIFYCAFILE:
            vfyCAfile = opt_arg();
            break;
        case OPT_DANE_TLSA_DOMAIN:
            dane_tlsa_domain = opt_arg();
            break;
        case OPT_DANE_TLSA_RRDATA:
            if (dane_tlsa_rrset == NULL)
                dane_tlsa_rrset = sk_OPENSSL_STRING_new_null();
            if (dane_tlsa_rrset == NULL ||
                !sk_OPENSSL_STRING_push(dane_tlsa_rrset, opt_arg())) {
                BIO_printf(bio_err, "%s: Memory allocation failure\n", prog);
                goto end;
            }
            break;
        case OPT_DANE_EE_NO_NAME:
            dane_ee_no_name = 1;
            break;
        case OPT_NEXTPROTONEG:
#ifndef OPENSSL_NO_NEXTPROTONEG
            next_proto_neg_in = opt_arg();
#endif
            break;
        case OPT_ALPN:
            alpn_in = opt_arg();
            break;
        case OPT_SERVERINFO:
            p = opt_arg();
            len = strlen(p);
            for (start = 0, i = 0; i <= len; ++i) {
                if (i == len || p[i] == ',') {
                    serverinfo_types[serverinfo_count] = atoi(p + start);
                    if (++serverinfo_count == MAX_SI_TYPES)
                        break;
                    start = i + 1;
                }
            }
            break;
        case OPT_STARTTLS:
            if (!opt_pair(opt_arg(), services, &starttls_proto))
                goto end;
            break;
        case OPT_SERVERNAME:
            servername = opt_arg();
            break;
        case OPT_USE_SRTP:
            srtp_profiles = opt_arg();
            break;
        case OPT_KEYMATEXPORT:
            keymatexportlabel = opt_arg();
            break;
        case OPT_KEYMATEXPORTLEN:
            keymatexportlen = atoi(opt_arg());
            break;
        case OPT_ASYNC:
            async = 1;
            break;
        case OPT_SPLIT_SEND_FRAG:
            split_send_fragment = atoi(opt_arg());
            if (split_send_fragment == 0) {
                /*
                 * Not allowed - set to a deliberately bad value so we get an
                 * error message below
                 */
                split_send_fragment = SSL3_RT_MAX_PLAIN_LENGTH + 1;
            }
            break;
        case OPT_MAX_PIPELINES:
            max_pipelines = atoi(opt_arg());
            break;
        case OPT_READ_BUF:
            read_buf_len = atoi(opt_arg());
            break;
        }
    }
    if (count4or6 >= 2) {
        BIO_printf(bio_err, "%s: Can't use both -4 and -6\n", prog);
        goto opthelp;
    }
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    if (e)
        BIO_printf(bio_err, "Using configuration from %s\n", configfile);
    if ((conf = app_load_config(configfile)) == NULL)
        goto end;
    if (configfile != default_config_file && !app_load_modules(conf))
        goto end;

    if (proxystr) {
        int res;
        char *tmp_host = host, *tmp_port = port;
        if (connectstr == NULL) {
            BIO_printf(bio_err, "%s: -proxy requires use of -connect\n", prog);
            goto opthelp;
        }
        res = BIO_parse_hostserv(proxystr, &host, &port, BIO_PARSE_PRIO_HOST);
        if (tmp_host != host)
            OPENSSL_free(tmp_host);
        if (tmp_port != port)
            OPENSSL_free(tmp_port);
        if (!res) {
            BIO_printf(bio_err,
                       "%s: -proxy argument malformed or ambiguous\n", prog);
            goto end;
        }
    } else {
        int res = 1;
        char *tmp_host = host, *tmp_port = port;
        if (connectstr != NULL)
            res = BIO_parse_hostserv(connectstr, &host, &port,
                                     BIO_PARSE_PRIO_HOST);
        if (tmp_host != host)
            OPENSSL_free(tmp_host);
        if (tmp_port != port)
            OPENSSL_free(tmp_port);
        if (!res) {
            BIO_printf(bio_err,
                       "%s: -connect argument malformed or ambiguous\n",
                       prog);
            goto end;
        }
    }

    if (socket_family == AF_UNIX && socket_type != SOCK_STREAM) {
        BIO_printf(bio_err,
                   "Can't use unix sockets and datagrams together\n");
        goto end;
    }

    if (split_send_fragment > SSL3_RT_MAX_PLAIN_LENGTH) {
        BIO_printf(bio_err, "Bad split send fragment size\n");
        goto end;
    }

    if (max_pipelines > SSL_MAX_PIPELINES) {
        BIO_printf(bio_err, "Bad max pipelines value\n");
        goto end;
    }

#if !defined(OPENSSL_NO_NEXTPROTONEG)
    next_proto.status = -1;
    if (next_proto_neg_in) {
        next_proto.data =
            next_protos_parse(&next_proto.len, next_proto_neg_in);
        if (next_proto.data == NULL) {
            BIO_printf(bio_err, "Error parsing -nextprotoneg argument\n");
            goto end;
        }
    } else
        next_proto.data = NULL;
#endif

    if (!app_passwd(passarg, dpassarg, &pass, &dpass)) {
        BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }

    if (key_file == NULL)
        key_file = cert_file;

    if (key_file) {
        key = load_key(key_file, key_format, 0, pass, e,
                       "client certificate private key file");
        if (key == NULL) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (cert_file) {
        cert = load_cert(cert_file, cert_format, "client certificate file");
        if (cert == NULL) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (chain_file) {
        if (!load_certs(chain_file, &chain, FORMAT_PEM, NULL,
                        "client certificate chain"))
            goto end;
    }

    if (crl_file) {
        X509_CRL *crl;
        crl = load_crl(crl_file, crl_format);
        if (crl == NULL) {
            BIO_puts(bio_err, "Error loading CRL\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        crls = sk_X509_CRL_new_null();
        if (crls == NULL || !sk_X509_CRL_push(crls, crl)) {
            BIO_puts(bio_err, "Error adding CRL\n");
            ERR_print_errors(bio_err);
            X509_CRL_free(crl);
            goto end;
        }
    }

    if (!load_excert(&exc))
        goto end;

    if (!app_RAND_load_file(NULL, 1) && inrand == NULL
        && !RAND_status()) {
        BIO_printf(bio_err,
                   "warning, not much extra random data, consider using the -rand option\n");
    }
    if (inrand != NULL) {
        randamt = app_RAND_load_files(inrand);
        BIO_printf(bio_err, "%ld semi-random bytes loaded\n", randamt);
    }

    if (dcert_file) {
        if (dkey_file == NULL) {
            dkey_file = dcert_file;
        }

        dkey = load_key(dkey_file, dkey_format, 0, dpass, e,
                        "second certificate private key file");
        if (!dkey) {
            ERR_print_errors(bio_err);
            goto end;
        }

        dcert = load_cert(dcert_file, dcert_format,
                            "second server certificate file");
        if (!dcert) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (bio_c_out == NULL) {
        if (c_quiet && !c_debug) {
            bio_c_out = BIO_new(BIO_s_null());
            if (c_msg && !bio_c_msg)
                bio_c_msg = dup_bio_out(FORMAT_TEXT);
        } else if (bio_c_out == NULL)
            bio_c_out = dup_bio_out(FORMAT_TEXT);
    }
#ifndef OPENSSL_NO_SRP
    if (!app_passwd(srppass, NULL, &srp_arg.srppassin, NULL)) {
        BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }
#endif

    ctx = SSL_CTX_new(meth);
    if (ctx == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }

    if (sdebug)
        ssl_ctx_security_debug(ctx, sdebug);

    if (ssl_config) {
        if (SSL_CTX_config(ctx, ssl_config) == 0) {
            BIO_printf(bio_err, "Error using configuration \"%s\"\n",
                       ssl_config);
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (SSL_CTX_set_min_proto_version(ctx, min_version) == 0)
        goto end;
    if (SSL_CTX_set_max_proto_version(ctx, max_version) == 0)
        goto end;

    if (vpmtouched && !SSL_CTX_set1_param(ctx, vpm)) {
        BIO_printf(bio_err, "Error setting verify params\n");
        ERR_print_errors(bio_err);
        goto end;
    }

    if (async) {
        SSL_CTX_set_mode(ctx, SSL_MODE_ASYNC);
    }
    if (split_send_fragment > 0) {
        SSL_CTX_set_split_send_fragment(ctx, split_send_fragment);
    }
    if (max_pipelines > 0) {
        SSL_CTX_set_max_pipelines(ctx, max_pipelines);
    }

    if (read_buf_len > 0) {
        SSL_CTX_set_default_read_buffer_len(ctx, read_buf_len);
    }

    if (!config_ctx(cctx, ssl_args, ctx))
        goto end;

    if (!ssl_load_stores(ctx, vfyCApath, vfyCAfile, chCApath, chCAfile,
                         crls, crl_download)) {
        BIO_printf(bio_err, "Error loading store locations\n");
        ERR_print_errors(bio_err);
        goto end;
    }
#ifndef OPENSSL_NO_ENGINE
    if (ssl_client_engine) {
        if (!SSL_CTX_set_client_cert_engine(ctx, ssl_client_engine)) {
            BIO_puts(bio_err, "Error setting client auth engine\n");
            ERR_print_errors(bio_err);
            ENGINE_free(ssl_client_engine);
            goto end;
        }
        ENGINE_free(ssl_client_engine);
    }
#endif

#ifndef OPENSSL_NO_PSK
    if (psk_key != NULL) {
        if (c_debug)
            BIO_printf(bio_c_out, "PSK key given, setting client callback\n");
        SSL_CTX_set_psk_client_callback(ctx, psk_client_cb);
    }
#endif
#ifndef OPENSSL_NO_SRTP
    if (srtp_profiles != NULL) {
        /* Returns 0 on success! */
        if (SSL_CTX_set_tlsext_use_srtp(ctx, srtp_profiles) != 0) {
            BIO_printf(bio_err, "Error setting SRTP profile\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    }
#endif

    if (exc)
        ssl_ctx_set_excert(ctx, exc);

#if !defined(OPENSSL_NO_NEXTPROTONEG)
    if (next_proto.data)
        SSL_CTX_set_next_proto_select_cb(ctx, next_proto_cb, &next_proto);
#endif
    if (alpn_in) {
        size_t alpn_len;
        unsigned char *alpn = next_protos_parse(&alpn_len, alpn_in);

        if (alpn == NULL) {
            BIO_printf(bio_err, "Error parsing -alpn argument\n");
            goto end;
        }
        /* Returns 0 on success! */
        if (SSL_CTX_set_alpn_protos(ctx, alpn, alpn_len) != 0) {
            BIO_printf(bio_err, "Error setting ALPN\n");
            goto end;
        }
        OPENSSL_free(alpn);
    }

    for (i = 0; i < serverinfo_count; i++) {
        if (!SSL_CTX_add_client_custom_ext(ctx,
                                           serverinfo_types[i],
                                           NULL, NULL, NULL,
                                           serverinfo_cli_parse_cb, NULL)) {
            BIO_printf(bio_err,
                       "Warning: Unable to add custom extension %u, skipping\n",
                       serverinfo_types[i]);
        }
    }

    if (state)
        SSL_CTX_set_info_callback(ctx, apps_ssl_info_callback);

#ifndef OPENSSL_NO_CT
    /* Enable SCT processing, without early connection termination */
    if (ct_validation &&
        !SSL_CTX_enable_ct(ctx, SSL_CT_VALIDATION_PERMISSIVE)) {
        ERR_print_errors(bio_err);
        goto end;
    }

    if (!ctx_set_ctlog_list_file(ctx, ctlog_file)) {
        if (ct_validation) {
            ERR_print_errors(bio_err);
            goto end;
        }

        /*
         * If CT validation is not enabled, the log list isn't needed so don't
         * show errors or abort. We try to load it regardless because then we
         * can show the names of the logs any SCTs came from (SCTs may be seen
         * even with validation disabled).
         */
        ERR_clear_error();
    }
#endif

    SSL_CTX_set_verify(ctx, verify, verify_callback);

    if (!ctx_set_verify_locations(ctx, CAfile, CApath, noCAfile, noCApath)) {
        ERR_print_errors(bio_err);
        goto end;
    }

    ssl_ctx_add_crls(ctx, crls, crl_download);

    if (!set_cert_key_stuff(ctx, cert, key, chain, build_chain))
        goto end;

    if (dcert != NULL) {
        if (!set_cert_key_stuff(ctx, dcert, dkey, dchain, build_chain)) {
            goto end;
        }
    }

    if (servername != NULL) {
        tlsextcbp.biodebug = bio_err;
        SSL_CTX_set_tlsext_servername_callback(ctx, ssl_servername_cb);
        SSL_CTX_set_tlsext_servername_arg(ctx, &tlsextcbp);
    }
# ifndef OPENSSL_NO_SRP
    if (srp_arg.srplogin) {
        if (!srp_lateuser && !SSL_CTX_set_srp_username(ctx, srp_arg.srplogin)) {
            BIO_printf(bio_err, "Unable to set SRP username\n");
            goto end;
        }
        srp_arg.msg = c_msg;
        srp_arg.debug = c_debug;
        SSL_CTX_set_srp_cb_arg(ctx, &srp_arg);
        SSL_CTX_set_srp_client_pwd_callback(ctx, ssl_give_srp_client_pwd_cb);
        SSL_CTX_set_srp_strength(ctx, srp_arg.strength);
        if (c_msg || c_debug || srp_arg.amp == 0)
            SSL_CTX_set_srp_verify_param_callback(ctx,
                                                  ssl_srp_verify_param_cb);
    }
# endif

    if (dane_tlsa_domain != NULL) {
        if (SSL_CTX_dane_enable(ctx) <= 0) {
            BIO_printf(bio_err,
                       "%s: Error enabling DANE TLSA authentication.\n",
                       prog);
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    con = SSL_new(ctx);
    if (sess_in) {
        SSL_SESSION *sess;
        BIO *stmp = BIO_new_file(sess_in, "r");
        if (!stmp) {
            BIO_printf(bio_err, "Can't open session file %s\n", sess_in);
            ERR_print_errors(bio_err);
            goto end;
        }
        sess = PEM_read_bio_SSL_SESSION(stmp, NULL, 0, NULL);
        BIO_free(stmp);
        if (!sess) {
            BIO_printf(bio_err, "Can't open session file %s\n", sess_in);
            ERR_print_errors(bio_err);
            goto end;
        }
        if (!SSL_set_session(con, sess)) {
            BIO_printf(bio_err, "Can't set session\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        SSL_SESSION_free(sess);
    }

    if (fallback_scsv)
        SSL_set_mode(con, SSL_MODE_SEND_FALLBACK_SCSV);

    if (servername != NULL) {
        if (!SSL_set_tlsext_host_name(con, servername)) {
            BIO_printf(bio_err, "Unable to set TLS servername extension.\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (dane_tlsa_domain != NULL) {
        if (SSL_dane_enable(con, dane_tlsa_domain) <= 0) {
            BIO_printf(bio_err, "%s: Error enabling DANE TLSA "
                       "authentication.\n", prog);
            ERR_print_errors(bio_err);
            goto end;
        }
        if (dane_tlsa_rrset == NULL) {
            BIO_printf(bio_err, "%s: DANE TLSA authentication requires at "
                       "least one -dane_tlsa_rrdata option.\n", prog);
            goto end;
        }
        if (tlsa_import_rrset(con, dane_tlsa_rrset) <= 0) {
            BIO_printf(bio_err, "%s: Failed to import any TLSA "
                       "records.\n", prog);
            goto end;
        }
        if (dane_ee_no_name)
            SSL_dane_set_flags(con, DANE_FLAG_NO_DANE_EE_NAMECHECKS);
    } else if (dane_tlsa_rrset != NULL) {
        BIO_printf(bio_err, "%s: DANE TLSA authentication requires the "
                   "-dane_tlsa_domain option.\n", prog);
        goto end;
    }

 re_start:
    if (init_client(&s, host, port, socket_family, socket_type) == 0) {
        BIO_printf(bio_err, "connect:errno=%d\n", get_last_socket_error());
        BIO_closesocket(s);
        goto end;
    }
    BIO_printf(bio_c_out, "CONNECTED(%08X)\n", s);

    if (c_nbio) {
        if (!BIO_socket_nbio(s, 1)) {
            ERR_print_errors(bio_err);
            goto end;
        }
        BIO_printf(bio_c_out, "Turned on non blocking io\n");
    }
#ifndef OPENSSL_NO_DTLS
    if (socket_type == SOCK_DGRAM) {
        union BIO_sock_info_u peer_info;

        sbio = BIO_new_dgram(s, BIO_NOCLOSE);
        if ((peer_info.addr = BIO_ADDR_new()) == NULL) {
            BIO_printf(bio_err, "memory allocation failure\n");
            BIO_closesocket(s);
            goto end;
        }
        if (!BIO_sock_info(s, BIO_SOCK_INFO_ADDRESS, &peer_info)) {
            BIO_printf(bio_err, "getsockname:errno=%d\n",
                       get_last_socket_error());
            BIO_ADDR_free(peer_info.addr);
            BIO_closesocket(s);
            goto end;
        }

        (void)BIO_ctrl_set_connected(sbio, peer_info.addr);
        BIO_ADDR_free(peer_info.addr);
        peer_info.addr = NULL;

        if (enable_timeouts) {
            timeout.tv_sec = 0;
            timeout.tv_usec = DGRAM_RCV_TIMEOUT;
            BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

            timeout.tv_sec = 0;
            timeout.tv_usec = DGRAM_SND_TIMEOUT;
            BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &timeout);
        }

        if (socket_mtu) {
            if (socket_mtu < DTLS_get_link_min_mtu(con)) {
                BIO_printf(bio_err, "MTU too small. Must be at least %ld\n",
                           DTLS_get_link_min_mtu(con));
                BIO_free(sbio);
                goto shut;
            }
            SSL_set_options(con, SSL_OP_NO_QUERY_MTU);
            if (!DTLS_set_link_mtu(con, socket_mtu)) {
                BIO_printf(bio_err, "Failed to set MTU\n");
                BIO_free(sbio);
                goto shut;
            }
        } else
            /* want to do MTU discovery */
            BIO_ctrl(sbio, BIO_CTRL_DGRAM_MTU_DISCOVER, 0, NULL);
    } else
#endif /* OPENSSL_NO_DTLS */
        sbio = BIO_new_socket(s, BIO_NOCLOSE);

    if (nbio_test) {
        BIO *test;

        test = BIO_new(BIO_f_nbio_test());
        sbio = BIO_push(test, sbio);
    }

    if (c_debug) {
        BIO_set_callback(sbio, bio_dump_callback);
        BIO_set_callback_arg(sbio, (char *)bio_c_out);
    }
    if (c_msg) {
#ifndef OPENSSL_NO_SSL_TRACE
        if (c_msg == 2)
            SSL_set_msg_callback(con, SSL_trace);
        else
#endif
            SSL_set_msg_callback(con, msg_cb);
        SSL_set_msg_callback_arg(con, bio_c_msg ? bio_c_msg : bio_c_out);
    }

    if (c_tlsextdebug) {
        SSL_set_tlsext_debug_callback(con, tlsext_cb);
        SSL_set_tlsext_debug_arg(con, bio_c_out);
    }
#ifndef OPENSSL_NO_OCSP
    if (c_status_req) {
        SSL_set_tlsext_status_type(con, TLSEXT_STATUSTYPE_ocsp);
        SSL_CTX_set_tlsext_status_cb(ctx, ocsp_resp_cb);
        SSL_CTX_set_tlsext_status_arg(ctx, bio_c_out);
    }
#endif

    SSL_set_bio(con, sbio, sbio);
    SSL_set_connect_state(con);

    /* ok, lets connect */
    if (fileno_stdin() > SSL_get_fd(con))
        width = fileno_stdin() + 1;
    else
        width = SSL_get_fd(con) + 1;

    read_tty = 1;
    write_tty = 0;
    tty_on = 0;
    read_ssl = 1;
    write_ssl = 1;

    cbuf_len = 0;
    cbuf_off = 0;
    sbuf_len = 0;
    sbuf_off = 0;

    switch ((PROTOCOL_CHOICE) starttls_proto) {
    case PROTO_OFF:
        break;
    case PROTO_SMTP:
        {
            /*
             * This is an ugly hack that does a lot of assumptions. We do
             * have to handle multi-line responses which may come in a single
             * packet or not. We therefore have to use BIO_gets() which does
             * need a buffering BIO. So during the initial chitchat we do
             * push a buffering BIO into the chain that is removed again
             * later on to not disturb the rest of the s_client operation.
             */
            int foundit = 0;
            BIO *fbio = BIO_new(BIO_f_buffer());
            BIO_push(fbio, sbio);
            /* wait for multi-line response to end from SMTP */
            do {
                mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
            }
            while (mbuf_len > 3 && mbuf[3] == '-');
            BIO_printf(fbio, "EHLO %s\r\n", ehlo);
            (void)BIO_flush(fbio);
            /* wait for multi-line response to end EHLO SMTP response */
            do {
                mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
                if (strstr(mbuf, "STARTTLS"))
                    foundit = 1;
            }
            while (mbuf_len > 3 && mbuf[3] == '-');
            (void)BIO_flush(fbio);
            BIO_pop(fbio);
            BIO_free(fbio);
            if (!foundit)
                BIO_printf(bio_err,
                           "didn't find starttls in server response,"
                           " trying anyway...\n");
            BIO_printf(sbio, "STARTTLS\r\n");
            BIO_read(sbio, sbuf, BUFSIZZ);
        }
        break;
    case PROTO_POP3:
        {
            BIO_read(sbio, mbuf, BUFSIZZ);
            BIO_printf(sbio, "STLS\r\n");
            mbuf_len = BIO_read(sbio, sbuf, BUFSIZZ);
            if (mbuf_len < 0) {
                BIO_printf(bio_err, "BIO_read failed\n");
                goto end;
            }
        }
        break;
    case PROTO_IMAP:
        {
            int foundit = 0;
            BIO *fbio = BIO_new(BIO_f_buffer());
            BIO_push(fbio, sbio);
            BIO_gets(fbio, mbuf, BUFSIZZ);
            /* STARTTLS command requires CAPABILITY... */
            BIO_printf(fbio, ". CAPABILITY\r\n");
            (void)BIO_flush(fbio);
            /* wait for multi-line CAPABILITY response */
            do {
                mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
                if (strstr(mbuf, "STARTTLS"))
                    foundit = 1;
            }
            while (mbuf_len > 3 && mbuf[0] != '.');
            (void)BIO_flush(fbio);
            BIO_pop(fbio);
            BIO_free(fbio);
            if (!foundit)
                BIO_printf(bio_err,
                           "didn't find STARTTLS in server response,"
                           " trying anyway...\n");
            BIO_printf(sbio, ". STARTTLS\r\n");
            BIO_read(sbio, sbuf, BUFSIZZ);
        }
        break;
    case PROTO_FTP:
        {
            BIO *fbio = BIO_new(BIO_f_buffer());
            BIO_push(fbio, sbio);
            /* wait for multi-line response to end from FTP */
            do {
                mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
            }
            while (mbuf_len > 3 && mbuf[3] == '-');
            (void)BIO_flush(fbio);
            BIO_pop(fbio);
            BIO_free(fbio);
            BIO_printf(sbio, "AUTH TLS\r\n");
            BIO_read(sbio, sbuf, BUFSIZZ);
        }
        break;
    case PROTO_XMPP:
    case PROTO_XMPP_SERVER:
        {
            int seen = 0;
            BIO_printf(sbio, "<stream:stream "
                       "xmlns:stream='http://etherx.jabber.org/streams' "
                       "xmlns='jabber:%s' to='%s' version='1.0'>",
                       starttls_proto == PROTO_XMPP ? "client" : "server",
                       xmpphost ? xmpphost : host);
            seen = BIO_read(sbio, mbuf, BUFSIZZ);
            mbuf[seen] = 0;
            while (!strstr
                   (mbuf, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'")
                   && !strstr(mbuf,
                              "<starttls xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\""))
            {
                seen = BIO_read(sbio, mbuf, BUFSIZZ);

                if (seen <= 0)
                    goto shut;

                mbuf[seen] = 0;
            }
            BIO_printf(sbio,
                       "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
            seen = BIO_read(sbio, sbuf, BUFSIZZ);
            sbuf[seen] = 0;
            if (!strstr(sbuf, "<proceed"))
                goto shut;
            mbuf[0] = 0;
        }
        break;
    case PROTO_TELNET:
        {
            static const unsigned char tls_do[] = {
                /* IAC    DO   START_TLS */
                   255,   253, 46
            };
            static const unsigned char tls_will[] = {
                /* IAC  WILL START_TLS */
                   255, 251, 46
            };
            static const unsigned char tls_follows[] = {
                /* IAC  SB   START_TLS FOLLOWS IAC  SE */
                   255, 250, 46,       1,      255, 240
            };
            int bytes;

            /* Telnet server should demand we issue START_TLS */
            bytes = BIO_read(sbio, mbuf, BUFSIZZ);
            if (bytes != 3 || memcmp(mbuf, tls_do, 3) != 0)
                goto shut;
            /* Agree to issue START_TLS and send the FOLLOWS sub-command */
            BIO_write(sbio, tls_will, 3);
            BIO_write(sbio, tls_follows, 6);
            (void)BIO_flush(sbio);
            /* Telnet server also sent the FOLLOWS sub-command */
            bytes = BIO_read(sbio, mbuf, BUFSIZZ);
            if (bytes != 6 || memcmp(mbuf, tls_follows, 6) != 0)
                goto shut;
        }
        break;
    case PROTO_CONNECT:
        {
            enum {
                error_proto,     /* Wrong protocol, not even HTTP */
                error_connect,   /* CONNECT failed */
                success
            } foundit = error_connect;
            BIO *fbio = BIO_new(BIO_f_buffer());

            BIO_push(fbio, sbio);
            BIO_printf(fbio, "CONNECT %s HTTP/1.0\r\n\r\n", connectstr);
            (void)BIO_flush(fbio);
            /*
             * The first line is the HTTP response.  According to RFC 7230,
             * it's formated exactly like this:
             *
             * HTTP/d.d ddd Reason text\r\n
             */
            mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
            if (mbuf[8] != ' ') {
                BIO_printf(bio_err,
                           "%s: HTTP CONNECT failed, incorrect response "
                           "from proxy\n", prog);
                foundit = error_proto;
            } else if (mbuf[9] != '2') {
                BIO_printf(bio_err, "%s: HTTP CONNECT failed: %s ", prog,
                           &mbuf[9]);
            } else {
                foundit = success;
            }
            if (foundit != error_proto) {
                /* Read past all following headers */
                do {
                    mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
                } while (mbuf_len > 2);
            }
            (void)BIO_flush(fbio);
            BIO_pop(fbio);
            BIO_free(fbio);
            if (foundit != success) {
                goto shut;
            }
        }
        break;
    case PROTO_IRC:
        {
            int numeric;
            BIO *fbio = BIO_new(BIO_f_buffer());

            BIO_push(fbio, sbio);
            BIO_printf(fbio, "STARTTLS\r\n");
            (void)BIO_flush(fbio);
            width = SSL_get_fd(con) + 1;

            do {
                numeric = 0;

                FD_ZERO(&readfds);
                openssl_fdset(SSL_get_fd(con), &readfds);
                timeout.tv_sec = S_CLIENT_IRC_READ_TIMEOUT;
                timeout.tv_usec = 0;
                /*
                 * If the IRCd doesn't respond within
                 * S_CLIENT_IRC_READ_TIMEOUT seconds, assume
                 * it doesn't support STARTTLS. Many IRCds
                 * will not give _any_ sort of response to a
                 * STARTTLS command when it's not supported.
                 */
                if (!BIO_get_buffer_num_lines(fbio)
                    && !BIO_pending(fbio)
                    && !BIO_pending(sbio)
                    && select(width, (void *)&readfds, NULL, NULL,
                              &timeout) < 1) {
                    BIO_printf(bio_err,
                               "Timeout waiting for response (%d seconds).\n",
                               S_CLIENT_IRC_READ_TIMEOUT);
                    break;
                }

                mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
                if (mbuf_len < 1 || sscanf(mbuf, "%*s %d", &numeric) != 1)
                    break;
                /* :example.net 451 STARTTLS :You have not registered */
                /* :example.net 421 STARTTLS :Unknown command */
                if ((numeric == 451 || numeric == 421)
                    && strstr(mbuf, "STARTTLS") != NULL) {
                    BIO_printf(bio_err, "STARTTLS not supported: %s", mbuf);
                    break;
                }
                if (numeric == 691) {
                    BIO_printf(bio_err, "STARTTLS negotiation failed: ");
                    ERR_print_errors(bio_err);
                    break;
                }
            } while (numeric != 670);

            (void)BIO_flush(fbio);
            BIO_pop(fbio);
            BIO_free(fbio);
            if (numeric != 670) {
                BIO_printf(bio_err, "Server does not support STARTTLS.\n");
                ret = 1;
                goto shut;
            }
        }
    }

    for (;;) {
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);

        if ((SSL_version(con) == DTLS1_VERSION) &&
            DTLSv1_get_timeout(con, &timeout))
            timeoutp = &timeout;
        else
            timeoutp = NULL;

        if (SSL_in_init(con) && !SSL_total_renegotiations(con)) {
            in_init = 1;
            tty_on = 0;
        } else {
            tty_on = 1;
            if (in_init) {
                in_init = 0;

                if (servername != NULL && !SSL_session_reused(con)) {
                    BIO_printf(bio_c_out,
                               "Server did %sacknowledge servername extension.\n",
                               tlsextcbp.ack ? "" : "not ");
                }

                if (sess_out) {
                    BIO *stmp = BIO_new_file(sess_out, "w");
                    if (stmp) {
                        PEM_write_bio_SSL_SESSION(stmp, SSL_get_session(con));
                        BIO_free(stmp);
                    } else
                        BIO_printf(bio_err, "Error writing session file %s\n",
                                   sess_out);
                }
                if (c_brief) {
                    BIO_puts(bio_err, "CONNECTION ESTABLISHED\n");
                    print_ssl_summary(con);
                }

                print_stuff(bio_c_out, con, full_log);
                if (full_log > 0)
                    full_log--;

                if (starttls_proto) {
                    BIO_write(bio_err, mbuf, mbuf_len);
                    /* We don't need to know any more */
                    if (!reconnect)
                        starttls_proto = PROTO_OFF;
                }

                if (reconnect) {
                    reconnect--;
                    BIO_printf(bio_c_out,
                               "drop connection and then reconnect\n");
                    do_ssl_shutdown(con);
                    SSL_set_connect_state(con);
                    BIO_closesocket(SSL_get_fd(con));
                    goto re_start;
                }
            }
        }

        ssl_pending = read_ssl && SSL_has_pending(con);

        if (!ssl_pending) {
#if !defined(OPENSSL_SYS_WINDOWS) && !defined(OPENSSL_SYS_MSDOS)
            if (tty_on) {
                /*
                 * Note that select() returns when read _would not block_,
                 * and EOF satisfies that.  To avoid a CPU-hogging loop,
                 * set the flag so we exit.
                 */
                if (read_tty && !at_eof)
                    openssl_fdset(fileno_stdin(), &readfds);
#if !defined(OPENSSL_SYS_VMS)
                if (write_tty)
                    openssl_fdset(fileno_stdout(), &writefds);
#endif
            }
            if (read_ssl)
                openssl_fdset(SSL_get_fd(con), &readfds);
            if (write_ssl)
                openssl_fdset(SSL_get_fd(con), &writefds);
#else
            if (!tty_on || !write_tty) {
                if (read_ssl)
                    openssl_fdset(SSL_get_fd(con), &readfds);
                if (write_ssl)
                    openssl_fdset(SSL_get_fd(con), &writefds);
            }
#endif

            /*
             * Note: under VMS with SOCKETSHR the second parameter is
             * currently of type (int *) whereas under other systems it is
             * (void *) if you don't have a cast it will choke the compiler:
             * if you do have a cast then you can either go for (int *) or
             * (void *).
             */
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS)
            /*
             * Under Windows/DOS we make the assumption that we can always
             * write to the tty: therefore if we need to write to the tty we
             * just fall through. Otherwise we timeout the select every
             * second and see if there are any keypresses. Note: this is a
             * hack, in a proper Windows application we wouldn't do this.
             */
            i = 0;
            if (!write_tty) {
                if (read_tty) {
                    tv.tv_sec = 1;
                    tv.tv_usec = 0;
                    i = select(width, (void *)&readfds, (void *)&writefds,
                               NULL, &tv);
                    if (!i && (!has_stdin_waiting() || !read_tty))
                        continue;
                } else
                    i = select(width, (void *)&readfds, (void *)&writefds,
                               NULL, timeoutp);
            }
#else
            i = select(width, (void *)&readfds, (void *)&writefds,
                       NULL, timeoutp);
#endif
            if (i < 0) {
                BIO_printf(bio_err, "bad select %d\n",
                           get_last_socket_error());
                goto shut;
                /* goto end; */
            }
        }

        if ((SSL_version(con) == DTLS1_VERSION)
            && DTLSv1_handle_timeout(con) > 0) {
            BIO_printf(bio_err, "TIMEOUT occurred\n");
        }

        if (!ssl_pending && FD_ISSET(SSL_get_fd(con), &writefds)) {
            k = SSL_write(con, &(cbuf[cbuf_off]), (unsigned int)cbuf_len);
            switch (SSL_get_error(con, k)) {
            case SSL_ERROR_NONE:
                cbuf_off += k;
                cbuf_len -= k;
                if (k <= 0)
                    goto end;
                /* we have done a  write(con,NULL,0); */
                if (cbuf_len <= 0) {
                    read_tty = 1;
                    write_ssl = 0;
                } else {        /* if (cbuf_len > 0) */

                    read_tty = 0;
                    write_ssl = 1;
                }
                break;
            case SSL_ERROR_WANT_WRITE:
                BIO_printf(bio_c_out, "write W BLOCK\n");
                write_ssl = 1;
                read_tty = 0;
                break;
            case SSL_ERROR_WANT_ASYNC:
                BIO_printf(bio_c_out, "write A BLOCK\n");
                wait_for_async(con);
                write_ssl = 1;
                read_tty = 0;
                break;
            case SSL_ERROR_WANT_READ:
                BIO_printf(bio_c_out, "write R BLOCK\n");
                write_tty = 0;
                read_ssl = 1;
                write_ssl = 0;
                break;
            case SSL_ERROR_WANT_X509_LOOKUP:
                BIO_printf(bio_c_out, "write X BLOCK\n");
                break;
            case SSL_ERROR_ZERO_RETURN:
                if (cbuf_len != 0) {
                    BIO_printf(bio_c_out, "shutdown\n");
                    ret = 0;
                    goto shut;
                } else {
                    read_tty = 1;
                    write_ssl = 0;
                    break;
                }

            case SSL_ERROR_SYSCALL:
                if ((k != 0) || (cbuf_len != 0)) {
                    BIO_printf(bio_err, "write:errno=%d\n",
                               get_last_socket_error());
                    goto shut;
                } else {
                    read_tty = 1;
                    write_ssl = 0;
                }
                break;
            case SSL_ERROR_WANT_ASYNC_JOB:
                /* This shouldn't ever happen in s_client - treat as an error */
            case SSL_ERROR_SSL:
                ERR_print_errors(bio_err);
                goto shut;
            }
        }
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS) || defined(OPENSSL_SYS_VMS)
        /* Assume Windows/DOS/BeOS can always write */
        else if (!ssl_pending && write_tty)
#else
        else if (!ssl_pending && FD_ISSET(fileno_stdout(), &writefds))
#endif
        {
#ifdef CHARSET_EBCDIC
            ascii2ebcdic(&(sbuf[sbuf_off]), &(sbuf[sbuf_off]), sbuf_len);
#endif
            i = raw_write_stdout(&(sbuf[sbuf_off]), sbuf_len);

            if (i <= 0) {
                BIO_printf(bio_c_out, "DONE\n");
                ret = 0;
                goto shut;
                /* goto end; */
            }

            sbuf_len -= i;;
            sbuf_off += i;
            if (sbuf_len <= 0) {
                read_ssl = 1;
                write_tty = 0;
            }
        } else if (ssl_pending || FD_ISSET(SSL_get_fd(con), &readfds)) {
#ifdef RENEG
            {
                static int iiii;
                if (++iiii == 52) {
                    SSL_renegotiate(con);
                    iiii = 0;
                }
            }
#endif
            k = SSL_read(con, sbuf, 1024 /* BUFSIZZ */ );

            switch (SSL_get_error(con, k)) {
            case SSL_ERROR_NONE:
                if (k <= 0)
                    goto end;
                sbuf_off = 0;
                sbuf_len = k;

                read_ssl = 0;
                write_tty = 1;
                break;
            case SSL_ERROR_WANT_ASYNC:
                BIO_printf(bio_c_out, "read A BLOCK\n");
                wait_for_async(con);
                write_tty = 0;
                read_ssl = 1;
                if ((read_tty == 0) && (write_ssl == 0))
                    write_ssl = 1;
                break;
            case SSL_ERROR_WANT_WRITE:
                BIO_printf(bio_c_out, "read W BLOCK\n");
                write_ssl = 1;
                read_tty = 0;
                break;
            case SSL_ERROR_WANT_READ:
                BIO_printf(bio_c_out, "read R BLOCK\n");
                write_tty = 0;
                read_ssl = 1;
                if ((read_tty == 0) && (write_ssl == 0))
                    write_ssl = 1;
                break;
            case SSL_ERROR_WANT_X509_LOOKUP:
                BIO_printf(bio_c_out, "read X BLOCK\n");
                break;
            case SSL_ERROR_SYSCALL:
                ret = get_last_socket_error();
                if (c_brief)
                    BIO_puts(bio_err, "CONNECTION CLOSED BY SERVER\n");
                else
                    BIO_printf(bio_err, "read:errno=%d\n", ret);
                goto shut;
            case SSL_ERROR_ZERO_RETURN:
                BIO_printf(bio_c_out, "closed\n");
                ret = 0;
                goto shut;
            case SSL_ERROR_WANT_ASYNC_JOB:
                /* This shouldn't ever happen in s_client. Treat as an error */
            case SSL_ERROR_SSL:
                ERR_print_errors(bio_err);
                goto shut;
                /* break; */
            }
        }
/* OPENSSL_SYS_MSDOS includes OPENSSL_SYS_WINDOWS */
#if defined(OPENSSL_SYS_MSDOS)
        else if (has_stdin_waiting())
#else
        else if (FD_ISSET(fileno_stdin(), &readfds))
#endif
        {
            if (crlf) {
                int j, lf_num;

                i = raw_read_stdin(cbuf, BUFSIZZ / 2);
                lf_num = 0;
                /* both loops are skipped when i <= 0 */
                for (j = 0; j < i; j++)
                    if (cbuf[j] == '\n')
                        lf_num++;
                for (j = i - 1; j >= 0; j--) {
                    cbuf[j + lf_num] = cbuf[j];
                    if (cbuf[j] == '\n') {
                        lf_num--;
                        i++;
                        cbuf[j + lf_num] = '\r';
                    }
                }
                assert(lf_num == 0);
            } else
                i = raw_read_stdin(cbuf, BUFSIZZ);
#if !defined(OPENSSL_SYS_WINDOWS) && !defined(OPENSSL_SYS_MSDOS)
            if (i == 0)
                at_eof = 1;
#endif

            if ((!c_ign_eof) && ((i <= 0) || (cbuf[0] == 'Q' && cmdletters))) {
                BIO_printf(bio_err, "DONE\n");
                ret = 0;
                goto shut;
            }

            if ((!c_ign_eof) && (cbuf[0] == 'R' && cmdletters)) {
                BIO_printf(bio_err, "RENEGOTIATING\n");
                SSL_renegotiate(con);
                cbuf_len = 0;
            }
#ifndef OPENSSL_NO_HEARTBEATS
            else if ((!c_ign_eof) && (cbuf[0] == 'B' && cmdletters)) {
                BIO_printf(bio_err, "HEARTBEATING\n");
                SSL_heartbeat(con);
                cbuf_len = 0;
            }
#endif
            else {
                cbuf_len = i;
                cbuf_off = 0;
#ifdef CHARSET_EBCDIC
                ebcdic2ascii(cbuf, cbuf, i);
#endif
            }

            write_ssl = 1;
            read_tty = 0;
        }
    }

    ret = 0;
 shut:
    if (in_init)
        print_stuff(bio_c_out, con, full_log);
    do_ssl_shutdown(con);
#if defined(OPENSSL_SYS_WINDOWS)
    /*
     * Give the socket time to send its last data before we close it.
     * No amount of setting SO_LINGER etc on the socket seems to persuade
     * Windows to send the data before closing the socket...but sleeping
     * for a short time seems to do it (units in ms)
     * TODO: Find a better way to do this
     */
    Sleep(50);
#endif
    BIO_closesocket(SSL_get_fd(con));
 end:
    if (con != NULL) {
        if (prexit != 0)
            print_stuff(bio_c_out, con, 1);
        SSL_free(con);
    }
#if !defined(OPENSSL_NO_NEXTPROTONEG)
    OPENSSL_free(next_proto.data);
#endif
    SSL_CTX_free(ctx);
    X509_free(cert);
    X509_free(dcert);
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
    EVP_PKEY_free(key);
    EVP_PKEY_free(dkey);
    sk_X509_pop_free(chain, X509_free);
    sk_X509_pop_free(dchain, X509_free);
    OPENSSL_free(pass);
    OPENSSL_free(dpass);
#ifndef OPENSSL_NO_SRP
    OPENSSL_free(srp_arg.srppassin);
#endif
    OPENSSL_free(connectstr);
    OPENSSL_free(host);
    OPENSSL_free(port);
    X509_VERIFY_PARAM_free(vpm);
    ssl_excert_free(exc);
    sk_OPENSSL_STRING_free(ssl_args);
    sk_OPENSSL_STRING_free(dane_tlsa_rrset);
    SSL_CONF_CTX_free(cctx);
    OPENSSL_clear_free(cbuf, BUFSIZZ);
    OPENSSL_clear_free(sbuf, BUFSIZZ);
    OPENSSL_clear_free(mbuf, BUFSIZZ);
    release_engine(e);
    BIO_free(bio_c_out);
    bio_c_out = NULL;
    BIO_free(bio_c_msg);
    bio_c_msg = NULL;
    NCONF_free(conf);
    return (ret);
}

static void print_stuff(BIO *bio, SSL *s, int full)
{
    X509 *peer = NULL;
    char buf[BUFSIZ];
    STACK_OF(X509) *sk;
    STACK_OF(X509_NAME) *sk2;
    const SSL_CIPHER *c;
    X509_NAME *xn;
    int i;
#ifndef OPENSSL_NO_COMP
    const COMP_METHOD *comp, *expansion;
#endif
    unsigned char *exportedkeymat;
#ifndef OPENSSL_NO_CT
    const SSL_CTX *ctx = SSL_get_SSL_CTX(s);
#endif

    if (full) {
        int got_a_chain = 0;

        sk = SSL_get_peer_cert_chain(s);
        if (sk != NULL) {
            got_a_chain = 1;

            BIO_printf(bio, "---\nCertificate chain\n");
            for (i = 0; i < sk_X509_num(sk); i++) {
                X509_NAME_oneline(X509_get_subject_name(sk_X509_value(sk, i)),
                                  buf, sizeof buf);
                BIO_printf(bio, "%2d s:%s\n", i, buf);
                X509_NAME_oneline(X509_get_issuer_name(sk_X509_value(sk, i)),
                                  buf, sizeof buf);
                BIO_printf(bio, "   i:%s\n", buf);
                if (c_showcerts)
                    PEM_write_bio_X509(bio, sk_X509_value(sk, i));
            }
        }

        BIO_printf(bio, "---\n");
        peer = SSL_get_peer_certificate(s);
        if (peer != NULL) {
            BIO_printf(bio, "Server certificate\n");

            /* Redundant if we showed the whole chain */
            if (!(c_showcerts && got_a_chain))
                PEM_write_bio_X509(bio, peer);
            X509_NAME_oneline(X509_get_subject_name(peer), buf, sizeof buf);
            BIO_printf(bio, "subject=%s\n", buf);
            X509_NAME_oneline(X509_get_issuer_name(peer), buf, sizeof buf);
            BIO_printf(bio, "issuer=%s\n", buf);
        } else
            BIO_printf(bio, "no peer certificate available\n");

        sk2 = SSL_get_client_CA_list(s);
        if ((sk2 != NULL) && (sk_X509_NAME_num(sk2) > 0)) {
            BIO_printf(bio, "---\nAcceptable client certificate CA names\n");
            for (i = 0; i < sk_X509_NAME_num(sk2); i++) {
                xn = sk_X509_NAME_value(sk2, i);
                X509_NAME_oneline(xn, buf, sizeof(buf));
                BIO_write(bio, buf, strlen(buf));
                BIO_write(bio, "\n", 1);
            }
        } else {
            BIO_printf(bio, "---\nNo client certificate CA names sent\n");
        }

        ssl_print_sigalgs(bio, s);
        ssl_print_tmp_key(bio, s);

#ifndef OPENSSL_NO_CT
        /*
         * When the SSL session is anonymous, or resumed via an abbreviated
         * handshake, no SCTs are provided as part of the handshake.  While in
         * a resumed session SCTs may be present in the session's certificate,
         * no callbacks are invoked to revalidate these, and in any case that
         * set of SCTs may be incomplete.  Thus it makes little sense to
         * attempt to display SCTs from a resumed session's certificate, and of
         * course none are associated with an anonymous peer.
         */
        if (peer != NULL && !SSL_session_reused(s) && SSL_ct_is_enabled(s)) {
            const STACK_OF(SCT) *scts = SSL_get0_peer_scts(s);
            int sct_count = scts != NULL ? sk_SCT_num(scts) : 0;

            BIO_printf(bio, "---\nSCTs present (%i)\n", sct_count);
            if (sct_count > 0) {
                const CTLOG_STORE *log_store = SSL_CTX_get0_ctlog_store(ctx);

                BIO_printf(bio, "---\n");
                for (i = 0; i < sct_count; ++i) {
                    SCT *sct = sk_SCT_value(scts, i);

                    BIO_printf(bio, "SCT validation status: %s\n",
                               SCT_validation_status_string(sct));
                    SCT_print(sct, bio, 0, log_store);
                    if (i < sct_count - 1)
                        BIO_printf(bio, "\n---\n");
                }
                BIO_printf(bio, "\n");
            }
        }
#endif

        BIO_printf(bio,
                   "---\nSSL handshake has read %" PRIu64
                   " bytes and written %" PRIu64 " bytes\n",
                   BIO_number_read(SSL_get_rbio(s)),
                   BIO_number_written(SSL_get_wbio(s)));
    }
    print_verify_detail(s, bio);
    BIO_printf(bio, (SSL_session_reused(s) ? "---\nReused, " : "---\nNew, "));
    c = SSL_get_current_cipher(s);
    BIO_printf(bio, "%s, Cipher is %s\n",
               SSL_CIPHER_get_version(c), SSL_CIPHER_get_name(c));
    if (peer != NULL) {
        EVP_PKEY *pktmp;

        pktmp = X509_get0_pubkey(peer);
        BIO_printf(bio, "Server public key is %d bit\n",
                   EVP_PKEY_bits(pktmp));
    }
    BIO_printf(bio, "Secure Renegotiation IS%s supported\n",
               SSL_get_secure_renegotiation_support(s) ? "" : " NOT");
#ifndef OPENSSL_NO_COMP
    comp = SSL_get_current_compression(s);
    expansion = SSL_get_current_expansion(s);
    BIO_printf(bio, "Compression: %s\n",
               comp ? SSL_COMP_get_name(comp) : "NONE");
    BIO_printf(bio, "Expansion: %s\n",
               expansion ? SSL_COMP_get_name(expansion) : "NONE");
#endif

#ifdef SSL_DEBUG
    {
        /* Print out local port of connection: useful for debugging */
        int sock;
        union BIO_sock_info_u info;

        sock = SSL_get_fd(s);
        if ((info.addr = BIO_ADDR_new()) != NULL
            && BIO_sock_info(sock, BIO_SOCK_INFO_ADDRESS, &info)) {
            BIO_printf(bio_c_out, "LOCAL PORT is %u\n",
                       ntohs(BIO_ADDR_rawport(info.addr)));
        }
        BIO_ADDR_free(info.addr);
    }
#endif

#if !defined(OPENSSL_NO_NEXTPROTONEG)
    if (next_proto.status != -1) {
        const unsigned char *proto;
        unsigned int proto_len;
        SSL_get0_next_proto_negotiated(s, &proto, &proto_len);
        BIO_printf(bio, "Next protocol: (%d) ", next_proto.status);
        BIO_write(bio, proto, proto_len);
        BIO_write(bio, "\n", 1);
    }
#endif
    {
        const unsigned char *proto;
        unsigned int proto_len;
        SSL_get0_alpn_selected(s, &proto, &proto_len);
        if (proto_len > 0) {
            BIO_printf(bio, "ALPN protocol: ");
            BIO_write(bio, proto, proto_len);
            BIO_write(bio, "\n", 1);
        } else
            BIO_printf(bio, "No ALPN negotiated\n");
    }

#ifndef OPENSSL_NO_SRTP
    {
        SRTP_PROTECTION_PROFILE *srtp_profile =
            SSL_get_selected_srtp_profile(s);

        if (srtp_profile)
            BIO_printf(bio, "SRTP Extension negotiated, profile=%s\n",
                       srtp_profile->name);
    }
#endif

    SSL_SESSION_print(bio, SSL_get_session(s));
    if (SSL_get_session(s) != NULL && keymatexportlabel != NULL) {
        BIO_printf(bio, "Keying material exporter:\n");
        BIO_printf(bio, "    Label: '%s'\n", keymatexportlabel);
        BIO_printf(bio, "    Length: %i bytes\n", keymatexportlen);
        exportedkeymat = app_malloc(keymatexportlen, "export key");
        if (!SSL_export_keying_material(s, exportedkeymat,
                                        keymatexportlen,
                                        keymatexportlabel,
                                        strlen(keymatexportlabel),
                                        NULL, 0, 0)) {
            BIO_printf(bio, "    Error\n");
        } else {
            BIO_printf(bio, "    Keying material: ");
            for (i = 0; i < keymatexportlen; i++)
                BIO_printf(bio, "%02X", exportedkeymat[i]);
            BIO_printf(bio, "\n");
        }
        OPENSSL_free(exportedkeymat);
    }
    BIO_printf(bio, "---\n");
    X509_free(peer);
    /* flush, or debugging output gets mixed with http response */
    (void)BIO_flush(bio);
}

# ifndef OPENSSL_NO_OCSP
static int ocsp_resp_cb(SSL *s, void *arg)
{
    const unsigned char *p;
    int len;
    OCSP_RESPONSE *rsp;
    len = SSL_get_tlsext_status_ocsp_resp(s, &p);
    BIO_puts(arg, "OCSP response: ");
    if (!p) {
        BIO_puts(arg, "no response sent\n");
        return 1;
    }
    rsp = d2i_OCSP_RESPONSE(NULL, &p, len);
    if (!rsp) {
        BIO_puts(arg, "response parse error\n");
        BIO_dump_indent(arg, (char *)p, len, 4);
        return 0;
    }
    BIO_puts(arg, "\n======================================\n");
    OCSP_RESPONSE_print(arg, rsp, 0);
    BIO_puts(arg, "======================================\n");
    OCSP_RESPONSE_free(rsp);
    return 1;
}
# endif

#endif                          /* OPENSSL_NO_SOCK */
