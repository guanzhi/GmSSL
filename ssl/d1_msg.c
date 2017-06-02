/*
 * Copyright 2005-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#define USE_SOCKETS
#include "ssl_locl.h"

int dtls1_write_app_data_bytes(SSL *s, int type, const void *buf_, int len)
{
    int i;

#ifndef OPENSSL_NO_SCTP
    /*
     * Check if we have to continue an interrupted handshake for reading
     * belated app data with SCTP.
     */
    if ((SSL_in_init(s) && !ossl_statem_get_in_handshake(s)) ||
        (BIO_dgram_is_sctp(SSL_get_wbio(s)) &&
         ossl_statem_in_sctp_read_sock(s)))
#else
    if (SSL_in_init(s) && !ossl_statem_get_in_handshake(s))
#endif
    {
        i = s->handshake_func(s);
        if (i < 0)
            return (i);
        if (i == 0) {
            SSLerr(SSL_F_DTLS1_WRITE_APP_DATA_BYTES,
                   SSL_R_SSL_HANDSHAKE_FAILURE);
            return -1;
        }
    }

    if (len > SSL3_RT_MAX_PLAIN_LENGTH) {
        SSLerr(SSL_F_DTLS1_WRITE_APP_DATA_BYTES, SSL_R_DTLS_MESSAGE_TOO_BIG);
        return -1;
    }

    i = dtls1_write_bytes(s, type, buf_, len);
    return i;
}

int dtls1_dispatch_alert(SSL *s)
{
    int i, j;
    void (*cb) (const SSL *ssl, int type, int val) = NULL;
    unsigned char buf[DTLS1_AL_HEADER_LENGTH];
    unsigned char *ptr = &buf[0];

    s->s3->alert_dispatch = 0;

    memset(buf, 0, sizeof(buf));
    *ptr++ = s->s3->send_alert[0];
    *ptr++ = s->s3->send_alert[1];

#ifdef DTLS1_AD_MISSING_HANDSHAKE_MESSAGE
    if (s->s3->send_alert[1] == DTLS1_AD_MISSING_HANDSHAKE_MESSAGE) {
        s2n(s->d1->handshake_read_seq, ptr);
        l2n3(s->d1->r_msg_hdr.frag_off, ptr);
    }
#endif

    i = do_dtls1_write(s, SSL3_RT_ALERT, &buf[0], sizeof(buf), 0);
    if (i <= 0) {
        s->s3->alert_dispatch = 1;
        /* fprintf( stderr, "not done with alert\n" ); */
    } else {
        if (s->s3->send_alert[0] == SSL3_AL_FATAL
#ifdef DTLS1_AD_MISSING_HANDSHAKE_MESSAGE
            || s->s3->send_alert[1] == DTLS1_AD_MISSING_HANDSHAKE_MESSAGE
#endif
            )
            (void)BIO_flush(s->wbio);

        if (s->msg_callback)
            s->msg_callback(1, s->version, SSL3_RT_ALERT, s->s3->send_alert,
                            2, s, s->msg_callback_arg);

        if (s->info_callback != NULL)
            cb = s->info_callback;
        else if (s->ctx->info_callback != NULL)
            cb = s->ctx->info_callback;

        if (cb != NULL) {
            j = (s->s3->send_alert[0] << 8) | s->s3->send_alert[1];
            cb(s, SSL_CB_WRITE_ALERT, j);
        }
    }
    return (i);
}
