/* ssl/gm_srvr.c */
/* ====================================================================
 * Copyright (c) 2015 The GmSSL Project.  All rights reserved.
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
 *
 */


#include <stdio.h>
#include "ssl_locl.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/gmssl.h>

static const SSL_METHOD *gmssl_get_server_method(int ver)
{
	if (ver == GMSSL1_1_VERSION) {
		return GMSSLv1_1_server_method();
	}
	return NULL;
}

IMPLEMENT_gmssl_meth_func(GMSSL1_1_VERSION, GMSSLv1_1_server_method,
                        ssl3_accept,
                        ssl_undefined_function,
                        gmssl_get_server_method, GMSSLv1_1_enc_data)

int gm1_send_server_certificate(SSL *s)
{

    CERT_PKEY *cpk;

    if (s->state == SSL3_ST_SW_CERT_A) {
        cpk = ssl_get_server_send_pkey(s);
        if (cpk == NULL) {
            /* VRS: allow null cert if auth == KRB5 */
            if ((s->s3->tmp.new_cipher->algorithm_auth != SSL_aKRB5) ||
                (s->s3->tmp.new_cipher->algorithm_mkey & SSL_kKRB5)) {
                SSLerr(SSL_F_SSL3_SEND_SERVER_CERTIFICATE,
                       ERR_R_INTERNAL_ERROR);
                s->state = SSL_ST_ERR;
                return (0);
            }
        }

        if (!ssl3_output_cert_chain(s, cpk)) {
            SSLerr(SSL_F_SSL3_SEND_SERVER_CERTIFICATE, ERR_R_INTERNAL_ERROR);
            s->state = SSL_ST_ERR;
            return (0);
        }
        s->state = SSL3_ST_SW_CERT_B;
    }

    /* SSL3_ST_SW_CERT_B */
    return ssl_do_write(s);
}

/*

s3_srvr.c:s3_send_server_certificate
	ssl_get_server_send_pkey
	ssl3_output_cert_chain
		ssl_add_cert_chain
		ssl_set_handshake_header
	ssl_do_write
*/
