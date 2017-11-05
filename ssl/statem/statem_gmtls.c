/* ====================================================================
 * Copyright (c) 2014 - 2017 The GmSSL Project.  All rights reserved.
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

#include <stdio.h>
#include <openssl/opensslconf.h>

# include "../ssl_locl.h"
# include "statem_locl.h"
# include "internal/constant_time_locl.h"
# include <openssl/buffer.h>
# include <openssl/rand.h>
# include <openssl/objects.h>
# include <openssl/evp.h>
# include <openssl/hmac.h>
# include <openssl/x509.h>
# include <openssl/x509v3.h>
# include <openssl/bn.h>
# include <openssl/sm2.h>
# include <openssl/crypto.h>

int gmtls_construct_server_certificate(SSL *s)
{
	SSLerr(SSL_F_GMTLS_CONSTRUCT_SERVER_CERTIFICATE,
		SSL_R_NOT_IMPLEMENTED);
	ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
	ossl_statem_set_error(s);
	return 0;
}

int gmtls_construct_server_key_exchange(SSL *s)
{
	SSLerr(SSL_F_GMTLS_CONSTRUCT_SERVER_KEY_EXCHANGE,
		SSL_R_NOT_IMPLEMENTED);
	ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
	ossl_statem_set_error(s);
	return 0;
}

int gmtls_construct_client_certificate(SSL *s)
{
	SSLerr(SSL_F_GMTLS_CONSTRUCT_CLIENT_CERTIFICATE,
		SSL_R_NOT_IMPLEMENTED);
	ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
	ossl_statem_set_error(s);
	return 0;
}

int gmtls_construct_client_key_exchange(SSL *s)
{
	SSLerr(SSL_F_GMTLS_CONSTRUCT_CLIENT_KEY_EXCHANGE,
		SSL_R_NOT_IMPLEMENTED);
	ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
	ossl_statem_set_error(s);
	return 0;
}

MSG_PROCESS_RETURN gmtls_process_server_certificate(SSL *s, PACKET *pkt)
{
	SSLerr(SSL_F_GMTLS_PROCESS_SERVER_CERTIFICATE,
		SSL_R_NOT_IMPLEMENTED);
	ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
	ossl_statem_set_error(s);
	return MSG_PROCESS_ERROR;
}

MSG_PROCESS_RETURN gmtls_process_server_key_exchange(SSL *s, PACKET *pkt)
{
	SSLerr(SSL_F_GMTLS_PROCESS_SERVER_KEY_EXCHANGE,
		SSL_R_NOT_IMPLEMENTED);
	ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
	ossl_statem_set_error(s);
	return MSG_PROCESS_ERROR;
}

MSG_PROCESS_RETURN gmtls_process_client_certificate(SSL *s, PACKET *pkt)
{
	SSLerr(SSL_F_GMTLS_PROCESS_CLIENT_CERTIFICATE,
		SSL_R_NOT_IMPLEMENTED);
	ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
	ossl_statem_set_error(s);
	return MSG_PROCESS_ERROR;
}

MSG_PROCESS_RETURN gmtls_process_client_key_exchange(SSL *s, PACKET *pkt)
{
	SSLerr(SSL_F_GMTLS_PROCESS_CLIENT_KEY_EXCHANGE,
		SSL_R_NOT_IMPLEMENTED);
	ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
	ossl_statem_set_error(s);
	return MSG_PROCESS_ERROR;
}
