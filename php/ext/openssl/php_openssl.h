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
   +----------------------------------------------------------------------+
   | PHP Version 7                                                        |
   +----------------------------------------------------------------------+
   | Copyright (c) 1997-2018 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Authors: Stig Venaas <venaas@php.net>                                |
   |          Wez Furlong <wez@thebrainroom.com                           |
   +----------------------------------------------------------------------+
 */

/* $Id$ */

#ifndef PHP_OPENSSL_H
#define PHP_OPENSSL_H
/* HAVE_OPENSSL would include SSL MySQL stuff */
#ifdef HAVE_OPENSSL_EXT
extern zend_module_entry openssl_module_entry;
#define phpext_openssl_ptr &openssl_module_entry

#include "php_version.h"
#define PHP_OPENSSL_VERSION PHP_VERSION

#define OPENSSL_RAW_DATA 1
#define OPENSSL_ZERO_PADDING 2
#define OPENSSL_DONT_ZERO_PAD_KEY 4

#define OPENSSL_ERROR_X509_PRIVATE_KEY_VALUES_MISMATCH 0x0B080074

/* Used for client-initiated handshake renegotiation DoS protection*/
#define OPENSSL_DEFAULT_RENEG_LIMIT 2
#define OPENSSL_DEFAULT_RENEG_WINDOW 300
#define OPENSSL_DEFAULT_STREAM_VERIFY_DEPTH 9
#define OPENSSL_DEFAULT_STREAM_CIPHERS "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:" \
	"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:" \
	"DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:" \
	"ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:" \
	"ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:" \
	"DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:" \
	"AES256-GCM-SHA384:AES128:AES256:HIGH:!SSLv2:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!RC4:!ADH"

#include <openssl/err.h>

struct php_openssl_errors {
	int buffer[ERR_NUM_ERRORS];
	int top;
	int bottom;
};

ZEND_BEGIN_MODULE_GLOBALS(openssl)
	struct php_openssl_errors *errors;
ZEND_END_MODULE_GLOBALS(openssl)

#define OPENSSL_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(openssl, v)

#if defined(ZTS) && defined(COMPILE_DL_OPENSSL)
ZEND_TSRMLS_CACHE_EXTERN();
#endif

php_stream_transport_factory_func php_openssl_ssl_socket_factory;

void php_openssl_store_errors();

PHP_MINIT_FUNCTION(openssl);
PHP_MSHUTDOWN_FUNCTION(openssl);
PHP_MINFO_FUNCTION(openssl);
PHP_GINIT_FUNCTION(openssl);
PHP_GSHUTDOWN_FUNCTION(openssl);

PHP_FUNCTION(openssl_pkey_get_private);
PHP_FUNCTION(openssl_pkey_get_public);
PHP_FUNCTION(openssl_pkey_free);
PHP_FUNCTION(openssl_pkey_new);
PHP_FUNCTION(openssl_pkey_export);
PHP_FUNCTION(openssl_pkey_export_to_file);
PHP_FUNCTION(openssl_pkey_get_details);

PHP_FUNCTION(openssl_sign);
PHP_FUNCTION(openssl_verify);
PHP_FUNCTION(openssl_seal);
PHP_FUNCTION(openssl_open);
PHP_FUNCTION(openssl_private_encrypt);
PHP_FUNCTION(openssl_private_decrypt);
PHP_FUNCTION(openssl_public_encrypt);
PHP_FUNCTION(openssl_public_decrypt);

PHP_FUNCTION(openssl_pbkdf2);

PHP_FUNCTION(openssl_pkcs7_verify);
PHP_FUNCTION(openssl_pkcs7_decrypt);
PHP_FUNCTION(openssl_pkcs7_sign);
PHP_FUNCTION(openssl_pkcs7_encrypt);
PHP_FUNCTION(openssl_pkcs7_read);

PHP_FUNCTION(openssl_error_string);

PHP_FUNCTION(openssl_x509_read);
PHP_FUNCTION(openssl_x509_free);
PHP_FUNCTION(openssl_x509_parse);
PHP_FUNCTION(openssl_x509_checkpurpose);
PHP_FUNCTION(openssl_x509_export);
PHP_FUNCTION(openssl_x509_fingerprint);
PHP_FUNCTION(openssl_x509_export_to_file);
PHP_FUNCTION(openssl_x509_check_private_key);

PHP_FUNCTION(openssl_pkcs12_export);
PHP_FUNCTION(openssl_pkcs12_export_to_file);
PHP_FUNCTION(openssl_pkcs12_read);

PHP_FUNCTION(openssl_csr_new);
PHP_FUNCTION(openssl_csr_export);
PHP_FUNCTION(openssl_csr_export_to_file);
PHP_FUNCTION(openssl_csr_sign);
PHP_FUNCTION(openssl_csr_get_subject);
PHP_FUNCTION(openssl_csr_get_public_key);

PHP_FUNCTION(openssl_spki_new);
PHP_FUNCTION(openssl_spki_verify);
PHP_FUNCTION(openssl_spki_export);
PHP_FUNCTION(openssl_spki_export_challenge);

PHP_FUNCTION(openssl_get_cert_locations);

#ifdef PHP_WIN32
#define PHP_OPENSSL_BIO_MODE_R(flags) (((flags) & PKCS7_BINARY) ? "rb" : "r")
#define PHP_OPENSSL_BIO_MODE_W(flags) (((flags) & PKCS7_BINARY) ? "wb" : "w")
#else
#define PHP_OPENSSL_BIO_MODE_R(flags) "r"
#define PHP_OPENSSL_BIO_MODE_W(flags) "w"
#endif

#else

#define phpext_openssl_ptr NULL

#endif


#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 */
