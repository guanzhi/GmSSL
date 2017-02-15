/* ====================================================================
 * Copyright (c) 2016 The GmSSL Project.  All rights reserved.
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
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sgd.h>

const EVP_MD *EVP_get_digestbysgd(int sgd)
{
	switch (sgd) {
	case SGD_SM3:
		return EVP_sm3();
	case SGD_SHA1:
		return EVP_sha1();
	case SGD_SHA256:
		return EVP_sha256();
	}
	return NULL;
}

const EVP_CIPHER *EVP_get_cipherbysgd(int sgd)
{
	switch (sgd) {
	case SGD_SM4_ECB:
		return EVP_sms4_ecb();
	case SGD_SM4_CBC:
		return EVP_sms4_cbc();
	case SGD_SM4_CFB:
		return EVP_sms4_cfb();
	case SGD_SM4_OFB:
		return EVP_sms4_ofb();
#define OPENSSL_NO_ZUC
#ifndef OPENSSL_NO_ZUC
	case SGD_ZUC:
		return EVP_zuc();
	case SGD_ZUC_EEA3:
		return EVP_zuc_eea3();
#endif
	}
	return NULL;
}

/*
int load_engine(void)
{
	ENGINE *e;

	ENGINE_load_builtin_engines(0);

	ENGINE_register_all_complete();


}
*/


const char *GMAPI_keyusage2str(int usage)
{
	return NULL;
}

int GMAPI_sgd2ciphernid(int sgd)
{
	return 0;
}

int GMAPI_sgd2mdnid(int sgd)
{
	return 0;
}

