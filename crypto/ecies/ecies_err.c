/* crypto/ecies/ecies_err.c */
/* ====================================================================
 * Copyright (c) 2007 - 2015 The GmSSL Project.  All rights reserved.
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
#include <openssl/err.h>
#include "ecies.h"

#ifndef OPENSSL_NO_ERR

#define ERR_FUNC(func) ERR_PACK(ERR_LIB_ECIES,func,0)
#define ERR_REASON(reason) ERR_PACK(ERR_LIB_ECIES,0,reason)


static ERR_STRING_DATA ECIES_str_functs[] = {
	{ERR_FUNC(ECIES_F_ECIES_SET_PARAMETERS),"ECIES_set_parameters"},
	{ERR_FUNC(ECIES_F_ECIES_GET_PARAMETERS),"ECIES_get_parameters"},
	{ERR_FUNC(ECIES_F_ECIES_DO_ENCRYPT),	"ECIES_do_encrypt"},
	{ERR_FUNC(ECIES_F_ECIES_DO_DECRYPT),	"ECIES_do_decrypt"},
	{ERR_FUNC(ECIES_F_ECIES_ENCRYPT),	"ECIES_encrypt"},
	{ERR_FUNC(ECIES_F_ECIES_DECRYPT),	"ECIES_decrypt"},
	{0,NULL}
};

static ERR_STRING_DATA ECIES_str_reasons[] = {
	{ERR_REASON(ECIES_R_BAD_DATA),		"bad data"},
	{ERR_REASON(ECIES_R_UNKNOWN_CIPHER_TYPE),"unknown cipher type"},
	{ERR_REASON(ECIES_R_ENCRYPT_FAILED),	"encrypt failed"},
	{ERR_REASON(ECIES_R_DECRYPT_FAILED),	"decrypt failed"},
	{ERR_REASON(ECIES_R_UNKNOWN_MAC_TYPE),	"unknown MAC type"},
	{ERR_REASON(ECIES_R_GEN_MAC_FAILED),	"MAC generation failed"},
	{ERR_REASON(ECIES_R_VERIFY_MAC_FAILED),	"MAC verification failed"},
	{ERR_REASON(ECIES_R_ECDH_FAILED),	"ECDH failed"},
	{ERR_REASON(ECIES_R_BUFFER_TOO_SMALL),	"buffer too small"},
	{0,NULL}
};

#endif

void ERR_load_ECIES_strings(void)
{
#ifndef OPENSSL_NO_ERR

	if (ERR_func_error_string(ECIES_str_functs[0].error) == NULL) {
		ERR_load_strings(0,ECIES_str_functs);
		ERR_load_strings(0,ECIES_str_reasons);
	}
#endif
}

