/* ====================================================================
 * Copyright (c) 2015 - 2016 The GmSSL Project.  All rights reserved.
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

#ifndef HEADER_PEM3_H
#define HEADER_PEM3_H

#ifndef OPENSSL_NO_CPK
# include <openssl/cpk.h>
#endif
#ifndef OPENSSL_NO_SM9
# include <openssl/sm9.h>
#endif
#ifndef OPENSSL_NO_BFIBE
# include <openssl/bfibe.h>
#endif
#ifndef OPENSSL_NO_BB1IBE
# include <openssl/bb1ibe.h>
#endif
#ifndef OPENSSL_NO_PAILLIER
# include <openssl/paillier.h>
#endif


#ifdef __cplusplus
extern "C" {
#endif


#include <openssl/pem.h>


#define PEM_STRING_PAILLIER		"PAILLIER PRIVATE KEY"
#define PEM_STRING_PAILLIER_PUBLIC	"PAILLIER PUBLIC KEY"
#define PEM_STRING_CPK_PARAMS		"CPK PUBLIC PARAMETERS"
#define PEM_STRING_CPK_MASTER		"CPK MASTER SECRET"
#define PEM_STRING_SM9_PARAMS		"SM9 PUBLIC PARAMETERS"
#define PEM_STRING_SM9_MASTER		"SM9 MASTER SECRET"
#define PEM_STRING_SM9_PRIVATE		"SM9 PRIVATE KEY"
#define PEM_STRING_BFIBE_PARAMS		"BFIBE PUBLIC PARAMETERS"
#define PEM_STRING_BFIBE_MASTER		"BFIBE MASTER SECRET"
#define PEM_STRING_BFIBE_PRIVATE	"BFIBE PRIVATE KEY"
#define PEM_STRING_BB1IBE_PARAMS	"BB1IBE PUBLIC PARAMETERS"
#define PEM_STRING_BB1IBE_MASTER	"BB1IBE MASTER SECRET"
#define PEM_STRING_BB1IBE_PRIVATE	"BB1IBE PRIVATE KEY"


# ifndef OPENSSL_NO_PAILLIER
/*
DECLARE_PEM_rw_cb(PAILLIERPrivateKey, PAILLIER)
DECLARE_PEM_rw_const(PAILLIERPublicKey, PAILLIER)
DECLARE_PEM_rw(PAILLIER_PUBKEY, PAILLIER)
*/
# endif


#ifdef __cplusplus
}
#endif
#endif
