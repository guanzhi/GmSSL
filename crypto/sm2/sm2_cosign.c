/* ====================================================================
 * Copyright (c) 2015 - 2019 The GmSSL Project.  All rights reserved.
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

#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sm2.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/paillier.h>
#include "../ec/ec_lcl.h"
#include "sm2_lcl.h"

SM2_COSIGNER1_SHARE *SM2_cosigner1_setup(BIGNUM **k1, EC_KEY *ec_key, PAILLIER *pk)
{
	SM2err(SM2_F_SM2_COSIGNER1_SETUP, SM2_R_NOT_IMPLEMENTED);
	return NULL;
}

SM2_COSIGNER2_SHARE *SM2_cosigner2_setup(const SM2_COSIGNER1_SHARE *s1, BIGNUM **k2, EC_KEY *ec_key, PAILLIER *pk)
{
	SM2err(SM2_F_SM2_COSIGNER2_SETUP, SM2_R_NOT_IMPLEMENTED);
	return NULL;
}

SM2_COSIGNER1_PROOF *SM2_cosigner1_generate_proof(EC_KEY *ec_key, PAILLIER *pk)
{
	SM2err(SM2_F_SM2_COSIGNER1_GENERATE_PROOF, SM2_R_NOT_IMPLEMENTED);
	return NULL;
}

SM2_COSIGNER2_PROOF *SM2_cosigner2_generate_proof(EC_KEY *ec_key, PAILLIER *pk)
{
	SM2err(SM2_F_SM2_COSIGNER2_GENERATE_PROOF, SM2_R_NOT_IMPLEMENTED);
	return NULL;
}

ECDSA_SIG *SM2_cosigner1_generate_signature(EC_KEY *ec_key, PAILLIER *pk)
{
	SM2err(SM2_F_SM2_COSIGNER1_GENERATE_SIGNATURE, SM2_R_NOT_IMPLEMENTED);
	return NULL;
}
