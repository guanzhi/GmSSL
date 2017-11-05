/*
 * Copyright (c) 2015 - 2017 The GmSSL Project.  All rights reserved.
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
 */

#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>


#ifdef OPENSSL_NO_MACRO
int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid)
{
	return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
		EVP_PKEY_OP_PARAMGEN|EVP_PKEY_OP_KEYGEN,
		EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, nid, NULL);
}

int EVP_PKEY_CTX_set_ec_param_enc(EVP_PKEY_CTX *ctx, int param_enc)
{
	return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
		EVP_PKEY_OP_PARAMGEN|EVP_PKEY_OP_KEYGEN,
		EVP_PKEY_CTRL_EC_PARAM_ENC, param_enc, NULL);
}

int EVP_PKEY_CTX_set_ecdh_cofactor_mode(EVP_PKEY_CTX *ctx, int co_mode)
{
	return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
		EVP_PKEY_OP_DERIVE,
		EVP_PKEY_CTRL_EC_ECDH_COFACTOR, co_mode, NULL);
}

int EVP_PKEY_CTX_get_ecdh_cofactor_mode(EVP_PKEY_CTX *ctx)
{
	return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
		EVP_PKEY_OP_DERIVE,
		EVP_PKEY_CTRL_EC_ECDH_COFACTOR, -2, NULL);
}

int EVP_PKEY_CTX_set_ecdh_kdf_type(EVP_PKEY_CTX *ctx, int kdf)
{
	return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
		EVP_PKEY_OP_DERIVE,
		EVP_PKEY_CTRL_EC_KDF_TYPE, kdf, NULL);
}

int EVP_PKEY_CTX_get_ecdh_kdf_type(EVP_PKEY_CTX *ctx)
{
	return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
		EVP_PKEY_OP_DERIVE,
		EVP_PKEY_CTRL_EC_KDF_TYPE, -2, NULL);
}

int EVP_PKEY_CTX_set_ecdh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)
{
	return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
		EVP_PKEY_OP_DERIVE,
		EVP_PKEY_CTRL_EC_KDF_MD, 0, (void *)md);
}

int EVP_PKEY_CTX_get_ecdh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD **pmd)
{
	return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
		EVP_PKEY_OP_DERIVE,
		EVP_PKEY_CTRL_GET_EC_KDF_MD, 0, (void *)pmd);
}

int EVP_PKEY_CTX_set_ecdh_kdf_outlen(EVP_PKEY_CTX *ctx, int len)
{
	return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
		EVP_PKEY_OP_DERIVE,
		EVP_PKEY_CTRL_EC_KDF_OUTLEN, len, NULL);
}

int EVP_PKEY_CTX_get_ecdh_kdf_outlen(EVP_PKEY_CTX *ctx, int *plen)
{
	return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
		EVP_PKEY_OP_DERIVE,
		EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN, 0, (void *)plen);
}

int EVP_PKEY_CTX_set0_ecdh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char *der, int len)
{
	return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
		EVP_PKEY_OP_DERIVE,
		EVP_PKEY_CTRL_EC_KDF_UKM, len, (void *)der)
}

int EVP_PKEY_CTX_get0_ecdh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char **pder)
{
	return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
		EVP_PKEY_OP_DERIVE,
		EVP_PKEY_CTRL_GET_EC_KDF_UKM, 0, (void *)pder)
}
#endif
