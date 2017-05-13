/* ====================================================================
 * Copyright (c) 2014 - 2016 The GmSSL Project.  All rights reserved.
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
 * we need some testing data for signature and ciphertext
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../e_os.h"

#ifdef OPENSSL_NO_GMAPI
int main(int argc, char **argv)
{
	printf("NO GMAPI support\n");
	return 0;
}
#else
# include <openssl/evp.h>
# include <openssl/gmapi.h>

/*
static int test_sgd(int verbose)
{
	int usage[] = {
		SGD_PK_SIGN,
		SGD_PK_DH,
		SGD_PK_ENC,
	};
	int cipher[] = {
		SGD_SM1_ECB,
		SGD_SM1_CBC,
		SGD_SM1_CFB,
		SGD_SM1_OFB,
		SGD_SSF33_ECB,
		SGD_SSF33_CBC,
		SGD_SSF33_CFB,
		SGD_SSF33_OFB,
		SGD_SM4_ECB,
		SGD_SM4_CBC,
		SGD_SM4_CFB,
		SGD_SM4_OFB,
		SGD_ZUC_EEA3,
	};
	int md[] = {
		SGD_SM3,
		SGD_SHA1,
		SGD_SHA256,
	};
	int i;

	for (i = 0; i < OSSL_NELEM(usage); i++) {
		if (!GMAPI_keyusage2str(usage[i])) {
			return 0;
		}
	}

	for (i = 0; i < OSSL_NELEM(cipher); i++) {
		if (GMAPI_sgd2ciphernid(cipher[i]) == NID_undef) {
			return 0;
		}
	}

	for (i = 0; i < OSSL_NELEM(md); i++) {
		if (GMAPI_sgd2mdnid(md[i]) == NID_undef) {
			return 0;
		}
	}

	return 1;
}

static int test_sdf_rsa(int verbose)
{
	int ret = 0;
	unsigned char pkbuf[] = {
		0x01, 0x02,
	};
	unsigned char skbuf[] = {
		0x01, 0x02,
	};
	RSArefPublicKey *pkref = (RSArefPublicKey *)pkbuf;
	RSArefPrivateKey *skref = (RSArefPrivateKey *)skbuf;
	RSA *pk = NULL;
	RSA *sk = NULL;

	if (!(pk = RSA_new_from_RSArefPublicKey(pkref))
		|| !RSA_set_RSArefPublicKey(pk, pkref)
		|| !RSA_get_RSArefPublicKey(pk, pkref)
		|| !(sk = RSA_new_from_RSArefPrivateKey(skref))
		|| !RSA_set_RSArefPrivateKey(sk, skref)
		|| !RSA_get_RSArefPrivateKey(sk, skref)) {
		goto end;
	}

	ret = 1;
end:
	RSA_free(pk);
	RSA_free(sk);
	return ret;
}

static int test_sdf_ec(int verbose)
{
	int ret = 0;

	unsigned char pkbuf[] = {
		0x01, 0x02,
	};
	unsigned char skbuf[] = {
		0x01, 0x02,
	};
	unsigned char cvbuf[] = {
		0x01, 0x02,
	};
	unsigned char sigbuf[] = {
		0x01, 0x02,
	};
	ECCrefPublicKey *pkref = (ECCrefPublicKey *)pkbuf;
	ECCrefPrivateKey *skref = (ECCrefPrivateKey *)skbuf;
	ECCCipher *cvref = (ECCCipher *)cvbuf;
	ECCSignature *sigref = (ECCSignature *)sigbuf;
	EC_KEY *pk = NULL;
	EC_KEY *sk = NULL;
	SM2_CIPHERTEXT_VALUE *cv = NULL;
	ECDSA_SIG *sig = NULL;

	if (!(pk = EC_KEY_new_from_ECCrefPublicKey(pkref))
		|| !EC_KEY_set_ECCrefPublicKey(pk, pkref)
		|| !EC_KEY_get_ECCrefPublicKey(pk, pkref)
		|| !(sk = EC_KEY_new_from_ECCrefPrivateKey(skref))
		|| !EC_KEY_set_ECCrefPrivateKey(sk, skref)
		|| !EC_KEY_get_ECCrefPrivateKey(sk, skref)
		|| !(cv = SM2_CIPHERTEXT_VALUE_new_from_ECCCipher(cvref))
		|| !SM2_CIPHERTEXT_VALUE_set_ECCCipher(cv, cvref)
		|| !SM2_CIPHERTEXT_VALUE_get_ECCCipher(cv, cvref)
		|| !(sig = ECDSA_SIG_new_from_ECCSignature(sigref))
		|| !ECDSA_SIG_set_ECCSignature(sig, sigref)
		|| !ECDSA_SIG_get_ECCSignature(sig, sigref)) {
		goto end;
	}

	ret = 1;
end:
	EC_KEY_free(pk);
	EC_KEY_free(sk);
	SM2_CIPHERTEXT_VALUE_free(cv);
	ECDSA_SIG_free(sig);
	return ret;
}

static int test_skf_rsa(int verbose)
{
	int ret = 0;
	unsigned char pkbuf[] = {
		0x01, 0x02,
	};
	unsigned char skbuf[] = {
		0x01, 0x02,
	};
	RSAPUBLICKEYBLOB *pkref = (RSAPUBLICKEYBLOB *)pkbuf;
	RSArefPrivateKey *skref = (RSArefPrivateKey *)skbuf;
	RSA *pk = NULL;
	RSA *sk = NULL;

	if (!(pk = RSA_new_from_RSAPUBLICKEYBLOB(pkref))
		|| !RSA_set_RSAPUBLICKEYBLOB(pk, pkref)
		|| !RSA_get_RSAPUBLICKEYBLOB(pk, pkref)
		|| !(sk = RSA_new_from_RSArefPrivateKey(skref))
		|| !RSA_set_RSArefPrivateKey(sk, skref)
		|| !RSA_get_RSArefPrivateKey(sk, skref)) {
		goto end;
	}

	ret = 1;
end:
	RSA_free(pk);
	RSA_free(sk);
	return ret;
}

static int test_skf_ec(int verbose)
{
	int ret = 0;

	unsigned char pkbuf[] = {
		0x01, 0x02,
	};
	unsigned char skbuf[] = {
		0x01, 0x02,
	};
	unsigned char cvbuf[] = {
		0x01, 0x02,
	};
	unsigned char sigbuf[] = {
		0x01, 0x02,
	};
	ECCPUBLICKEYBLOB *pkref = (ECCPUBLICKEYBLOB *)pkbuf;
	ECCPRIVATEKEYBLOB *skref = (ECCPRIVATEKEYBLOB *)skbuf;
	ECCCIPHERBLOB *cvref = (ECCCIPHERBLOB *)cvbuf;
	ECCSIGNATUREBLOB *sigref = (ECCSIGNATUREBLOB *)sigbuf;
	EC_KEY *pk = NULL;
	EC_KEY *sk = NULL;
	SM2_CIPHERTEXT_VALUE *cv = NULL;
	ECDSA_SIG *sig = NULL;

	if (!(pk = EC_KEY_new_from_ECCPUBLICKEYBLOB(pkref))
		|| !EC_KEY_set_ECCPUBLICKEYBLOB(pk, pkref)
		|| !EC_KEY_get_ECCPUBLICKEYBLOB(pk, pkref)
		|| !(sk = EC_KEY_new_from_ECCPRIVATEKEYBLOB(skref))
		|| !EC_KEY_set_ECCPRIVATEKEYBLOB(sk, skref)
		|| !EC_KEY_get_ECCPRIVATEKEYBLOB(sk, skref)
		|| !(cv = SM2_CIPHERTEXT_VALUE_new_from_ECCCIPHERBLOB(cvref))
		|| !SM2_CIPHERTEXT_VALUE_set_ECCCIPHERBLOB(cv, cvref)
		|| !SM2_CIPHERTEXT_VALUE_get_ECCCIPHERBLOB(cv, cvref)
		|| !(sig = ECDSA_SIG_new_from_ECCSIGNATUREBLOB(sigref))
		|| !ECDSA_SIG_set_ECCSIGNATUREBLOB(sig, sigref)
		|| !ECDSA_SIG_get_ECCSIGNATUREBLOB(sig, sigref)) {
		goto end;
	}

	ret = 1;
end:
	EC_KEY_free(pk);
	EC_KEY_free(sk);
	SM2_CIPHERTEXT_VALUE_free(cv);
	ECDSA_SIG_free(sig);
	return ret;
}
*/
int main(int argc, char **argv)
{
/*
	int verbose = 1;
	if (!test_sgd(verbose)
		|| !test_sdf_ec(verbose)
		|| !test_sdf_rsa(verbose)
		|| !test_skf_ec(verbose)
		|| !test_skf_rsa(verbose)) {
		printf("test failed\n");
		return 1;
	} else {
		printf("test ok\n");
		return 0;
	}
*/
return 0;
}
#endif
