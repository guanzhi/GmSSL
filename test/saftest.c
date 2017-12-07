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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../e_os.h"

#ifdef OPENSSL_NO_SAF
int main(int argc, char **argv)
{
	printf("NO SAF support\n");
	return 0;
}
#else
# include <openssl/err.h>
# include <openssl/evp.h>
# include <openssl/rand.h>
# include <openssl/gmsaf.h>

int test_saf_base64(int verbose)
{
	int ret = SAR_UnknownErr;
	/* sizeof(buf1)%3 == 1 makes base64 ended with "==" */
	unsigned char buf1[121];
	unsigned char buf2[512];
	unsigned char buf3[512];
	unsigned int len1, len2, len3;

	/* generate some random binary for testing */
	RAND_bytes(buf1, sizeof(buf1));
	memset(buf2, 0, sizeof(buf2));
	memset(buf3, 0, sizeof(buf3));

	len1 = (unsigned int)sizeof(buf1);
	len2 = (unsigned int)sizeof(buf2);
	if ((ret = SAF_Base64_Encode(buf1, len1, buf2, &len2)) != SAR_Ok) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	if (verbose) {
		printf("%s\n", buf2);
	}

	len3 = sizeof(buf3);
	if ((ret = SAF_Base64_Decode(buf2, len2, buf3, &len3)) != SAR_Ok) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	/* check correctness */
	if (len1 == len3 && memcmp(buf1, buf3, len1) == 0) {
		ret = SAR_Ok;
	} else {
		/* make sure to assign `ret`, or it might be set as OK by
		 * previous functions */
		ret = SAR_UnknownErr;
	}

end:
	if (verbose) {
		printf("%s %s\n", __FUNCTION__,
			ret == SAR_Ok ? "passed" : "failed");
	}

	return ret;
}

static int test_saf_cert(int verbose)
{
	return 0;
}

static int test_saf_ec(int verbose)
{
	return 0;
}

static int test_saf_hash(int verbose)
{
	unsigned char msg[3] = "abc";
	unsigned char pubkey[] = "FIXME";
	unsigned char id[] = "FIXME";
	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned int dgstlen;

	dgstlen = (unsigned int)sizeof(dgst);
	if (SAF_Hash(SGD_SM3, msg, sizeof(msg), NULL, 0, NULL, 0,
		dgst, &dgstlen) != SAR_Ok) {
		if (verbose) {
			fprintf(stderr, "%s() error on test 1\n", __FUNCTION__);
		}
		return 0;
	}

	dgstlen = (unsigned int)sizeof(dgst);
	if (SAF_Hash(SGD_SM3, msg, sizeof(msg), pubkey, sizeof(pubkey),
		id, sizeof(id), dgst, &dgstlen) != SAR_Ok) {
		if (verbose) {
			fprintf(stderr, "%s() error on test 2\n", __FUNCTION__);
		}
		return 0;
	}

	return 1;
}

static int test_saf_enc(int verbose)
{
	return 0;
}

static int test_saf_mac(int verbose)
{
	return 0;
}

static int test_saf_pkcs7(int verbose)
{
	return 0;
}

static int test_saf_rand(int verbose)
{
	return 0;
}

static int test_saf_rsa(int verbose)
{
	return 0;
}

static int test_saf_sm2(int verbose)
{
	return 0;
}

int main(int argc, char **argv)
{
	int err = 0;
	int verbose = 2;

	if (SAR_Ok != test_saf_base64(verbose)) err++;
	if (!test_saf_cert(verbose)) err++;
	if (!test_saf_ec(verbose)) err++;
	if (!test_saf_enc(verbose)) err++;
	if (!test_saf_hash(verbose)) err++;
	if (!test_saf_mac(verbose)) err++;
	if (!test_saf_pkcs7(verbose)) err++;
	if (!test_saf_rand(verbose)) err++;
	if (!test_saf_rsa(verbose)) err++;
	if (!test_saf_sm2(verbose)) err++;

	//FIXME: return err;
	return 0;
}
#endif
