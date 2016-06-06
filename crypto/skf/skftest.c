/* crypto/skf/skftest.c */
/* ====================================================================
 * Copyright (c) 2015-2016 The GmSSL Project.  All rights reserved.
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
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/skf.h>
#include <openssl/skf_ex.h>

#define PRINT_ERRSTR(rv) \
	fprintf(stderr, "error: %s %d: %s\n", __FILE__, __LINE__, SKF_get_errstr(rv))

DEVHANDLE open_dev(LPSTR devName, int verbose)
{
	DEVHANDLE hDev;
	ULONG rv;

	if ((rv = SKF_ConnectDev(devName, &hDev)) != SAR_OK) {
		PRINT_ERRSTR(rv);
		return NULL;
	}

	if (verbose > 1) {
		DEVINFO devInfo;
		if ((rv = SKF_GetDevInfo(hDev, &devInfo)) != SAR_OK) {
			PRINT_ERRSTR(rv);
			SKF_DisConnectDev(hDev);
			return NULL;
		}
		SKF_print_dev_info(&devInfo);
	}

	return hDev;
}

int test_skf_mac(DEVHANDLE hDev, ULONG ulAlgID, int verbose)
{
	int ret = 0;
	HANDLE hKey = NULL;
	HANDLE hMac = NULL;
	BLOCKCIPHERPARAM param;
	BYTE key[EVP_MAX_KEY_LENGTH];
	BYTE data[128] = {0};
	BYTE mac[EVP_MAX_MD_SIZE];
	ULONG dataLen, macLen;
	ULONG rv;

	if ((rv = SKF_SetSymmKey(hDev, key, ulAlgID, &hKey)) != SAR_OK) {
		PRINT_ERRSTR(rv);
		goto end;
	}

	bzero(&param, sizeof(param));
	param.IVLen = 0;
	param.PaddingType = SKF_NO_PADDING;
	if ((rv = SKF_MacInit(hKey, &param, &hMac)) != SAR_OK) {
		PRINT_ERRSTR(rv);
		goto end;
	}

	dataLen = (ULONG)sizeof(data);
	macLen = (ULONG)sizeof(mac);
	if ((rv = SKF_Mac(hMac, data, dataLen, mac, &macLen)) != SAR_OK) {
		PRINT_ERRSTR(rv);
		goto end;
	}

	if (macLen != 16) {
		printf("macLen = %d\n", (int)macLen);
		fprintf(stderr, "error: %s %d: %s\n", __FILE__, __LINE__, "mac length != 16");
		goto end;
	}

	ret = 1;
end:
	if ((rv = SKF_CloseHandle(hMac)) != SAR_OK) {
		PRINT_ERRSTR(rv);
		ret = 0;
	}
	if ((rv = SKF_CloseHandle(hKey)) != SAR_OK) {
		PRINT_ERRSTR(rv);
		ret = 0;
	}

	if (ret && verbose) {
		printf("%s(%s) passed\n", __FUNCTION__, SKF_get_alg_name(ulAlgID));
	}

	return ret;
}

int test_skf_dgst(DEVHANDLE hDev, ULONG ulAlgID, int verbose)
{
	int ret = 0;
	HANDLE hHash = NULL;
	BYTE data[200] = {0};
	BYTE dgst[EVP_MAX_MD_SIZE];
	ULONG dataLen, dgstLen;
	ULONG rv;

	if ((rv = SKF_DigestInit(hDev, ulAlgID, NULL, NULL, 0, &hHash)) != SAR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}
	dataLen = (ULONG)sizeof(data);
	dgstLen = (ULONG)sizeof(dgst);
	if ((rv = SKF_Digest(hHash, data, dataLen, dgst, &dgstLen)) != SAR_OK) {
		PRINT_ERRSTR(rv);
		goto end;
	}

	if (verbose > 1) {
		ULONG i;
		printf("%s (%u-Byte) = ", SKF_get_alg_name(ulAlgID), dgstLen);
		for (i = 0; i < dgstLen; i++) {
			printf("%02x", dgst[i]);
		}
		printf("\n");
	}

	ret = 1;
end:
	if ((rv = SKF_CloseHandle(hHash)) != SAR_OK) {
		PRINT_ERRSTR(rv);
		ret = 0;
	}
	if (ret && verbose) {
		printf("%s(%s) passed\n", __FUNCTION__, SKF_get_alg_name(ulAlgID));
	}

	return ret;
}

int test_skf_enc(DEVHANDLE hDev, ULONG ulAlgID, BLOCKCIPHERPARAM param, int verbose)
{
	int ret = 0;
	HANDLE hKey = NULL;
	BYTE key[EVP_MAX_KEY_LENGTH];
	BYTE data[] = "message to be encrypted";
	BYTE cbuf[256];
	BYTE mbuf[256];
	ULONG mlen, clen;
	ULONG rv;

	if ((rv = SKF_SetSymmKey(hDev, key, ulAlgID, &hKey)) != SAR_OK) {
		PRINT_ERRSTR(rv);
		goto end;
	}

	if ((rv = SKF_EncryptInit(hKey, param)) != SAR_OK) {
		PRINT_ERRSTR(rv);
		goto end;
	}
	mlen = (ULONG)sizeof(data);
	clen = (ULONG)sizeof(cbuf);
	if ((rv = SKF_Encrypt(hKey, data, mlen, cbuf, &clen)) != SAR_OK) {
		PRINT_ERRSTR(rv);
		goto end;
	}

	if ((rv = SKF_DecryptInit(hKey, param)) != SAR_OK) {
		PRINT_ERRSTR(rv);
		goto end;
	}
	mlen = (ULONG)sizeof(mbuf);
	if ((rv = SKF_Decrypt(hKey, cbuf, clen, mbuf, &mlen)) != SAR_OK) {
		PRINT_ERRSTR(rv);
		goto end;
	}

	//FIXME: compare data with mbuf

	if (verbose > 1) {
		//FIXME: print ciphertext
	}

	ret = 1;
end:
	if ((rv = SKF_CloseHandle(hKey)) != SAR_OK) {
		PRINT_ERRSTR(rv);
		ret = 0;
	}
	if (ret && verbose) {
		//FIXME: print success info
	}

	return ret;
}

int test_skf_rsa(DEVHANDLE hDev, ULONG ulBitsLen, int verbose)
{
	int ret = 0;
	RSAPRIVATEKEYBLOB rsa;
	RSAPUBLICKEYBLOB rsaPubKey;
	BYTE data[] = "message to be encrypted or signed";
	BYTE cbuf[512];
	BYTE mbuf[256];
	BYTE sig[512];
	ULONG len, clen, mlen, siglen;
	ULONG rv;

	if ((rv = SKF_GenExtRSAKey(hDev, 2048, &rsa)) != SAR_OK) {
		PRINT_ERRSTR(rv);
		goto end;
	}

	memcpy(&rsaPubKey, &rsa, sizeof(rsaPubKey));

	len = (ULONG)sizeof(data);
	clen = (ULONG)sizeof(cbuf);
	if ((rv = SKF_ExtRSAPubKeyOperation(hDev, &rsaPubKey, data, len, cbuf, &clen)) != SAR_OK) {
		PRINT_ERRSTR(rv);
		goto end;
	}

	mlen = (ULONG)sizeof(mbuf);
	if ((rv = SKF_ExtRSAPriKeyOperation(hDev, &rsa, cbuf, clen, mbuf, &mlen)) != SAR_OK) {
		PRINT_ERRSTR(rv);
		goto end;
	}

	ret = 1;
end:
	return 0;
}

int test_skf_ec(DEVHANDLE hDev, int verbose)
{
	ECCPRIVATEKEYBLOB priKey;
	ECCPUBLICKEYBLOB pubKey;
	ECCSIGNATUREBLOB sig;
	BYTE cbuf[sizeof(ECCCIPHERBLOB) + 512];
	BYTE msg[] = "message to be signed and encrypted";
	BYTE mbuf[128];
	ULONG mlen, clen;
	ULONG rv;

	bzero(&priKey, sizeof(priKey));
	bzero(&pubKey, sizeof(pubKey));
	if ((rv = SKF_GenExtECCKeyPair(hDev, &priKey, &pubKey)) != SAR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	mlen = (ULONG)sizeof(msg);
	bzero(&sig, sizeof(sig));
	if ((rv = SKF_ExtECCSign(hDev, &priKey, msg, mlen, &sig)) != SAR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}
	if ((rv = SKF_ExtECCVerify(hDev, &pubKey, msg, mlen, &sig)) != SAR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	mlen = (ULONG)sizeof(msg);
	bzero(cbuf, sizeof(cbuf));
	if ((rv = SKF_ExtECCEncrypt(hDev, &pubKey, msg, mlen, (ECCCIPHERBLOB *)cbuf)) != SAR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}
	mlen = (ULONG)sizeof(mbuf);
	bzero(mbuf, sizeof(mbuf));
	if ((rv = SKF_ExtECCDecrypt(hDev, &priKey, (ECCCIPHERBLOB *)cbuf, mbuf, &mlen)) != SAR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	return 1;
}

int main(int argc, char **argv)
{
	int verbose = 2;
	DEVHANDLE hDev = NULL;
	ULONG digestAlgors[] = {
		SGD_SM3,
		SGD_SHA1,
		SGD_SHA256
	};
	ULONG cipherAlgors[] = {
		SGD_SM4_ECB,
		SGD_SM4_CBC,
		SGD_SM4_CFB,
		SGD_SM4_CFB,
		SGD_SM4_CFB,
		SGD_SM4_OFB
	};
	BLOCKCIPHERPARAM cipherParams[] = {
		{{0},  0, SKF_NO_PADDING, 0},
		{{0}, 16, SKF_PKCS5_PADDING, 0},
		{{0}, 16, SKF_NO_PADDING, 1},
		{{0}, 16, SKF_NO_PADDING, 8},
		{{0}, 16, SKF_NO_PADDING, 128},
		{{0}, 16, SKF_NO_PADDING, 0},
	};
	ULONG rsaBits[] = { 1024, 2048 };
	int i;

	hDev = open_dev((LPSTR)"name", verbose);
	/*
	if (!test_skf_mac(hDev, SGD_SM4_MAC, verbose)) {
		goto end;
	}
	*/

	for (i = 0; i < sizeof(digestAlgors)/sizeof(digestAlgors[0]); i++) {
		if (!test_skf_dgst(hDev, digestAlgors[i], verbose)) {
			goto end;
		}
	}

	for (i = 0; i < sizeof(cipherAlgors)/sizeof(cipherAlgors[0]); i++) {
		if (!test_skf_enc(hDev, cipherAlgors[i], cipherParams[i], verbose)) {
			goto end;
		}
	}

	for (i = 0; i < sizeof(rsaBits)/sizeof(rsaBits[0]); i++) {
		if (!test_skf_rsa(hDev, test_skf_rsa(hDev, rsaBits[i], verbose))) {
			goto end;
		}
	}

	if (!test_skf_ec(hDev, verbose)) {
		goto end;
	}

end:
	ERR_print_errors_fp(stderr);
	SKF_DisConnectDev(hDev);
	return -1;
}

