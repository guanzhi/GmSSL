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
#include <stdlib.h>
#include <strings.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#include <openssl/x509.h>
#include "GmSSL.h"

JNIEXPORT jint JNICALL JNI_onload(JavaVM *vm, void *reserved)
{
	return JNI_VERSION_1_2;
}

JNIEXPORT void JNICALL JNI_onunload(JavaVM *vm, void *reserved)
{
}

JNIEXPORT jstring JNICALL Java_GmSSL_getVersion(
	JNIEnv *env, jobject this, jint type)
{
	return (*env)->NewStringUTF(env, OpenSSL_version(type));
}

JNIEXPORT jbyteArray JNICALL Java_GmSSL_generateRandom(
	JNIEnv *env, jobject this, jint outlen)
{
	jbyteArray ret = NULL;
	jbyte outbuf[outlen];

	if (!RAND_bytes((unsigned char *)outbuf, outlen)) {
		return NULL;
	}
	if ((ret = (*env)->NewByteArray(env, outlen))) {
		(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);
	}

	return ret;
}

JNIEXPORT jobjectArray JNICALL Java_GmSSL_getCiphers(
	JNIEnv *env, jobject this, jboolean aliases)
{
	char *algors = "sms4-ecb:sms4-cbc:sms4-ofb:sms4-cfb:sms4-ctr";
	return (*env)->NewStringUTF(env, algors);
}

JNIEXPORT jint JNICALL Java_GmSSL_getCipherIVLength(
	JNIEnv *env, jobject this, jstring algor)
{
	jint ret = -1;
	const char *alg = NULL;
	const EVP_CIPHER *cipher;

	alg = (*env)->GetStringUTFChars(env, algor, 0);
	if ((cipher = EVP_get_cipherbyname(alg))) {
		ret = EVP_CIPHER_iv_length(cipher);
	}

	(*env)->ReleaseStringUTFChars(env, algor, alg);
	return ret;
}

JNIEXPORT jint JNICALL Java_GmSSL_getCipherKeyLength(
	JNIEnv *env, jobject this, jstring algor)
{
	jint ret = -1;
	const char *alg = NULL;
	const EVP_CIPHER *cipher;

	alg = (*env)->GetStringUTFChars(env, algor, 0);
	cipher = EVP_get_cipherbyname(alg);
	if (cipher) {
		ret = EVP_CIPHER_key_length(cipher);
	}

	(*env)->ReleaseStringUTFChars(env, algor, alg);
	return ret;
}

JNIEXPORT jint JNICALL Java_GmSSL_getCipherBlockSize(
	JNIEnv *env, jobject this, jstring algor)
{
	jint ret = -1;
	const char *alg = NULL;
	const EVP_CIPHER *cipher;

	alg = (*env)->GetStringUTFChars(env, algor, 0);
	if ((cipher = EVP_get_cipherbyname(alg))) {
		ret = EVP_CIPHER_block_size(cipher);
	}

	(*env)->ReleaseStringUTFChars(env, algor, alg);
	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_GmSSL_symmetricEncrypt(
	JNIEnv *env, jobject this, jstring algor, jint flag,
	jbyteArray in, jbyteArray key, jbyteArray iv)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	const unsigned char *keybuf = NULL;
	const unsigned char *ivbuf = NULL;
	const unsigned char *inbuf = NULL;
	unsigned char *outbuf = NULL;
	int inlen, keylen, ivlen, outlen, lastlen;
	const EVP_CIPHER *cipher;
	EVP_CIPHER_CTX *cctx = NULL;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))
		|| !(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))
		|| (inlen = (*env)->GetArrayLength(env, in)) <= 0
		|| !(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))
		|| (keylen = (*env)->GetArrayLength(env, key)) <= 0) {
		goto end;
	}
	ivbuf = (unsigned char *)(*env)->GetByteArrayElements(env, iv, 0);
	ivlen = (*env)->GetArrayLength(env, iv);

	if (!(cipher = EVP_get_cipherbyname(alg))
		|| keylen != EVP_CIPHER_key_length(cipher)
		|| ivlen != EVP_CIPHER_iv_length(cipher)
		|| !(outbuf = OPENSSL_malloc(inlen + 2 * EVP_CIPHER_block_size(cipher)))
		|| !(cctx = EVP_CIPHER_CTX_new())
		|| !EVP_EncryptInit_ex(cctx, cipher, NULL, keybuf, ivbuf)
		|| !EVP_EncryptUpdate(cctx, outbuf, &outlen, inbuf, inlen)
		|| !EVP_EncryptFinal_ex(cctx, outbuf + outlen, &lastlen)) {
		goto end;
	}
	outlen += lastlen;

	if ((ret = (*env)->NewByteArray(env, outlen))) {
		(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);
	}

end:
	(*env)->ReleaseStringUTFChars(env, algor, alg);
	(*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, iv, (jbyte *)ivbuf, JNI_ABORT);
	OPENSSL_free(outbuf);
	EVP_CIPHER_CTX_free(cctx);
	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_GmSSL_symmetricDecrypt(
	JNIEnv *env, jobject this, jstring algor, jint flag,
	jbyteArray in, jbyteArray key, jbyteArray iv)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	const unsigned char *inbuf = NULL;
	const unsigned char *keybuf = NULL;
	const unsigned char *ivbuf = NULL;
	unsigned char *outbuf = NULL;
	int inlen, keylen, ivlen, outlen, lastlen;
	const EVP_CIPHER *cipher;
	EVP_CIPHER_CTX *cctx = NULL;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))
		|| !(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))
		|| (inlen = (*env)->GetArrayLength(env, in)) <= 0
		|| !(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))
		|| (keylen = (*env)->GetArrayLength(env, key)) <= 0) {
		goto end;
	}
	ivbuf = (unsigned char *)(*env)->GetByteArrayElements(env, iv, 0);
	ivlen = (*env)->GetArrayLength(env, iv);

	if (!(cipher = EVP_get_cipherbyname(alg))
		|| keylen != EVP_CIPHER_key_length(cipher)
		|| ivlen != EVP_CIPHER_iv_length(cipher)
		|| !(outbuf = OPENSSL_malloc(inlen))
		|| !(cctx = EVP_CIPHER_CTX_new())
		|| !EVP_EncryptInit_ex(cctx, cipher, NULL, keybuf, ivbuf)
		|| !EVP_EncryptUpdate(cctx, outbuf, &outlen, inbuf, inlen)
		|| !EVP_EncryptFinal_ex(cctx, outbuf + outlen, &lastlen)) {
		goto end;
	}
	outlen += lastlen;

	if ((ret = (*env)->NewByteArray(env, outlen))) {
		(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);
	}

end:
	(*env)->ReleaseStringUTFChars(env, algor, alg);
	(*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, iv, (jbyte *)ivbuf, JNI_ABORT);
	EVP_CIPHER_CTX_free(cctx);
	return ret;
}

JNIEXPORT jobjectArray JNICALL Java_GmSSL_getDigests(
	JNIEnv *env, jobject this, jboolean aliases)
{
	char *digests = "sm3:sha1:sha256:sha512";
	return (*env)->NewStringUTF(env, digests);
}

JNIEXPORT jint JNICALL Java_GmSSL_getDigestLength(
	JNIEnv *env, jobject this, jstring algor)
{
	jint ret = -1;
	const char *alg = NULL;
	const EVP_MD *md;

	alg = (*env)->GetStringUTFChars(env, algor, 0);
	if ((md = EVP_get_digestbyname(alg))) {
		ret = EVP_MD_size(md);
	}

	(*env)->ReleaseStringUTFChars(env, algor, alg);
	return ret;
}

JNIEXPORT jint JNICALL Java_GmSSL_getDigestBlockSize(
	JNIEnv *env, jobject this, jstring algor)
{
	jint ret = -1;
	const char *alg = NULL;
	const EVP_MD *md;

	alg = (*env)->GetStringUTFChars(env, algor, 0);
	if ((md = EVP_get_digestbyname(alg))) {
		ret = EVP_MD_block_size(md);
	}

	(*env)->ReleaseStringUTFChars(env, algor, alg);
	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_GmSSL_digest(JNIEnv *env, jobject this,
	jstring algor, jint flag, jbyteArray in)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	const unsigned char *inbuf = NULL;
	unsigned char outbuf[EVP_MAX_MD_SIZE];
	int inlen;
	unsigned int outlen = sizeof(outbuf);
	const EVP_MD *md;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))
		|| !(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))
		|| (inlen = (size_t)(*env)->GetArrayLength(env, in)) <= 0) {
		goto end;
	}

	if (!(md = EVP_get_digestbyname(alg))
		|| !EVP_Digest(inbuf, inlen, outbuf, &outlen, md, NULL)) {
		goto end;
	}

	if ((ret = (*env)->NewByteArray(env, outlen))) {
		(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);
	}

end:
	(*env)->ReleaseStringUTFChars(env, algor, alg);
	(*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	return ret;
}

JNIEXPORT jobjectArray JNICALL Java_GmSSL_getMacs(
	JNIEnv *env, jobject this, jboolean aliases)
{
	char *macs = "cmac-sms4:hmac-sm3:hmac-sha1:hmac-sha256:hmac-sha512";
	return (*env)->NewStringUTF(env, macs);
}

JNIEXPORT jbyteArray JNICALL Java_GmSSL_mac(JNIEnv *env, jobject this,
	jstring algor, jint flag, jbyteArray in, jbyteArray key)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	const unsigned char *inbuf = NULL;
	const unsigned char *keybuf = NULL;
	unsigned char outbuf[EVP_MAX_MD_SIZE];
	int inlen, keylen, outlen = sizeof(outbuf);

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))
		|| !(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))
		|| (inlen = (*env)->GetArrayLength(env, in)) <= 0
		|| !(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))
		|| (keylen = (*env)->GetArrayLength(env, key)) <= 0) {
		goto end;
	}

	if (memcmp(alg, "cmac-", strlen("cmac-")) == 0) {
		const EVP_CIPHER *cipher;
		CMAC_CTX *cctx = NULL;
		size_t len = sizeof(outbuf);

		if (!(cipher = EVP_get_cipherbyname(alg + strlen("cmac-")))
			|| !(cctx = CMAC_CTX_new())
			|| !CMAC_Init(cctx, keybuf, keylen, cipher, NULL)
			|| !CMAC_Update(cctx, inbuf, inlen)
			|| !CMAC_Final(cctx, outbuf, &len)) {
			CMAC_CTX_free(cctx);
			goto end;
		}

		outlen = len;
		CMAC_CTX_free(cctx);

	} else if (memcmp(alg, "hmac-", strlen("hmac-")) == 0) {
		const EVP_MD *md;
		unsigned int len = sizeof(outbuf);

		if (!(md = EVP_get_digestbyname(alg + strlen("hmac-")))
			|| !HMAC(md, keybuf, keylen, inbuf, inlen, outbuf, &len)) {
			goto end;
		}

		outlen = len;

	} else {
		goto end;
	}

	if ((ret = (*env)->NewByteArray(env, outlen))) {
		(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);
	}

end:
	(*env)->ReleaseStringUTFChars(env, algor, alg);
	(*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	return ret;
}

JNIEXPORT jobjectArray JNICALL Java_GmSSL_getSignAlgorithms(
	JNIEnv *env, jobject this, jboolean aliases)
{
	char *sign_algors = "sm2sign:ecdsa:dsa:rsa";
	return (*env)->NewStringUTF(env, sign_algors);
}

JNIEXPORT jbyteArray JNICALL Java_GmSSL_sign(JNIEnv *env, jobject this,
	jstring algor, jint flag, jbyteArray in, jbyteArray key)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	const unsigned char *inbuf = NULL;
	const unsigned char *keybuf = NULL;
	unsigned char outbuf[1024];
	int inlen, keylen;
	size_t outlen = sizeof(outbuf);
	int pkey_type;
	const unsigned char *cp;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))
		|| !(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))
		|| (keylen = (*env)->GetArrayLength(env, key)) <= 0
		|| !(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))
		|| (inlen = (*env)->GetArrayLength(env, in)) <= 0) {
		goto end;
	}

	if (!strcmp(alg, "sm2")) {
		pkey_type = EVP_PKEY_EC;
	} else if (!strcmp(alg, "ecdsa")) {
		pkey_type = EVP_PKEY_EC;
	} else if (!strcmp(alg, "dsa")) {
		pkey_type = EVP_PKEY_DSA;
	} else if (!strcmp(alg, "rsa")) {
		pkey_type = EVP_PKEY_RSA;
	} else {
		goto end;
	}

	cp = keybuf;
	if (!(pkey = d2i_PrivateKey(pkey_type, NULL, &cp, keylen))
		|| !(pkctx = EVP_PKEY_CTX_new(pkey, NULL))
		|| !EVP_PKEY_sign_init(pkctx)
		|| !EVP_PKEY_sign(pkctx, outbuf, &outlen, inbuf, inlen)) {
		goto end;
	}

	if ((ret = (*env)->NewByteArray(env, outlen))) {
		(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);
	}

end:
	(*env)->ReleaseStringUTFChars(env, algor, alg);
	(*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pkctx);
	return ret;
}

JNIEXPORT jint JNICALL Java_GmSSL_verify(JNIEnv *env, jobject this,
	jstring algor, jint flag, jbyteArray in, jbyteArray sig, jbyteArray key)
{
	jint ret = 0;
	const char *alg = NULL;
	const unsigned char *inbuf = NULL;
	const unsigned char *sigbuf = NULL;
	const unsigned char *keybuf = NULL;
	int inlen, siglen, keylen;
	const unsigned char *cp;
	int pkey_type;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))
		|| !(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))
		|| (inlen = (*env)->GetArrayLength(env, in)) <= 0
		|| !(sigbuf = (unsigned char *)(*env)->GetByteArrayElements(env, sig, 0))
		|| (siglen = (*env)->GetArrayLength(env, sig)) <= 0
		|| !(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))
		|| (keylen = (*env)->GetArrayLength(env, key)) <= 0) {
		goto end;
	}

	if (!strcmp(alg, "sm2")) {
		pkey_type = EVP_PKEY_EC;
	} else if (!strcmp(alg, "ecdsa")) {
		pkey_type = EVP_PKEY_EC;
	} else if (!strcmp(alg, "dsa")) {
		pkey_type = EVP_PKEY_DSA;
	} else if (!strcmp(alg, "rsa")) {
		pkey_type = EVP_PKEY_RSA;
	} else {
		goto end;
	}

	cp = keybuf;
	if (!(pkey = d2i_PUBKEY(NULL, &cp, (long)keylen))
		|| EVP_PKEY_id(pkey) != pkey_type
		|| !(pkctx = EVP_PKEY_CTX_new(pkey, NULL))
		|| !EVP_PKEY_verify_init(pkctx)
		|| !EVP_PKEY_verify(pkctx, sigbuf, siglen, inbuf, inlen)) {
		goto end;
	}

	ret = 1;
end:
	(*env)->ReleaseStringUTFChars(env, algor, alg);
	(*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, sig, (jbyte *)sigbuf, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pkctx);
	return ret;
}

JNIEXPORT jobjectArray JNICALL Java_GmSSL_getPublicKeyEncryptions(
	JNIEnv *env, jobject this, jboolean aliases)
{
	char *algors = "sm2:ecies:rsa";
	return (*env)->NewStringUTF(env, algors);
}

JNIEXPORT jbyteArray JNICALL Java_GmSSL_publicKeyEncrypt(
	JNIEnv *env, jobject this, jstring algor, jint flag,
	jbyteArray in, jbyteArray key)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	const unsigned char *inbuf = NULL;
	const unsigned char *keybuf = NULL;
	unsigned char *outbuf = NULL;
	int inlen, keylen;
	size_t outlen;
	int pkey_type;
	const unsigned char *cp;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))
		|| !(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))
		|| (inlen = (*env)->GetArrayLength(env, in)) <= 0
		|| (inlen = (*env)->GetArrayLength(env, in)) > 256
		|| !(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))
		|| (keylen = (*env)->GetArrayLength(env, key)) <= 0) {
		goto end;
	}
	cp = keybuf;
	outlen = inlen + 1024;

	if (!strcmp(alg, "sm2")) {
		pkey_type = EVP_PKEY_EC;
	} else if (!strcmp(alg, "ecies")) {
		pkey_type = EVP_PKEY_EC;
	} else if (!strcmp(alg, "rsa")) {
		pkey_type = EVP_PKEY_RSA;
	} else {
		goto end;
	}

	if (!(outbuf = OPENSSL_malloc(outlen))
		|| !(pkey = d2i_PUBKEY(NULL, &cp, (long)keylen))
		|| EVP_PKEY_id(pkey) != pkey_type
		|| !(pkctx = EVP_PKEY_CTX_new(pkey, NULL))
		|| !EVP_PKEY_encrypt_init(pkctx)
		|| !EVP_PKEY_encrypt(pkctx, outbuf, &outlen, inbuf, inlen)) {
		goto end;
	}

	if ((ret = (*env)->NewByteArray(env, outlen))) {
		(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);
	}

end:
	(*env)->ReleaseStringUTFChars(env, algor, alg);
	(*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	OPENSSL_free(outbuf);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pkctx);
	return ret;

}

JNIEXPORT jbyteArray JNICALL Java_GmSSL_privateKeyDecrypt(
	JNIEnv *env, jobject this, jstring algor, jint flag,
	jbyteArray in, jbyteArray key)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	const unsigned char *inbuf = NULL;
	const unsigned char *keybuf = NULL;
	unsigned char *outbuf = NULL;
	int inlen, keylen;
	size_t outlen;
	int pkey_type;
	const unsigned char *cp;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))
		|| !(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))
		|| (inlen = (*env)->GetArrayLength(env, in)) <= 0
		|| !(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))
		|| (keylen = (*env)->GetArrayLength(env, key)) <= 0) {
		goto end;
	}
	cp = keybuf;
	outlen = inlen;

	if (!strcmp(alg, "sm2")) {
		pkey_type = EVP_PKEY_EC;
	} else if (!strcmp(alg, "ecies")) {
		pkey_type = EVP_PKEY_EC;
	} else if (!strcmp(alg, "rsa")) {
		pkey_type = EVP_PKEY_RSA;
	} else {
		goto end;
	}

	if (!(outbuf = OPENSSL_malloc(outlen))
		|| !(pkey = d2i_PrivateKey(pkey_type, NULL, &cp, (long)keylen))
		|| !(pkctx = EVP_PKEY_CTX_new(pkey, NULL))
		|| !EVP_PKEY_decrypt_init(pkctx)
		|| !EVP_PKEY_decrypt(pkctx, outbuf, &outlen, inbuf, inlen)) {
		goto end;
	}

	if ((ret = (*env)->NewByteArray(env, outlen))) {
		(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);
	}

end:
	(*env)->ReleaseStringUTFChars(env, algor, alg);
	(*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	OPENSSL_free(outbuf);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pkctx);
	return ret;
}

JNIEXPORT jobjectArray JNICALL Java_GmSSL_getDeriveKeyAlgorithms(
	JNIEnv *env, jobject this, jboolean aliases)
{
	char *algors = "sm2:ecdh:dh";
	return (*env)->NewStringUTF(env, algors);
}

JNIEXPORT jbyteArray JNICALL Java_GmSSL_deriveKey(
	JNIEnv *env, jobject this, jstring algor, jint flag,
	jint outkeylen, jbyteArray peerkey, jbyteArray key)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	const unsigned char *inbuf = NULL;
	const unsigned char *keybuf = NULL;
	unsigned char outbuf[256];
	int inlen, keylen;
	size_t outlen = outkeylen;
	int pkey_type;
	const unsigned char *cpin, *cpkey;
	EVP_PKEY *peerpkey = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))
		|| (outkeylen <= 0 || outkeylen > sizeof(outbuf))
		|| !(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, peerkey, 0))
		|| (inlen = (*env)->GetArrayLength(env, peerkey)) <= 0
		|| !(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))
		|| (keylen = (*env)->GetArrayLength(env, key)) <= 0) {
		goto end;
	}
	cpin = inbuf;
	cpkey = keybuf;

	if (!strcmp(alg, "sm2")) {
		pkey_type = EVP_PKEY_EC;
	} else if (!strcmp(alg, "ecdh")) {
		pkey_type = EVP_PKEY_EC;
	} else if (!strcmp(alg, "dh")) {
		pkey_type = EVP_PKEY_DH;
	} else {
		goto end;
	}

	if (!(peerpkey = d2i_PUBKEY(NULL, &cpin, (long)inlen))
		|| EVP_PKEY_id(peerpkey) != pkey_type
		|| !(pkey = d2i_PrivateKey(pkey_type, NULL, &cpkey, (long)keylen))
		|| !(pkctx = EVP_PKEY_CTX_new(pkey, NULL))
		|| !EVP_PKEY_derive_init(pkctx)
		|| !EVP_PKEY_derive_set_peer(pkctx, peerpkey)
		|| !EVP_PKEY_derive(pkctx, outbuf, &outlen)) {
		goto end;
	}

	if ((ret = (*env)->NewByteArray(env, outlen))) {
		(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);
	}

end:
	(*env)->ReleaseStringUTFChars(env, algor, alg);
	(*env)->ReleaseByteArrayElements(env, peerkey, (jbyte *)inbuf, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	EVP_PKEY_free(peerpkey);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pkctx);
	return ret;
}

JNIEXPORT jstring JNICALL Java_GmSSL_getErrorString(JNIEnv *env, jobject this)
{
	int err;
	if (!(err = ERR_get_error())) {
		return NULL;
	}
	return (*env)->NewStringUTF(env, ERR_error_string(err, NULL));
}

