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
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#ifndef OPENSSL_NO_CMAC
# include <openssl/cmac.h>
#endif
#ifndef OPENSSL_NO_SM2
#include <openssl/sm2.h>
#endif
#include <openssl/x509.h>
#include <openssl/stack.h>
#include <openssl/crypto.h>
#include <openssl/safestack.h>
#include "../e_os.h"
#include "gmssl_err.h"
#include "gmssl_err.c"
#include "GmSSL.h"

#define GMSSL_JNI_VERSION	"GmSSL-JNI API/1.1 2017-09-01"

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
	(void)ERR_load_JNI_strings();
	return JNI_VERSION_1_2;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved)
{
	ERR_unload_JNI_strings();
}

JNIEXPORT jobjectArray JNICALL Java_org_gmssl_GmSSL_getVersions(JNIEnv *env, jobject this)
{
	jobjectArray ret = NULL;
	int i;

	if (!(ret = (jobjectArray)(*env)->NewObjectArray(env, 7,
		(*env)->FindClass(env, "java/lang/String"),
		(*env)->NewStringUTF(env, "")))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GETVERSIONS, JNI_R_JNI_MALLOC_FAILURE);
		return NULL;
	}

	(*env)->SetObjectArrayElement(env, ret, 0,
		(*env)->NewStringUTF(env, GMSSL_JNI_VERSION));

	for (i = 1; i < 7; i++) {
		(*env)->SetObjectArrayElement(env, ret, i,
			(*env)->NewStringUTF(env, OpenSSL_version(i-1)));
	}

	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSL_generateRandom(
	JNIEnv *env, jobject this, jint outlen)
{
	jbyteArray ret = NULL;
	jbyte *outbuf = NULL;

	if (outlen <= 0 || outlen >= INT_MAX) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GENERATERANDOM, JNI_R_INVALID_LENGTH);
		return NULL;
	}

	if (!(outbuf = OPENSSL_malloc(outlen))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GENERATERANDOM, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	if (!RAND_bytes((unsigned char *)outbuf, outlen)) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GENERATERANDOM, JNI_R_GMSSL_RNG_ERROR);
		goto end;
	}
	if (!(ret = (*env)->NewByteArray(env, outlen))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GENERATERANDOM, JNI_R_JNI_MALLOC_FAILURE);
		goto end;
	}

	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);

end:
	OPENSSL_free(outbuf);
	return ret;
}

static void list_cipher_fn(const EVP_CIPHER *c,
	const char *from, const char *to, void *argv)
{
	STACK_OF(OPENSSL_CSTRING) *sk = argv;
	if (c) {
		sk_OPENSSL_CSTRING_push(sk, EVP_CIPHER_name(c));
	} else {
		sk_OPENSSL_CSTRING_push(sk, from);
	}
}

JNIEXPORT jobjectArray JNICALL Java_org_gmssl_GmSSL_getCiphers(
	JNIEnv *env, jobject this)
{
	jobjectArray ret = NULL;
	STACK_OF(OPENSSL_CSTRING) *sk = NULL;
	int i;

	if (!(sk = sk_OPENSSL_CSTRING_new_null())) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GETCIPHERS, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	EVP_CIPHER_do_all_sorted(list_cipher_fn, sk);

	if (!(ret = (jobjectArray)(*env)->NewObjectArray(env,
		sk_OPENSSL_CSTRING_num(sk),
		(*env)->FindClass(env, "java/lang/String"),
		(*env)->NewStringUTF(env, "")))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GETCIPHERS, JNI_R_JNI_MALLOC_FAILURE);
		goto end;
	}

	for (i = 0; i < sk_OPENSSL_CSTRING_num(sk); i++) {
		(*env)->SetObjectArrayElement(env, ret, i,
			(*env)->NewStringUTF(env, sk_OPENSSL_CSTRING_value(sk, i)));
	}

end:
	sk_OPENSSL_CSTRING_free(sk);
	return ret;
}

JNIEXPORT jint JNICALL Java_org_gmssl_GmSSL_getCipherIVLength(
	JNIEnv *env, jobject this, jstring algor)
{
	jint ret = -1;
	const char *alg = NULL;
	const EVP_CIPHER *cipher;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GETCIPHERIVLENGTH, JNI_R_BAD_ARGUMENT);
		goto end;
	}

	if (!(cipher = EVP_get_cipherbyname(alg))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GETCIPHERIVLENGTH, JNI_R_INVALID_CIPHER);
		goto end;
	}

	ret = EVP_CIPHER_iv_length(cipher);

end:
	(*env)->ReleaseStringUTFChars(env, algor, alg);
	return ret;
}

JNIEXPORT jint JNICALL Java_org_gmssl_GmSSL_getCipherKeyLength(
	JNIEnv *env, jobject this, jstring algor)
{
	jint ret = -1;
	const char *alg = NULL;
	const EVP_CIPHER *cipher;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GETCIPHERKEYLENGTH, JNI_R_BAD_ARGUMENT);
		goto end;
	}

	if (!(cipher = EVP_get_cipherbyname(alg))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GETCIPHERKEYLENGTH, JNI_R_INVALID_CIPHER);
		goto end;
	}

	ret = EVP_CIPHER_key_length(cipher);

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	return ret;
}

JNIEXPORT jint JNICALL Java_org_gmssl_GmSSL_getCipherBlockSize(
	JNIEnv *env, jobject this, jstring algor)
{
	jint ret = -1;
	const char *alg = NULL;
	const EVP_CIPHER *cipher;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GETCIPHERBLOCKSIZE, JNI_R_BAD_ARGUMENT);
		goto end;
	}

	if (!(cipher = EVP_get_cipherbyname(alg))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GETCIPHERBLOCKSIZE, JNI_R_NONSUPPORTED_CIPHER);
		goto end;
	}

	ret = EVP_CIPHER_block_size(cipher);

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSL_symmetricEncrypt(
	JNIEnv *env, jobject this, jstring algor,
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

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICENCRYPT, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if (!(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICENCRYPT, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if ((inlen = (*env)->GetArrayLength(env, in)) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICENCRYPT, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if (!(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICENCRYPT, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if ((keylen = (*env)->GetArrayLength(env, key)) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICENCRYPT, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	/* null IV can be valid input for some ciphers */
	ivbuf = (unsigned char *)(*env)->GetByteArrayElements(env, iv, 0);
	ivlen = (*env)->GetArrayLength(env, iv);

	if (!(cipher = EVP_get_cipherbyname(alg))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICENCRYPT, JNI_R_INVALID_CIPHER);
		goto end;
	}
	if (keylen != EVP_CIPHER_key_length(cipher)) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICENCRYPT, JNI_R_INVALID_KEY_LENGTH);
		goto end;
	}
	if (ivlen != EVP_CIPHER_iv_length(cipher)) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICENCRYPT, JNI_R_INVALID_IV_LENGTH);
		goto end;
	}
	if (!(outbuf = OPENSSL_malloc(inlen + 2 * EVP_CIPHER_block_size(cipher)))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!(cctx = EVP_CIPHER_CTX_new())) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!EVP_EncryptInit_ex(cctx, cipher, NULL, keybuf, ivbuf)) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICENCRYPT, ERR_R_EVP_LIB);
		goto end;
	}
	if (!EVP_EncryptUpdate(cctx, outbuf, &outlen, inbuf, inlen)) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICENCRYPT, ERR_R_EVP_LIB);
		goto end;
	}
	if (!EVP_EncryptFinal_ex(cctx, outbuf + outlen, &lastlen)) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICENCRYPT, ERR_R_EVP_LIB);
		goto end;
	}
	outlen += lastlen;

	if (!(ret = (*env)->NewByteArray(env, outlen))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICENCRYPT, JNI_R_JNI_MALLOC_FAILURE);
		goto end;
	}

	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	if (ivbuf) (*env)->ReleaseByteArrayElements(env, iv, (jbyte *)ivbuf, JNI_ABORT);
	OPENSSL_free(outbuf);
	EVP_CIPHER_CTX_free(cctx);
	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSL_symmetricDecrypt(
	JNIEnv *env, jobject this, jstring algor,
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

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICDECRYPT, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if (!(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICDECRYPT, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if ((inlen = (*env)->GetArrayLength(env, in)) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICDECRYPT, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if (!(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICDECRYPT, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if ((keylen = (*env)->GetArrayLength(env, key)) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICDECRYPT, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	ivbuf = (unsigned char *)(*env)->GetByteArrayElements(env, iv, 0);
	ivlen = (*env)->GetArrayLength(env, iv);


	if (!(cipher = EVP_get_cipherbyname(alg))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICDECRYPT, JNI_R_INVALID_CIPHER);
		goto end;
	}
	if (keylen != EVP_CIPHER_key_length(cipher)) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICDECRYPT, JNI_R_KEY_LENGTH);
		goto end;
	}
	if (ivlen != EVP_CIPHER_iv_length(cipher)) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICDECRYPT, JNI_R_IV_LENGTH);
		goto end;
	}
	if (!(outbuf = OPENSSL_malloc(inlen))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICDECRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!(cctx = EVP_CIPHER_CTX_new())) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICDECRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!EVP_DecryptInit_ex(cctx, cipher, NULL, keybuf, ivbuf)) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICDECRYPT, ERR_R_EVP_LIB);
		goto end;
	}
	if (!EVP_DecryptUpdate(cctx, outbuf, &outlen, inbuf, inlen)) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICDECRYPT, ERR_R_EVP_LIB);
		goto end;
	}
	if (!EVP_DecryptFinal_ex(cctx, outbuf + outlen, &lastlen)) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICDECRYPT, ERR_R_EVP_LIB);
		goto end;
	}
	outlen += lastlen;

	if (!(ret = (*env)->NewByteArray(env, outlen))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SYMMETRICDECRYPT, JNI_R_JNI_MALLOC_FAILURE);
	}

	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	if (ivbuf) (*env)->ReleaseByteArrayElements(env, iv, (jbyte *)ivbuf, JNI_ABORT);
	EVP_CIPHER_CTX_free(cctx);
	return ret;
}

static void list_md_fn(const EVP_MD *md,
	const char *from, const char *to, void *argv)
{
	STACK_OF(OPENSSL_CSTRING) *sk = argv;
	if (md) {
		sk_OPENSSL_CSTRING_push(sk, EVP_MD_name(md));
	} else {
		sk_OPENSSL_CSTRING_push(sk, from);
	}
}

JNIEXPORT jobjectArray JNICALL Java_org_gmssl_GmSSL_getDigests(
	JNIEnv *env, jobject this)
{
	jobjectArray ret = NULL;
	STACK_OF(OPENSSL_CSTRING) *sk = NULL;
	int i;

	if (!(sk = sk_OPENSSL_CSTRING_new_null())) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GETDIGESTS, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	EVP_MD_do_all_sorted(list_md_fn, sk);

	if (!(ret = (jobjectArray)(*env)->NewObjectArray(env,
		sk_OPENSSL_CSTRING_num(sk),
		(*env)->FindClass(env, "java/lang/String"),
		(*env)->NewStringUTF(env, "")))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GETDIGESTS, JNI_R_JNI_MALLOC_FAILURE);
		goto end;
	}

	for (i = 0; i < sk_OPENSSL_CSTRING_num(sk); i++) {
		(*env)->SetObjectArrayElement(env, ret, i,
			(*env)->NewStringUTF(env, sk_OPENSSL_CSTRING_value(sk, i)));
	}

end:
	sk_OPENSSL_CSTRING_free(sk);
	return ret;
}

JNIEXPORT jint JNICALL Java_org_gmssl_GmSSL_getDigestLength(
	JNIEnv *env, jobject this, jstring algor)
{
	jint ret = -1;
	const char *alg = NULL;
	const EVP_MD *md;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GETDIGESTLENGTH, JNI_R_BAD_ARGUMENT);
		goto end;
	}

	if (!(md = EVP_get_digestbyname(alg))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GETDIGESTLENGTH, JNI_R_INVALID_DIGEST);
		goto end;
	}

	ret = EVP_MD_size(md);

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	return ret;
}

JNIEXPORT jint JNICALL Java_org_gmssl_GmSSL_getDigestBlockSize(
	JNIEnv *env, jobject this, jstring algor)
{
	jint ret = -1;
	const char *alg = NULL;
	const EVP_MD *md;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GETDIGESTBLOCKSIZE, JNI_R_BAD_ARGUMENT);
		goto end;
	}

	if (!(md = EVP_get_digestbyname(alg))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GETDIGESTBLOCKSIZE, JNI_R_INVALID_DIGEST);
		goto end;
	}

	ret = EVP_MD_block_size(md);

end:
	(*env)->ReleaseStringUTFChars(env, algor, alg);
	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSL_digest(JNIEnv *env, jobject this,
	jstring algor, jbyteArray in)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	const unsigned char *inbuf = NULL;
	unsigned char outbuf[EVP_MAX_MD_SIZE];
	int inlen;
	unsigned int outlen = sizeof(outbuf);
	const EVP_MD *md;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DIGEST, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if (!(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DIGEST, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if ((inlen = (size_t)(*env)->GetArrayLength(env, in)) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DIGEST, JNI_R_BAD_ARGUMENT);
		goto end;
	}

	if (!(md = EVP_get_digestbyname(alg))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DIGEST, JNI_R_INVALID_DIGEST);
		goto end;
	}
	if (!EVP_Digest(inbuf, inlen, outbuf, &outlen, md, NULL)) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DIGEST, ERR_R_EVP_LIB);
		goto end;
	}

	if (!(ret = (*env)->NewByteArray(env, outlen))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DIGEST, JNI_R_JNI_MALLOC_FAILURE);
		goto end;
	}

	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	return ret;
}

char *mac_algors[] = {
	"CMAC-SMS4",
	"HMAC-SM3",
	"HMAC-SHA1",
	"HMAC-SHA256",
	"HMAC-SHA512",
};

JNIEXPORT jobjectArray JNICALL Java_org_gmssl_GmSSL_getMacs(
	JNIEnv *env, jobject this)
{
	jobjectArray ret = NULL;
	int i;

	if (!(ret = (jobjectArray)(*env)->NewObjectArray(env,
		OSSL_NELEM(mac_algors),
		(*env)->FindClass(env, "java/lang/String"),
		(*env)->NewStringUTF(env, "")))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GETMACS, JNI_R_JNI_MALLOC_FAILURE);
		return NULL;
	}

	for (i = 0; i < OSSL_NELEM(mac_algors); i++) {
		(*env)->SetObjectArrayElement(env, ret, i,
			(*env)->NewStringUTF(env, mac_algors[i]));
	}

	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSL_mac(JNIEnv *env, jobject this,
	jstring algor, jbyteArray in, jbyteArray key)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	const unsigned char *inbuf = NULL;
	const unsigned char *keybuf = NULL;
	unsigned char outbuf[EVP_MAX_MD_SIZE];
	int inlen, keylen, outlen = sizeof(outbuf);
#ifndef OPENSSL_NO_CMAC
	CMAC_CTX *cctx = NULL;
#endif

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_MAC, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if (!(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_MAC, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if ((inlen = (*env)->GetArrayLength(env, in)) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_MAC, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if (!(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_MAC, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if ((keylen = (*env)->GetArrayLength(env, key)) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_MAC, JNI_R_BAD_ARGUMENT);
		goto end;
	}

	if (memcmp(alg, "HMAC-", strlen("HMAC-")) == 0) {
		const EVP_MD *md;
		unsigned int len = sizeof(outbuf);

		if (!(md = EVP_get_digestbyname(alg + strlen("HMAC-")))) {
			JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_MAC, JNI_R_INVALID_DIGEST);
			goto end;
		}

		if (!HMAC(md, keybuf, keylen, inbuf, inlen, outbuf, &len)) {
			JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_MAC, JNI_R_HMAC_ERROR);
			goto end;
		}

		outlen = len;

#ifndef OPENSSL_NO_CMAC
	} else if (memcmp(alg, "CMAC-", strlen("CMAC-")) == 0) {
		const EVP_CIPHER *cipher;
		size_t len = sizeof(outbuf);

		if (!(cipher = EVP_get_cipherbyname(alg + strlen("CMAC-")))) {
			JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_MAC, JNI_R_INVALID_CIPHER);
			goto end;
		}
		if (!(cctx = CMAC_CTX_new())) {
			JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_MAC, ERR_R_MALLOC_FAILURE);
			goto end;
		}
		if (!CMAC_Init(cctx, keybuf, keylen, cipher, NULL)) {
			JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_MAC, JNI_R_CMAC_ERROR);
			goto end;
		}
		if (!CMAC_Update(cctx, inbuf, inlen)) {
			JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_MAC, JNI_R_CMAC_ERROR);
			goto end;
		}
		if (!CMAC_Final(cctx, outbuf, &len)) {
			JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_MAC, JNI_R_CMAC_ERROR);
			goto end;
		}

		outlen = len;
#endif
	} else {
		goto end;
	}

	if (!(ret = (*env)->NewByteArray(env, outlen))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_MAC, JNI_R_JNI_MALLOC_FAILURE);
		goto end;
	}

	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
#ifndef OPENSSL_NO_CMAC
	CMAC_CTX_free(cctx);
#endif
	return ret;
}

int sign_nids[] = {
#ifndef OPENSSL_NO_SM2
	NID_sm2sign,
#endif
	NID_ecdsa_with_Recommended,
#ifndef OPENSSL_NO_SHA
	NID_ecdsa_with_SHA1,
	NID_ecdsa_with_SHA256,
	NID_ecdsa_with_SHA512,
# ifndef OPENSSL_NO_RSA
	NID_sha1WithRSAEncryption,
	NID_sha256WithRSAEncryption,
	NID_sha512WithRSAEncryption,
# endif
# ifndef OPENSSL_NO_DSA
	NID_dsaWithSHA1,
# endif
#endif
};

static int get_sign_info(const char *alg, int *ppkey_type,
	const EVP_MD **pmd, int *pec_scheme)
{
	int pkey_type;
	const EVP_MD *md = NULL;
	int ec_scheme = -1;

	switch (OBJ_txt2nid(alg)) {
#ifndef OPENSSL_NO_SM2
	case NID_sm2sign:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_sm_scheme;
		break;
#endif
	case NID_ecdsa_with_Recommended:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_secg_scheme;
		break;
#ifndef OPENSSL_NO_SHA
	case NID_ecdsa_with_SHA1:
		pkey_type = EVP_PKEY_EC;
		md = EVP_sha1();
		ec_scheme = NID_secg_scheme;
		break;
	case NID_ecdsa_with_SHA256:
		pkey_type = EVP_PKEY_EC;
		md = EVP_sha256();
		ec_scheme = NID_secg_scheme;
		break;
	case NID_ecdsa_with_SHA512:
		pkey_type = EVP_PKEY_EC;
		md = EVP_sha512();
		ec_scheme = NID_secg_scheme;
		break;
# ifndef OPENSSL_NO_RSA
	case NID_sha1WithRSAEncryption:
		pkey_type = EVP_PKEY_RSA;
		md = EVP_sha1();
		break;
	case NID_sha256WithRSAEncryption:
		pkey_type = EVP_PKEY_RSA;
		md = EVP_sha256();
		break;
	case NID_sha512WithRSAEncryption:
		pkey_type = EVP_PKEY_RSA;
		md = EVP_sha512();
		break;
# endif
# ifndef OPENSSL_NO_DSA
	case NID_dsaWithSHA1:
		pkey_type = EVP_PKEY_DSA;
		md = EVP_sha1();
		break;
# endif
#endif
	default:
		return 0;
	}

	*ppkey_type = pkey_type;
	*pmd = md;
	*pec_scheme = ec_scheme;

	return 1;
}

JNIEXPORT jobjectArray JNICALL Java_org_gmssl_GmSSL_getSignAlgorithms(
	JNIEnv *env, jobject this)
{
	jobjectArray ret = NULL;
	int num_algors = sizeof(sign_nids)/sizeof(sign_nids[0]);
	int i;

	if (!(ret = (jobjectArray)(*env)->NewObjectArray(env,
		OSSL_NELEM(sign_nids),
		(*env)->FindClass(env, "java/lang/String"),
		(*env)->NewStringUTF(env, "")))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GETSIGNALGORITHMS, JNI_R_JNI_MALLOC_FAILURE);
		return NULL;
	}

	for (i = 0; i < num_algors; i++) {
		(*env)->SetObjectArrayElement(env, ret, i,
			(*env)->NewStringUTF(env, OBJ_nid2sn(sign_nids[i])));
	}

	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSL_sign(JNIEnv *env, jobject this,
	jstring algor, jbyteArray in, jbyteArray key)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	const unsigned char *inbuf = NULL;
	const unsigned char *keybuf = NULL;
	unsigned char outbuf[1024];
	int inlen, keylen;
	size_t outlen = sizeof(outbuf);
	int pkey_type = 0;
	const EVP_MD *md = NULL;
	int ec_scheme = -1;
	const unsigned char *cp;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SIGN, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if (!(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SIGN, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if ((keylen = (*env)->GetArrayLength(env, key)) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SIGN, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if (!(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SIGN, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if ((inlen = (*env)->GetArrayLength(env, in)) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SIGN, JNI_R_BAD_ARGUMENT);
		goto end;
	}

	if (!get_sign_info(alg, &pkey_type, &md, &ec_scheme)) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SIGN, JNI_R_INVALID_SIGN_ALGOR);
		goto end;
	}

	cp = keybuf;
	if (!(pkey = d2i_PrivateKey(pkey_type, NULL, &cp, keylen))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SIGN, JNI_R_INVALID_PRIVATE_KEY);
		goto end;
	}
	if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SIGN, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (EVP_PKEY_sign_init(pkctx) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SIGN, ERR_R_EVP_LIB);
		goto end;
	}

	if (md) {
		if (!EVP_PKEY_CTX_set_signature_md(pkctx, md)) {
			JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SIGN, ERR_R_EVP_LIB);
			goto end;
		}
	}
	if (pkey_type == EVP_PKEY_RSA) {
#ifndef OPENSSL_NO_RSA
		if (!EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING)) {
			JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SIGN, ERR_R_RSA_LIB);
			goto end;
		}
#endif
	} else if (pkey_type == EVP_PKEY_EC) {
#ifndef OPENSSL_NO_SM2
		if (!EVP_PKEY_CTX_set_ec_scheme(pkctx, OBJ_txt2nid(alg) == NID_sm2sign ?
			NID_sm_scheme : NID_secg_scheme)) {
			JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SIGN, ERR_R_EC_LIB);
			goto end;
		}
#endif
	}

	if (EVP_PKEY_sign(pkctx, outbuf, &outlen, inbuf, inlen) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SIGN, ERR_R_EVP_LIB);
		goto end;
	}

	if (!(ret = (*env)->NewByteArray(env, outlen))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_SIGN, JNI_R_JNI_MALLOC_FAILURE);
		goto end;
	}

	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pkctx);
	return ret;
}

JNIEXPORT jint JNICALL Java_org_gmssl_GmSSL_verify(JNIEnv *env, jobject this,
	jstring algor, jbyteArray in, jbyteArray sig, jbyteArray key)
{
	jint ret = 0;
	const char *alg = NULL;
	const unsigned char *inbuf = NULL;
	const unsigned char *sigbuf = NULL;
	const unsigned char *keybuf = NULL;
	int inlen, siglen, keylen;
	const unsigned char *cp;
	int pkey_type = 0;
	const EVP_MD *md = NULL;
	int ec_scheme = -1;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_VERIFY, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if (!(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_VERIFY, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if ((inlen = (*env)->GetArrayLength(env, in)) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_VERIFY, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if (!(sigbuf = (unsigned char *)(*env)->GetByteArrayElements(env, sig, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_VERIFY, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if ((siglen = (*env)->GetArrayLength(env, sig)) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_VERIFY, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if (!(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_VERIFY, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if ((keylen = (*env)->GetArrayLength(env, key)) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_VERIFY, JNI_R_BAD_ARGUMENT);
		goto end;
	}

	if (!get_sign_info(alg, &pkey_type, &md, &ec_scheme)) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_VERIFY, JNI_R_INVALID_SIGN_ALGOR);
		goto end;
	}

	cp = keybuf;
	if (!(pkey = d2i_PUBKEY(NULL, &cp, (long)keylen))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_VERIFY, JNI_R_INVALID_PUBLIC_KEY);
		goto end;
	}

	if (EVP_PKEY_id(pkey) != pkey_type) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_VERIFY, JNI_R_INVALID_PUBLIC_KEY);
		goto end;
	}
	if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_VERIFY, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	if (EVP_PKEY_verify_init(pkctx) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_VERIFY, ERR_R_EVP_LIB);
		goto end;
	}

	if (md && !EVP_PKEY_CTX_set_signature_md(pkctx, md)) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_VERIFY, ERR_R_EVP_LIB);
		goto end;
	}


	if (pkey_type == EVP_PKEY_RSA) {
#ifndef OPENSSL_NO_RSA
		if (!EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING)) {
			JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_VERIFY, ERR_R_RSA_LIB);
			goto end;
		}
#endif
	} else if (pkey_type == EVP_PKEY_EC) {
#ifndef OPENSSL_NO_SM2
		if (!EVP_PKEY_CTX_set_ec_scheme(pkctx, OBJ_txt2nid(alg) == NID_sm2sign ?
			NID_sm_scheme : NID_secg_scheme)) {
			JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_VERIFY, ERR_R_EC_LIB);
			goto end;
		}
#endif
	}

	if (EVP_PKEY_verify(pkctx, sigbuf, siglen, inbuf, inlen) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_VERIFY, ERR_R_EVP_LIB);
		goto end;
	}

	ret = 1;
end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	if (sigbuf) (*env)->ReleaseByteArrayElements(env, sig, (jbyte *)sigbuf, JNI_ABORT);
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pkctx);
	return ret;
}

int pke_nids[] = {
#ifndef OPENSSL_NO_RSA
	NID_rsaesOaep,
#endif
#ifndef OPENSSL_NO_ECIES
	NID_ecies_recommendedParameters,
	NID_ecies_specifiedParameters,
# ifndef OPENSSL_NO_SHA
	NID_ecies_with_x9_63_sha1_xor_hmac,
	NID_ecies_with_x9_63_sha256_xor_hmac,
	NID_ecies_with_x9_63_sha512_xor_hmac,
	NID_ecies_with_x9_63_sha1_aes128_cbc_hmac,
	NID_ecies_with_x9_63_sha256_aes128_cbc_hmac,
	NID_ecies_with_x9_63_sha512_aes256_cbc_hmac,
	NID_ecies_with_x9_63_sha256_aes128_ctr_hmac,
	NID_ecies_with_x9_63_sha512_aes256_ctr_hmac,
	NID_ecies_with_x9_63_sha256_aes128_cbc_hmac_half,
	NID_ecies_with_x9_63_sha512_aes256_cbc_hmac_half,
	NID_ecies_with_x9_63_sha256_aes128_ctr_hmac_half,
	NID_ecies_with_x9_63_sha512_aes256_ctr_hmac_half,
	NID_ecies_with_x9_63_sha1_aes128_cbc_cmac,
	NID_ecies_with_x9_63_sha256_aes128_cbc_cmac,
	NID_ecies_with_x9_63_sha512_aes256_cbc_cmac,
	NID_ecies_with_x9_63_sha256_aes128_ctr_cmac,
	NID_ecies_with_x9_63_sha512_aes256_ctr_cmac,
# endif
#endif
#ifndef OPENSSL_NO_SM2
	NID_sm2encrypt_with_sm3,
# ifndef OPENSSL_NO_SHA
	NID_sm2encrypt_with_sha1,
	NID_sm2encrypt_with_sha256,
	NID_sm2encrypt_with_sha512,
# endif
#endif
};

static int get_pke_info(const char *alg, int *ppkey_type,
	int *pec_scheme, int *pec_encrypt_param)
{
	int pkey_type = 0;
	int ec_scheme = 0;
	int ec_encrypt_param = 0;

	switch (OBJ_txt2nid(alg)) {
#ifndef OPENSSL_NO_RSA
	case NID_rsaesOaep:
		pkey_type = EVP_PKEY_RSA;
		break;
#endif
#ifndef OPENSSL_NO_ECIES
	case NID_ecies_recommendedParameters:
	case NID_ecies_specifiedParameters:
# ifndef OPENSSL_NO_SHA
	case NID_ecies_with_x9_63_sha1_xor_hmac:
	case NID_ecies_with_x9_63_sha256_xor_hmac:
	case NID_ecies_with_x9_63_sha512_xor_hmac:
	case NID_ecies_with_x9_63_sha1_aes128_cbc_hmac:
	case NID_ecies_with_x9_63_sha256_aes128_cbc_hmac:
	case NID_ecies_with_x9_63_sha512_aes256_cbc_hmac:
	case NID_ecies_with_x9_63_sha256_aes128_ctr_hmac:
	case NID_ecies_with_x9_63_sha512_aes256_ctr_hmac:
	case NID_ecies_with_x9_63_sha256_aes128_cbc_hmac_half:
	case NID_ecies_with_x9_63_sha512_aes256_cbc_hmac_half:
	case NID_ecies_with_x9_63_sha256_aes128_ctr_hmac_half:
	case NID_ecies_with_x9_63_sha512_aes256_ctr_hmac_half:
	case NID_ecies_with_x9_63_sha1_aes128_cbc_cmac:
	case NID_ecies_with_x9_63_sha256_aes128_cbc_cmac:
	case NID_ecies_with_x9_63_sha512_aes256_cbc_cmac:
	case NID_ecies_with_x9_63_sha256_aes128_ctr_cmac:
	case NID_ecies_with_x9_63_sha512_aes256_ctr_cmac:
# endif
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_secg_scheme;
		ec_encrypt_param = OBJ_txt2nid(alg);
		break;
#endif
#ifndef OPENSSL_NO_SM2
	case NID_sm2encrypt_with_sm3:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_sm_scheme;
		ec_encrypt_param = NID_sm3;
		break;
# ifndef OPENSSL_NO_SHA
	case NID_sm2encrypt_with_sha1:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_sm_scheme;
		ec_encrypt_param = NID_sha1;
		break;
	case NID_sm2encrypt_with_sha256:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_sm_scheme;
		ec_encrypt_param = NID_sha256;
		break;
	case NID_sm2encrypt_with_sha512:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_sm_scheme;
		ec_encrypt_param = NID_sha512;
		break;
# endif
#endif
	default:
		return 0;
	}

	*ppkey_type = pkey_type;
	*pec_scheme = ec_scheme;
	*pec_encrypt_param = ec_encrypt_param;

	return 1;
}

JNIEXPORT jobjectArray JNICALL Java_org_gmssl_GmSSL_getPublicKeyEncryptions(
	JNIEnv *env, jobject this)
{
	jobjectArray ret = NULL;
	int i;

	if (!(ret = (jobjectArray)(*env)->NewObjectArray(env,
		OSSL_NELEM(pke_nids),
		(*env)->FindClass(env, "java/lang/String"),
		(*env)->NewStringUTF(env, "")))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GETPUBLICKEYENCRYPTIONS, JNI_R_JNI_MALLOC_FAILURE);
		return NULL;
	}

	for (i = 0; i < OSSL_NELEM(pke_nids); i++) {
		(*env)->SetObjectArrayElement(env, ret, i,
			(*env)->NewStringUTF(env, OBJ_nid2sn(pke_nids[i])));
	}

	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSL_publicKeyEncrypt(
	JNIEnv *env, jobject this, jstring algor,
	jbyteArray in, jbyteArray key)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	const unsigned char *inbuf = NULL;
	const unsigned char *keybuf = NULL;
	unsigned char *outbuf = NULL;
	int inlen, keylen;
	size_t outlen;
	int pkey_type = NID_undef;
	int ec_scheme = NID_undef;
	int ec_encrypt_param = NID_undef;
	const unsigned char *cp;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;


	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYENCRYPT, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if (!(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYENCRYPT, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if ((inlen = (*env)->GetArrayLength(env, in)) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYENCRYPT, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if ((inlen = (*env)->GetArrayLength(env, in)) > 256) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYENCRYPT, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if (!(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYENCRYPT, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if ((keylen = (*env)->GetArrayLength(env, key)) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYENCRYPT, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	cp = keybuf;
	outlen = inlen + 1024;

	if (!get_pke_info(alg, &pkey_type, &ec_scheme, &ec_encrypt_param)) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYENCRYPT, JNI_R_INVALID_PUBLIC_KEY_ENCRYPTION_ALGOR);
		goto end;
	}

	if (!(outbuf = OPENSSL_malloc(outlen))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!(pkey = d2i_PUBKEY(NULL, &cp, (long)keylen))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYENCRYPT, JNI_R_INVALID_PUBLIC_KEY);
		goto end;
	}
	if (EVP_PKEY_id(pkey) != pkey_type) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYENCRYPT, JNI_R_INVALID_PUBLIC_KEY);
		goto end;
	}
	if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	if (EVP_PKEY_encrypt_init(pkctx) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYENCRYPT, ERR_R_EVP_LIB);
		goto end;
	}

	if (pkey_type == EVP_PKEY_EC) {
#if !defined(OPENSSL_NO_ECIES) || !defined(OPENSSL_NO_SM2)
		if (!EVP_PKEY_CTX_set_ec_scheme(pkctx, ec_scheme)) {
			JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYENCRYPT, ERR_R_EC_LIB);
			goto end;
		}
		if (!EVP_PKEY_CTX_set_ec_encrypt_param(pkctx, ec_encrypt_param)) {
			JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYENCRYPT, ERR_R_EC_LIB);
			goto end;
		}
#endif
	}

	if (EVP_PKEY_encrypt(pkctx, outbuf, &outlen, inbuf, inlen) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYENCRYPT, ERR_R_EVP_LIB);
		goto end;
	}

	if (!(ret = (*env)->NewByteArray(env, outlen))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYENCRYPT, JNI_R_JNI_MALLOC_FAILURE);
		goto end;
	}

	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	OPENSSL_free(outbuf);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pkctx);
	return ret;

}

/*
static int gmssl_pkey_encrypt(const char *algor, const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, const unsigned char *key, size_t keylen)
{
}
*/

JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSL_publicKeyDecrypt(
	JNIEnv *env, jobject this, jstring algor,
	jbyteArray in, jbyteArray key)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	const unsigned char *inbuf = NULL;
	const unsigned char *keybuf = NULL;
	unsigned char *outbuf = NULL;
	int inlen, keylen;
	size_t outlen;
	int pkey_type = NID_undef;
	int ec_scheme = NID_undef;
	int ec_encrypt_param = NID_undef;
	const unsigned char *cp;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYDECRYPT, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if (!(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYDECRYPT, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if ((inlen = (*env)->GetArrayLength(env, in)) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYDECRYPT, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if (!(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYDECRYPT, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if ((keylen = (*env)->GetArrayLength(env, key)) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYDECRYPT, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	cp = keybuf;
	outlen = inlen;


	if(!get_pke_info(alg, &pkey_type, &ec_scheme, &ec_encrypt_param)) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYDECRYPT, JNI_R_INVALID_PUBLIC_KEY_ENCRYPTION_ALGOR);
		goto end;
	}

	if (!(outbuf = OPENSSL_malloc(outlen))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYDECRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!(pkey = d2i_PrivateKey(pkey_type, NULL, &cp, (long)keylen))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYDECRYPT, JNI_R_INVALID_PRIVATE_KEY);
		goto end;
	}
	if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYDECRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (EVP_PKEY_decrypt_init(pkctx) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYDECRYPT, ERR_R_EVP_LIB);
		goto end;
	}

	if (pkey_type == EVP_PKEY_EC) {
#if !defined(OPENSSL_NO_ECIES) || !defined(OPENSSL_NO_SM2)
		if (!EVP_PKEY_CTX_set_ec_scheme(pkctx, ec_scheme)) {
			JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYDECRYPT, ERR_R_EC_LIB);
			goto end;
		}

		if (!EVP_PKEY_CTX_set_ec_encrypt_param(pkctx, ec_encrypt_param)) {
			JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYDECRYPT, ERR_R_EC_LIB);
			goto end;
		}
#endif
	}

	if (EVP_PKEY_decrypt(pkctx, outbuf, &outlen, inbuf, inlen) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYDECRYPT, ERR_R_EVP_LIB);
		goto end;
	}

	if (!(ret = (*env)->NewByteArray(env, outlen))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_PUBLICKEYDECRYPT, JNI_R_JNI_MALLOC_FAILURE);
		goto end;
	}

	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	OPENSSL_free(outbuf);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pkctx);
	return ret;
}

int exch_nids[] = {
#ifndef OPENSSL_NO_SM2
	NID_sm2exchange,
#endif
#ifndef OPENSSL_NO_SHA
	NID_dhSinglePass_stdDH_sha1kdf_scheme,
	NID_dhSinglePass_stdDH_sha224kdf_scheme,
	NID_dhSinglePass_stdDH_sha256kdf_scheme,
	NID_dhSinglePass_stdDH_sha384kdf_scheme,
	NID_dhSinglePass_stdDH_sha512kdf_scheme,
	NID_dhSinglePass_cofactorDH_sha1kdf_scheme,
	NID_dhSinglePass_cofactorDH_sha224kdf_scheme,
	NID_dhSinglePass_cofactorDH_sha256kdf_scheme,
	NID_dhSinglePass_cofactorDH_sha384kdf_scheme,
	NID_dhSinglePass_cofactorDH_sha512kdf_scheme,
#endif
#ifndef OPENSSL_NO_DH
	NID_dhKeyAgreement,
#endif
};

static int get_exch_info(const char *alg, int *ppkey_type, int *pec_scheme,
	int *pecdh_cofactor_mode, int *pecdh_kdf_type, int *pecdh_kdf_md,
	int *pecdh_kdf_outlen, char **pecdh_kdf_ukm, int *pecdh_kdf_ukmlen)
{
	int pkey_type = 0;
	int ec_scheme = 0;
	int ecdh_cofactor_mode = 0;
	int ecdh_kdf_type = 0;
	int ecdh_kdf_md = 0;
	int ecdh_kdf_outlen = 0;
	char *ecdh_kdf_ukm = NULL;
	int ecdh_kdf_ukmlen = 0;

	switch (OBJ_txt2nid(alg)) {
#ifndef OPENSSL_NO_SM2
	case NID_sm2exchange:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_sm_scheme;
		ecdh_kdf_md = NID_sm3;
		break;
#endif
#ifndef OPENSSL_NO_SHA
	case NID_dhSinglePass_stdDH_sha1kdf_scheme:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_secg_scheme;
		ecdh_cofactor_mode = 0;
		ecdh_kdf_type = NID_sha1;
		break;
	case NID_dhSinglePass_stdDH_sha224kdf_scheme:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_secg_scheme;
		ecdh_cofactor_mode = 0;
		ecdh_kdf_type = NID_sha224;
		break;
	case NID_dhSinglePass_stdDH_sha256kdf_scheme:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_secg_scheme;
		ecdh_cofactor_mode = 0;
		ecdh_kdf_type = NID_sha256;
		break;
	case NID_dhSinglePass_stdDH_sha384kdf_scheme:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_secg_scheme;
		ecdh_cofactor_mode = 0;
		ecdh_kdf_type = NID_sha384;
		break;
	case NID_dhSinglePass_stdDH_sha512kdf_scheme:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_secg_scheme;
		ecdh_cofactor_mode = 0;
		ecdh_kdf_type = NID_sha512;
		break;
	case NID_dhSinglePass_cofactorDH_sha1kdf_scheme:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_secg_scheme;
		ecdh_cofactor_mode = 1;
		ecdh_kdf_type = NID_sha1;
		break;
	case NID_dhSinglePass_cofactorDH_sha224kdf_scheme:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_secg_scheme;
		ecdh_cofactor_mode = 1;
		ecdh_kdf_type = NID_sha224;
		break;
	case NID_dhSinglePass_cofactorDH_sha256kdf_scheme:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_secg_scheme;
		ecdh_cofactor_mode = 1;
		ecdh_kdf_type = NID_sha256;
		break;
	case NID_dhSinglePass_cofactorDH_sha384kdf_scheme:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_secg_scheme;
		ecdh_cofactor_mode = 1;
		ecdh_kdf_type = NID_sha384;
		break;
	case NID_dhSinglePass_cofactorDH_sha512kdf_scheme:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_secg_scheme;
		ecdh_cofactor_mode = 1;
		ecdh_kdf_type = NID_sha512;
		break;
#endif
#ifndef OPENSSL_NO_DH
	case NID_dhKeyAgreement:
		pkey_type = EVP_PKEY_DH;
		break;
#endif
	default:
		return 0;
	}

	*ppkey_type = pkey_type;
	*pec_scheme = ec_scheme;
	*pecdh_cofactor_mode = ecdh_cofactor_mode;
	*pecdh_kdf_type = ecdh_kdf_type;
	*pecdh_kdf_md = ecdh_kdf_md;
	*pecdh_kdf_outlen = ecdh_kdf_outlen;
	*pecdh_kdf_ukm = ecdh_kdf_ukm;
	*pecdh_kdf_ukmlen = ecdh_kdf_ukmlen;

	return 1;
}

JNIEXPORT jobjectArray JNICALL Java_org_gmssl_GmSSL_getDeriveKeyAlgorithms(
	JNIEnv *env, jobject this)
{
	jobjectArray ret = NULL;
	int i;

	if (!(ret = (jobjectArray)(*env)->NewObjectArray(env,
		OSSL_NELEM(exch_nids),
		(*env)->FindClass(env, "java/lang/String"),
		(*env)->NewStringUTF(env, "")))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GETDERIVEKEYALGORITHMS, JNI_R_JNI_MALLOC_FAILURE);
		return NULL;
	}

	for (i = 0; i < OSSL_NELEM(exch_nids); i++) {
		(*env)->SetObjectArrayElement(env, ret, i,
			(*env)->NewStringUTF(env, OBJ_nid2sn(exch_nids[i])));
	}

	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSL_deriveKey(
	JNIEnv *env, jobject this, jstring algor,
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
	int ec_scheme;
	const unsigned char *cpin, *cpkey;
	EVP_PKEY *peerpkey = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;

	int ecdh_cofactor_mode;
	int ecdh_kdf_type;
	int ecdh_kdf_md;
	int ecdh_kdf_outlen;
	char *ecdh_kdf_ukm;
	int ecdh_kdf_ukm_len;


	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DERIVEKEY, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if ((outkeylen <= 0 || outkeylen > sizeof(outbuf))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DERIVEKEY, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if (!(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, peerkey, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DERIVEKEY, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if ((inlen = (*env)->GetArrayLength(env, peerkey)) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DERIVEKEY, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if (!(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DERIVEKEY, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	if ((keylen = (*env)->GetArrayLength(env, key)) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DERIVEKEY, JNI_R_BAD_ARGUMENT);
		goto end;
	}
	cpin = inbuf;
	cpkey = keybuf;

	if (!get_exch_info(alg, &pkey_type, &ec_scheme,
		&ecdh_cofactor_mode, &ecdh_kdf_type, &ecdh_kdf_md, &ecdh_kdf_outlen, &ecdh_kdf_ukm, &ecdh_kdf_ukm_len)) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DERIVEKEY, JNI_R_INVALID_DERIVE_KEY_ALGOR);
		goto end;
	}


	if (!(peerpkey = d2i_PUBKEY(NULL, &cpin, (long)inlen))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DERIVEKEY, JNI_R_INVALID_PUBLIC_KEY);
		goto end;
	}
	if (EVP_PKEY_id(peerpkey) != pkey_type) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DERIVEKEY, JNI_R_INVALID_PUBLIC_KEY);
		goto end;
	}
	if (!(pkey = d2i_PrivateKey(pkey_type, NULL, &cpkey, (long)keylen))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DERIVEKEY, JNI_R_INVALID_PRIVATE_KEY);
		goto end;
	}
	if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DERIVEKEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (EVP_PKEY_derive_init(pkctx) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DERIVEKEY, ERR_R_EVP_LIB);
		goto end;
	}

	if (pkey_type == EVP_PKEY_EC) {
		if (!EVP_PKEY_CTX_set_ec_scheme(pkctx, ec_scheme)) {
			JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DERIVEKEY, ERR_R_EC_LIB);
			goto end;
		}
	}
	if (ec_scheme == NID_secg_scheme) {
		if (!EVP_PKEY_CTX_set_ecdh_cofactor_mode(pkctx, ecdh_cofactor_mode)) {
			JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DERIVEKEY, ERR_R_EC_LIB);
			goto end;
		}
		if (!EVP_PKEY_CTX_set_ecdh_kdf_type(pkctx, ecdh_kdf_type)) {
			JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DERIVEKEY, ERR_R_EC_LIB);
			goto end;
		}
		if (!EVP_PKEY_CTX_set_ecdh_kdf_md(pkctx, EVP_get_digestbynid(ecdh_kdf_md))) {
			JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DERIVEKEY, ERR_R_EC_LIB);
			goto end;
		}
		if (!EVP_PKEY_CTX_set_ecdh_kdf_outlen(pkctx, ecdh_kdf_outlen)) {
			JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DERIVEKEY, ERR_R_EC_LIB);
			goto end;
		}
		if (!EVP_PKEY_CTX_set0_ecdh_kdf_ukm(pkctx, ecdh_kdf_ukm, ecdh_kdf_ukm_len)) {
			JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DERIVEKEY, ERR_R_EC_LIB);
			goto end;
		}
	} else if (ec_scheme == NID_sm_scheme) {
	}

	if (EVP_PKEY_derive_set_peer(pkctx, peerpkey) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DERIVEKEY, ERR_R_EVP_LIB);
		goto end;
	}
	if (EVP_PKEY_derive(pkctx, outbuf, &outlen) <= 0) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DERIVEKEY, ERR_R_EVP_LIB);
		goto end;
	}

	if (!(ret = (*env)->NewByteArray(env, outlen))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_DERIVEKEY, JNI_R_JNI_MALLOC_FAILURE);
		goto end;
	}

	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, peerkey, (jbyte *)inbuf, JNI_ABORT);
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	EVP_PKEY_free(peerpkey);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pkctx);
	return ret;
}

static int print_errors_cb(const char *str, size_t len, void *u)
{
	STACK_OF(OPENSSL_STRING *)sk = u;
	char *errstr;

	if (!(errstr = OPENSSL_strdup(str))) {
		JNIerr(JNI_F_PRINT_ERRORS_CB, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	if (!sk_OPENSSL_STRING_push(sk, errstr)) {
		JNIerr(JNI_F_PRINT_ERRORS_CB, JNI_R_ERRORS_STACK_ERROR);
		return 0;
	}

	return len;
}

static void free_errstr(char *s)
{
	OPENSSL_free(s);
}

JNIEXPORT jobjectArray JNICALL Java_org_gmssl_GmSSL_getErrorStrings(JNIEnv *env, jobject this)
{
	jobjectArray ret = NULL;
	STACK_OF(OPENSSL_STRING) *sk = NULL;
	int i;

	if (!(sk = sk_OPENSSL_STRING_new_null())) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GETERRORSTRINGS, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	ERR_print_errors_cb(print_errors_cb, sk);

	if (!(ret = (jobjectArray)(*env)->NewObjectArray(env,
		sk_OPENSSL_STRING_num(sk),
		(*env)->FindClass(env, "java/lang/String"),
		(*env)->NewStringUTF(env, "")))) {
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GETERRORSTRINGS, JNI_R_JNI_MALLOC_FAILURE);
		return NULL;
	}

	for (i = 0; i < sk_OPENSSL_STRING_num(sk); i++) {
		(*env)->SetObjectArrayElement(env, ret, i,
			(*env)->NewStringUTF(env, sk_OPENSSL_STRING_value(sk, i)));
	}

end:
	sk_OPENSSL_STRING_pop_free(sk, free_errstr);
	return ret;
}
