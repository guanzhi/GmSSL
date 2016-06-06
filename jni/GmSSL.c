/* jni/GmSSL.c */
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
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "GmSSL.h"

#define PRINT_ERROR() \
	fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__)

static int alg2pktype(const char *alg)
{
	return 0;
}

JNIEXPORT
jint JNICALL JNI_onload(JavaVM *jvm, void *reserved)
{
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	return JNI_VERSION_1_2;
}

JNIEXPORT
void JNICALL JNI_onunload(JavaVM *vm, void *reserved)
{
	ERR_free_strings();
	EVP_cleanup();
}

JNIEXPORT
jbyteArray JNICALL Java_GmSSL_symmetricEncrypt(JNIEnv *env, jobject this,
	jstring algor, jint flag, jbyteArray in, jbyteArray key, jbyteArray iv)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	unsigned char *inbuf = NULL;
	unsigned char *keybuf = NULL;
	unsigned char *ivbuf = NULL;
	unsigned char *outbuf = NULL;
	size_t inlen, keylen, ivlen, outlen;
	unsigned char *p;
	int len;
	const EVP_CIPHER *cipher;
	EVP_CIPHER_CTX *cctx = NULL;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		PRINT_ERROR();
		goto end;
	}
	if (!(cipher = EVP_get_cipherbyname(alg))) {
		PRINT_ERROR();
		goto end;
	}

	if (!(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))) {
		PRINT_ERROR();
		goto end;
	}
	inlen = (size_t)(*env)->GetArrayLength(env, in);
	if (inlen <= 0) {
		PRINT_ERROR();
		goto end;
	}

	if (!(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))) {
		PRINT_ERROR();
		goto end;
	}
	keylen = (size_t)(*env)->GetArrayLength(env, key);
	if (keylen < EVP_CIPHER_key_length(cipher)) {
		PRINT_ERROR();
		goto end;
	}

	if (!(ivbuf = (unsigned char *)(*env)->GetByteArrayElements(env, iv, 0))) {
		PRINT_ERROR();
		goto end;
	}
	ivlen = (size_t)(*env)->GetArrayLength(env, iv);
	if (ivlen != EVP_CIPHER_iv_length(cipher)) {
		PRINT_ERROR();
		goto end;
	}

	outlen = inlen + EVP_CIPHER_block_size(cipher) * 2;
	if (!(outbuf = malloc(outlen))) {
		PRINT_ERROR();
		goto end;
	}
	bzero(outbuf, outlen);

	if (!(cctx = EVP_CIPHER_CTX_new())) {
		PRINT_ERROR();
		goto end;
	}

	if (!EVP_EncryptInit_ex(cctx, cipher, NULL, keybuf, ivbuf)) {
		PRINT_ERROR();
		goto end;
	}

	p = outbuf;
	len = outlen;

	if (!EVP_EncryptUpdate(cctx, p, &len, inbuf, inlen)) {
		PRINT_ERROR();
		goto end;
	}
	p += len;
	len = outlen - len;

	if (!EVP_EncryptFinal_ex(cctx, p, &len)) {
		PRINT_ERROR();
		goto end;
	}
	p += len;

	if (!(ret = (*env)->NewByteArray(env, outlen))) {
		PRINT_ERROR();
		goto end;
	}

	outlen = p - outbuf;
	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);
end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	if (ivbuf) (*env)->ReleaseByteArrayElements(env, iv, (jbyte *)ivbuf, JNI_ABORT);
	if (outbuf) free(outbuf);
	EVP_CIPHER_CTX_free(cctx);
	return ret;
}

JNIEXPORT
jbyteArray JNICALL Java_GmSSL_symmetricDecrypt(JNIEnv *env, jobject this,
	jstring algor, jint flag, jbyteArray in, jbyteArray key, jbyteArray iv)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	unsigned char *inbuf = NULL;
	unsigned char *keybuf = NULL;
	unsigned char *ivbuf = NULL;
	unsigned char *outbuf = NULL;
	size_t inlen, keylen, ivlen, outlen;
	unsigned char *p;
	int len;
	const EVP_CIPHER *cipher;
	EVP_CIPHER_CTX *cctx = NULL;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		PRINT_ERROR();
		goto end;
	}
	if (!(cipher = EVP_get_cipherbyname(alg))) {
		PRINT_ERROR();
		goto end;
	}

	if (!(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))) {
		PRINT_ERROR();
		goto end;
	}
	inlen = (size_t)(*env)->GetArrayLength(env, in);
	if (inlen <= 0) {
		PRINT_ERROR();
		goto end;
	}

	if (!(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))) {
		PRINT_ERROR();
		goto end;
	}
	keylen = (size_t)(*env)->GetArrayLength(env, key);
	if (keylen < EVP_CIPHER_key_length(cipher)) {
		PRINT_ERROR();
		goto end;
	}

	if (!(ivbuf = (unsigned char *)(*env)->GetByteArrayElements(env, iv, 0))) {
		PRINT_ERROR();
		goto end;
	}
	ivlen = (size_t)(*env)->GetArrayLength(env, iv);
	if (ivlen != EVP_CIPHER_iv_length(cipher)) {
		PRINT_ERROR();
		goto end;
	}

	outlen = inlen + EVP_CIPHER_block_size(cipher) * 2;
	if (!(outbuf = malloc(outlen))) {
		PRINT_ERROR();
		goto end;
	}
	bzero(outbuf, outlen);

	if (!(cctx = EVP_CIPHER_CTX_new())) {
		PRINT_ERROR();
		goto end;
	}

	if (!EVP_DecryptInit_ex(cctx, cipher, NULL, keybuf, ivbuf)) {
		PRINT_ERROR();
		goto end;
	}

	p = outbuf;
	len = outlen;

	if (!EVP_DecryptUpdate(cctx, p, &len, inbuf, inlen)) {
		PRINT_ERROR();
		goto end;
	}
	p += len;
	len = outlen - len;

	if (!EVP_DecryptFinal_ex(cctx, p, &len)) {
		PRINT_ERROR();
		goto end;
	}
	p += len;

	if (!(ret = (*env)->NewByteArray(env, outlen))) {
		PRINT_ERROR();
		goto end;
	}

	outlen = p - outbuf;
	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	if (ivbuf) (*env)->ReleaseByteArrayElements(env, iv, (jbyte *)ivbuf, JNI_ABORT);
	if (outbuf) free(outbuf);
	EVP_CIPHER_CTX_free(cctx);
	return ret;

}

JNIEXPORT
jbyteArray JNICALL Java_GmSSL_digest(JNIEnv *env, jobject this,
	jstring algor, jint flag, jbyteArray in)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	unsigned char *inbuf = NULL;
	unsigned char *outbuf = NULL;
	size_t inlen, outlen;
	unsigned int len;
	const EVP_MD *md;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		PRINT_ERROR();
		goto end;
	}
	if (!(md = EVP_get_digestbyname(alg))) {
		PRINT_ERROR();
		goto end;
	}

	if (!(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))) {
		PRINT_ERROR();
		goto end;
	}
	inlen = (size_t)(*env)->GetArrayLength(env, in);
	if (inlen <= 0) {
		PRINT_ERROR();
		goto end;
	}

	outlen = EVP_MD_size(md);
	if (!(outbuf = malloc(outlen))) {
		PRINT_ERROR();
		goto end;
	}
	bzero(outbuf, outlen);

	if (!EVP_Digest(inbuf, inlen, outbuf, &len, md, NULL)) {
		PRINT_ERROR();
		goto end;
	}

	if (!(ret = (*env)->NewByteArray(env, outlen))) {
		PRINT_ERROR();
		goto end;
	}

	outlen = len;
	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	if (outbuf) free(outbuf);
	return ret;
}

JNIEXPORT
jbyteArray JNICALL Java_GmSSL_mac(JNIEnv *env, jobject this,
	jstring algor, jint flag, jbyteArray in, jbyteArray key)
{
	jbyteArray ret = NULL;
	return ret;
}

JNIEXPORT
jbyteArray JNICALL Java_GmSSL_sign(JNIEnv *env, jobject this,
	jstring algor, jint flag, jbyteArray in, jbyteArray key)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	unsigned char *inbuf = NULL;
	unsigned char *keybuf = NULL;
	unsigned char *outbuf = NULL;
	size_t inlen, keylen, outlen;
	const unsigned char *p;
	int type;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		PRINT_ERROR();
		goto end;
	}
	if ((type = alg2pktype(alg)) == NID_undef) {
		PRINT_ERROR();
		goto end;
	}

	if (!(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))) {
		PRINT_ERROR();
		goto end;
	}
	inlen = (size_t)(*env)->GetArrayLength(env, in);
	if (inlen < SHA_DIGEST_LENGTH) {
		PRINT_ERROR();
		goto end;
	}

	if (!(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))) {
		PRINT_ERROR();
		goto end;
	}
	keylen = (size_t)(*env)->GetArrayLength(env, key);

	p = keybuf;
	if (!(pkey = d2i_AutoPrivateKey(NULL, &p, keylen))) {
		PRINT_ERROR();
		goto end;
	}

	outlen = EVP_PKEY_size(pkey);
	if (!(outbuf = malloc(outlen))) {
		PRINT_ERROR();
		goto end;
	}

	if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
		PRINT_ERROR();
		goto end;
	}

	if (!EVP_PKEY_sign_init(pkctx)) {
		PRINT_ERROR();
		goto end;
	}

	if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC) {
		if (!EVP_PKEY_CTX_ctrl_str(pkctx, "ec_sign_algor", alg)) {
			PRINT_ERROR();
			goto end;
		}
	}

	if (!EVP_PKEY_sign(pkctx, outbuf, &outlen, inbuf, inlen)) {
		PRINT_ERROR();
		goto end;
	}

	if (!(ret = (*env)->NewByteArray(env, outlen))) {
		PRINT_ERROR();
		goto end;
	}

	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	if (outbuf) free(outbuf);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pkctx);
	return ret;
}

JNIEXPORT
jint JNICALL Java_GmSSL_verify(JNIEnv *env, jobject this,
	jstring algor, jint flag, jbyteArray in, jbyteArray signature,
	jbyteArray key)
{
	jint ret = 0;
	const char *alg = NULL;
	unsigned char *inbuf = NULL;
	unsigned char *sigbuf = NULL;
	unsigned char *keybuf = NULL;
	size_t inlen, siglen, keylen;
	const unsigned char *p;
	int type;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		PRINT_ERROR();
		goto end;
	}
	if ((type = alg2pktype(alg)) == NID_undef) {
		PRINT_ERROR();
		goto end;
	}

	if (!(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))) {
		PRINT_ERROR();
		goto end;
	}
	inlen = (size_t)(*env)->GetArrayLength(env, in);
	if (inlen < SHA_DIGEST_LENGTH) {
		PRINT_ERROR();
		goto end;
	}

	if (!(sigbuf = (unsigned char *)(*env)->GetByteArrayElements(env, signature, 0))) {
		PRINT_ERROR();
		goto end;
	}
	siglen = (size_t)(*env)->GetArrayLength(env, signature);
	if (siglen < 40) {
		PRINT_ERROR();
		goto end;
	}

	if (!(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))) {
		PRINT_ERROR();
		goto end;
	}
	keylen = (size_t)(*env)->GetArrayLength(env, key);

	p = keybuf;
	if (!(pkey = d2i_PublicKey(type, NULL, &p, keylen))) {
		PRINT_ERROR();
		goto end;
	}

	if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
		PRINT_ERROR();
		goto end;
	}

	if (!EVP_PKEY_verify_init(pkctx)) {
		PRINT_ERROR();
		goto end;
	}

	if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC) {
		if (!EVP_PKEY_CTX_ctrl_str(pkctx, "ec_sign_algor", alg)) {
			PRINT_ERROR();
			goto end;
		}
	}

	if ((ret = EVP_PKEY_verify(pkctx, sigbuf, siglen, inbuf, inlen)) != 1) {
		PRINT_ERROR();
		goto end;
	}

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	if (sigbuf) (*env)->ReleaseByteArrayElements(env, signature, (jbyte *)sigbuf, JNI_ABORT);
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pkctx);
	return ret;
}

JNIEXPORT
jbyteArray JNICALL Java_GmSSL_publicKeyEncrypt(JNIEnv *env, jobject this,
	jstring algor, jint flag, jbyteArray in, jbyteArray key)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	unsigned char *inbuf = NULL;
	unsigned char *keybuf = NULL;
	unsigned char *outbuf = NULL;
	size_t inlen, keylen, outlen;
	const unsigned char *p;
	int type;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		PRINT_ERROR();
		goto end;
	}
	if ((type = alg2pktype(alg)) == NID_undef) {
		PRINT_ERROR();
		goto end;
	}

	if (!(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))) {
		PRINT_ERROR();
		goto end;
	}
	inlen = (size_t)(*env)->GetArrayLength(env, in);
	if (inlen <= 0) {
		PRINT_ERROR();
		goto end;
	}

	if (!(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))) {
		PRINT_ERROR();
		goto end;
	}
	keylen = (size_t)(*env)->GetArrayLength(env, key);

	p = keybuf;
	if (!(pkey = d2i_PublicKey(type, NULL, &p, keylen))) {
		PRINT_ERROR();
		goto end;
	}

	/* we can not get ciphertext length from plaintext
	 * so malloc the max buffer
	 */
	outlen = inlen + 2048;
	if (!(outbuf = malloc(outlen))) {
		PRINT_ERROR();
		goto end;
	}

	if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
		PRINT_ERROR();
		goto end;
	}

	if (!EVP_PKEY_encrypt_init(pkctx)) {
		PRINT_ERROR();
		goto end;
	}

	if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC) {
		if (!EVP_PKEY_CTX_ctrl_str(pkctx, "ec_encrypt_algor", alg)) {
			PRINT_ERROR();
			goto end;
		}
	}

	if (!EVP_PKEY_encrypt(pkctx, outbuf, &outlen, inbuf, inlen)) {
		PRINT_ERROR();
		goto end;
	}

	if (!(ret = (*env)->NewByteArray(env, outlen))) {
		PRINT_ERROR();
		goto end;
	}

	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	if (outbuf) free(outbuf);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pkctx);
	return ret;

}

JNIEXPORT
jbyteArray JNICALL Java_GmSSL_publicKeyDecrypt(JNIEnv *env, jobject this,
	jstring algor, jint flag, jbyteArray in, jbyteArray key)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	unsigned char *inbuf = NULL;
	unsigned char *keybuf = NULL;
	unsigned char *outbuf = NULL;
	size_t inlen, keylen, outlen;
	const unsigned char *p;
	int type;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		PRINT_ERROR();
		goto end;
	}
	if ((type = alg2pktype(alg)) == NID_undef) {
		PRINT_ERROR();
		goto end;
	}

	if (!(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))) {
		PRINT_ERROR();
		goto end;
	}
	inlen = (size_t)(*env)->GetArrayLength(env, in);
	if (inlen <= 0) {
		PRINT_ERROR();
		goto end;
	}

	if (!(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))) {
		PRINT_ERROR();
		goto end;
	}
	keylen = (size_t)(*env)->GetArrayLength(env, key);

	p = keybuf;
	if (!(pkey = d2i_AutoPrivateKey(NULL, &p, keylen))) {
		PRINT_ERROR();
		goto end;
	}

	outlen = inlen;
	if (!(outbuf = malloc(outlen))) {
		PRINT_ERROR();
		goto end;
	}

	if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
		PRINT_ERROR();
		goto end;
	}

	if (!EVP_PKEY_encrypt_init(pkctx)) {
		PRINT_ERROR();
		goto end;
	}

	if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC) {
		if (!EVP_PKEY_CTX_ctrl_str(pkctx, "ec_encrypt_algor", alg)) {
			PRINT_ERROR();
			goto end;
		}
	}

	if (!EVP_PKEY_encrypt(pkctx, outbuf, &outlen, inbuf, inlen)) {
		PRINT_ERROR();
		goto end;
	}

	if (!(ret = (*env)->NewByteArray(env, outlen))) {
		PRINT_ERROR();
		goto end;
	}

	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	if (outbuf) free(outbuf);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pkctx);
	return ret;
}

