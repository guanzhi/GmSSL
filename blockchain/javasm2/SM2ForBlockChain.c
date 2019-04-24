
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "SM2ForBlockChain.h"
#include "sm2.h"

JNIEXPORT jstring JNICALL Java_SM2ForBlockChain_SM2Error
  (JNIEnv *env, jobject obj)
{
  char buf[4096] = {0};
  int eno = SM2Error(buf,4096);
  if (eno == 0)
  {//no error;
    return (*env)->NewStringUTF(env, "");
  }
  return (*env)->NewStringUTF(env, buf);
}

JNIEXPORT jstring JNICALL Java_SM2ForBlockChain_stringMethod
  (JNIEnv *env, jobject obj, jstring string)
{
    const char* str = (*env)->GetStringUTFChars(env, string, 0);
    jstring jstr = (*env)->NewStringUTF(env, str);
    (*env)->ReleaseStringUTFChars(env, string, 0);
    return jstr;
}


JNIEXPORT jstring JNICALL Java_SM2ForBlockChain_GenPrivateKey
  (JNIEnv *env, jobject obj)
{
    char *priv = GeneratePrivateKey_hex();
    if (priv == NULL)
    {
      return (*env)->NewStringUTF(env, "");
    }
    jstring jstr =  (*env)->NewStringUTF(env, priv);
    SM2Free(priv);
    return jstr;
}

JNIEXPORT jstring JNICALL Java_SM2ForBlockChain_GetPublicKeyByPriv
  (JNIEnv *env, jobject obj, jstring string)
{
    const char* str = (*env)->GetStringUTFChars(env, string, 0);
    char *pub = GetPublicKeyByPriv_hex(str);
    (*env)->ReleaseStringUTFChars(env, string, 0);
    //
    if (pub == NULL)
    {
      return (*env)->NewStringUTF(env, "");
    }
    jstring jstr = (*env)->NewStringUTF(env, pub);
    SM2Free(pub);
    return jstr;
}

/*
 * Class:     SM2ForBlockChain
 * Method:    Sign
 * Signature: (Ljava/lang/String;[BI)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_SM2ForBlockChain_Sign
  (JNIEnv *env, jobject obj, jstring privStr, jbyteArray data,jint dlen)
{
  const char* priv = (*env)->GetStringUTFChars(env, privStr, 0);
  jbyte* rawdata = (*env)->GetByteArrayElements(env,data,0);
  
  char *sig = Sign_hex(priv, (char*)rawdata, (int)dlen);
  //
  (*env)->ReleaseByteArrayElements(env,data,rawdata,0);
  (*env)->ReleaseStringUTFChars(env, privStr, 0);
  //
  if (sig == NULL)
  {
    return  (*env)->NewStringUTF(env, "");
  }
  //
  jstring jstr = (*env)->NewStringUTF(env, sig);
  SM2Free(sig);
  return jstr;
}

// /*
//  * Class:     SM2ForBlockChain
//  * Method:    Verify
//  * Signature: (Ljava/lang/String;Ljava/lang/String;[BI)I
//  */
JNIEXPORT jboolean JNICALL Java_SM2ForBlockChain_Verify
  (JNIEnv *env, jobject obj, jstring pubStr, jstring sigStr, jbyteArray data, jint len)
{
  const char* pub = (*env)->GetStringUTFChars(env, pubStr, 0);
  const char* sig = (*env)->GetStringUTFChars(env, sigStr, 0);
  jbyte* rawdata = (*env)->GetByteArrayElements(env,data,0);

  int result = Verify_hex(pub,sig, rawdata, len);

  //
  (*env)->ReleaseByteArrayElements(env,data,rawdata,0);
  (*env)->ReleaseStringUTFChars(env, pubStr, 0);
  (*env)->ReleaseStringUTFChars(env, sigStr, 0);
  
  return (unsigned char)result;
}


