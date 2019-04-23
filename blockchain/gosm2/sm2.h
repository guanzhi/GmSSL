#pragma once

 #ifdef  __cplusplus
 extern "C" {
 #endif

 //log打印信息;
 #ifdef _KTEST_

 #include <stdio.h>
 #define LOGDEBUG(fmt,...) printf("%s(%d):"fmt"\n",__FILE__,__LINE__,##__VA_ARGS__);

 int initPrivKey();
 void testSameSM2();
 #else
 #define LOGDEBUG(fmt,...)

 inline int initPrivKey() { return 0; }
 inline void testSameSM2(){}
 #endif

 //-----------------------------------------------------------------------
 void SM2Free(char *d);

 char *GetPublicKeyByPriv_hex(const char *hexstr);

 char *GeneratePrivateKey_hex();

 char *Sign_hex(const char *hexpriv,const char *oridata,int dlen);

 //returns: 1-success;0-failed;
 int Verify_hex(const char *hexpub,const char *hexsig,const char *oridata,int dlen);

 enum SM2Size
 {
	 Size_PriKey = 32,
	 Size_Signure = 64,
	 Size_PubKey = 65,
 };

char *GetPublicKeyByPriv_bin(const char *bindata,int len);
char *GeneratePrivateKey_bin();
char *Sign_bin(const char *binpriv,int len,const char *oridata,int dlen);
//returns: 1-success;0-failed;
int Verify_bin(const char *binpub,const char *binsig,const char *oridata,int dlen);

 inline char *GetPublicKeyByPriv_bin2(const unsigned char *bindata,int len)
 {
    return GetPublicKeyByPriv_bin((const char*)bindata,len);
 }

 inline char *GeneratePrivateKey_bin2()
 {
	 return GeneratePrivateKey_bin();
 }

 inline char *Sign_bin2(const unsigned char *binpriv,int len,const unsigned char *oridata,int dlen)
 {
    return Sign_bin((const char *)binpriv,len,(const char *)oridata,dlen);
 }
 //returns: 1-success;0-failed;
 inline int Verify_bin2(const unsigned char *binpub,const unsigned char *binsig,const unsigned char *oridata,int dlen)
 {
     return Verify_bin((const char *)binpub,(const char *)binsig,(const char *)oridata,dlen);
 }


 #ifdef  __cplusplus
 }
 #endif