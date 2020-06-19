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
 */

#pragma once

#ifdef  __cplusplus
extern "C" {
#endif

//log打印信息;
#ifdef _KTEST_

#include <stdio.h>
#define SM2DEBUG(fmt,...) printf("%s(%d):"fmt"\n",__FILE__,__LINE__,##__VA_ARGS__);

int initPrivKey();
void testSameSM2();
#else
#define SM2DEBUG(fmt,...)

inline int initPrivKey() { return 0; }
inline void testSameSM2(){}
#endif

//void SSLInit();

//-----------------------------------------------------------------------
//return errno;0-->success;errors for others and errinfo set to errbuf;
unsigned long SM2Error(unsigned char *errbuf, int max);

void SM2Free(char *d);

char *GetPublicKeyByPriv_hex(const char *hexstr);

char *GeneratePrivateKey_hex();

char *Sign_hex(const char *hexpriv,const char *oridata,int dlen);

//returns: 1-success;0-failed;
int Verify_hex(const char *hexpub,const char *hexsig,const char *oridata,int dlen);

//
// static const int Size_PubKey  = 65;
// static const int Size_PriKey  = 32;
// static const int Size_Signure = 64;
enum SM2Size 
{
    Size_PriKey = 32,
    Size_Signure = 64,
    Size_PubKey = 65,
};

char *GetPublicKeyByPriv_bin(const unsigned char *bindata,int len);
char *GeneratePrivateKey_bin();
char *Sign_bin(const unsigned char *binpriv,int len,const unsigned char *oridata,int dlen);
//returns: 1-success;0-failed;
int Verify_bin(const unsigned char *binpub,const unsigned char *binsig,const unsigned char *oridata,int dlen);


#ifdef  __cplusplus
}
#endif