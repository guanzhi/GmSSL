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

#include <string.h>

#include <openssl/sm2.h>
#include <openssl/sm3.h>

#include "sm2.h"

EC_GROUP* getGroup();

void GroupFree(EC_GROUP* gp);

int doSM3(EC_KEY* sm2Key,const char *oridata,int dlen,char *zValue,int zValueLen);

EC_KEY* bin2PrivateKey(const char *bindata,int len)
{
    EC_KEY* sm2Key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    if (!sm2Key)
    {
        return NULL;
    }
    BIGNUM* privNum = BN_bin2bn((unsigned const char *)bindata,len, NULL);
    EC_KEY_set_private_key(sm2Key, privNum);
    BN_clear_free(privNum);
    return sm2Key;
}

void setBinByte(const char *src,int slen,char *dst,int NN)
{
    int dlen = slen;
    int off = NN - slen;
    if (off < 0)
    {
        off = 0;
        dlen = NN;
    }
    memcpy(dst+off,src,dlen);
}

char *makeSigBin(ECDSA_SIG* signData)
{
    const BIGNUM *sig_r;
	const BIGNUM *sig_s;
    ECDSA_SIG_get0(signData, &sig_r, &sig_s);
    char *buf = OPENSSL_malloc(Size_Signure);
    memset(buf,0,Size_Signure);
    //
    char temp[32] = {0};
    int len = BN_bn2bin(sig_r,temp);
    setBinByte(temp,len,buf,32); 

    len = BN_bn2bin(sig_s,temp);
    setBinByte(temp,len,buf+32,32); 
    return buf;
}

ECDSA_SIG *makeSignData_bin(const char *bindata)
{
    //BN_bin2bn
	char buf[32] = { 0 };
    memcpy(buf,bindata,32);
	BIGNUM *sig_r = BN_new();
    if (!BN_bin2bn(buf,32,sig_r))
    {
        LOGDEBUG("[SM2::veify] ERROR of BN_hex2bn R:" );
        BN_free(sig_r);
        return NULL;
    }
	BIGNUM *sig_s = BN_new();
    memcpy(buf,bindata+32,32);
    if (!BN_bin2bn(buf,32,sig_s))
    {
        LOGDEBUG("[SM2::veify] ERROR BN_hex2bn S:" );
        BN_free(sig_r);
        BN_free(sig_s);
        return NULL;
    }
	ECDSA_SIG *signData = ECDSA_SIG_new();
    ECDSA_SIG_set0(signData,sig_r,sig_s);
    return signData;
}

char *GeneratePrivateKey_bin()
{
	char* pri = NULL;
    EC_KEY* sm2Key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    if (!sm2Key)
    {
        LOGDEBUG("Error Of Alloc Memory for SM2 Key");
        return pri;
    }

    if (EC_KEY_generate_key(sm2Key) == 0)
    {
        LOGDEBUG("Error Of Generate SM2 Key");
        EC_KEY_free(sm2Key);
        return pri;
    }
    char buf[Size_PriKey] = {0};
    size_t sz = BN_bn2bin(EC_KEY_get0_private_key(sm2Key),buf);
    pri = OPENSSL_malloc(Size_PriKey);
    setBinByte(buf,sz,pri,Size_PriKey);
    //
    EC_KEY_free(sm2Key);
    return pri;
}

char *GetPublicKeyByPriv_bin(const char *bindata,int len)
{
    EC_POINT * pubkey = NULL;
    BIGNUM *privNum = NULL;    
    EC_GROUP* sm2Group = NULL;
    BN_CTX *ctx = NULL;

    size_t sz = Size_PubKey;
    char *pub = NULL;
    char buf[Size_PubKey] = {0};

    //
    privNum = BN_bin2bn((unsigned const char *)bindata,len, NULL);
    //LOGDEBUG("in_bin=%s",BN_bn2hex(privNum));
    ctx = BN_CTX_new();
    //
    sm2Group = getGroup();
    if (!sm2Group)
    {
        LOGDEBUG("Error Of Gain SM2 Group Object");
        goto err;
    }
    
	pubkey = EC_POINT_new(sm2Group);
    if (pubkey == NULL)
    {
        LOGDEBUG("Error Of Gain SM2 EC_POINT Object");
        goto err;
    }
    if (!EC_POINT_mul(sm2Group, pubkey,privNum,NULL,NULL,ctx))
    {
        LOGDEBUG("Error Of Set SM2 EC_POINT Object");
        goto err;
    }
    sz = EC_POINT_point2oct(sm2Group, pubkey, POINT_CONVERSION_UNCOMPRESSED, buf,Size_PubKey, NULL);
	//pub = EC_POINT_point2hex(sm2Group, pubkey, POINT_CONVERSION_UNCOMPRESSED, NULL);
    pub = OPENSSL_malloc(Size_PubKey);
    setBinByte(buf,sz,pub,Size_PubKey);
err: 
    if (pubkey)  EC_POINT_free(pubkey);
    if (privNum) BN_clear_free(privNum);
    if (sm2Group) GroupFree(sm2Group);
    if (ctx) BN_CTX_free(ctx);

    return pub;
}
//char *makeSigHex(ECDSA_SIG* signData);
char *Sign_bin(const char *binpriv,int len,const char *oridata,int dlen)
{
    char* ret = NULL;
    unsigned char zValue[SM3_DIGEST_LENGTH] = {0};
    size_t zValueLen = SM3_DIGEST_LENGTH;

    BN_CTX* ctx = NULL;
    EC_KEY* sm2Key = NULL;
    ECDSA_SIG* signData = NULL;
    EC_POINT * pubPoint = NULL;
    //    
    ctx = BN_CTX_new();

    sm2Key = bin2PrivateKey(binpriv,len);
    if (!sm2Key)
    {
        LOGDEBUG("Error Of Gain SM2 Group Object");
        goto err;
    }
    
	pubPoint = EC_POINT_new(EC_KEY_get0_group(sm2Key));
    if (pubPoint == NULL)
    {
        LOGDEBUG("Error Of Gain SM2 EC_POINT Object");
        goto err;
    }
    if (!EC_POINT_mul(EC_KEY_get0_group(sm2Key), pubPoint,EC_KEY_get0_private_key(sm2Key),NULL,NULL,ctx))
    {
        LOGDEBUG("Error Of Set SM2 EC_POINT Object");
        goto err;
    }
    if (!EC_KEY_set_public_key(sm2Key, pubPoint))
    {
        LOGDEBUG("[SM2::veify] ERROR of Sign EC_KEY_set_public_key");
        goto err;
    }
    //
    zValueLen = doSM3(sm2Key,oridata,dlen,zValue,sizeof(zValue));
    if (zValueLen < 0)
    {
        goto err;
    }
    signData = ECDSA_do_sign_ex(zValue, zValueLen, NULL, NULL, sm2Key);
    if (signData == NULL)
    {
        LOGDEBUG("[SM2::sign] Error Of SM2 Signature");
        goto err;
    }
    // ret = makeSigHex(signData);
    // LOGDEBUG("Signure=%s",ret);
    ret = makeSigBin(signData);
err:
    if (ctx)BN_CTX_free(ctx);
    if (sm2Key)EC_KEY_free(sm2Key);
    if (signData)ECDSA_SIG_free(signData);
    if (pubPoint)EC_POINT_free(pubPoint);
    return ret;
}

int Verify_bin(const char *binpub,const char *binsig,const char *oridata,int dlen)
{
    EC_KEY* sm2Key = NULL;
    EC_POINT* pubPoint = NULL;
    ECDSA_SIG* signData = NULL;
    const EC_GROUP* sm2Group = NULL;

    char buf[64] = {0};
    int lresult = 0; 
    unsigned char zValue[SM3_DIGEST_LENGTH] = {0};
    size_t zValueLen = SM3_DIGEST_LENGTH;
    //
    sm2Key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    if (!sm2Key)
    {
        LOGDEBUG("Error Of Alloc Memory for SM2 Key");
        goto err;
    }

    sm2Group = EC_KEY_get0_group(sm2Key);

    if ((pubPoint = EC_POINT_new(sm2Group)) == NULL)
    {
        LOGDEBUG("[SM2::veify] ERROR of Verify EC_POINT_new");
        goto err;
    }
    
    //if (!EC_POINT_hex2point(sm2Group, hexpub, pubPoint, NULL))
    if (!EC_POINT_oct2point(sm2Group,pubPoint,binpub,Size_PubKey,NULL))
    {
        LOGDEBUG("[SM2::veify] ERROR of Verify EC_POINT_hex2point");
        goto err;
    }

    if (!EC_KEY_set_public_key(sm2Key, pubPoint))
    {
        LOGDEBUG("[SM2::veify] ERROR of Verify EC_KEY_set_public_key");
        goto err;
    }
    //
    zValueLen = doSM3(sm2Key,oridata,dlen,zValue,sizeof(zValue));
    if (zValueLen < 0)
    {
        goto err;
    }
    signData = makeSignData_bin(binsig);
    if (signData == NULL)
    {
        goto err;
    }
    if (ECDSA_do_verify(zValue, zValueLen, signData, sm2Key) != 1)
    {
        //LOGDEBUG("[SM2::veify] Error Of SM2 Verify:\n\tpubkey=%s;\n\tsigdat=%s",hexpub,hexsig);
        if (ECDSA_do_verify(zValue, zValueLen, signData, sm2Key)==1)
        {
            LOGDEBUG("verify ok");
        }
        else
        {
            LOGDEBUG("verify failed");
        }        
        goto err;
    }
    lresult = 1;
err:
    if (sm2Key)EC_KEY_free(sm2Key);
    if (pubPoint)EC_POINT_free(pubPoint);
    if (signData)ECDSA_SIG_free(signData);

    return lresult;
}