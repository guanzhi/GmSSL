/* +build cgo */
package gosm2

/*
 #include <string.h>

 #include <openssl/sm2.h>
 #include <openssl/sm3.h>

 #include "sm2.h"

 EC_GROUP* getGroup()
 {
     return EC_GROUP_new_by_curve_name(NID_sm2p256v1);
 }

 void GroupFree(EC_GROUP* gp)
 {
     EC_GROUP_free(gp);
 }


 EC_KEY* hex2PrivateKey(const char *hexstr)
 {
     BIGNUM* res = BN_new();
     BN_hex2bn(&res, hexstr);
     EC_KEY* sm2Key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
     if (!sm2Key)
     {
         BN_clear_free(res);
         return NULL;
     }
     EC_KEY_set_private_key(sm2Key, res);
     BN_clear_free(res);
     return sm2Key;
 }


 int doSM3(EC_KEY* sm2Key,const char *oridata,int dlen,char *zValue,int zValueLen)
 {
     char id[] = {"0123456789abcdef"};
     size_t sz = (size_t)zValueLen;
     if (!SM2_compute_id_digest(EVP_sm3(),id,sizeof(id)-1,zValue,&sz,sm2Key))
     {
         return -1;
     }
     sm3_ctx_t sm3Ctx;
     sm3_init(&sm3Ctx);
     sm3_update(&sm3Ctx, zValue, zValueLen);
     sm3_update(&sm3Ctx, oridata, dlen);
     sm3_final(&sm3Ctx,zValue);
     return (int)sz;
 }

 void setNByte(const char *src,char *dst,int NN)
 {
     int dlen = strlen(src);
     int off = NN - dlen;
     if (off < 0)
     {
         off = 0;
         dlen = NN;
     }
     memcpy(dst+off,src,dlen);
 }

 char *makeSigHex(ECDSA_SIG* signData)
 {
     const BIGNUM *sig_r;
     const BIGNUM *sig_s;
     ECDSA_SIG_get0(signData, &sig_r, &sig_s);
     //r(32*2);s(32*2);
     char *buf = OPENSSL_malloc(32*2*2+1);
     memset(buf,'0',32*2*2);
     buf[32*2*2] = '\0';
     char * phex_r = BN_bn2hex(sig_r);
     char * phex_s = BN_bn2hex(sig_s);
     if (phex_r != NULL && phex_s != NULL)
     {
         setNByte(phex_r,buf,64);
         setNByte(phex_s,buf+64,64);
     }
     else
     {
         memset(buf,0,32*2*2);
     }
     if (phex_r)OPENSSL_free((void*)phex_r);
     if (phex_s)OPENSSL_free((void*)phex_s);
     return buf;
 }

 ECDSA_SIG *makeSignData(const char *hexsig)
 {
     //BN_bin2bn
     char buf[64 + 1] = { 0 };
     setNByte(hexsig,buf,64);
     BIGNUM *sig_r = NULL;
     if (!BN_hex2bn(&sig_r, buf))
     {
         LOGDEBUG("[SM2::veify] ERROR of BN_hex2bn R:" );
         //if (sig_r) BN_free(sig_r);
         return NULL;
     }
     BIGNUM *sig_s = NULL;
     setNByte(hexsig+64,buf,64);
     if (!BN_hex2bn(&sig_s, buf))
     {
         LOGDEBUG("[SM2::veify] ERROR BN_hex2bn S:" );
         if (sig_r) BN_free(sig_r);
         //if (sig_s) BN_free(sig_s);
         return NULL;
     }
     ECDSA_SIG *signData = ECDSA_SIG_new();
     ECDSA_SIG_set0(signData,sig_r,sig_s);
     return signData;
 }

 //用于释放PrivateKey/PublicKey/Singure;
 void SM2Free(char *d)
 {
     if (d)
     {
         OPENSSL_free(d);
     }
 }

 //EC_POINT_point2oct
 //EC_POINT_point2buf
 //EC_POINT_oct2point
 char *GetPublicKeyByPriv_hex(const char *hexstr)
 {
     EC_POINT * pubkey = NULL;
     BIGNUM* privNum = NULL;
     EC_GROUP* sm2Group = NULL;
     BN_CTX *ctx = NULL;

     char *pub = NULL;
     //
     BN_hex2bn(&privNum, hexstr);
     //LOGDEBUG(" no_bin=%s",BN_bn2hex(privNum));

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
     pub = EC_POINT_point2hex(sm2Group, pubkey, POINT_CONVERSION_UNCOMPRESSED, NULL);
     if (pub == NULL)
     {
         LOGDEBUG("Error Of Output SM2 Public key");
         goto err;
     }
     //ret = SM2StrDup(pub);
 err:
     if (pubkey)  EC_POINT_free(pubkey);
     if (privNum) BN_clear_free(privNum);
     if (sm2Group) GroupFree(sm2Group);
     if (ctx) BN_CTX_free(ctx);
     //if (pub) OPENSSL_free(pub);
     //return ret;
     return pub;
 }


 char *GeneratePrivateKey_hex()
 {
     EC_KEY* sm2Key = NULL;
     char* pri = NULL;
     //char *ret = NULL;

     sm2Key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
     if (!sm2Key)
     {
         LOGDEBUG("Error Of Alloc Memory for SM2 Key");
         goto err;
     }

     if (EC_KEY_generate_key(sm2Key) == 0)
     {
         LOGDEBUG("Error Of Generate SM2 Key");
         goto err;
     }

     pri = BN_bn2hex(EC_KEY_get0_private_key(sm2Key));
     if (!pri)
     {
         LOGDEBUG("Error Of Output SM2 Private key");
         goto err;
     }
 err:
     if (sm2Key)EC_KEY_free(sm2Key);
     return pri;
 }

 char *Sign_hex(const char *hexpriv,const char *oridata,int dlen)
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

     sm2Key = hex2PrivateKey(hexpriv);
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
     ret = makeSigHex(signData);

 err:
     if (ctx)BN_CTX_free(ctx);
     if (sm2Key)EC_KEY_free(sm2Key);
     if (signData)ECDSA_SIG_free(signData);
     if (pubPoint)EC_POINT_free(pubPoint);
     return ret;
 }


 int Verify_hex(const char *hexpub,const char *hexsig,const char *oridata,int dlen)
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

     if (!EC_POINT_hex2point(sm2Group, hexpub, pubPoint, NULL))
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
     signData = makeSignData(hexsig);
     if (signData == NULL)
     {
         goto err;
     }
     if (ECDSA_do_verify(zValue, zValueLen, signData, sm2Key) != 1)
     {
         LOGDEBUG("[SM2::veify] Error Of SM2 Verify:\n\tpubkey=%s;\n\tsigdat=%s",hexpub,hexsig);
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


 #ifdef _KTEST_
 static  unsigned char zValue[SM3_DIGEST_LENGTH] = {0};
 static  size_t zValueLen = SM3_DIGEST_LENGTH;
 static char testdata[] = {"test data for test!!!!!!!!!!"};
 EC_KEY* sm2Key = NULL;
 int initPrivKey()
 {
     sm2Key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
     if (!sm2Key)
     {
         LOGDEBUG("Error Of Alloc Memory for SM2 Key");
         return 0;
     }

     if (EC_KEY_generate_key(sm2Key) == 0)
     {
         LOGDEBUG("Error Of Generate SM2 Key");
         return 0;
     }
     return 1;
 }

 void testSameSM2()
 {

     ECDSA_SIG* signData = NULL;
     int zlen = 0;

     //sign;
     zlen = doSM3(sm2Key,testdata,sizeof(testdata)-1,zValue,sizeof(zValue));
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
     //verify;
     zlen = doSM3(sm2Key,testdata,sizeof(testdata)-1,zValue,sizeof(zValue));
     if (zValueLen < 0)
     {
         goto err;
     }
     if (ECDSA_do_verify(zValue, zlen, signData, sm2Key) != 1)
     {
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
 err:
     //if (sm2Key)EC_KEY_free(sm2Key);
     if (signData)ECDSA_SIG_free(signData);
 }
 #endif
*/
import "C"

import (
	"encoding/hex"
	"fmt"
	"unsafe"
)

func GenPrivateKey_hex() ([]byte, error) {
	key := C.GeneratePrivateKey_hex()
	gokey := C.GoString(key)
	C.SM2Free(key)
	return hex.DecodeString(gokey)
}

func GenPublicKeyByPriv_hex(pri []byte) ([]byte, error) {
	hexstr := C.CString(fmt.Sprintf("%x", pri))
	pub := C.GetPublicKeyByPriv_hex(hexstr)
	C.free(unsafe.Pointer(hexstr))

	gokey := C.GoString(pub)
	C.SM2Free(pub)
	return hex.DecodeString(gokey)
}

func SignData_hex(priv []byte, data string) ([]byte, error) {
	hexstr := C.CString(fmt.Sprintf("%x", priv))
	hexmsg := C.CString(data)

	sdata := C.Sign_hex(hexstr, hexmsg, C.int(len(data)))

	C.free(unsafe.Pointer(hexstr))
	C.free(unsafe.Pointer(hexmsg))

	gokey := C.GoString(sdata)
	C.SM2Free(sdata)

	if len(gokey) == 0 {
		return []byte{}, nil
	}
	return hex.DecodeString(gokey)
}

func VerifyData_hex(pub, sig []byte, msg string) bool {
	hexstr := C.CString(fmt.Sprintf("%x", pub))
	hexsig := C.CString(fmt.Sprintf("%x", sig))
	hexmsg := C.CString(msg)

	ret := C.Verify_hex(hexstr, hexsig, hexmsg, C.int(len(msg)))

	C.free(unsafe.Pointer(hexstr))
	C.free(unsafe.Pointer(hexsig))
	C.free(unsafe.Pointer(hexmsg))
	//
	return (ret == 1)
}
