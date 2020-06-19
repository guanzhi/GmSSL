#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <stdint.h>

#include "sm2.h"

#ifdef WIN32

char buf[] = {"just test sm2 sign/verify!!!"};
char pvd[] = {"EDE9E0C0EAA4BF0B9B0B9BF2643E1DD3C57FE16ABF2F33A92F07A2849E6812E3"};

int testSM2_hex()
{
    char *prv = NULL;
    char *pub = NULL;
    char *sig = NULL;
    int ret = 0;
    prv = GeneratePrivateKey_hex();
    if (!prv)
    {
        goto err;
    }
    pub = GetPublicKeyByPriv_hex(prv);
    if (!pub)
    {
        goto err;
    }
    sig = Sign_hex(prv,buf,strlen(buf));
    if (!sig)
    {
        goto err;
    }
    ret = Verify_hex(pub,sig,buf,strlen(buf));
    //ret = 1;
err :
    if (prv && prv != pvd)SM2Free(prv);
    if (pub)SM2Free(pub);
    if (sig)SM2Free(sig);
    return ret;
}

int testSM2_bin()
{
    char *prv = NULL;
    char *pub = NULL;
    char *sig = NULL;
    int ret = 0;
    prv = GeneratePrivateKey_bin();
    if (!prv)
    {
        goto err;
    }
    pub = GetPublicKeyByPriv_bin(prv,Size_PriKey);
    if (!pub)
    {
        goto err;
    }
    sig = Sign_bin(prv,Size_PriKey,buf,strlen(buf));
    if (!sig)
    {
        goto err;
    }
    ret = Verify_bin(pub,sig,buf,strlen(buf));
err :
    if (prv && prv != pvd)SM2Free(prv);
    if (pub)SM2Free(pub);
    if (sig)SM2Free(sig);
    return ret;
}

int testSM2(int dohex)
{
    if (dohex)
    {
        return testSM2_hex();
    }
    else
    {
        return testSM2_bin();
    }
    
}


void testAll()
{
	int64_t i = 0;
	int64_t times = 16 * 1000;
    int dohex = 0;
	while (testSM2(dohex) && i < times)
	{
		i++;
		if (i % 1000 == 0)
		{
			printf("%lld times\n", i);
			Sleep(1000);
		}
	}
}

void verify()
{
	char *priv = "EDE9E0C0EAA4BF0B9B0B9BF2643E1DD3C57FE16ABF2F33A92F07A2849E6812E3";
	char *pub = GetPublicKeyByPriv_hex(priv);
	printf("pub=%s\n", pub);
    char *sig = "BAA1837998CCA657A341FBDB2C09E7CCC3ABEC7AB39F97D1B60AE2A98B3202B347C4151FF3170C05FEDD8405CA801F922D052ACFCF1A7A9D8283D0B1C84BDB52";
    //char *pub = "04AA5AEB19F1B4B39C201638ECBD05B2C33C0637D4B7E0AE630D619266A94540E68CCC0D33462C7AEE41D69765CCD178250B6BDA0E234ABC3C5F71018F9D370FAB";
    if (!Verify_hex(pub,sig, buf,strlen(buf)))
    {
		printf("Verify failed\n");
		char c;
		scanf("%c", &c);
    }
}

inline char hex2bin1(char c)
{
	if (c >= 'a')return (c - 'a'+10)&0xf;
	if (c >= 'A')return (c - 'A'+10)&0xf;
	return (c - '0')&0xf;
}
inline char hex2bin(char ha,char hb)
{
    char a = hex2bin1(ha);
	int i = (int)a << 4;
	a <<= 4;
    char b = hex2bin1(hb);
    char tmp =  (a) | b;
	return tmp;
}

inline char lowhalf2hex(char c)
{
    c = c &0xf;
	if (c < 10)return c + '0';
	return c-10 + 'A';
}
inline void bin2hex(char b,char *ha,char *hb)
{
    *ha = lowhalf2hex(b>>4);
    *hb = lowhalf2hex(b&0xf);
}

char* bindata2hex(const char * bin,int blen,char *buf)
{
    int pos = 0;
    for (int i=0;i<blen;++i)
    {
        bin2hex(bin[i],buf+pos,buf+pos+1);
        pos+=2;
    }
    buf[pos] = '\0';
    return buf;
}

int strhex2bin(const char *hex,char *buf)
{
    int len = strlen(hex);
    int pos = 0;
    for (int i=0;i<len;i+=2)
    {
		buf[pos++] = hex2bin(hex[i], hex[i + 1]);
    }
    return pos;
}

void testbin()
{
    
    char binbuf[128] = {0};
    char hexbuf[256] = {0};
    char *hexpriv = "EDE9E0C0EAA4BF0B9B0B9BF2643E1DD3C57FE16ABF2F33A92F07A2849E6812E3";
    //priv key;
    // char *priv = GeneratePrivateKey_bin();
    // hexpriv = bindata2hex(priv,Size_PriKey,hexbuf);
    //pubkey;
    int len = strhex2bin(hexpriv, binbuf);
	//printf("priv(%d)=%s\n",strlen(hexpriv), hexpriv);
    char *pubbin = GetPublicKeyByPriv_bin(binbuf,len);
    //printf("pub (%d)=%s\n",strlen(hexbuf),bindata2hex(pub,Size_PubKey,hexbuf));
    char *sigbin = Sign_bin(binbuf,len,buf,strlen(buf));
    char *sighex = bindata2hex(sigbin,Size_Signure,hexbuf);
    printf("sig (%zd)=%s\n",strlen(sighex),sighex);
    if (!Verify_bin(pubbin,sigbin,buf,strlen(buf)))
    {
        printf("Verify_bin failed\n");
    }
	else
	{
		printf("Verify_bin OK\n");
	}

	//------------------OLD* OLD * old * OLD* OLD-------------------
    //priv key;
	// hexpriv = bindata2hex(priv, Size_PriKey, hexbuf);
    //pub key;
	char *pubhex = GetPublicKeyByPriv_hex(hexpriv);
	//printf("pub2(%d)=%s\n",strlen(pub), pub);
    if (!Verify_hex(pubhex, sighex, buf, strlen(buf)))
    {
        printf("Verify failed\n");
    }
	else
	{
		printf("Verify OK\n");
	}
}

int main()
{
    //testbin();
	//testVerify1();
	testAll();
	char c;
	scanf("%c", &c);
	return 0;
}


#endif//WIN32