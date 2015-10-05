#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sms4.h"

void sms4_cbc_encrypt(const unsigned char *in, unsigned char *out,
		     size_t len, const sms4_key_t *key,
		     unsigned char *ivec, int encrypt)
{
        if(encrypt)
                CRYPTO_cbc128_encrypt(in,out,len,key,ivec,(block128_f)sms4_encrypt);
        else
                CRYPTO_cbc128_decrypt(in,out,len,key,ivec,(block128_f)sms4_encrypt);
}


