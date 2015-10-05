#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sms4.h"
#include <assert.h>

void sms4_ecb_encrypt(const unsigned char *in, unsigned char *out, const sms4_key_t *key, int encrypt) {
        assert(in && out && key);
        if(encrypt)
                sms4_encrypt(in, out, key);
        else
                sms4_decrypt(in, out, key);
}

//sms4_decrypt = sms4_encrypt, but the key is in reverse order
