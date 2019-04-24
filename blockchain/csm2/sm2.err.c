#include <openssl/err.h>

#include "sm2.h"

unsigned long SM2Error(unsigned char *errbuf, int max)
{
    unsigned long eno = ERR_get_error();
    if (eno == 0)
    {
        return 0;
    }
    ERR_error_string_n(eno,errbuf,max);
    return eno;
}