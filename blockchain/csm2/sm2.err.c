#include <openssl/err.h>
#include "sm2.h"

unsigned long SM2Error(unsigned char *errbuf, int max)
{
    unsigned long eno = ERR_get_error();
    if (eno == 0)
    {
        return 0;
    }
    ERR_error_string_n(eno,(char *)errbuf,max);
    return eno;
}

//--------------------------------------自定义内存分配---------------------------------

// static void *local_malloc(size_t sz, const char *, int)
// {
//     return NULL;
// }

// static void local_free(void *ptr, const char *, int)
// {
// }

// static void *local_realloc(void *old, size_t sz, const char *, int)
// {
// }

// void SSLInit()
// {
//     CRYPTO_set_mem_functions(local_malloc,local_realloc,local_free);
// }