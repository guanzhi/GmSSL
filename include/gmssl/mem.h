/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_MEM_H
#define GMSSL_MEM_H

#include <stdint.h>
#include <stddef.h> // where size_t from


void memxor(void *r, const void *a, size_t len);
void gmssl_memxor(void *r, const void *a, const void *b, size_t len);

int gmssl_secure_memcmp(const volatile void * volatile in_a, const volatile void * volatile in_b, size_t len);
void gmssl_secure_clear(void *ptr, size_t len);

int mem_is_zero(const uint8_t *buf, size_t len); // FIXME: uint8_t * to void *

#endif

