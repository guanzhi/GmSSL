/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#ifndef GMSSL_MEM_H
#define GMSSL_MEM_H

#include <stddef.h> // where size_t from


void memxor(void *r, const void *a, size_t len);
void gmssl_memxor(void *r, const void *a, const void *b, size_t len);
int gmssl_memcmp(const void *s1, const void *s2, size_t n);


#endif
