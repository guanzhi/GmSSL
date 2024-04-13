/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_ASM_H
#define GMSSL_ASM_H

#ifdef ENABLE_ASM_UNDERSCORE_PREFIX
# define func(foo) _##foo
#else
# define func(foo) foo
#endif

#endif
