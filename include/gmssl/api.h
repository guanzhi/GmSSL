/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_API_H
#define GMSSL_API_H


#ifdef WIN32
#define _gmssl_export  __declspec(dllexport)
#elif defined(__GNUC__)
// use -fvisibility=hidden to change the "default" behavior
#define _gmssl_export  __attribute__((visibility("default")))
#else
#define _gmssl_export
#endif

#endif
