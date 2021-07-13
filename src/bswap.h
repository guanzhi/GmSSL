/*
 * Copyright 2010-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#ifndef GMSSL_MODES_LCL_H
#define GMSSL_MODES_LCL_H


# if defined(__GNUC__) && __GNUC__>=2
#  if defined(__x86_64) || defined(__x86_64__)
#   define BSWAP8(x) ({ uint64_t ret_=(x);                   \
                        asm ("bswapq %0"                \
                        : "+r"(ret_));   ret_;          })
#   define BSWAP4(x) ({ uint32_t ret_=(x);                   \
                        asm ("bswapl %0"                \
                        : "+r"(ret_));   ret_;          })
#  elif defined(__aarch64__)
#   define BSWAP8(x) ({ uint64_t ret_;                       \
                        asm ("rev %0,%1"                \
                        : "=r"(ret_) : "r"(x)); ret_;   })
#   define BSWAP4(x) ({ uint32_t ret_;                       \
                        asm ("rev %w0,%w1"              \
                        : "=r"(ret_) : "r"(x)); ret_;   })
#  endif
# elif defined(_MSC_VER)
#  if _MSC_VER>=1300
#   pragma intrinsic(_byteswap_uint64,_byteswap_ulong)
#   define BSWAP8(x)    _byteswap_uint64((uint64_t)(x))
#   define BSWAP4(x)    _byteswap_ulong((uint32_t)(x))
# endif
#endif

#if defined(BSWAP4) && !defined(STRICT_ALIGNMENT)
#	define GETU32(p)       BSWAP4(*(const uint32_t *)(p))
#	define PUTU32(p,v)     *(uint32_t *)(p) = BSWAP4(v)
#	define GETU64(p)       BSWAP8(*(const uint64_t *)(p))
#	define PUTU64(p,v)     *(uint64_t *)(p) = BSWAP8(v)
#else
#	define GETU32(p)       ((uint32_t)(p)[0]<<24|(uint32_t)(p)[1]<<16|(uint32_t)(p)[2]<<8|(uint32_t)(p)[3])
#	define PUTU32(p,v)     ((p)[0]=(u8)((v)>>24),(p)[1]=(u8)((v)>>16),(p)[2]=(u8)((v)>>8),(p)[3]=(u8)(v))
#	define GETU64(p)       ((uint64_t)(p)[0]<<56|(uint64_t)(p)[1]<<48|(uint64_t)(p)[2]<<40|(uint64_t)(p)[3]<<32| \
				(uint64_t)(p)[4]<<24|(uint64_t)(p)[5]<<16|(uint64_t)(p)[6]<<8|(uint64_t)(p)[7])
#	define PUTU64(p,v)     ((p)[0]=(u8)((v)>>56),(p)[1]=(u8)((v)>>48),(p)[2]=(u8)((v)>>40),(p)[3]=(u8)((v)>>32),\
				(p)[4]=(u8)((v)>>24),(p)[5]=(u8)((v)>>16),(p)[6]=(u8)((v)>>8),(p)[7]=(u8)(v)
#endif

#define GETU32_LE(p)	(*(const uint32_t *)(p))
#define PUTU32_LE(p,a)	*(uint32_t *)(p) = (a)
#define PUTU64_LE(p,a) 	*(uint64_t *)(p) = (a)

#endif

