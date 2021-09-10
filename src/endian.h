/*
 * Copyright (c) 2014 - 2020 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef GMSSL_ENDIAN_H
#define GMSSL_ENDIAN_H


/* Big Endian R/W */

#define GETU16(p) \
	((uint16_t)(p)[0] <<  8 | \
	 (uint16_t)(p)[1])

#define GETU32(p) \
	((uint32_t)(p)[0] << 24 | \
	 (uint32_t)(p)[1] << 16 | \
	 (uint32_t)(p)[2] <<  8 | \
	 (uint32_t)(p)[3])

#define GETU64(p) \
	((uint64_t)(p)[0] << 56 | \
	 (uint64_t)(p)[1] << 48 | \
	 (uint64_t)(p)[2] << 40 | \
	 (uint64_t)(p)[3] << 32 | \
	 (uint64_t)(p)[4] << 24 | \
	 (uint64_t)(p)[5] << 16 | \
	 (uint64_t)(p)[6] <<  8 | \
	 (uint64_t)(p)[7])


// 注意：PUTU32(buf, val++) 会出错！
#define PUTU16(p,V) \
	((p)[0] = (uint8_t)((V) >> 8), \
	 (p)[1] = (uint8_t)(V))

#define PUTU32(p,V) \
	((p)[0] = (uint8_t)((V) >> 24), \
	 (p)[1] = (uint8_t)((V) >> 16), \
	 (p)[2] = (uint8_t)((V) >>  8), \
	 (p)[3] = (uint8_t)(V))

#define PUTU64(p,V) \
	((p)[0] = (uint8_t)((V) >> 56), \
	 (p)[1] = (uint8_t)((V) >> 48), \
	 (p)[2] = (uint8_t)((V) >> 40), \
	 (p)[3] = (uint8_t)((V) >> 32), \
	 (p)[4] = (uint8_t)((V) >> 24), \
	 (p)[5] = (uint8_t)((V) >> 16), \
	 (p)[6] = (uint8_t)((V) >>  8), \
	 (p)[7] = (uint8_t)(V))

/* Little Endian R/W */

#define GETU16_LE(p)	(*(const uint16_t *)(p))
#define GETU32_LE(p)	(*(const uint32_t *)(p))
#define GETU64_LE(p)	(*(const uint64_t *)(p))

#define PUTU16_LE(p,V)	*(uint16_t *)(p) = (V)
#define PUTU32_LE(p,V)	*(uint32_t *)(p) = (V)
#define PUTU64_LE(p,V)	*(uint64_t *)(p) = (V)

/* Rotate */

#define ROL32(a,n)     (((a)<<(n))|(((a)&0xffffffff)>>(32-(n))))
#define ROL64(a,n)	(((a)<<(n))|((a)>>(64-(n))))

#define ROR32(a,n)	ROL32((a),32-(n))
#define ROR64(a,n)	ROL64(a,64-n)


#endif
