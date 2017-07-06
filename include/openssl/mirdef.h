/*
 *   MIRACL compiler/hardware definitions - mirdef.h
 *   For C++ build of library
 */

#ifndef HEADER_MIRDEF_H
#define HEADER_MIRDEF_H

#ifdef __cplusplus
extern "C"{
#endif

#define MR_LITTLE_ENDIAN
#define MIRACL 64
#define mr_utype long
#define mr_dltype long long
#define mr_unsign64 unsigned long
#define MR_IBITS 32
#define MR_LBITS 64
#define mr_unsign32 unsigned int
#define MR_FLASH 52
#define MAXBASE ((mr_small)1<<(MIRACL-1))
#define MR_BITSINCHAR 8
#define MR_CPP

#ifdef __cplusplus
}
#endif

#endif
