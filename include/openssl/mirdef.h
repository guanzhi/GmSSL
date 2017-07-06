/*
 *   MIRACL compiler/hardware definitions - mirdef.h
 *
 *   This version is suitable for use with the GCC compiler
 *   in a C/C++ only unix environment.
 *   Remove mrmuldv.c from the build
 *
 *   For MS C on a PC, change BIG_ENDIAN to LITTLE_ENDIAN
 *   and "long long" to "__int64"
 *
 *   Assembly language routines for the mrmuldv module will 
 *   probably speed things up, so in most cases the generic 
 *   mirdef.h32 file is appropriate
 *
 *   NOT recommended for Linux on PCs - read linux.txt
 *
 *   NOTE:- Read comments in miracl.mak unix make file
 */

#ifdef HEADER_MIRDEF_H
#define HEADER_MIRDEF_H

#ifdef __cplusplus
extern "C"{
#endif


#define MIRACL 32
#define MR_BIG_ENDIAN    /* This may need to be changed        */
#define mr_utype int
#define mr_unsign32 unsigned int
#define mr_dltype long long
#define mr_unsign64 unsigned long long
#define MR_IBITS 32
#define MR_LBITS 32
#define MR_NOASM
#define MR_FLASH 52
#define MAXBASE ((mr_small)1<<(MIRACL-1))

#ifdef __cplusplus
}
#endif

#endif
