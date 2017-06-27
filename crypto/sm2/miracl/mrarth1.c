
/***************************************************************************
                                                                           *
Copyright 2013 CertiVox IOM Ltd.                                           *
                                                                           *
This file is part of CertiVox MIRACL Crypto SDK.                           *
                                                                           *
The CertiVox MIRACL Crypto SDK provides developers with an                 *
extensive and efficient set of cryptographic functions.                    *
For further information about its features and functionalities please      *
refer to http://www.certivox.com                                           *
                                                                           *
* The CertiVox MIRACL Crypto SDK is free software: you can                 *
  redistribute it and/or modify it under the terms of the                  *
  GNU Affero General Public License as published by the                    *
  Free Software Foundation, either version 3 of the License,               *
  or (at your option) any later version.                                   *
                                                                           *
* The CertiVox MIRACL Crypto SDK is distributed in the hope                *
  that it will be useful, but WITHOUT ANY WARRANTY; without even the       *
  implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. *
  See the GNU Affero General Public License for more details.              *
                                                                           *
* You should have received a copy of the GNU Affero General Public         *
  License along with CertiVox MIRACL Crypto SDK.                           *
  If not, see <http://www.gnu.org/licenses/>.                              *
                                                                           *
You can be released from the requirements of the license by purchasing     *
a commercial license. Buying such a license is mandatory as soon as you    *
develop commercial activities involving the CertiVox MIRACL Crypto SDK     *
without disclosing the source code of your own applications, or shipping   *
the CertiVox MIRACL Crypto SDK with a closed source product.               *
                                                                           *
***************************************************************************/

/*
 *
 *   MIRACL arithmetic routines 1 - multiplying and dividing BIG NUMBERS by  
 *   integer numbers.
 *   mrarth1.c
 *
 */

#include "miracl.h"

#ifdef MR_FP
#include <math.h>
#endif

#ifdef MR_WIN64
#include <intrin.h>
#endif

#ifdef MR_FP_ROUNDING
#ifdef __GNUC__
#include <ieeefp.h>
#endif

/* Invert n and set FP rounding. 
 * Set to round up
 * Calculate 1/n
 * set to round down (towards zero)
 * If rounding cannot be controlled, this function returns 0.0 */

mr_large mr_invert(mr_small n)
{
    mr_large inn;
    int up=  0x1BFF; 

#ifdef _MSC_VER
  #ifdef MR_NOASM
#define NO_EXTENDED
  #endif 
#endif

#ifdef NO_EXTENDED
    int down=0x1EFF;
#else
    int down=0x1FFF;
#endif

#ifdef __TURBOC__
    asm
    {
        fldcw WORD PTR up
        fld1
        fld QWORD PTR n;
        fdiv
        fstp TBYTE PTR inn;
        fldcw WORD PTR down;
    }
    return inn;   
#endif
#ifdef _MSC_VER
    _asm
    {
        fldcw WORD PTR up
        fld1
        fld QWORD PTR n;
        fdiv
        fstp QWORD  PTR inn;
        fldcw WORD PTR down;
    }
    return inn;   
#endif
#ifdef __GNUC__
#ifdef i386
    __asm__ __volatile__ (
    "fldcw %2\n"
    "fld1\n"
    "fldl %1\n"
    "fdivrp\n"
    "fstpt %0\n"
    "fldcw %3\n"
    : "=m"(inn)
    : "m"(n),"m"(up),"m"(down)
    : "memory"
    );
    return inn;   
#else
    fpsetround(FP_RP);
    inn=(mr_large)1.0/n;
    fpsetround(FP_RZ);
    return inn;
#endif
#endif
    return 0.0L;   
}

#endif

void mr_pmul(_MIPD_ big x,mr_small sn,big z)
{ 
    int m,xl;
    mr_lentype sx;
    mr_small carry,*xg,*zg;

#ifdef MR_ITANIUM
    mr_small tm;
#endif
#ifdef MR_WIN64
    mr_small tm;
#endif
#ifdef MR_NOASM
    union doubleword dble;
    mr_large dbled;
    mr_large ldres;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    if (x!=z)
    {
        zero(z);
        if (sn==0) return;
    }
    else if (sn==0)
    {
        zero(z);
        return;
    }
    m=0;
    carry=0;
    sx=x->len&MR_MSBIT;
    xl=(int)(x->len&MR_OBITS);

#ifndef MR_SIMPLE_BASE
    if (mr_mip->base==0) 
    {
#endif
#ifndef MR_NOFULLWIDTH
        xg=x->w; zg=z->w;
/* inline 8086 assembly - substitutes for loop below */
#ifdef INLINE_ASM
#if INLINE_ASM == 1
        ASM cld
        ASM mov cx,xl
        ASM or cx,cx
        ASM je out1
#ifdef MR_LMM
        ASM push ds
        ASM push es
        ASM les di,DWORD PTR zg
        ASM lds si,DWORD PTR xg
#else
        ASM mov ax,ds
        ASM mov es,ax
        ASM mov di,zg
        ASM mov si,xg
#endif
        ASM mov bx,sn
        ASM push bp
        ASM xor bp,bp
    tcl1:
        ASM lodsw
        ASM mul bx
        ASM add ax,bp
        ASM adc dx,0
        ASM stosw
        ASM mov bp,dx
        ASM loop tcl1

        ASM mov ax,bp
        ASM pop bp
#ifdef MR_LMM
        ASM pop es
        ASM pop ds
#endif
        ASM mov carry,ax
     out1: 
#endif
#if INLINE_ASM == 2
        ASM cld
        ASM mov cx,xl
        ASM or cx,cx
        ASM je out1
#ifdef MR_LMM
        ASM push ds
        ASM push es
        ASM les di,DWORD PTR zg
        ASM lds si,DWORD PTR xg
#else
        ASM mov ax,ds
        ASM mov es,ax
        ASM mov di,zg
        ASM mov si,xg
#endif
        ASM mov ebx,sn
        ASM push ebp
        ASM xor ebp,ebp
    tcl1:
        ASM lodsd
        ASM mul ebx
        ASM add eax,ebp
        ASM adc edx,0
        ASM stosd
        ASM mov ebp,edx
        ASM loop tcl1

        ASM mov eax,ebp
        ASM pop ebp
#ifdef MR_LMM
        ASM pop es
        ASM pop ds
#endif
        ASM mov carry,eax
     out1: 
#endif
#if INLINE_ASM == 3
        ASM mov ecx,xl
        ASM or ecx,ecx
        ASM je out1
        ASM mov ebx,sn
        ASM mov edi,zg
        ASM mov esi,xg
        ASM push ebp
        ASM xor ebp,ebp
    tcl1:
        ASM mov eax,[esi]
        ASM add esi,4
        ASM mul ebx
        ASM add eax,ebp
        ASM adc edx,0
        ASM mov [edi],eax
        ASM add edi,4
        ASM mov ebp,edx
        ASM dec ecx
        ASM jnz tcl1

        ASM mov eax,ebp
        ASM pop ebp
        ASM mov carry,eax
     out1: 
#endif
#if INLINE_ASM == 4

        ASM (
           "movl %4,%%ecx\n"
           "orl  %%ecx,%%ecx\n"
           "je 1f\n"
           "movl %3,%%ebx\n"
           "movl %1,%%edi\n"
           "movl %2,%%esi\n"
           "pushl %%ebp\n"
           "xorl %%ebp,%%ebp\n"  
        "0:\n"  
           "movl (%%esi),%%eax\n"
           "addl $4,%%esi\n"
           "mull %%ebx\n"
           "addl %%ebp,%%eax\n"
           "adcl $0,%%edx\n"
           "movl %%eax,(%%edi)\n"
           "addl $4,%%edi\n"
           "movl %%edx,%%ebp\n"
           "decl %%ecx\n"
           "jnz 0b\n"
 
           "movl %%ebp,%%eax\n"
           "popl %%ebp\n"
           "movl %%eax,%0\n"
        "1:"  
        :"=m"(carry)
        :"m"(zg),"m"(xg),"m"(sn),"m"(xl)
        :"eax","edi","esi","ebx","ecx","edx","memory"
        );

#endif
#endif
#ifndef INLINE_ASM
        for (m=0;m<xl;m++)
#ifdef MR_NOASM
        {
            dble.d=(mr_large)x->w[m]*sn+carry;
            carry=dble.h[MR_TOP];
            z->w[m]=dble.h[MR_BOT];
        }
#else
            carry=muldvd(x->w[m],sn,carry,&z->w[m]);
#endif
#endif
        if (carry>0)
        {
            m=xl;
            if (m>=mr_mip->nib && mr_mip->check)
            {
                mr_berror(_MIPP_ MR_ERR_OVERFLOW);
                return;
            }
            z->w[m]=carry;
            z->len=m+1;
        }
        else z->len=xl;
#endif
#ifndef MR_SIMPLE_BASE
    }
    else while (m<xl || carry>0)
    { /* multiply each digit of x by n */ 
    
        if (m>mr_mip->nib && mr_mip->check)
        {
            mr_berror(_MIPP_ MR_ERR_OVERFLOW);
            return;
        }
#ifdef MR_NOASM
        dbled=(mr_large)x->w[m]*sn+carry;
 #ifdef MR_FP_ROUNDING
        carry=(mr_small)MR_LROUND(dbled*mr_mip->inverse_base);
 #else
  #ifndef MR_FP
        if (mr_mip->base==mr_mip->base2)
          carry=(mr_small)(dbled>>mr_mip->lg2b);
        else 
  #endif  
          carry=(mr_small)MR_LROUND(dbled/mr_mip->base);
 #endif
        z->w[m]=(mr_small)(dbled-(mr_large)carry*mr_mip->base);
#else
 #ifdef MR_FP_ROUNDING
        carry=imuldiv(x->w[m],sn,carry,mr_mip->base,mr_mip->inverse_base,&z->w[m]);
 #else
        carry=muldiv(x->w[m],sn,carry,mr_mip->base,&z->w[m]);
 #endif
#endif

        m++;
        z->len=m;
    }
#endif
    if (z->len!=0) z->len|=sx;
}

void premult(_MIPD_ big x,int n,big z)
{ /* premultiply a big number by an int z=x.n */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(9)


#ifdef MR_FLASH
    if (mr_notint(x))
    {
        mr_berror(_MIPP_ MR_ERR_INT_OP);
        MR_OUT
        return;
    }
#endif
    if (n==0)  /* test for some special cases  */
    {
        zero(z);
        MR_OUT
        return;
    }
    if (n==1)
    {
        copy(x,z);
        MR_OUT
        return;
    }
    if (n<0)
    {
        n=(-n);
        mr_pmul(_MIPP_ x,(mr_small)n,z);
        if (z->len!=0) z->len^=MR_MSBIT;
    }
    else mr_pmul(_MIPP_ x,(mr_small)n,z);
    MR_OUT
}

#ifdef MR_FP_ROUNDING
mr_small mr_sdiv(_MIPD_ big x,mr_small sn,mr_large isn,big z)
#else
mr_small mr_sdiv(_MIPD_ big x,mr_small sn,big z)
#endif
{
    int i,xl;
    mr_small sr,*xg,*zg;
#ifdef MR_NOASM
    union doubleword dble;
    mr_large dbled;
    mr_large ldres;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    sr=0;
    xl=(int)(x->len&MR_OBITS);
    if (x!=z) zero(z);
#ifndef MR_SIMPLE_BASE
    if (mr_mip->base==0) 
    {
#endif
#ifndef MR_NOFULLWIDTH
        xg=x->w; zg=z->w;
/* inline - substitutes for loop below */
#ifdef INLINE_ASM
#if INLINE_ASM == 1
        ASM std
        ASM mov cx,xl
        ASM or cx,cx
        ASM je out2
        ASM mov bx,cx
        ASM shl bx,1
        ASM sub bx,2
#ifdef MR_LMM
        ASM push ds
        ASM push es
        ASM les di,DWORD PTR zg
        ASM lds si,DWORD PTR xg
#else
        ASM mov ax,ds
        ASM mov es,ax
        ASM mov di,zg
        ASM mov si,xg
#endif
        ASM add si,bx
        ASM add di,bx
        ASM mov bx,sn
        ASM push bp
        ASM xor bp,bp
    tcl2:
        ASM mov dx,bp
        ASM lodsw
        ASM div bx
        ASM mov bp,dx
        ASM stosw
        ASM loop tcl2

        ASM mov ax,bp
        ASM pop bp
#ifdef MR_LMM
        ASM pop es
        ASM pop ds
#endif
        ASM mov sr,ax
     out2:
        ASM cld
#endif
#if INLINE_ASM == 2
        ASM std
        ASM mov cx,xl
        ASM or cx,cx
        ASM je out2
        ASM mov bx,cx
        ASM shl bx,2
        ASM sub bx,4
#ifdef MR_LMM
        ASM push ds
        ASM push es
        ASM les di,DWORD PTR zg
        ASM lds si,DWORD PTR xg
#else
        ASM mov ax,ds
        ASM mov es,ax
        ASM mov di, zg
        ASM mov si, xg
#endif
        ASM add si,bx
        ASM add di,bx
        ASM mov ebx,sn
        ASM push ebp
        ASM xor ebp,ebp
    tcl2:
        ASM mov edx,ebp
        ASM lodsd
        ASM div ebx
        ASM mov ebp,edx
        ASM stosd
        ASM loop tcl2

        ASM mov eax,ebp
        ASM pop ebp
#ifdef MR_LMM
        ASM pop es
        ASM pop ds
#endif
        ASM mov sr,eax
     out2: 
        ASM cld
#endif
#if INLINE_ASM == 3
        ASM mov ecx,xl
        ASM or ecx,ecx
        ASM je out2
        ASM mov ebx,ecx
        ASM shl ebx,2
        ASM mov esi, xg
        ASM add esi,ebx
        ASM mov edi, zg
        ASM add edi,ebx
        ASM mov ebx,sn
        ASM push ebp
        ASM xor ebp,ebp
    tcl2:
        ASM sub esi,4
        ASM mov edx,ebp
        ASM mov eax,[esi]
        ASM div ebx
        ASM sub edi,4
        ASM mov ebp,edx
        ASM mov [edi],eax
        ASM dec ecx
        ASM jnz tcl2

        ASM mov eax,ebp
        ASM pop ebp
        ASM mov sr,eax
     out2:
        ASM nop
#endif
#if INLINE_ASM == 4

        ASM (
           "movl %4,%%ecx\n"
           "orl  %%ecx,%%ecx\n"
           "je 3f\n"
           "movl %%ecx,%%ebx\n"
           "shll $2,%%ebx\n"
           "movl %2,%%esi\n"
           "addl %%ebx,%%esi\n"
           "movl %1,%%edi\n"
           "addl %%ebx,%%edi\n"
           "movl %3,%%ebx\n"
           "pushl %%ebp\n"
           "xorl %%ebp,%%ebp\n"  
         "2:\n"  
           "subl $4,%%esi\n"
           "movl %%ebp,%%edx\n"
           "movl (%%esi),%%eax\n"
           "divl %%ebx\n"
           "subl $4,%%edi\n"
           "movl %%edx,%%ebp\n"
           "movl %%eax,(%%edi)\n"
           "decl %%ecx\n"
           "jnz 2b\n"
 
           "movl %%ebp,%%eax\n"
           "popl %%ebp\n"
           "movl %%eax,%0\n"
        "3:"
           "nop"  
        :"=m"(sr)
        :"m"(zg),"m"(xg),"m"(sn),"m"(xl)
        :"eax","edi","esi","ebx","ecx","edx","memory"
        );
#endif
#endif
#ifndef INLINE_ASM
        for (i=xl-1;i>=0;i--)
        {
#ifdef MR_NOASM
            dble.h[MR_BOT]=x->w[i];
            dble.h[MR_TOP]=sr;
            z->w[i]=(mr_small)(dble.d/sn);
            sr=(mr_small)(dble.d-(mr_large)z->w[i]*sn);
#else
            z->w[i]=muldvm(sr,x->w[i],sn,&sr);
#endif
        }
#endif
#endif
#ifndef MR_SIMPLE_BASE
    }
    else for (i=xl-1;i>=0;i--)
    { /* divide each digit of x by n */
#ifdef MR_NOASM
        dbled=(mr_large)sr*mr_mip->base+x->w[i];
#ifdef MR_FP_ROUNDING
        z->w[i]=(mr_small)MR_LROUND(dbled*isn);
#else
        z->w[i]=(mr_small)MR_LROUND(dbled/sn);
#endif
        sr=(mr_small)(dbled-(mr_large)z->w[i]*sn);
#else
#ifdef MR_FP_ROUNDING
        z->w[i]=imuldiv(sr,mr_mip->base,x->w[i],sn,isn,&sr);
#else
        z->w[i]=muldiv(sr,mr_mip->base,x->w[i],sn,&sr);
#endif
#endif
    }
#endif
    z->len=x->len;
    mr_lzero(z);
    return sr;
}
         
int subdiv(_MIPD_ big x,int n,big z)
{  /*  subdivide a big number by an int   z=x/n  *
    *  returns int remainder                     */ 
    mr_lentype sx;
#ifdef MR_FP_ROUNDING
    mr_large in;
#endif
    int r,i,msb;
    mr_small lsb;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return 0;

    MR_IN(10)
#ifdef MR_FLASH
    if (mr_notint(x)) mr_berror(_MIPP_ MR_ERR_INT_OP);
#endif
    if (n==0) mr_berror(_MIPP_ MR_ERR_DIV_BY_ZERO);
    if (mr_mip->ERNUM) 
    {
        MR_OUT
        return 0;
    }

    if (x->len==0)
    {
        zero(z);
        MR_OUT
        return 0;
    }
    if (n==1) /* special case */
    {
        copy(x,z);
        MR_OUT
        return 0;
    }
    sx=(x->len&MR_MSBIT);
    if (n==2 && mr_mip->base==0)
    { /* fast division by 2 using shifting */
#ifndef MR_NOFULLWIDTH

/* I don't want this code upsetting the compiler ... */
/* mr_mip->base==0 can't happen with MR_NOFULLWIDTH  */

        copy(x,z);
        msb=(int)(z->len&MR_OBITS)-1;
        r=(int)z->w[0]&1;
        for (i=0;;i++)
        {
            z->w[i]>>=1;
            if (i==msb) 
            {
                if (z->w[i]==0) mr_lzero(z);
                break;
            }
            lsb=z->w[i+1]&1;
            z->w[i]|=(lsb<<(MIRACL-1));
        }

        MR_OUT
        if (sx==0) return r;
        else       return (-r);
#endif
    }

#ifdef MR_FP_ROUNDING
    in=mr_invert(n);
#endif
    if (n<0)
    {
        n=(-n);
#ifdef MR_FP_ROUNDING
        r=(int)mr_sdiv(_MIPP_ x,(mr_small)n,in,z);
#else
        r=(int)mr_sdiv(_MIPP_ x,(mr_small)n,z);
#endif
        if (z->len!=0) z->len^=MR_MSBIT;
    }
#ifdef MR_FP_ROUNDING
    else r=(int)mr_sdiv(_MIPP_ x,(mr_small)n,in,z);
#else
    else r=(int)mr_sdiv(_MIPP_ x,(mr_small)n,z);
#endif
    MR_OUT
    if (sx==0) return r;
    else       return (-r);
}

int remain(_MIPD_ big x,int n)
{ /* return integer remainder when x divided by n */
    int r;
    mr_lentype sx;
#ifdef MR_FP
    mr_small dres;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return FALSE;

    MR_IN(88);

    sx=(x->len&MR_MSBIT);

    if (n==2 && MR_REMAIN(mr_mip->base,2)==0)
    { /* fast odd/even check if base is even */
        MR_OUT
        if ((int)MR_REMAIN(x->w[0],2)==0) return 0;
        else
        {
            if (sx==0) return 1;
            else       return (-1);
        } 
    }
    if (n==8 && MR_REMAIN(mr_mip->base,8)==0)
    { /* fast check */
        MR_OUT
        r=(int)MR_REMAIN(x->w[0],8);
        if (sx!=0) r=-r;
        return r;
    }
    
    copy(x,mr_mip->w0);
    r=subdiv(_MIPP_ mr_mip->w0,n,mr_mip->w0);
    MR_OUT
    return r;
}

BOOL subdivisible(_MIPD_ big x,int n)
{
    if (remain(_MIPP_ x,n)==0) return TRUE;
    else                return FALSE;
}

int hamming(_MIPD_ big x)
{
    int h;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return 0;
    MR_IN(148);
    h=0;
    copy(x,mr_mip->w1);
    absol(mr_mip->w1,mr_mip->w1);
    while (size(mr_mip->w1)!=0)
        h+=subdiv(_MIPP_ mr_mip->w1,2,mr_mip->w1);
    
    MR_OUT
    return h;
}

void bytes_to_big(_MIPD_ int len,const char *ptr,big x)
{ /* convert len bytes into a big           *
   * The first byte is the Most significant */
    int i,j,m,n,r;
    unsigned int dig;
    unsigned char ch;
    mr_small wrd;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(140);

    zero(x);

    if (len<=0)
    {
        MR_OUT
        return;
    }
/* remove leading zeros.. */

    while (*ptr==0) 
    {
        ptr++; len--;
        if (len==0) 
        {
            MR_OUT
            return;
        } 
    }

#ifndef MR_SIMPLE_BASE
    if (mr_mip->base==0)
    { /* pack bytes directly into big */
#endif
#ifndef MR_NOFULLWIDTH
        m=MIRACL/8;  
        n=len/m;

        r=len%m;
		wrd=(mr_small)0;  
        if (r!=0)
        {
            n++; 
            for (j=0;j<r;j++) {wrd<<=8; wrd|=MR_TOBYTE(*ptr++); }
        }
        x->len=n;
        if (n>mr_mip->nib && mr_mip->check)
        {
            mr_berror(_MIPP_ MR_ERR_OVERFLOW);
            MR_OUT
            return;
        }
        if (r!=0) 
        {
            n--;
            x->w[n]=wrd;
        }

        for (i=n-1;i>=0;i--)
        {
            for (j=0;j<m;j++) { wrd<<=8; wrd|=MR_TOBYTE(*ptr++); }
            x->w[i]=wrd;
        }
        mr_lzero(x);     /* needed */
#endif
#ifndef MR_SIMPLE_BASE
    }
    else
    {
        for (i=0;i<len;i++)
        {
            if (mr_mip->ERNUM) break;
#if MIRACL==8
            mr_shift(_MIPP_ x,1,x);
#else
            premult(_MIPP_ x,256,x);
#endif
            ch=MR_TOBYTE(ptr[i]);
            dig=ch;  
            incr(_MIPP_ x,(int)dig,x);
        }
    }
#endif
    MR_OUT
} 

int big_to_bytes(_MIPD_ int max,big x,char *ptr,BOOL justify)
{ /* convert positive big into octet string */
    int i,j,r,m,n,len,start;
    unsigned int dig;
    unsigned char ch;
    mr_small wrd;

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM || max<0) return 0;

	if (max==0 && justify) return 0; 
	if (size(x)==0)
	{
		if (justify)
		{
			for (i=0;i<max;i++) ptr[i]=0;
			return max;
		}
		return 0;
	}
     
    MR_IN(141);

    mr_lzero(x);        /* should not be needed.... */
#ifndef MR_SIMPLE_BASE
    if (mr_mip->base==0)
    {
#endif
#ifndef MR_NOFULLWIDTH
        m=MIRACL/8;
        n=(int)(x->len&MR_OBITS);
        n--;
        len=n*m;
        wrd=x->w[n]; /* most significant */
        r=0;
        while (wrd!=(mr_small)0) { r++; wrd>>=8; len++;}
        r%=m;

        if (max>0 && len>max)
        {
            mr_berror(_MIPP_ MR_ERR_TOO_BIG);
            MR_OUT
            return 0; 
        }

        if (justify)
        {
            start=max-len;
            for (i=0;i<start;i++) ptr[i]=0; 
        }
        else start=0;
        
        if (r!=0)
        {
            wrd=x->w[n--];
            for (i=r-1;i>=0;i--)
            {
                ptr[start+i]=(char)(wrd&0xFF);
                wrd>>=8;
            }  
        }

        for (i=r;i<len;i+=m)
        {
            wrd=x->w[n--];
            for (j=m-1;j>=0;j--)
            {
                ptr[start+i+j]=(char)(wrd&0xFF);
                wrd>>=8;
            }
        }
#endif
#ifndef MR_SIMPLE_BASE
    }
    else
    {
        copy(x,mr_mip->w1);
        for (len=0;;len++)
        {
            if (mr_mip->ERNUM) break;

            if (size(mr_mip->w1)==0)
            {
                if (justify)
                {
                   if (len==max) break;
                }
                else break;
            }

            if (max>0 && len>=max)
            {
                mr_berror(_MIPP_ MR_ERR_TOO_BIG);
                MR_OUT
                return 0; 
            }
#if MIRACL==8
            ch=mr_mip->w1->w[0];
            mr_shift(_MIPP_ mr_mip->w1,-1,mr_mip->w1);
#else
            dig=(unsigned int)subdiv(_MIPP_ mr_mip->w1,256,mr_mip->w1);
            ch=MR_TOBYTE(dig);
#endif
            for (i=len;i>0;i--) ptr[i]=ptr[i-1];
            ptr[0]=MR_TOBYTE(ch);
        }
    }
#endif
    MR_OUT
    if (justify) return max;
    else         return len;
}

#ifndef MR_NO_ECC_MULTIADD

/* Solinas's Joint Sparse Form */

void mr_jsf(_MIPD_ big k0,big k1,big u0p,big u0m,big u1p,big u1m)
{
    int j,u0,u1,d0,d1,l0,l1;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;   

    MR_IN(191)

    d0=d1=0;

    convert(_MIPP_ 1,mr_mip->w1);
    copy(k0,mr_mip->w2);
    copy(k1,mr_mip->w3);
    zero(u0p); zero(u0m); zero(u1p); zero(u1m);

    j=0;
    while (!mr_mip->ERNUM)
    {
        if (size(mr_mip->w2)==0 && d0==0 && size(mr_mip->w3)==0 && d1==0) break;
        l0=remain(_MIPP_ mr_mip->w2,8);
        l0=(l0+d0)&0x7;
        l1=remain(_MIPP_ mr_mip->w3,8);
        l1=(l1+d1)&0x7;

        if (l0%2==0) u0=0;
        else
        {
            u0=2-(l0%4);
            if ((l0==3 || l0==5) && l1%4==2) u0=-u0;
        }
        if (l1%2==0) u1=0;
        else
        {
            u1=2-(l1%4);
            if ((l1==3 || l1==5) && l0%4==2) u1=-u1;
        }
#ifndef MR_ALWAYS_BINARY
        if (mr_mip->base==mr_mip->base2)
        {
#endif
            if (u0>0) mr_addbit(_MIPP_ u0p,j);
            if (u0<0) mr_addbit(_MIPP_ u0m,j);
            if (u1>0) mr_addbit(_MIPP_ u1p,j);
            if (u1<0) mr_addbit(_MIPP_ u1m,j);

#ifndef MR_ALWAYS_BINARY
        }
        else
        {
            if (u0>0) add(_MIPP_ u0p,mr_mip->w1,u0p);
            if (u0<0) add(_MIPP_ u0m,mr_mip->w1,u0m);
            if (u1>0) add(_MIPP_ u1p,mr_mip->w1,u1p);
            if (u1<0) add(_MIPP_ u1m,mr_mip->w1,u1m);
        }
#endif
      
        if (d0+d0==1+u0) d0=1-d0;
        if (d1+d1==1+u1) d1=1-d1;

        subdiv(_MIPP_ mr_mip->w2,2,mr_mip->w2);
        subdiv(_MIPP_ mr_mip->w3,2,mr_mip->w3);

#ifndef MR_ALWAYS_BINARY
        if (mr_mip->base==mr_mip->base2)
#endif
            j++;
#ifndef MR_ALWAYS_BINARY
        else
            premult(_MIPP_ mr_mip->w1,2,mr_mip->w1);
#endif        
    }
    MR_OUT
    return;
}

#endif
