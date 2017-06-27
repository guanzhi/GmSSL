
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
 *   MIRACL arithmetic routines 2 - multiplying and dividing BIG NUMBERS.
 *   mrarth2.c
 *
 */

#include "miracl.h"

#ifdef MR_FP
#include <math.h>
#endif

#ifdef MR_WIN64
#include <intrin.h>
#endif


/* If a number has more than this number of digits, then squaring is faster */

#define SQR_FASTER_THRESHOLD 5

mr_small normalise(_MIPD_ big x,big y)
{ /* normalise divisor */
    mr_small norm,r;
#ifdef MR_FP
    mr_small dres;
#endif
    int len;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    MR_IN(4)

    if (x!=y) copy(x,y);
    len=(int)(y->len&MR_OBITS);
#ifndef MR_SIMPLE_BASE
    if (mr_mip->base==0)
    {
#endif
#ifndef MR_NOFULLWIDTH
        if ((r=y->w[len-1]+1)==0) norm=1;
#ifdef MR_NOASM
        else norm=(mr_small)(((mr_large)1 << MIRACL)/r);
#else
        else norm=muldvm((mr_small)1,(mr_small)0,r,&r);
#endif
        if (norm!=1) mr_pmul(_MIPP_ y,norm,y);
#endif
#ifndef MR_SIMPLE_BASE
    }
    else
    {
        norm=MR_DIV(mr_mip->base,(mr_small)(y->w[len-1]+1));   
        if (norm!=1) mr_pmul(_MIPP_ y,norm,y);
    }
#endif
    MR_OUT
    return norm;
}

void multiply(_MIPD_ big x,big y,big z)
{  /*  multiply two big numbers: z=x.y  */
    int i,xl,yl,j,ti;
    mr_small carry,*xg,*yg,*w0g;

#ifdef MR_ITANIUM
    mr_small tm;
#endif
#ifdef MR_WIN64
    mr_small tm,tr;
#endif
    mr_lentype sz;
    big w0;
#ifdef MR_NOASM
    union doubleword dble;
    mr_large dbled;
    mr_large ldres;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    if (y->len==0 || x->len==0) 
    {
        zero(z);
        return;
    }
    if (x!=mr_mip->w5 && y!=mr_mip->w5 && z==mr_mip->w5) w0=mr_mip->w5;
    else w0=mr_mip->w0;    /* local pointer */

    MR_IN(5)

#ifdef MR_FLASH
    if (mr_notint(x) || mr_notint(y))
    {
        mr_berror(_MIPP_ MR_ERR_INT_OP);
        MR_OUT
        return;
    }
#endif
    sz=((x->len&MR_MSBIT)^(y->len&MR_MSBIT));
    xl=(int)(x->len&MR_OBITS);
    yl=(int)(y->len&MR_OBITS);
    zero(w0);
    if (mr_mip->check && xl+yl>mr_mip->nib)
    {
        mr_berror(_MIPP_ MR_ERR_OVERFLOW);
        MR_OUT
        return;
    }
#ifndef MR_SIMPLE_BASE
    if (mr_mip->base==0)
    {
#endif
#ifndef MR_NOFULLWIDTH
        xg=x->w; yg=y->w; w0g=w0->w; 
        if (x==y && xl>SQR_FASTER_THRESHOLD)    
                             /* extra hassle make it not    */
                             /* worth it for small numbers */
        { /* fast squaring */
            for (i=0;i<xl-1;i++)
            {  /* long multiplication */
           /* inline - substitutes for loop below */
#ifdef INLINE_ASM
#if INLINE_ASM == 1
                ASM cld
                ASM mov dx,i
                ASM mov cx,xl
                ASM sub cx,dx
                ASM dec cx
                ASM shl dx,1
#ifdef MR_LMM
                ASM push ds
                ASM push es
                ASM les bx,DWORD PTR w0g
                ASM lds si,DWORD PTR xg
                ASM add si,dx
                ASM mov di,[si]
#else
                ASM mov bx,w0g
                ASM mov si,xg
                ASM add si,dx
                ASM mov di,[si]
#endif
                ASM add bx,dx
                ASM add bx,dx 
                ASM add bx,2
                ASM add si,2
                ASM push bp
                ASM xor bp,bp
              tcl4:
                ASM lodsw
                ASM mul di
                ASM add ax,bp
                ASM adc dx,0
#ifdef MR_LMM
                ASM add es:[bx],ax
#else
                ASM add [bx],ax 
#endif
                ASM adc dx,0
                ASM inc bx
                ASM inc bx 
                ASM mov bp,dx
                ASM loop tcl4

#ifdef MR_LMM
                ASM mov es:[bx],bp
                ASM pop bp
                ASM pop es
                ASM pop ds
#else
                ASM mov [bx],bp
                ASM pop bp
#endif
#endif
#if INLINE_ASM == 2
                ASM cld
                ASM mov dx,i
                ASM mov cx,xl
                ASM sub cx,dx
                ASM dec cx
                ASM shl dx,2
#ifdef MR_LMM
                ASM push ds
                ASM push es
                ASM les bx,DWORD PTR w0g
                ASM lds si,DWORD PTR xg
                ASM add si,dx
                ASM mov edi,[si]
#else
                ASM mov bx,w0g
                ASM mov si,xg
                ASM add si,dx
                ASM mov edi,[si]
#endif
                ASM add bx,dx
                ASM add bx,dx
                ASM add bx,4
                ASM add si,4   
                ASM push ebp
                ASM xor ebp,ebp
              tcl4:
                ASM lodsd
                ASM mul edi
                ASM add eax,ebp
                ASM adc edx,0
#ifdef MR_LMM
                ASM add es:[bx],eax
#else
                ASM add [bx],eax
#endif
                ASM adc edx,0
                ASM add bx,4
                ASM mov ebp,edx
                ASM loop tcl4

#ifdef MR_LMM
                ASM mov es:[bx],ebp
                ASM pop ebp
                ASM pop es
                ASM pop ds
#else
                ASM mov [bx],ebp
                ASM pop ebp
#endif
#endif
#if INLINE_ASM == 3
                ASM mov esi,i
                ASM mov ecx,xl
                ASM sub ecx,esi
                ASM dec ecx
                ASM shl esi,2
                ASM mov edx, xg
                ASM mov ebx,edx
                ASM add ebx,esi
                ASM mov edi,[ebx]
                ASM mov ebx,w0g
                ASM add ebx,esi
                ASM add esi,edx
                ASM sub ebx,edx
                ASM add esi,4  
                ASM sub ebx,4
                ASM push ebp
                ASM xor ebp,ebp
              tcl4:
                ASM mov eax,[esi]   /* optimized for Pentium */
                ASM add esi,4
                ASM mul edi
                ASM add eax,ebp
                ASM mov ebp,[esi+ebx]
                ASM adc edx,0
                ASM add ebp,eax
                ASM adc edx,0
                ASM mov [esi+ebx],ebp
                ASM dec ecx
                ASM mov ebp,edx
                ASM jnz tcl4

                ASM mov [esi+ebx+4],ebp
                ASM pop ebp
#endif
#if INLINE_ASM == 4
   ASM (
           "movl %0,%%esi\n"
           "movl %1,%%ecx\n"
           "subl %%esi,%%ecx\n"
           "decl %%ecx\n"
           "shll $2,%%esi\n"
           "movl %2,%%edx\n"
           "movl %%edx,%%ebx\n"
           "addl %%esi,%%ebx\n"
           "movl (%%ebx),%%edi\n"
           "movl %3,%%ebx\n"
           "addl %%esi,%%ebx\n"
           "addl %%edx,%%esi\n"
           "subl %%edx,%%ebx\n"
           "addl $4,%%esi\n"
           "subl $4,%%ebx\n"
           "pushl %%ebp\n"
           "xorl %%ebp,%%ebp\n"
         "tcl4:\n"
           "movl (%%esi),%%eax\n"
           "addl $4,%%esi\n"
           "mull %%edi\n"
           "addl %%ebp,%%eax\n"
           "movl (%%esi,%%ebx),%%ebp\n"
           "adcl $0,%%edx\n"
           "addl %%eax,%%ebp\n"
           "adcl $0,%%edx\n"
           "movl %%ebp,(%%esi,%%ebx)\n"
           "decl %%ecx\n"
           "movl %%edx,%%ebp\n"
           "jnz tcl4\n"

           "movl %%ebp,4(%%esi,%%ebx)\n"
           "popl %%ebp\n"
           
        :
        :"m"(i),"m"(xl),"m"(xg),"m"(w0g)
        :"eax","edi","esi","ebx","ecx","edx","memory"
       );
#endif
#endif
#ifndef INLINE_ASM
                carry=0;
                for (j=i+1;j<xl;j++)
                { /* Only do above the diagonal */
#ifdef MR_NOASM
                    dble.d=(mr_large)x->w[i]*x->w[j]+carry+w0->w[i+j];
                    w0->w[i+j]=dble.h[MR_BOT];
                    carry=dble.h[MR_TOP];
#else
                    muldvd2(x->w[i],x->w[j],&carry,&w0->w[i+j]);
#endif
                }
                w0->w[xl+i]=carry;
#endif
            }
#ifdef INLINE_ASM
#if INLINE_ASM == 1
            ASM mov cx,xl
            ASM shl cx,1
#ifdef MR_LMM
            ASM push ds
            ASM push es
            ASM les bx,DWORD PTR w0g  
#else
            ASM mov bx,w0g
#endif
          tcl5:
#ifdef MR_LMM
            ASM rcl WORD PTR es:[bx],1
#else
            ASM rcl WORD PTR [bx],1
#endif
            ASM inc bx
            ASM inc bx
            ASM loop tcl5

            ASM cld
            ASM mov cx,xl
#ifdef MR_LMM
            ASM les di,DWORD PTR w0g
            ASM lds si,DWORD PTR xg
#else
            ASM mov di,w0g
            ASM mov si,xg
#endif
       
            ASM xor bx,bx
          tcl7:
            ASM lodsw
            ASM mul ax
            ASM add ax,bx
            ASM adc dx,0
#ifdef MR_LMM
            ASM add es:[di],ax
#else
            ASM add [di],ax
#endif
            ASM adc dx,0
            ASM xor bx,bx
            ASM inc di
            ASM inc di
#ifdef MR_LMM
            ASM add es:[di],dx
#else
            ASM add [di],dx
#endif
            ASM adc bx,0
            ASM inc di
            ASM inc di
            ASM loop tcl7
#ifdef MR_LMM
            ASM pop es
            ASM pop ds
#endif
#endif
#if INLINE_ASM == 2
            ASM mov cx,xl
            ASM shl cx,1
#ifdef MR_LMM
            ASM push ds
            ASM push es
            ASM les bx,DWORD PTR w0g
#else
            ASM mov bx,w0g
#endif
          tcl5:
#ifdef MR_LMM
            ASM rcl DWORD PTR es:[bx],1
#else
            ASM rcl DWORD PTR [bx],1
#endif
            ASM inc bx
            ASM inc bx
            ASM inc bx
            ASM inc bx
            ASM loop tcl5

            ASM cld
            ASM mov cx,xl
#ifdef MR_LMM
            ASM les di,DWORD PTR w0g
            ASM lds si,DWORD PTR xg
#else
            ASM mov di,w0g
            ASM mov si,xg
#endif
            ASM xor ebx,ebx
          tcl7:
            ASM lodsd
            ASM mul eax
            ASM add eax,ebx
            ASM adc edx,0
#ifdef MR_LMM
            ASM add es:[di],eax
#else
            ASM add [di],eax
#endif
            ASM adc edx,0
            ASM xor ebx,ebx
            ASM add di,4
#ifdef MR_LMM
            ASM add es:[di],edx
#else
            ASM add [di],edx
#endif
            ASM adc ebx,0
            ASM add di,4
            ASM loop tcl7
#ifdef MR_LMM
            ASM pop es
            ASM pop ds
#endif
#endif
#if INLINE_ASM == 3
            ASM mov ecx,xl
            ASM shl ecx,1
            ASM mov edi,w0g
          tcl5:
            ASM rcl DWORD PTR [edi],1
            ASM inc edi
            ASM inc edi
            ASM inc edi
            ASM inc edi
            ASM loop tcl5

            ASM mov ecx,xl
            ASM mov esi,xg
            ASM mov edi,w0g
            ASM xor ebx,ebx
          tcl7:
            ASM mov eax,[esi]
            ASM add esi,4
            ASM mul eax
            ASM add eax,ebx
            ASM adc edx,0
            ASM add [edi],eax
            ASM adc edx,0
            ASM xor ebx,ebx
            ASM add edi,4
            ASM add [edi],edx
            ASM adc ebx,0
            ASM add edi,4
            ASM dec ecx
            ASM jnz tcl7
#endif
#if INLINE_ASM == 4
   ASM (
           "movl %0,%%ecx\n"
           "shll $1,%%ecx\n"
           "movl %1,%%edi\n"
         "tcl5:\n"
           "rcll $1,(%%edi)\n"
           "incl %%edi\n"
           "incl %%edi\n"
           "incl %%edi\n"
           "incl %%edi\n"
           "loop tcl5\n"

           "movl %0,%%ecx\n"
           "movl %2,%%esi\n"
           "movl %1,%%edi\n"
           "xorl %%ebx,%%ebx\n"
         "tcl7:\n"
           "movl (%%esi),%%eax\n"
           "addl $4,%%esi\n"
           "mull %%eax\n"
           "addl %%ebx,%%eax\n"
           "adcl $0,%%edx\n"
           "addl %%eax,(%%edi)\n"
           "adcl $0,%%edx\n"
           "xorl %%ebx,%%ebx\n"
           "addl $4,%%edi\n"
           "addl %%edx,(%%edi)\n"
           "adcl $0,%%ebx\n"
           "addl $4,%%edi\n"
           "decl %%ecx\n"
           "jnz tcl7\n"                       
        :
        :"m"(xl),"m"(w0g),"m"(xg)
        :"eax","edi","esi","ebx","ecx","edx","memory"
       );
#endif
#endif
#ifndef INLINE_ASM
            w0->len=xl+xl-1;
            mr_padd(_MIPP_ w0,w0,w0);     /* double it */
            carry=0;
            for (i=0;i<xl;i++)
            { /* add in squared elements */
                ti=i+i;
#ifdef MR_NOASM               
                dble.d=(mr_large)x->w[i]*x->w[i]+carry+w0->w[ti];
                w0->w[ti]=dble.h[MR_BOT];
                carry=dble.h[MR_TOP];
#else
                muldvd2(x->w[i],x->w[i],&carry,&w0->w[ti]);
#endif
                w0->w[ti+1]+=carry;
                if (w0->w[ti+1]<carry) carry=1;
                else                   carry=0;
            }
#endif
        }
        else for (i=0;i<xl;i++)
        { /* long multiplication */
       /* inline - substitutes for loop below */
#ifdef INLINE_ASM
#if INLINE_ASM == 1
            ASM cld
            ASM mov cx,yl
            ASM mov dx,i
            ASM shl dx,1
#ifdef MR_LMM
            ASM push ds
            ASM push es
            ASM les bx,DWORD PTR w0g
            ASM add bx,dx
            ASM lds si,DWORD PTR xg
            ASM add si,dx
            ASM mov di,[si]
            ASM lds si,DWORD PTR yg
#else
            ASM mov bx,w0g
            ASM add bx,dx
            ASM mov si,xg
            ASM add si,dx
            ASM mov di,[si]
            ASM mov si,yg
#endif
            ASM push bp
            ASM xor bp,bp
          tcl6:
            ASM lodsw
            ASM mul di
            ASM add ax,bp
            ASM adc dx,0
#ifdef MR_LMM
            ASM add es:[bx],ax
#else
            ASM add [bx],ax
#endif
            ASM inc bx
            ASM inc bx
            ASM adc dx,0
            ASM mov bp,dx
            ASM loop tcl6

#ifdef MR_LMM
            ASM mov es:[bx],bp
            ASM pop bp
            ASM pop es
            ASM pop ds
#else
            ASM mov [bx],bp
            ASM pop bp
#endif
#endif
#if INLINE_ASM == 2
            ASM cld
            ASM mov cx,yl
            ASM mov dx,i
            ASM shl dx,2
#ifdef MR_LMM
            ASM push ds
            ASM push es
            ASM les bx,DWORD PTR w0g
            ASM add bx,dx
            ASM lds si,DWORD PTR xg
            ASM add si,dx
            ASM mov edi,[si]
            ASM lds si,DWORD PTR yg
#else           
            ASM mov bx,w0g
            ASM add bx,dx
            ASM mov si,xg
            ASM add si,dx
            ASM mov edi,[si]
            ASM mov si,yg
#endif
            ASM push ebp
            ASM xor ebp,ebp
          tcl6:
            ASM lodsd
            ASM mul edi
            ASM add eax,ebp
            ASM adc edx,0
#ifdef MR_LMM
            ASM add es:[bx],eax
#else
            ASM add [bx],eax
#endif
            ASM adc edx,0
            ASM add bx,4
            ASM mov ebp,edx
            ASM loop tcl6

#ifdef MR_LMM
            ASM mov es:[bx],ebp
            ASM pop ebp
            ASM pop es
            ASM pop ds
#else
            ASM mov [bx],ebp
            ASM pop ebp
#endif
#endif
#if INLINE_ASM == 3
            ASM mov ecx,yl
            ASM mov esi,i
            ASM shl esi,2
            ASM mov ebx,xg
            ASM add ebx,esi
            ASM mov edi,[ebx]
            ASM mov ebx,w0g
            ASM add ebx,esi
            ASM mov esi,yg
            ASM sub ebx,esi
            ASM sub ebx,4
            ASM push ebp
            ASM xor ebp,ebp
          tcl6:
            ASM mov eax,[esi]
            ASM add esi,4
            ASM mul edi
            ASM add eax,ebp
            ASM mov ebp,[esi+ebx]
            ASM adc edx,0
            ASM add ebp,eax
            ASM adc edx,0
            ASM mov [esi+ebx],ebp
            ASM dec ecx
            ASM mov ebp,edx
            ASM jnz tcl6

            ASM mov [esi+ebx+4],ebp
            ASM pop ebp
#endif
#if INLINE_ASM == 4
   ASM (
           "movl %0,%%ecx\n"
           "movl %1,%%esi\n"
           "shll $2,%%esi\n"
           "movl %2,%%ebx\n"
           "addl %%esi,%%ebx\n"
           "movl (%%ebx),%%edi\n"
           "movl %3,%%ebx\n"
           "addl %%esi,%%ebx\n"
           "movl %4,%%esi\n"
           "subl %%esi,%%ebx\n"
           "subl $4,%%ebx\n"
           "pushl %%ebp\n"
           "xorl %%ebp,%%ebp\n"
         "tcl6:\n"
           "movl (%%esi),%%eax\n"
           "addl $4,%%esi\n" 
           "mull %%edi\n"
           "addl %%ebp,%%eax\n"
           "movl (%%esi,%%ebx),%%ebp\n"
           "adcl $0,%%edx\n"
           "addl %%eax,%%ebp\n" 
           "adcl $0,%%edx\n"
           "movl %%ebp,(%%esi,%%ebx)\n"
           "decl %%ecx\n"
           "movl %%edx,%%ebp\n"
           "jnz tcl6\n"   

           "movl %%ebp,4(%%esi,%%ebx)\n"
           "popl %%ebp\n"
        :
        :"m"(yl),"m"(i),"m"(xg),"m"(w0g),"m"(yg)
        :"eax","edi","esi","ebx","ecx","edx","memory"
       );
#endif
#endif
#ifndef INLINE_ASM
            carry=0;
            for (j=0;j<yl;j++)
            { /* multiply each digit of y by x[i] */
#ifdef MR_NOASM 
                dble.d=(mr_large)x->w[i]*y->w[j]+carry+w0->w[i+j];
                w0->w[i+j]=dble.h[MR_BOT];
                carry=dble.h[MR_TOP];
#else
                muldvd2(x->w[i],y->w[j],&carry,&w0->w[i+j]);
#endif
            }
            w0->w[yl+i]=carry;
#endif
        }
#endif
#ifndef MR_SIMPLE_BASE
    }
    else
    {
        if (x==y && xl>SQR_FASTER_THRESHOLD)
        { /* squaring can be done nearly twice as fast */
            for (i=0;i<xl-1;i++)
            { /* long multiplication */
                carry=0;
                for (j=i+1;j<xl;j++)
                { /* Only do above the diagonal */
#ifdef MR_NOASM
                   dbled=(mr_large)x->w[i]*x->w[j]+w0->w[i+j]+carry;
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
                   w0->w[i+j]=(mr_small)(dbled-(mr_large)carry*mr_mip->base);
#else

  #ifdef MR_FP_ROUNDING
              carry=imuldiv(x->w[i],x->w[j],w0->w[i+j]+carry,mr_mip->base,mr_mip->inverse_base,&w0->w[i+j]);
  #else
              carry=muldiv(x->w[i],x->w[j],w0->w[i+j]+carry,mr_mip->base,&w0->w[i+j]); 
  #endif
#endif
                }
                w0->w[xl+i]=carry;
            }
            w0->len=xl+xl-1;
            mr_padd(_MIPP_ w0,w0,w0);     /* double it */
            carry=0;
            for (i=0;i<xl;i++)
            { /* add in squared elements */
                ti=i+i;
#ifdef MR_NOASM
                dbled=(mr_large)x->w[i]*x->w[i]+w0->w[ti]+carry;
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
                w0->w[ti]=(mr_small)(dbled-(mr_large)carry*mr_mip->base);
#else

#ifdef MR_FP_ROUNDING
                carry=imuldiv(x->w[i],x->w[i],w0->w[ti]+carry,mr_mip->base,mr_mip->inverse_base,&w0->w[ti]);
#else
                carry=muldiv(x->w[i],x->w[i],w0->w[ti]+carry,mr_mip->base,&w0->w[ti]);
#endif

#endif
                w0->w[ti+1]+=carry;
                carry=0;
                if (w0->w[ti+1]>=mr_mip->base)
                {
                    carry=1;
                    w0->w[ti+1]-=mr_mip->base;
                }
            }
        }
        else for (i=0;i<xl;i++)
        { /* long multiplication */
            carry=0; 
            for (j=0;j<yl;j++)
            { /* multiply each digit of y by x[i] */
#ifdef MR_NOASM
                dbled=(mr_large)x->w[i]*y->w[j]+w0->w[i+j]+carry;

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
                w0->w[i+j]=(mr_small)(dbled-(mr_large)carry*mr_mip->base);
#else

#ifdef MR_FP_ROUNDING
                carry=imuldiv(x->w[i],y->w[j],w0->w[i+j]+carry,mr_mip->base,mr_mip->inverse_base,&w0->w[i+j]);
#else
                carry=muldiv(x->w[i],y->w[j],w0->w[i+j]+carry,mr_mip->base,&w0->w[i+j]);
#endif

#endif
            }
            w0->w[yl+i]=carry;
        }
    }
#endif
    w0->len=(sz|(xl+yl)); /* set length and sign of result */

    mr_lzero(w0);
    copy(w0,z);
    MR_OUT
}

void divide(_MIPD_ big x,big y,big z)
{  /*  divide two big numbers  z=x/y : x=x mod y  *
    *  returns quotient only if  divide(x,y,x)    *
    *  returns remainder only if divide(x,y,y)    */
    mr_small carry,attemp,ldy,sdy,ra,r,d,tst,psum;
#ifdef MR_FP
    mr_small dres;
#endif
    mr_lentype sx,sy,sz;
    mr_small borrow,dig,*w0g,*yg;
    int i,k,m,x0,y0,w00;
    big w0;

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
    BOOL check;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    w0=mr_mip->w0;

    MR_IN(6)

    if (x==y) mr_berror(_MIPP_ MR_ERR_BAD_PARAMETERS);
#ifdef MR_FLASH
    if (mr_notint(x) || mr_notint(y)) mr_berror(_MIPP_ MR_ERR_INT_OP);
#endif
    if (y->len==0) mr_berror(_MIPP_ MR_ERR_DIV_BY_ZERO);
    if (mr_mip->ERNUM)
    {
        MR_OUT
        return;
    }
    sx=(x->len&MR_MSBIT);   /*  extract signs ... */
    sy=(y->len&MR_MSBIT);
    sz=(sx^sy);
    x->len&=MR_OBITS;   /* ... and force operands to positive  */
    y->len&=MR_OBITS;
    x0=(int)x->len;
    y0=(int)y->len;
    copy(x,w0);
    w00=(int)w0->len;
    if (mr_mip->check && (w00-y0+1>mr_mip->nib))
    {
        mr_berror(_MIPP_ MR_ERR_OVERFLOW);
        MR_OUT
        return;
    }
    d=0;
    if (x0==y0)
    {
        if (x0==1) /* special case - x and y are both mr_smalls */
        { 
            d=MR_DIV(w0->w[0],y->w[0]);
            w0->w[0]=MR_REMAIN(w0->w[0],y->w[0]);
            mr_lzero(w0);
        }
        else if (MR_DIV(w0->w[x0-1],4)<y->w[x0-1])
        while (mr_compare(w0,y)>=0)
        {  /* mr_small quotient - so do up to four subtracts instead */
            mr_psub(_MIPP_ w0,y,w0);
            d++;
        }
    }
    if (mr_compare(w0,y)<0)
    {  /*  x less than y - so x becomes remainder */
        if (x!=z)  /* testing parameters */
        {
            copy(w0,x);
            if (x->len!=0) x->len|=sx;
        }
        if (y!=z)
        {
            zero(z);
            z->w[0]=d;
            if (d>0) z->len=(sz|1);
        }
        y->len|=sy;
        MR_OUT
        return;
    }

    if (y0==1)
    {  /* y is int - so use subdiv instead */
#ifdef MR_FP_ROUNDING
        r=mr_sdiv(_MIPP_ w0,y->w[0],mr_invert(y->w[0]),w0);
#else
        r=mr_sdiv(_MIPP_ w0,y->w[0],w0);
#endif
        if (y!=z)
        {
            copy(w0,z);
            z->len|=sz;
        }
        if (x!=z)
        {
            zero(x);
            x->w[0]=r;
            if (r>0) x->len=(sx|1);
        }
        y->len|=sy;
        MR_OUT
        return;
    }
    if (y!=z) zero(z);
    d=normalise(_MIPP_ y,y);
    check=mr_mip->check;
    mr_mip->check=OFF;
#ifndef MR_SIMPLE_BASE
    if (mr_mip->base==0)
    {
#endif
#ifndef MR_NOFULLWIDTH
        if (d!=1) mr_pmul(_MIPP_ w0,d,w0);
        ldy=y->w[y0-1];
        sdy=y->w[y0-2];
        w0g=w0->w; yg=y->w;
        for (k=w00-1;k>=y0-1;k--)
        {  /* long division */
#ifdef INLINE_ASM
#if INLINE_ASM == 1
#ifdef MR_LMM
            ASM push ds
            ASM lds bx,DWORD PTR w0g
#else
            ASM mov bx,w0g
#endif
            ASM mov si,k
            ASM shl si,1
            ASM add bx,si
            ASM mov dx,[bx+2]
            ASM mov ax,[bx]
            ASM cmp dx,ldy
            ASM jne tcl8
            ASM mov di,0xffff
            ASM mov si,ax
            ASM add si,ldy
            ASM jc tcl12
            ASM jmp tcl10
          tcl8:
            ASM div WORD PTR ldy
            ASM mov di,ax
            ASM mov si,dx
          tcl10:
            ASM mov ax,sdy
            ASM mul di
            ASM cmp dx,si
            ASM jb tcl12
            ASM jne tcl11
            ASM cmp ax,[bx-2]
            ASM jbe tcl12
          tcl11:
            ASM dec di
            ASM add si,ldy
            ASM jnc tcl10
          tcl12:
            ASM mov attemp,di
#ifdef MR_LMM
            ASM pop ds
#endif
#endif
/* NOTE push and pop of esi/edi should not be necessary - Borland C bug *
 * These pushes are needed here even if register variables are disabled */
#if INLINE_ASM == 2
            ASM push esi
            ASM push edi
#ifdef MR_LMM
            ASM push ds
            ASM lds bx,DWORD PTR w0g
#else
            ASM mov bx,w0g
#endif
            ASM mov si,k
            ASM shl si,2
            ASM add bx,si
            ASM mov edx,[bx+4]
            ASM mov eax,[bx]
            ASM cmp edx,ldy
            ASM jne tcl8
            ASM mov edi,0xffffffff
            ASM mov esi,eax
            ASM add esi,ldy
            ASM jc tcl12
            ASM jmp tcl10
          tcl8:
            ASM div DWORD PTR ldy
            ASM mov edi,eax
            ASM mov esi,edx
          tcl10:
            ASM mov eax,sdy
            ASM mul edi
            ASM cmp edx,esi
            ASM jb tcl12
            ASM jne tcl11
            ASM cmp eax,[bx-4]
            ASM jbe tcl12
          tcl11:
            ASM dec edi
            ASM add esi,ldy
            ASM jnc tcl10
          tcl12:
            ASM mov attemp,edi
#ifdef MR_LMM
            ASM pop ds
#endif
            ASM pop edi
            ASM pop esi
#endif  
#if INLINE_ASM == 3
            ASM push esi
            ASM push edi
            ASM mov ebx,w0g
            ASM mov esi,k
            ASM shl esi,2
            ASM add ebx,esi
            ASM mov edx,[ebx+4]
            ASM mov eax,[ebx]
            ASM cmp edx,ldy
            ASM jne tcl8
            ASM mov edi,0xffffffff
            ASM mov esi,eax
            ASM add esi,ldy
            ASM jc tcl12
            ASM jmp tcl10
          tcl8:
            ASM div DWORD PTR ldy
            ASM mov edi,eax
            ASM mov esi,edx
          tcl10:
            ASM mov eax,sdy
            ASM mul edi
            ASM cmp edx,esi
            ASM jb tcl12
            ASM jne tcl11
            ASM cmp eax,[ebx-4]
            ASM jbe tcl12
          tcl11:
            ASM dec edi
            ASM add esi,ldy
            ASM jnc tcl10
          tcl12:
            ASM mov attemp,edi
            ASM pop edi
            ASM pop esi
#endif       
#if INLINE_ASM == 4
   ASM (
           "movl %1,%%ebx\n"
           "movl %2,%%esi\n"
           "shll $2,%%esi\n"
           "addl %%esi,%%ebx\n"
           "movl 4(%%ebx),%%edx\n"
           "movl (%%ebx),%%eax\n"
           "cmpl %3,%%edx\n"
           "jne tcl8\n"
           "movl $0xffffffff,%%edi\n"
           "movl %%eax,%%esi\n"
           "addl %3,%%esi\n"
           "jc tcl12\n"
           "jmp tcl10\n"
         "tcl8:\n"
           "divl %3\n"
           "movl %%eax,%%edi\n"
           "movl %%edx,%%esi\n"
         "tcl10:\n"
           "movl %4,%%eax\n"
           "mull %%edi\n"
           "cmpl %%esi,%%edx\n"
           "jb tcl12\n"
           "jne tcl11\n"
           "cmpl -4(%%ebx),%%eax\n"
           "jbe tcl12\n"
         "tcl11:\n"
           "decl %%edi\n"
           "addl %3,%%esi\n"
           "jnc tcl10\n"
         "tcl12:\n"
           "movl %%edi,%0\n"
        :"=m"(attemp)
        :"m"(w0g),"m"(k),"m"(ldy),"m"(sdy)
        :"eax","edi","esi","ebx","ecx","edx","memory"
       );
#endif
#endif
#ifndef INLINE_ASM
            carry=0;
            if (w0->w[k+1]==ldy) /* guess next quotient digit */
            {
                attemp=(mr_small)(-1);
                ra=ldy+w0->w[k];
                if (ra<ldy) carry=1;
            }
#ifdef MR_NOASM
            else
            {
                dble.h[MR_BOT]=w0->w[k];
                dble.h[MR_TOP]=w0->w[k+1];
                attemp=(mr_small)(dble.d/ldy);
                ra=(mr_small)(dble.d-(mr_large)attemp*ldy);
            }
#else
            else attemp=muldvm(w0->w[k+1],w0->w[k],ldy,&ra);
#endif
            while (carry==0)
            {
#ifdef MR_NOASM
                dble.d=(mr_large)attemp*sdy;
                r=dble.h[MR_BOT];
                tst=dble.h[MR_TOP];
#else
                tst=muldvd(sdy,attemp,(mr_small)0,&r);
#endif
                if (tst< ra || (tst==ra && r<=w0->w[k-1])) break;
                attemp--;  /* refine guess */
                ra+=ldy;
                if (ra<ldy) carry=1;
            }
#endif    
            m=k-y0+1;
            if (attemp>0)
            { /* do partial subtraction */
                borrow=0;
    /*  inline - substitutes for loop below */
#ifdef INLINE_ASM
#if INLINE_ASM == 1
                ASM cld
                ASM mov cx,y0
                ASM mov si,m
                ASM shl si,1
                ASM mov di,attemp
#ifdef MR_LMM
                ASM push ds
                ASM push es
                ASM les bx,DWORD PTR w0g
                ASM add bx,si
                ASM sub bx,2
                ASM lds si,DWORD PTR yg
#else
                ASM mov bx,w0g
                ASM add bx,si
                ASM sub bx,2
                ASM mov si,yg
#endif
                ASM push bp
                ASM xor bp,bp

             tcl3:
                ASM lodsw
                ASM mul di
                ASM add ax,bp
                ASM adc dx,0
                ASM inc bx
                ASM inc bx
#ifdef MR_LMM
                ASM sub es:[bx],ax
#else
                ASM sub [bx],ax
#endif              
                ASM adc dx,0
                ASM mov bp,dx
                ASM loop tcl3

                ASM mov ax,bp
                ASM pop bp
#ifdef MR_LMM
                ASM pop es
                ASM pop ds
#endif
                ASM mov borrow,ax
#endif
/* NOTE push and pop of esi/edi should not be necessary - Borland C bug *
 * These pushes are needed here even if register variables are disabled */
#if INLINE_ASM == 2
                ASM push esi
                ASM push edi
                ASM cld
                ASM mov cx,y0
                ASM mov si,m
                ASM shl si,2
                ASM mov edi,attemp
#ifdef MR_LMM
                ASM push ds
                ASM push es
                ASM les bx,DWORD PTR w0g
                ASM add bx,si
                ASM sub bx,4
                ASM lds si,DWORD PTR yg
#else
                ASM mov bx,w0g
                ASM add bx,si
                ASM sub bx,4
                ASM mov si,yg
#endif
                ASM push ebp
                ASM xor ebp,ebp

             tcl3:
                ASM lodsd
                ASM mul edi
                ASM add eax,ebp
                ASM adc edx,0
                ASM add bx,4
#ifdef MR_LMM
                ASM sub es:[bx],eax
#else
                ASM sub [bx],eax
#endif
                ASM adc edx,0
                ASM mov ebp,edx
                ASM loop tcl3

                ASM mov eax,ebp
                ASM pop ebp
#ifdef MR_LMM
                ASM pop es
                ASM pop ds
#endif
                ASM mov borrow,eax
                ASM pop edi
                ASM pop esi
#endif
#if INLINE_ASM == 3
                ASM push esi
                ASM push edi
                ASM mov ecx,y0
                ASM mov esi,m
                ASM shl esi,2
                ASM mov edi,attemp
                ASM mov ebx,w0g
                ASM add ebx,esi
                ASM mov esi,yg
                ASM sub ebx,esi
                ASM sub ebx,4
                ASM push ebp
                ASM xor ebp,ebp

             tcl3:
                ASM mov eax,[esi]
                ASM add esi,4
                ASM mul edi
                ASM add eax,ebp
                ASM mov ebp,[esi+ebx]
                ASM adc edx,0
                ASM sub ebp,eax
                ASM adc edx,0
                ASM mov [esi+ebx],ebp
                ASM dec ecx
                ASM mov ebp,edx
                ASM jnz tcl3

                ASM mov eax,ebp
                ASM pop ebp
                ASM mov borrow,eax
                ASM pop edi
                ASM pop esi
#endif
#if INLINE_ASM == 4
   ASM (
           "movl %1,%%ecx\n"
           "movl %2,%%esi\n"
           "shll $2,%%esi\n"
           "movl %3,%%edi\n"
           "movl %4,%%ebx\n"
           "addl %%esi,%%ebx\n"
           "movl %5,%%esi\n"
           "subl %%esi,%%ebx\n"
           "subl $4,%%ebx\n"
           "pushl %%ebp\n"
           "xorl %%ebp,%%ebp\n"
         "tcl3:\n"
           "movl (%%esi),%%eax\n"
           "addl $4,%%esi\n"
           "mull %%edi\n"
           "addl %%ebp,%%eax\n"
           "movl (%%esi,%%ebx),%%ebp\n"
           "adcl $0,%%edx\n"
           "subl %%eax,%%ebp\n"
           "adcl $0,%%edx\n"
           "movl %%ebp,(%%esi,%%ebx)\n"
           "decl %%ecx\n"
           "movl %%edx,%%ebp\n"
           "jnz tcl3\n"
    
           "movl %%ebp,%%eax\n"
           "popl %%ebp\n"
           "movl %%eax,%0\n"
 
        :"=m"(borrow)
        :"m"(y0),"m"(m),"m"(attemp),"m"(w0g),"m"(yg)
        :"eax","edi","esi","ebx","ecx","edx","memory"
       );
#endif
#endif
#ifndef INLINE_ASM
                for (i=0;i<y0;i++)
                {
#ifdef MR_NOASM
                    dble.d=(mr_large)attemp*y->w[i]+borrow;
                    dig=dble.h[MR_BOT];
                    borrow=dble.h[MR_TOP];
#else
                  borrow=muldvd(attemp,y->w[i],borrow,&dig);
#endif
                  if (w0->w[m+i]<dig) borrow++;
                  w0->w[m+i]-=dig;
                }
#endif

                if (w0->w[k+1]<borrow)
                {  /* whoops! - over did it */
                    w0->w[k+1]=0;
                    carry=0;
                    for (i=0;i<y0;i++)
                    {  /* compensate for error ... */
                        psum=w0->w[m+i]+y->w[i]+carry;
                        if (psum>y->w[i]) carry=0;
                        if (psum<y->w[i]) carry=1;
                        w0->w[m+i]=psum;
                    }
                    attemp--;  /* ... and adjust guess */
                }
                else w0->w[k+1]-=borrow;
            }
            if (k==w00-1 && attemp==0) w00--;
            else if (y!=z) z->w[m]=attemp;
        }
#endif
#ifndef MR_SIMPLE_BASE
    }
    else
    {   /* have to do it the hard way */
        if (d!=1) mr_pmul(_MIPP_ w0,d,w0);
        ldy=y->w[y0-1];
        sdy=y->w[y0-2];

        for (k=w00-1;k>=y0-1;k--)
        {  /* long division */


            if (w0->w[k+1]==ldy) /* guess next quotient digit */
            {
                attemp=mr_mip->base-1;
                ra=ldy+w0->w[k];
            }
#ifdef MR_NOASM
            else 
            {
                dbled=(mr_large)w0->w[k+1]*mr_mip->base+w0->w[k];
                attemp=(mr_small)MR_LROUND(dbled/ldy);
                ra=(mr_small)(dbled-(mr_large)attemp*ldy);
            }
#else
            else attemp=muldiv(w0->w[k+1],mr_mip->base,w0->w[k],ldy,&ra);
#endif
            while (ra<mr_mip->base)
            {
#ifdef MR_NOASM
                dbled=(mr_large)sdy*attemp;
#ifdef MR_FP_ROUNDING
                tst=(mr_small)MR_LROUND(dbled*mr_mip->inverse_base);
#else
#ifndef MR_FP
                if (mr_mip->base==mr_mip->base2)
                    tst=(mr_small)(dbled>>mr_mip->lg2b);
                else 
#endif  
                    tst=(mr_small)MR_LROUND(dbled/mr_mip->base);
#endif
                r=(mr_small)(dbled-(mr_large)tst*mr_mip->base);
#else
#ifdef MR_FP_ROUNDING
                tst=imuldiv(sdy,attemp,(mr_small)0,mr_mip->base,mr_mip->inverse_base,&r); 
#else
                tst=muldiv(sdy,attemp,(mr_small)0,mr_mip->base,&r); 
#endif
#endif
                if (tst< ra || (tst==ra && r<=w0->w[k-1])) break;
                attemp--;  /* refine guess */
                ra+=ldy;
            }    
            m=k-y0+1;
            if (attemp>0)
            { /* do partial subtraction */
                borrow=0;
                for (i=0;i<y0;i++)
                {
#ifdef MR_NOASM
                  dbled=(mr_large)attemp*y->w[i]+borrow;
#ifdef MR_FP_ROUNDING
                  borrow=(mr_small)MR_LROUND(dbled*mr_mip->inverse_base);
#else
#ifndef MR_FP
                  if (mr_mip->base==mr_mip->base2)
                      borrow=(mr_small)(dbled>>mr_mip->lg2b);
                  else 
#endif  
                      borrow=(mr_small)MR_LROUND(dbled/mr_mip->base);
#endif
                  dig=(mr_small)(dbled-(mr_large)borrow*mr_mip->base);
#else
#ifdef MR_FP_ROUNDING
                  borrow=imuldiv(attemp,y->w[i],borrow,mr_mip->base,mr_mip->inverse_base,&dig);
#else
                  borrow=muldiv(attemp,y->w[i],borrow,mr_mip->base,&dig);
#endif
#endif
                  if (w0->w[m+i]<dig)
                  { /* set borrow */
                      borrow++;
                      w0->w[m+i]+=(mr_mip->base-dig);
                  }
                  else w0->w[m+i]-=dig;
                }
                if (w0->w[k+1]<borrow)
                {  /* whoops! - over did it */
                    w0->w[k+1]=0;
                    carry=0;
                    for (i=0;i<y0;i++)
                    {  /* compensate for error ... */
                        psum=w0->w[m+i]+y->w[i]+carry;
                        carry=0;
                        if (psum>=mr_mip->base)
                        {
                            carry=1;
                            psum-=mr_mip->base;
                        }
                        w0->w[m+i]=psum;
                    }
                    attemp--;  /* ... and adjust guess */
                }
                else
                    w0->w[k+1]-=borrow;
            }
            if (k==w00-1 && attemp==0) w00--;
            else if (y!=z) z->w[m]=attemp;
        }
    }
#endif
    if (y!=z) z->len=((w00-y0+1)|sz); /* set sign and length of result */

    w0->len=y0;

    mr_lzero(y);
    mr_lzero(z);

    if (x!=z)
    {
        mr_lzero(w0);
#ifdef MR_FP_ROUNDING
        if (d!=1) mr_sdiv(_MIPP_ w0,d,mr_invert(d),x);
#else
        if (d!=1) mr_sdiv(_MIPP_ w0,d,x);
#endif
        else copy(w0,x);
        if (x->len!=0) x->len|=sx;
    }
#ifdef MR_FP_ROUNDING
    if (d!=1) mr_sdiv(_MIPP_ y,d,mr_invert(d),y);
#else
    if (d!=1) mr_sdiv(_MIPP_ y,d,y);
#endif
    y->len|=sy;
    mr_mip->check=check;

    MR_OUT
}

BOOL divisible(_MIPD_ big x,big y)
{ /* returns y|x, that is TRUE if y divides x exactly */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return FALSE;

    MR_IN(87)

    copy (x,mr_mip->w0);
    divide(_MIPP_ mr_mip->w0,y,y);

    MR_OUT
    if (size(mr_mip->w0)==0) return TRUE;
    else                    return FALSE;
}     

void mad(_MIPD_ big x,big y,big z,big w,big q,big r)
{ /* Multiply, Add and Divide; q=(x*y+z)/w remainder r   *
   * returns remainder only if w=q, quotient only if q=r *
   * add done only if x, y and z are distinct.           */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    BOOL check;
    if (mr_mip->ERNUM) return;

    MR_IN(24)
    if (w==r)
    {
        mr_berror(_MIPP_ MR_ERR_BAD_PARAMETERS);
        MR_OUT
        return;
    }
    check=mr_mip->check;
    mr_mip->check=OFF;           /* turn off some error checks */

    multiply(_MIPP_ x,y,mr_mip->w0);
    if (x!=z && y!=z) add(_MIPP_ mr_mip->w0,z,mr_mip->w0);

    divide(_MIPP_ mr_mip->w0,w,q);
    if (q!=r) copy(mr_mip->w0,r);
    mr_mip->check=check;
    MR_OUT
}

