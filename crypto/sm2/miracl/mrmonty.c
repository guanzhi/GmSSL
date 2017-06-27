
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
 *   MIRACL Montgomery's method for modular arithmetic without division.
 *   mrmonty.c 
 *
 *   Programs to implement Montgomery's method
 *   See "Modular Multiplication Without Trial Division", Math. Comp. 
 *   Vol 44, Number 170, April 1985, Pages 519-521
 *   NOTE - there is an important correction to this paper mentioned as a
 *   footnote in  "Speeding the Pollard and Elliptic Curve Methods", 
 *   Math. Comput., Vol. 48, January 1987, 243-264
 *
 *   The advantage of this approach is that no division required in order
 *   to compute a modular reduction - useful if division is slow
 *   e.g. on a SPARC processor, or a DSP.
 *   
 *   The disadvantage is that numbers must first be converted to an internal
 *   "n-residue" form.
 *
 */

#include <stdlib.h> 
#include "miracl.h"

#ifdef MR_FP
#include <math.h>
#endif

#ifdef MR_WIN64
#include <intrin.h>
#endif

#ifdef MR_COUNT_OPS
extern int fpc,fpa; 
#endif

#ifdef MR_CELL
extern void mod256(_MIPD_ big,big);
#endif

void kill_monty(_MIPDO_ )
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    zero(mr_mip->modulus);
#ifdef MR_KCM
    zero(mr_mip->big_ndash);
#endif
}

mr_small prepare_monty(_MIPD_ big n)
{ /* prepare Montgomery modulus */ 
#ifdef MR_KCM
    int nl;
#endif
#ifdef MR_PENTIUM
    mr_small ndash;
    mr_small base;
    mr_small magic=13835058055282163712.0;   
    int control=0x1FFF;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return (mr_small)0;
/* Is it set-up already? */
    if (size(mr_mip->modulus)!=0)
        if (mr_compare(n,mr_mip->modulus)==0) return mr_mip->ndash;

    MR_IN(80)

    if (size(n)<=2) 
    {
        mr_berror(_MIPP_ MR_ERR_BAD_MODULUS);
        MR_OUT
        return (mr_small)0;
    }

    zero(mr_mip->w6);
    zero(mr_mip->w15);

/* set a small negative QNR (on the assumption that n is prime!) */
/* These defaults can be over-ridden                             */

/* Did you know that for p=2 mod 3, -3 is a QNR? */

    mr_mip->pmod8=remain(_MIPP_ n,8);
	
    switch (mr_mip->pmod8)
    {
    case 0:
    case 1:
    case 2:
    case 4:
    case 6:
        mr_mip->qnr=0;  /* none defined */
        break;
    case 3:
        mr_mip->qnr=-1;
        break;
    case 5:
        mr_mip->qnr=-2;
        break;
    case 7:
        mr_mip->qnr=-1;
        break;
    }
	mr_mip->pmod9=remain(_MIPP_ n,9);

	mr_mip->NO_CARRY=FALSE;
	if (n->w[n->len-1]>>M4 < 5) mr_mip->NO_CARRY=TRUE;

#ifdef MR_PENTIUM

mr_mip->ACTIVE=FALSE;
if (mr_mip->base!=0)
    if (MR_PENTIUM==n->len) mr_mip->ACTIVE=TRUE;
    if (MR_PENTIUM<0)
    {
        if (n->len<=(-MR_PENTIUM)) mr_mip->ACTIVE=TRUE;
        if (logb2(_MIPP_ n)%mr_mip->lg2b==0) mr_mip->ACTIVE=FALSE;
    }
#endif

#ifdef MR_DISABLE_MONTGOMERY
    mr_mip->MONTY=OFF;
#else
    mr_mip->MONTY=ON;
#endif

#ifdef MR_COMBA
    mr_mip->ACTIVE=FALSE;

    if (MR_COMBA==n->len && mr_mip->base==mr_mip->base2) 
    {
        mr_mip->ACTIVE=TRUE;
#ifdef MR_SPECIAL
        mr_mip->MONTY=OFF;      /* "special" modulus reduction */

#endif                          /* implemented in mrcomba.c    */
    }

#endif
    convert(_MIPP_ 1,mr_mip->one);
    if (!mr_mip->MONTY)
    { /* Montgomery arithmetic is turned off */
        copy(n,mr_mip->modulus);
        mr_mip->ndash=0;
        MR_OUT
        return (mr_small)0;
    }

#ifdef MR_KCM
  
/* test for base==0 & n->len=MR_KCM.2^x */

    mr_mip->ACTIVE=FALSE;
    if (mr_mip->base==0)
    {
        nl=(int)n->len;
        while (nl>=MR_KCM)
        {
            if (nl==MR_KCM)
            {
                mr_mip->ACTIVE=TRUE;
                break;
            }
            if (nl%2!=0) break;
            nl/=2;
        }
    }  
    if (mr_mip->ACTIVE)
    {
        mr_mip->w6->len=n->len+1;
        mr_mip->w6->w[n->len]=1;
        if (invmodp(_MIPP_ n,mr_mip->w6,mr_mip->w14)!=1)
        { /* problems */
            mr_berror(_MIPP_ MR_ERR_BAD_MODULUS);
            MR_OUT
            return (mr_small)0;
        }
    }
    else
    {
#endif
        mr_mip->w6->len=2;
        mr_mip->w6->w[0]=0;
        mr_mip->w6->w[1]=1;    /* w6 = base */
        mr_mip->w15->len=1;
        mr_mip->w15->w[0]=n->w[0];  /* w15 = n mod base */
        if (invmodp(_MIPP_ mr_mip->w15,mr_mip->w6,mr_mip->w14)!=1)
        { /* problems */
            mr_berror(_MIPP_ MR_ERR_BAD_MODULUS);
            MR_OUT
            return (mr_small)0;
        }
#ifdef MR_KCM
    }
    copy(mr_mip->w14,mr_mip->big_ndash);
#endif

    mr_mip->ndash=mr_mip->base-mr_mip->w14->w[0]; /* = N' mod b */
    copy(n,mr_mip->modulus);
    mr_mip->check=OFF;
    mr_shift(_MIPP_ mr_mip->modulus,(int)mr_mip->modulus->len,mr_mip->pR);
    mr_mip->check=ON;
#ifdef MR_PENTIUM
/* prime the FP stack */
    if (mr_mip->ACTIVE)
    {
        ndash=mr_mip->ndash;
        base=mr_mip->base;
        magic *=base;
        ASM
        {
            finit
            fldcw WORD PTR control
            fld QWORD PTR ndash
            fld1
            fld QWORD PTR base
            fdiv
            fld QWORD PTR magic
        }
    }
#endif
    nres(_MIPP_ mr_mip->one,mr_mip->one);
    MR_OUT

    return mr_mip->ndash;
}

void nres(_MIPD_ big x,big y)
{ /* convert x to n-residue format */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(81)

    if (size(mr_mip->modulus)==0)
    {
        mr_berror(_MIPP_ MR_ERR_NO_MODULUS);
        MR_OUT
        return;
    }
    copy(x,y);
    divide(_MIPP_ y,mr_mip->modulus,mr_mip->modulus);
    if (size(y)<0) add(_MIPP_ y,mr_mip->modulus,y);
    if (!mr_mip->MONTY) 
    {
        MR_OUT
        return;
    }
    mr_mip->check=OFF;

    mr_shift(_MIPP_ y,(int)mr_mip->modulus->len,mr_mip->w0);
    divide(_MIPP_ mr_mip->w0,mr_mip->modulus,mr_mip->modulus);
    mr_mip->check=ON;
    copy(mr_mip->w0,y);

    MR_OUT
}

void redc(_MIPD_ big x,big y)
{ /* Montgomery's REDC function p. 520 */
  /* also used to convert n-residues back to normal form */
    mr_small carry,delay_carry,m,ndash,*w0g,*mg;

#ifdef MR_ITANIUM
    mr_small tm;
#endif
#ifdef MR_WIN64
    mr_small tm,tr;
#endif
    int i,j,rn,rn2;
    big w0,modulus;
#ifdef MR_NOASM
    union doubleword dble;
    mr_large dbled,ldres;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(82)

    w0=mr_mip->w0;        /* get these into local variables (for inline assembly) */
    modulus=mr_mip->modulus;
    ndash=mr_mip->ndash;

    copy(x,w0);
    if (!mr_mip->MONTY)
    {
/*#ifdef MR_CELL
        mod256(_MIPP_ w0,w0);
#else */
        divide(_MIPP_ w0,modulus,modulus);
/* #endif */
        copy(w0,y);
        MR_OUT
        return;
    }
    delay_carry=0;
    rn=(int)modulus->len;
    rn2=rn+rn;
#ifndef MR_SIMPLE_BASE
    if (mr_mip->base==0) 
    {
#endif
#ifndef MR_NOFULLWIDTH
      mg=modulus->w;
      w0g=w0->w;
      for (i=0;i<rn;i++)
      {
       /* inline - substitutes for loop below */
#if INLINE_ASM == 1
            ASM cld
            ASM mov cx,rn
            ASM mov si,i
            ASM shl si,1
#ifdef MR_LMM
            ASM push ds
            ASM push es
            ASM les bx,DWORD PTR w0g
            ASM add bx,si
            ASM mov ax,es:[bx]
            ASM mul WORD PTR ndash
            ASM mov di,ax
            ASM lds si,DWORD PTR mg
#else
            ASM mov bx,w0g
            ASM add bx,si
            ASM mov ax,[bx]
            ASM mul WORD PTR ndash
            ASM mov di,ax
            ASM mov si,mg
#endif
            ASM push bp
            ASM xor bp,bp
          m1:
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
            ASM loop m1

            ASM pop bp
            ASM mov ax,delay_carry     
#ifdef MR_LMM
            ASM add es:[bx],ax
            ASM mov ax,0
            ASM adc ax,0
            ASM add es:[bx],dx
            ASM pop es
            ASM pop ds
#else
            ASM add [bx],ax
            ASM mov ax,0
            ASM adc ax,0
            ASM add [bx],dx
#endif
            ASM adc ax,0
            ASM mov delay_carry,ax
#endif
#if INLINE_ASM == 2
            ASM cld
            ASM mov cx,rn
            ASM mov si,i
            ASM shl si,2
#ifdef MR_LMM
            ASM push ds
            ASM push es
            ASM les bx,DWORD PTR w0g
            ASM add bx,si
            ASM mov eax,es:[bx]
            ASM mul DWORD PTR ndash
            ASM mov edi,eax
            ASM lds si,DWORD PTR mg
#else
            ASM mov bx,w0g
            ASM add bx,si
            ASM mov eax,[bx]
            ASM mul DWORD PTR ndash
            ASM mov edi,eax
            ASM mov si,mg
#endif
            ASM push ebp
            ASM xor ebp,ebp
          m1:
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
            ASM loop m1

            ASM pop ebp
            ASM mov eax,delay_carry    
#ifdef MR_LMM
            ASM add es:[bx],eax
            ASM mov eax,0
            ASM adc eax,0
            ASM add es:[bx],edx
            ASM pop es
            ASM pop ds
#else 
            ASM add [bx],eax
            ASM mov eax,0
            ASM adc eax,0
            ASM add [bx],edx
#endif
            ASM adc eax,0
            ASM mov delay_carry,eax

#endif
#if INLINE_ASM == 3
            ASM mov ecx,rn
            ASM mov esi,i
            ASM shl esi,2
            ASM mov ebx,w0g
            ASM add ebx,esi
            ASM mov eax,[ebx]
            ASM mul DWORD PTR ndash
            ASM mov edi,eax
            ASM mov esi,mg
            ASM sub ebx,esi
            ASM sub ebx,4
            ASM push ebp
            ASM xor ebp,ebp
          m1:
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
            ASM jnz m1

            ASM pop ebp
            ASM mov eax,delay_carry     
            ASM add [esi+ebx+4],eax
            ASM mov eax,0
            ASM adc eax,0
            ASM add [esi+ebx+4],edx
            ASM adc eax,0
            ASM mov delay_carry,eax

#endif
#if INLINE_ASM == 4
   ASM (
           "movl %0,%%ecx\n"
           "movl %1,%%esi\n"
           "shll $2,%%esi\n"
           "movl %2,%%ebx\n"
           "addl %%esi,%%ebx\n"
           "movl (%%ebx),%%eax\n"
           "mull %3\n"
           "movl %%eax,%%edi\n"
           "movl %4,%%esi\n"
           "subl %%esi,%%ebx\n"
           "subl $4,%%ebx\n"
           "pushl %%ebp\n"
           "xorl %%ebp,%%ebp\n"
        "m1:\n"
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
           "jnz m1\n"   

           "popl %%ebp\n"
           "movl %5,%%eax\n"
           "addl %%eax,4(%%esi,%%ebx)\n"
           "movl $0,%%eax\n"
           "adcl $0,%%eax\n"
           "addl %%edx,4(%%esi,%%ebx)\n"
           "adcl $0,%%eax\n"
           "movl %%eax,%5\n"
       
        :
        :"m"(rn),"m"(i),"m"(w0g),"m"(ndash),"m"(mg),"m"(delay_carry)
        :"eax","edi","esi","ebx","ecx","edx","memory"
       );
#endif

#ifndef INLINE_ASM
/*        muldvd(w0->w[i],ndash,0,&m);    Note that after this time   */
        m=ndash*w0->w[i];
        carry=0;                       /* around the loop, w0[i]=0    */

        for (j=0;j<rn;j++)
        {
#ifdef MR_NOASM 
            dble.d=(mr_large)m*modulus->w[j]+carry+w0->w[i+j];
            w0->w[i+j]=dble.h[MR_BOT];
            carry=dble.h[MR_TOP];
#else
            muldvd2(m,modulus->w[j],&carry,&w0->w[i+j]);
#endif
        }
        w0->w[rn+i]+=delay_carry;
        if (w0->w[rn+i]<delay_carry) delay_carry=1;
        else delay_carry=0;
        w0->w[rn+i]+=carry;
        if (w0->w[rn+i]<carry) delay_carry=1; 
#endif
      }
#endif

#ifndef MR_SIMPLE_BASE
    }
    else for (i=0;i<rn;i++) 
    {
#ifdef MR_FP_ROUNDING
        imuldiv(w0->w[i],ndash,0,mr_mip->base,mr_mip->inverse_base,&m);
#else
        muldiv(w0->w[i],ndash,0,mr_mip->base,&m);
#endif
        carry=0;
        for (j=0;j<rn;j++)
        {
#ifdef MR_NOASM 
          dbled=(mr_large)m*modulus->w[j]+carry+w0->w[i+j];
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
          carry=imuldiv(modulus->w[j],m,w0->w[i+j]+carry,mr_mip->base,mr_mip->inverse_base,&w0->w[i+j]);
#else
          carry=muldiv(modulus->w[j],m,w0->w[i+j]+carry,mr_mip->base,&w0->w[i+j]);
#endif
#endif
        }
        w0->w[rn+i]+=(delay_carry+carry);
        delay_carry=0;
        if (w0->w[rn+i]>=mr_mip->base)
        {
            w0->w[rn+i]-=mr_mip->base;
            delay_carry=1; 
        }
    }
#endif
    w0->w[rn2]=delay_carry;
    w0->len=rn2+1;
    mr_shift(_MIPP_ w0,(-rn),w0);
    mr_lzero(w0);
    
    if (mr_compare(w0,modulus)>=0) mr_psub(_MIPP_ w0,modulus,w0);
    copy(w0,y);
    MR_OUT
}

/* "Complex" method for ZZn2 squaring */

void nres_complex(_MIPD_ big a,big b,big r,big i)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
	MR_IN(225)

	if (mr_mip->NO_CARRY && mr_mip->qnr==-1)
	{ /* if modulus is small enough we can ignore carries, and use simple addition and subtraction */
	  /* recall that Montgomery reduction can cope as long as product is less than pR */
#ifdef MR_COMBA
#ifdef MR_COUNT_OPS
fpa+=3;
#endif
		if (mr_mip->ACTIVE)
		{
			comba_add(a,b,mr_mip->w1);
			comba_add(a,mr_mip->modulus,mr_mip->w2); /* a-b is p+a-b */
			comba_sub(mr_mip->w2,b,mr_mip->w2);
			comba_add(a,a,r);
		}
		else
		{
#endif
			mr_padd(_MIPP_ a,b,mr_mip->w1);
			mr_padd(_MIPP_ a,mr_mip->modulus,mr_mip->w2);
			mr_psub(_MIPP_ mr_mip->w2,b,mr_mip->w2);
			mr_padd(_MIPP_ a,a,r);
#ifdef MR_COMBA
		}
#endif
		nres_modmult(_MIPP_ r,b,i);
		nres_modmult(_MIPP_ mr_mip->w1,mr_mip->w2,r);
	}
	else
	{
		nres_modadd(_MIPP_ a,b,mr_mip->w1);
		nres_modsub(_MIPP_ a,b,mr_mip->w2);

		if (mr_mip->qnr==-2)
			nres_modsub(_MIPP_ mr_mip->w2,b,mr_mip->w2);
     
		nres_modmult(_MIPP_ a,b,i);
		nres_modmult(_MIPP_ mr_mip->w1,mr_mip->w2,r);

		if (mr_mip->qnr==-2)
			nres_modadd(_MIPP_ r,i,r);

		nres_modadd(_MIPP_ i,i,i);
	}
	MR_OUT
}

#ifndef MR_NO_LAZY_REDUCTION

/*

Lazy reduction technique for zzn2 multiplication - competitive if Reduction is more
expensive that Multiplication. This is true for pairing-based crypto. Note that
Lazy reduction can also be used with Karatsuba! Uses w1, w2, w5, and w6.

Reduction poly is X^2-D=0

(a0+a1.X).(b0+b1.X) = (a0.b0 + D.a1.b1) + (a1.b0+a0.b1).X

Karatsuba

   (a0.b0+D.a1.b1) + ((a0+a1)(b0+b1) - a0.b0 - a1.b1).X  
*/

void nres_lazy(_MIPD_ big a0,big a1,big b0,big b1,big r,big i)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    mr_mip->check=OFF;
#ifdef MR_COUNT_OPS
fpc+=3;
fpa+=5;
if (mr_mip->qnr==-2) fpa++;
#endif

#ifdef MR_COMBA
    if (mr_mip->ACTIVE)
    {
        comba_mult(a0,b0,mr_mip->w0);
        comba_mult(a1,b1,mr_mip->w5);
    }
    else
    {
#endif
#ifdef MR_KCM
    if (mr_mip->ACTIVE)
    {
        kcm_mul(_MIPP_ a1,b1,mr_mip->w5); /* this destroys w0! */
        kcm_mul(_MIPP_ a0,b0,mr_mip->w0);
    }
    else
    { 
#endif
        MR_IN(151)
        multiply(_MIPP_ a0,b0,mr_mip->w0);
        multiply(_MIPP_ a1,b1,mr_mip->w5);
#ifdef MR_COMBA
    }
#endif
#ifdef MR_KCM
    }
#endif

	if (mr_mip->NO_CARRY && mr_mip->qnr==-1)
	{ /* if modulus is small enough we can ignore carries, and use simple addition and subtraction */
#ifdef MR_COMBA
#ifdef MR_COUNT_OPS
fpa+=2;
#endif
		if (mr_mip->ACTIVE)
		{
			comba_double_add(mr_mip->w0,mr_mip->w5,mr_mip->w6);
			comba_add(a0,a1,mr_mip->w1);
			comba_add(b0,b1,mr_mip->w2); 
		}
		else
		{
#endif
			mr_padd(_MIPP_ mr_mip->w0,mr_mip->w5,mr_mip->w6);
			mr_padd(_MIPP_ a0,a1,mr_mip->w1);
			mr_padd(_MIPP_ b0,b1,mr_mip->w2); 
#ifdef MR_COMBA
		}
#endif
	}
	else
	{
		nres_double_modadd(_MIPP_ mr_mip->w0,mr_mip->w5,mr_mip->w6);  /* w6 =  a0.b0+a1.b1 */
		if (mr_mip->qnr==-2)
          nres_double_modadd(_MIPP_ mr_mip->w5,mr_mip->w5,mr_mip->w5);
		nres_modadd(_MIPP_ a0,a1,mr_mip->w1);
		nres_modadd(_MIPP_ b0,b1,mr_mip->w2); 
    }
	nres_double_modsub(_MIPP_ mr_mip->w0,mr_mip->w5,mr_mip->w0);  /* r = a0.b0+D.a1.b1 */

#ifdef MR_COMBA
    if (mr_mip->ACTIVE)
    {
        comba_redc(_MIPP_ mr_mip->w0,r);
        comba_mult(mr_mip->w1,mr_mip->w2,mr_mip->w0);
    }
    else
    {
#endif
#ifdef MR_KCM
    if (mr_mip->ACTIVE)
    {
        kcm_redc(_MIPP_ mr_mip->w0,r);
        kcm_mul(_MIPP_ mr_mip->w1,mr_mip->w2,mr_mip->w0);
    }
    else
    {
#endif
        redc(_MIPP_ mr_mip->w0,r);
        multiply(_MIPP_ mr_mip->w1,mr_mip->w2,mr_mip->w0);           /* w0=(a0+a1)*(b0+b1) */
#ifdef MR_COMBA
    }
#endif
#ifdef MR_KCM
    }
#endif

	if (mr_mip->NO_CARRY && mr_mip->qnr==-1)
	{
#ifdef MR_COMBA
		if (mr_mip->ACTIVE)
			comba_double_sub(mr_mip->w0,mr_mip->w6,mr_mip->w0);
		else
#endif
			mr_psub(_MIPP_ mr_mip->w0,mr_mip->w6,mr_mip->w0);
	}
	else
		nres_double_modsub(_MIPP_ mr_mip->w0,mr_mip->w6,mr_mip->w0); /* (a0+a1)*(b0+b1) - w6 */

#ifdef MR_COMBA
    if (mr_mip->ACTIVE)
    {
        comba_redc(_MIPP_ mr_mip->w0,i);
    }
    else
    {
#endif  
#ifdef MR_KCM
    if (mr_mip->ACTIVE)
    {
        kcm_redc(_MIPP_ mr_mip->w0,i);
    }
    else
    {
#endif      
        redc(_MIPP_ mr_mip->w0,i);
        MR_OUT
#ifdef MR_COMBA
    }
#endif
#ifdef MR_KCM
    }
#endif

    mr_mip->check=ON;

}

#endif

#ifndef MR_STATIC

void nres_dotprod(_MIPD_ int n,big *x,big *y,big w)
{
    int i;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    if (mr_mip->ERNUM) return;
    MR_IN(120)
    mr_mip->check=OFF;
    zero(mr_mip->w7);
    for (i=0;i<n;i++)
    {
        multiply(_MIPP_ x[i],y[i],mr_mip->w0);
        mr_padd(_MIPP_ mr_mip->w7,mr_mip->w0,mr_mip->w7);
    }
    copy(mr_mip->pR,mr_mip->w6);
        /* w6 = p.R */
    divide(_MIPP_ mr_mip->w7,mr_mip->w6,mr_mip->w6);
    redc(_MIPP_ mr_mip->w7,w);

    mr_mip->check=ON;
    MR_OUT
}

#endif

void nres_negate(_MIPD_ big x, big w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
	if (size(x)==0) 
	{
		zero(w);
		return;
	}
#ifdef MR_COMBA
    if (mr_mip->ACTIVE)
    {
        comba_negate(_MIPP_ x,w);
        return;
    }    
    else
    {
#endif
        if (mr_mip->ERNUM) return;

        MR_IN(92)
        mr_psub(_MIPP_ mr_mip->modulus,x,w);    
        MR_OUT

#ifdef MR_COMBA
    }
#endif

}

void nres_div2(_MIPD_ big x,big w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    MR_IN(198)
    copy(x,mr_mip->w1);
    if (remain(_MIPP_ mr_mip->w1,2)!=0)
        add(_MIPP_ mr_mip->w1,mr_mip->modulus,mr_mip->w1);
    subdiv(_MIPP_ mr_mip->w1,2,mr_mip->w1);
    copy(mr_mip->w1,w);

    MR_OUT
}

void nres_div3(_MIPD_ big x,big w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    MR_IN(199)
    copy(x,mr_mip->w1);
    while (remain(_MIPP_ mr_mip->w1,3)!=0)
        add(_MIPP_ mr_mip->w1,mr_mip->modulus,mr_mip->w1);
    subdiv(_MIPP_ mr_mip->w1,3,mr_mip->w1);
    copy(mr_mip->w1,w);

    MR_OUT
}

void nres_div5(_MIPD_ big x,big w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    MR_IN(208)
    copy(x,mr_mip->w1);
    while (remain(_MIPP_ mr_mip->w1,5)!=0)
        add(_MIPP_ mr_mip->w1,mr_mip->modulus,mr_mip->w1);
    subdiv(_MIPP_ mr_mip->w1,5,mr_mip->w1);
    copy(mr_mip->w1,w);

    MR_OUT
}

/* mod pR addition and subtraction */
#ifndef MR_NO_LAZY_REDUCTION

void nres_double_modadd(_MIPD_ big x,big y,big w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
#ifdef MR_COMBA

    if (mr_mip->ACTIVE)
    {
        comba_double_modadd(_MIPP_ x,y,w);
        return;
    }
    else
    {
#endif 

        if (mr_mip->ERNUM) return;
        MR_IN(153)

        mr_padd(_MIPP_ x,y,w);
        if (mr_compare(w,mr_mip->pR)>=0)
            mr_psub(_MIPP_ w,mr_mip->pR,w);

        MR_OUT
#ifdef MR_COMBA
    }
#endif
}

void nres_double_modsub(_MIPD_ big x,big y,big w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
#ifdef MR_COMBA

    if (mr_mip->ACTIVE)
    {
        comba_double_modsub(_MIPP_ x,y,w);
        return;
    }
    else
    {
#endif 

        if (mr_mip->ERNUM) return;
        MR_IN(154)

        if (mr_compare(x,y)>=0)
            mr_psub(_MIPP_ x,y,w);
        else
        {
            mr_psub(_MIPP_ y,x,w);
            mr_psub(_MIPP_ mr_mip->pR,w,w);
        }

        MR_OUT
#ifdef MR_COMBA
    }
#endif
}

#endif

void nres_modadd(_MIPD_ big x,big y,big w)
{ /* modular addition */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
#ifdef MR_COUNT_OPS
fpa++; 
#endif
#ifdef MR_COMBA

    if (mr_mip->ACTIVE)
    {
        comba_modadd(_MIPP_ x,y,w);
        return;
    }
    else
    {
#endif
        if (mr_mip->ERNUM) return;

        MR_IN(90)
        mr_padd(_MIPP_ x,y,w);
        if (mr_compare(w,mr_mip->modulus)>=0) mr_psub(_MIPP_ w,mr_mip->modulus,w);

        MR_OUT
#ifdef MR_COMBA
    }
#endif
}

void nres_modsub(_MIPD_ big x,big y,big w)
{ /* modular subtraction */

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
#ifdef MR_COUNT_OPS
fpa++;
#endif
#ifdef MR_COMBA
    if (mr_mip->ACTIVE)
    {
        comba_modsub(_MIPP_ x,y,w);
        return;
    }
    else
    {
#endif
        if (mr_mip->ERNUM) return;

        MR_IN(91)

        if (mr_compare(x,y)>=0)
            mr_psub(_MIPP_ x,y,w);
        else
        {
            mr_psub(_MIPP_ y,x,w);
            mr_psub(_MIPP_ mr_mip->modulus,w,w);
        }

        MR_OUT
#ifdef MR_COMBA
    }
#endif

}

int nres_moddiv(_MIPD_ big x,big y,big w)
{ /* Modular division using n-residues w=x/y mod n */
    int gcd;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return 0;

    MR_IN(85)

    if (x==y)
    { /* Illegal parameter usage */
        mr_berror(_MIPP_ MR_ERR_BAD_PARAMETERS);
        MR_OUT
        
        return 0;
    }
    redc(_MIPP_ y,mr_mip->w6);
    gcd=invmodp(_MIPP_ mr_mip->w6,mr_mip->modulus,mr_mip->w6);
   
    if (gcd!=1) zero(w); /* fails silently and returns 0 */
    else
    {
        nres(_MIPP_ mr_mip->w6,mr_mip->w6);
        nres_modmult(_MIPP_ x,mr_mip->w6,w);
    /*    mad(_MIPP_ x,mr_mip->w6,x,mr_mip->modulus,mr_mip->modulus,w); */
    }
    MR_OUT
    return gcd;
}

void nres_premult(_MIPD_ big x,int k,big w)
{ /* multiply n-residue by small ordinary integer */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    int sign=0;
    if (k==0) 
    {
        zero(w);
        return;
    }
    if (k<0)
    {
        k=-k;
        sign=1;
    }
    if (mr_mip->ERNUM) return;

    MR_IN(102)

    if (k<=6)
    {
        switch (k)
        {
        case 1: copy(x,w);
                break;
        case 2: nres_modadd(_MIPP_ x,x,w);
                break;    
        case 3:
                nres_modadd(_MIPP_ x,x,mr_mip->w0);
                nres_modadd(_MIPP_ x,mr_mip->w0,w);
                break;
        case 4:
                nres_modadd(_MIPP_ x,x,w);
                nres_modadd(_MIPP_ w,w,w);
                break;    
        case 5:
                nres_modadd(_MIPP_ x,x,mr_mip->w0);
                nres_modadd(_MIPP_ mr_mip->w0,mr_mip->w0,mr_mip->w0);
                nres_modadd(_MIPP_ x,mr_mip->w0,w);
                break;
        case 6:
                nres_modadd(_MIPP_ x,x,w);
                nres_modadd(_MIPP_ w,w,mr_mip->w0);
                nres_modadd(_MIPP_ w,mr_mip->w0,w);
                break;
        }
        if (sign==1) nres_negate(_MIPP_ w,w);
        MR_OUT
        return;
    }

    mr_pmul(_MIPP_ x,(mr_small)k,mr_mip->w0);
#ifdef MR_COMBA
#ifdef MR_SPECIAL
	comba_redc(_MIPP_ mr_mip->w0,w);
#else
	divide(_MIPP_ mr_mip->w0,mr_mip->modulus,mr_mip->modulus);
	copy(mr_mip->w0,w);
#endif
#else
    divide(_MIPP_ mr_mip->w0,mr_mip->modulus,mr_mip->modulus);
	copy(mr_mip->w0,w);
#endif 
	
    if (sign==1) nres_negate(_MIPP_ w,w);

    MR_OUT
}

void nres_modmult(_MIPD_ big x,big y,big w)
{ /* Modular multiplication using n-residues w=x*y mod n */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if ((x==NULL || x->len==0) && x==w) return;
    if ((y==NULL || y->len==0) && y==w) return;
    if (y==NULL || x==NULL || x->len==0 || y->len==0)
    {
        zero(w);
        return;
    }
#ifdef MR_COUNT_OPS
fpc++;
#endif
#ifdef MR_COMBA
    if (mr_mip->ACTIVE)
    {
        if (x==y) comba_square(x,mr_mip->w0);
        else      comba_mult(x,y,mr_mip->w0);
        comba_redc(_MIPP_ mr_mip->w0,w);
    }
    else
    {
#endif
#ifdef MR_KCM
    if (mr_mip->ACTIVE)
    {
        if (x==y) kcm_sqr(_MIPP_ x,mr_mip->w0);
        else      kcm_mul(_MIPP_ x,y,mr_mip->w0);
        kcm_redc(_MIPP_ mr_mip->w0,w);
    }
    else
    { 
#endif
#ifdef MR_PENTIUM
    if (mr_mip->ACTIVE)
    {
        if (x==y) fastmodsquare(_MIPP_ x,w);
        else      fastmodmult(_MIPP_ x,y,w);
    }
    else
    { 
#endif
        if (mr_mip->ERNUM) return;

        MR_IN(83)

        mr_mip->check=OFF;
        multiply(_MIPP_ x,y,mr_mip->w0);
        redc(_MIPP_ mr_mip->w0,w);
        mr_mip->check=ON;
        MR_OUT
#ifdef MR_COMBA
}
#endif
#ifdef MR_KCM
}
#endif
#ifdef MR_PENTIUM
}
#endif

}

/* Montgomery's trick for finding multiple   *
 * simultaneous modular inverses             *
 * Based on the observation that             *
 *           1/x = yz*(1/xyz)                *
 *           1/y = xz*(1/xyz)                *
 *           1/z = xy*(1/xyz)                *
 * Why are all of Peter Montgomery's clever  *
 * algorithms always described as "tricks" ??*/

BOOL nres_double_inverse(_MIPD_ big x,big y,big w,big z)
{ /* find y=1/x mod n and z=1/w mod n */
  /* 1/x = w/xw, and 1/w = x/xw       */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    MR_IN(145)

    nres_modmult(_MIPP_ x,w,mr_mip->w6);  /* xw */

    if (size(mr_mip->w6)==0)
    {
        mr_berror(_MIPP_ MR_ERR_DIV_BY_ZERO);
        MR_OUT
        return FALSE;
    }
    redc(_MIPP_ mr_mip->w6,mr_mip->w6);
    redc(_MIPP_ mr_mip->w6,mr_mip->w6);
    invmodp(_MIPP_ mr_mip->w6,mr_mip->modulus,mr_mip->w6);

    nres_modmult(_MIPP_ w,mr_mip->w6,mr_mip->w5);
    nres_modmult(_MIPP_ x,mr_mip->w6,z);
    copy(mr_mip->w5,y);

    MR_OUT
    return TRUE;
}

BOOL nres_multi_inverse(_MIPD_ int m,big *x,big *w)
{ /* find w[i]=1/x[i] mod n, for i=0 to m-1 *
   * x and w MUST be distinct               */
    int i;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (m==0) return TRUE;
    if (m<0) return FALSE;
    MR_IN(118)

    if (x==w)
    {
        mr_berror(_MIPP_ MR_ERR_BAD_PARAMETERS);
        MR_OUT
        return FALSE;
    }

    if (m==1)
    {
        copy(mr_mip->one,w[0]);
        nres_moddiv(_MIPP_ w[0],x[0],w[0]);
        MR_OUT
        return TRUE;
    }

    convert(_MIPP_ 1,w[0]);
    copy(x[0],w[1]);
    for (i=2;i<m;i++)
        nres_modmult(_MIPP_ w[i-1],x[i-1],w[i]); 

    nres_modmult(_MIPP_ w[m-1],x[m-1],mr_mip->w6);  /* y=x[0]*x[1]*x[2]....x[m-1] */
    if (size(mr_mip->w6)==0)
    {
        mr_berror(_MIPP_ MR_ERR_DIV_BY_ZERO);
        MR_OUT
        return FALSE;
    }

    redc(_MIPP_ mr_mip->w6,mr_mip->w6);
    redc(_MIPP_ mr_mip->w6,mr_mip->w6);

    invmodp(_MIPP_ mr_mip->w6,mr_mip->modulus,mr_mip->w6);

/* Now y=1/y */

    copy(x[m-1],mr_mip->w5);
    nres_modmult(_MIPP_ w[m-1],mr_mip->w6,w[m-1]);

    for (i=m-2;;i--)
    {
        if (i==0)
        {
            nres_modmult(_MIPP_ mr_mip->w5,mr_mip->w6,w[0]);
            break;
        }
        nres_modmult(_MIPP_ w[i],mr_mip->w5,w[i]);
        nres_modmult(_MIPP_ w[i],mr_mip->w6,w[i]);
        nres_modmult(_MIPP_ mr_mip->w5,x[i],mr_mip->w5);
    }

    MR_OUT 
    return TRUE;   
}

/* initialise elliptic curve */

void ecurve_init(_MIPD_ big a,big b,big p,int type)
{ /* Initialize the active ecurve    *
   * Asize indicate size of A        *
   * Bsize indicate size of B        */
    int as;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(93)

#ifndef MR_NO_SS
    mr_mip->SS=FALSE;       /* no special support for super-singular curves */ 
#endif

    prepare_monty(_MIPP_ p);

    mr_mip->Asize=size(a);
    if (mr_abs(mr_mip->Asize)==MR_TOOBIG)
    {
        if (mr_mip->Asize>=0)
        { /* big positive number - check it isn't minus something small */
           copy(a,mr_mip->w1);
           divide(_MIPP_ mr_mip->w1,p,p);
           subtract(_MIPP_ p,mr_mip->w1,mr_mip->w1);
           as=size(mr_mip->w1);
           if (as<MR_TOOBIG) mr_mip->Asize=-as;
        }
    }
    nres(_MIPP_ a,mr_mip->A);

    mr_mip->Bsize=size(b);
    if (mr_abs(mr_mip->Bsize)==MR_TOOBIG) 
    {
        if (mr_mip->Bsize>=0)
        { /* big positive number - check it isn't minus something small */
           copy(b,mr_mip->w1);
           divide(_MIPP_ mr_mip->w1,p,p);
           subtract(_MIPP_ p,mr_mip->w1,mr_mip->w1);
           as=size(mr_mip->w1);
           if (as<MR_TOOBIG) mr_mip->Bsize=-as;
        }
    }

    nres(_MIPP_ b,mr_mip->B);
#ifdef MR_EDWARDS
    mr_mip->coord=MR_PROJECTIVE; /* only type supported for Edwards curves */
#else
#ifndef MR_AFFINE_ONLY
    if (type==MR_BEST) mr_mip->coord=MR_PROJECTIVE;
    else mr_mip->coord=type;
#else
    if (type==MR_PROJECTIVE)
        mr_berror(_MIPP_ MR_ERR_NOT_SUPPORTED);
#endif
#endif
    MR_OUT
    return;
}
