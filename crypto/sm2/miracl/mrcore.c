
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
 *   MIRACL Core module - contains initialisation code and general purpose 
 *   utilities
 *   mrcore.c
 *
 *   Space can be saved by removing unneeded functions (mr_and ?) 
 *
 */

#include "miracl.h"
#include <stdlib.h>
#include <string.h>


#ifdef MR_FP
#include <math.h>
#endif


/*** Multi-Threaded Support ***/

#ifndef MR_GENERIC_MT

  #ifdef MR_OPENMP_MT
    #include <omp.h>

#define MR_MIP_EXISTS

    miracl *mr_mip;
    #pragma omp threadprivate(mr_mip)
    
    miracl *get_mip()
    {
        return mr_mip; 
    }

    void mr_init_threading()
    {
    }

    void mr_end_threading()
    {
    }

  #endif

  #ifdef MR_WINDOWS_MT
    #include <windows.h>
    DWORD mr_key;   

    miracl *get_mip()
    {
        return (miracl *)TlsGetValue(mr_key); 
    }

    void mr_init_threading()
    {
        mr_key=TlsAlloc();
    }

    void mr_end_threading()
    {
        TlsFree(mr_key);
    }

  #endif

  #ifdef MR_UNIX_MT
    #include <pthread.h>
    pthread_key_t mr_key;

    miracl *get_mip()
    {
        return (miracl *)pthread_getspecific(mr_key); 
    }

    void mr_init_threading()
    {
        pthread_key_create(&mr_key,(void(*)(void *))NULL);
    }

    void mr_end_threading()
    {
        pthread_key_delete(mr_key);
    }
  #endif

  #ifndef MR_WINDOWS_MT
    #ifndef MR_UNIX_MT
      #ifndef MR_OPENMP_MT
        #ifdef MR_STATIC
          miracl mip;
          miracl *mr_mip=&mip;
        #else
          miracl *mr_mip=NULL;  /* MIRACL's one and only global variable */
        #endif
#define MR_MIP_EXISTS
        miracl *get_mip()
        {
          return (miracl *)mr_mip; 
        }
      #endif
    #endif
  #endif

#ifdef MR_MIP_EXISTS
    void set_mip(miracl *mip)
    {
        mr_mip=mip;
    }
#endif

#endif

/* See Advanced Windows by Jeffrey Richter, Chapter 12 for methods for
   creating different instances of this global for each executing thread 
   when using Windows '95/NT
*/

#ifdef MR_STATIC

#if MIRACL==8

static const int mr_small_primes[]=
{2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,
107,109,113,127,0};

#else

static const int mr_small_primes[]=
{2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,
107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,
223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,
337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,
457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,
593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,
719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,
857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,
997,0};

#endif

#endif

#ifndef MR_STRIPPED_DOWN
#ifndef MR_NO_STANDARD_IO

static char *names[] =
{(char *)"your program",(char *)"innum",(char *)"otnum",(char *)"jack",(char *)"normalise",
(char *)"multiply",(char *)"divide",(char *)"incr",(char *)"decr",(char *)"premult",
(char *)"subdiv",(char *)"fdsize",(char *)"egcd",(char *)"cbase",
(char *)"cinnum",(char *)"cotnum",(char *)"nroot",(char *)"power",
(char *)"powmod",(char *)"bigdig",(char *)"bigrand",(char *)"nxprime",(char *)"isprime",
(char *)"mirvar",(char *)"mad",(char *)"multi_inverse",(char *)"putdig",
(char *)"add",(char *)"subtract",(char *)"mirsys",(char *)"xgcd",
(char *)"fpack",(char *)"dconv",(char *)"mr_shift",(char *)"mround",(char *)"fmul",
(char *)"fdiv",(char *)"fadd",(char *)"fsub",(char *)"fcomp",(char *)"fconv",
(char *)"frecip",(char *)"fpmul",(char *)"fincr",(char *)"",(char *)"ftrunc",
(char *)"frand",(char *)"sftbit",(char *)"build",(char *)"logb2",(char *)"expint",
(char *)"fpower",(char *)"froot",(char *)"fpi",(char *)"fexp",(char *)"flog",(char *)"fpowf",
(char *)"ftan",(char *)"fatan",(char *)"fsin",(char *)"fasin",(char *)"fcos",(char *)"facos",
(char *)"ftanh",(char *)"fatanh",(char *)"fsinh",(char *)"fasinh",(char *)"fcosh",
(char *)"facosh",(char *)"flop",(char *)"gprime",(char *)"powltr",(char *)"fft_mult",
(char *)"crt_init",(char *)"crt",(char *)"otstr",(char *)"instr",(char *)"cotstr",(char *)"cinstr",(char *)"powmod2",
(char *)"prepare_monty",(char *)"nres",(char *)"redc",(char *)"nres_modmult",(char *)"nres_powmod",
(char *)"nres_moddiv",(char *)"nres_powltr",(char *)"divisible",(char *)"remain",
(char *)"fmodulo",(char *)"nres_modadd",(char *)"nres_modsub",(char *)"nres_negate",
(char *)"ecurve_init",(char *)"ecurve_add",(char *)"ecurve_mult",
(char *)"epoint_init",(char *)"epoint_set",(char *)"epoint_get",(char *)"nres_powmod2",
(char *)"nres_sqroot",(char *)"sqroot",(char *)"nres_premult",(char *)"ecurve_mult2",
(char *)"ecurve_sub",(char *)"trial_division",(char *)"nxsafeprime",(char *)"nres_lucas",(char *)"lucas",
(char *)"brick_init",(char *)"pow_brick",(char *)"set_user_function",
(char *)"nres_powmodn",(char *)"powmodn",(char *)"ecurve_multn",
(char *)"ebrick_init",(char *)"mul_brick",(char *)"epoint_norm",(char *)"nres_multi_inverse",(char *)"",
(char *)"nres_dotprod",(char *)"epoint_negate",(char *)"ecurve_multi_add",
(char *)"ecurve2_init",(char *)"",(char *)"epoint2_set",(char *)"epoint2_norm",(char *)"epoint2_get",
(char *)"epoint2_comp",(char *)"ecurve2_add",(char *)"epoint2_negate",(char *)"ecurve2_sub",
(char *)"ecurve2_multi_add",(char *)"ecurve2_mult",(char *)"ecurve2_multn",(char *)"ecurve2_mult2",
(char *)"ebrick2_init",(char *)"mul2_brick",(char *)"prepare_basis",(char *)"strong_bigrand",
(char *)"bytes_to_big",(char *)"big_to_bytes",(char *)"set_io_buffer_size",
(char *)"epoint_getxyz",(char *)"epoint_double_add",(char *)"nres_double_inverse",
(char *)"double_inverse",(char *)"epoint_x",(char *)"hamming",(char *)"expb2",(char *)"bigbits",
(char *)"nres_lazy",(char *)"zzn2_imul",(char *)"nres_double_modadd",(char *)"nres_double_modsub",
/*155*/(char *)"",(char *)"zzn2_from_int",(char *)"zzn2_negate",(char *)"zzn2_conj",(char *)"zzn2_add",
(char *)"zzn2_sub",(char *)"zzn2_smul",(char *)"zzn2_mul",(char *)"zzn2_inv",(char *)"zzn2_timesi",(char *)"zzn2_powl",
(char *)"zzn2_from_bigs",(char *)"zzn2_from_big",(char *)"zzn2_from_ints",
(char *)"zzn2_sadd",(char *)"zzn2_ssub",(char *)"zzn2_times_irp",(char *)"zzn2_div2",
(char *)"zzn3_from_int",(char *)"zzn3_from_ints",(char *)"zzn3_from_bigs",
(char *)"zzn3_from_big",(char *)"zzn3_negate",(char *)"zzn3_powq",(char *)"zzn3_init",
(char *)"zzn3_add",(char *)"zzn3_sadd",(char *)"zzn3_sub",(char *)"zzn3_ssub",(char *)"zzn3_smul",
(char *)"zzn3_imul",(char *)"zzn3_mul",(char *)"zzn3_inv",(char *)"zzn3_div2",(char *)"zzn3_timesi",
(char *)"epoint_multi_norm",(char *)"mr_jsf",(char *)"epoint2_multi_norm",
(char *)"ecn2_compare",(char *)"ecn2_norm",(char *)"ecn2_set",(char *)"zzn2_txx",
(char *)"zzn2_txd",(char *)"nres_div2",(char *)"nres_div3",(char *)"zzn2_div3",
(char *)"ecn2_setx",(char *)"ecn2_rhs",(char *)"zzn2_qr",(char *)"zzn2_sqrt",(char *)"ecn2_add",(char *)"ecn2_mul2_jsf",(char *)"ecn2_mul",
(char *)"nres_div5",(char *)"zzn2_div5",(char *)"zzn2_sqr",(char *)"ecn2_add_sub",(char *)"ecn2_psi",(char *)"invmodp",
(char *)"zzn2_multi_inverse",(char *)"ecn2_multi_norm",(char *)"ecn2_precomp",(char *)"ecn2_mul4_gls_v",
(char *)"ecn2_mul2",(char *)"ecn2_precomp_gls",(char *)"ecn2_mul2_gls",
(char *)"ecn2_brick_init",(char *)"ecn2_mul_brick_gls",(char *)"ecn2_multn",(char *)"zzn3_timesi2",
(char *)"nres_complex",(char *)"zzn4_from_int",(char *)"zzn4_negate",(char *)"zzn4_conj",(char *)"zzn4_add",(char *)"zzn4_sadd",(char *)"zzn4_sub",(char *)"zzn4_ssub",(char *)"zzn4_smul",(char *)"zzn4_sqr",
(char *)"zzn4_mul",(char *)"zzn4_inv",(char *)"zzn4_div2",(char *)"zzn4_powq",(char *)"zzn4_tx",(char *)"zzn4_imul",(char *)"zzn4_lmul",(char *)"zzn4_from_big",
(char *)"ecn2_mult4"};

/* 0 - 243 (244 in all) */

#endif
#endif

#ifdef MR_NOASM

/* C only versions of muldiv/muldvd/muldvd2/muldvm */
/* Note that mr_large should be twice the size of mr_small */

mr_small muldiv(mr_small a,mr_small b,mr_small c,mr_small m,mr_small *rp)
{
    mr_small q;
    mr_large ldres,p=(mr_large)a*b+c;
    q=(mr_small)(MR_LROUND(p/m));
    *rp=(mr_small)(p-(mr_large)q*m);
    return q;
}

#ifdef MR_FP_ROUNDING

mr_small imuldiv(mr_small a,mr_small b,mr_small c,mr_small m,mr_large im,mr_small *rp)
{
    mr_small q;
    mr_large ldres,p=(mr_large)a*b+c;
    q=(mr_small)MR_LROUND(p*im);
    *rp=(mr_small)(p-(mr_large)q*m);
    return q;
}

#endif

#ifndef MR_NOFULLWIDTH

mr_small muldvm(mr_small a,mr_small c,mr_small m,mr_small *rp)
{
    mr_small q;
    union doubleword dble;
    dble.h[MR_BOT]=c;
    dble.h[MR_TOP]=a;

    q=(mr_small)(dble.d/m);
    *rp=(mr_small)(dble.d-(mr_large)q*m);
    return q;
}

mr_small muldvd(mr_small a,mr_small b,mr_small c,mr_small *rp)
{
    union doubleword dble;
    dble.d=(mr_large)a*b+c;

    *rp=dble.h[MR_BOT];
    return dble.h[MR_TOP];
}

void muldvd2(mr_small a,mr_small b,mr_small *c,mr_small *rp)
{
    union doubleword dble;
    dble.d=(mr_large)a*b+*c+*rp;
    *rp=dble.h[MR_BOT];
    *c=dble.h[MR_TOP];
}

#endif
#endif

#ifdef MR_NOFULLWIDTH

/* no FULLWIDTH working, so supply dummies */

/*

mr_small muldvd(mr_small a,mr_small b,mr_small c,mr_small *rp)
{
    return (mr_small)0;
}

mr_small muldvm(mr_small a,mr_small c,mr_small m,mr_small *rp)
{
    return (mr_small)0;
}

void muldvd2(mr_small a,mr_small b,mr_small *c,mr_small *rp)
{
}

*/

#endif

#ifndef MR_NO_STANDARD_IO

static void mputs(char *s)
{ /* output a string */
    int i=0;
    while (s[i]!=0) fputc((int)s[i++],stdout);
}
#endif

void mr_berror(_MIPD_ int nerr)
{  /*  Big number error routine  */
#ifndef MR_STRIPPED_DOWN
int i;
#endif

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

if (mr_mip->ERCON)
{
    mr_mip->ERNUM=nerr;
    return;
}
#ifndef MR_NO_STANDARD_IO

#ifndef MR_STRIPPED_DOWN
mputs((char *)"\nMIRACL error from routine ");
if (mr_mip->depth<MR_MAXDEPTH) mputs(names[mr_mip->trace[mr_mip->depth]]);
else                           mputs((char *)"???");
fputc('\n',stdout);

for (i=mr_mip->depth-1;i>=0;i--)
{
    mputs((char *)"              called from ");
    if (i<MR_MAXDEPTH) mputs(names[mr_mip->trace[i]]);
    else               mputs((char *)"???");
    fputc('\n',stdout);
}

switch (nerr)
{
case 1 :
mputs((char *)"Number base too big for representation\n");
break;
case 2 :
mputs((char *)"Division by zero attempted\n");
break;
case 3 : 
mputs((char *)"Overflow - Number too big\n");
break;
case 4 :
mputs((char *)"Internal result is negative\n");
break;
case 5 : 
mputs((char *)"Input format error\n");
break;
case 6 :
mputs((char *)"Illegal number base\n");
break;
case 7 : 
mputs((char *)"Illegal parameter usage\n");
break;
case 8 :
mputs((char *)"Out of space\n");
break;
case 9 :
mputs((char *)"Even root of a negative number\n");
break;
case 10:
mputs((char *)"Raising integer to negative power\n");
break;
case 11:
mputs((char *)"Attempt to take illegal root\n");
break;
case 12:
mputs((char *)"Integer operation attempted on Flash number\n");
break;
case 13:
mputs((char *)"Flash overflow\n");
break;
case 14:
mputs((char *)"Numbers too big\n");
break;
case 15:
mputs((char *)"Log of a non-positive number\n");
break;
case 16:
mputs((char *)"Flash to double conversion failure\n");
break;
case 17:
mputs((char *)"I/O buffer overflow\n");
break;
case 18:
mputs((char *)"MIRACL not initialised - no call to mirsys()\n");
break;
case 19:
mputs((char *)"Illegal modulus \n");
break;
case 20:
mputs((char *)"No modulus defined\n");
break;
case 21:
mputs((char *)"Exponent too big\n");
break;
case 22:
mputs((char *)"Unsupported Feature - check mirdef.h\n");
break;
case 23:
mputs((char *)"Specified double length type isn't double length\n");
break;
case 24:
mputs((char *)"Specified basis is NOT irreducible\n");
break;
case 25:
mputs((char *)"Unable to control Floating-point rounding\n");
break;
case 26:
mputs((char *)"Base must be binary (MR_ALWAYS_BINARY defined in mirdef.h ?)\n");
break;
case 27:
mputs((char *)"No irreducible basis defined\n");
break;
case 28:
mputs((char *)"Composite modulus\n");
break;
case 29:
mputs((char *)"Input/output error when reading from RNG device node\n");
break;
default:
mputs((char *)"Undefined error\n");
break;
}
exit(0);
#else
mputs((char *)"MIRACL error\n");
exit(0);
#endif

#endif
}

#ifndef MR_STRIPPED_DOWN

void mr_track(_MIPDO_ )
{ /* track course of program execution *
   * through the MIRACL routines       */

#ifndef MR_NO_STANDARD_IO

    int i;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    for (i=0;i<mr_mip->depth;i++) fputc('-',stdout);
    fputc('>',stdout);
    mputs(names[mr_mip->trace[mr_mip->depth]]);
    fputc('\n',stdout);
#endif
}

#endif

#ifndef MR_NO_RAND

mr_small brand(_MIPDO_ )
{ /* Marsaglia & Zaman random number generator */
    int i,k;
    mr_unsign32 pdiff,t;
    mr_small r;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->lg2b>32)
    { /* underlying type is > 32 bits. Assume <= 64 bits */
        mr_mip->rndptr+=2;
        if (mr_mip->rndptr<NK-1)
        {
            r=(mr_small)mr_mip->ira[mr_mip->rndptr];
            r=mr_shiftbits(r,mr_mip->lg2b-32);
            r+=(mr_small)mr_mip->ira[mr_mip->rndptr+1];
            return r;
        }
    }
    else
    {
        mr_mip->rndptr++;
        if (mr_mip->rndptr<NK) return (mr_small)mr_mip->ira[mr_mip->rndptr];
    }
    mr_mip->rndptr=0;
    for (i=0,k=NK-NJ;i<NK;i++,k++)
    { /* calculate next NK values */
        if (k==NK) k=0;
        t=mr_mip->ira[k];
        pdiff=t - mr_mip->ira[i] - mr_mip->borrow;
        if (pdiff<t) mr_mip->borrow=0;
        if (pdiff>t) mr_mip->borrow=1;
        mr_mip->ira[i]=pdiff; 
    }
    if (mr_mip->lg2b>32)
    { /* double up */
        r=(mr_small)mr_mip->ira[0];
        r=mr_shiftbits(r,mr_mip->lg2b-32);
        r+=(mr_small)mr_mip->ira[1];
        return r;
    }
    else return (mr_small)(mr_mip->ira[0]);
}

void irand(_MIPD_ mr_unsign32 seed)
{ /* initialise random number system */
    int i,in;
    mr_unsign32 t,m=1L;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    mr_mip->borrow=0L;
    mr_mip->rndptr=0;
    mr_mip->ira[0]=seed;
    for (i=1;i<NK;i++)
    { /* fill initialisation vector */
        in=(NV*i)%NK;
        mr_mip->ira[in]=m; 
        t=m;
        m=seed-m;
        seed=t;
    }
    for (i=0;i<1000;i++) brand(_MIPPO_ ); /* "warm-up" & stir the generator */
}

#endif

mr_small mr_shiftbits(mr_small x,int n)
{
#ifdef MR_FP
    int i;
    mr_small dres;
    if (n==0) return x;
    if (n>0)
    {
        for (i=0;i<n;i++) x=x+x;
        return x;
    }
    n=-n;
    for (i=0;i<n;i++) x=MR_DIV(x,2.0);
    return x;
#else
    if (n==0) return x;
    if (n>0) x<<=n;
    else x>>=(-n);
    return x;
#endif

}

mr_small mr_setbase(_MIPD_ mr_small nb)
{  /* set base. Pack as many digits as  *
    * possible into each computer word  */
    mr_small temp;
#ifdef MR_FP
    mr_small dres;
#endif
#ifndef MR_NOFULLWIDTH
    BOOL fits;
    int bits;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    fits=FALSE;
    bits=MIRACL;
    while (bits>1) 
    {
        bits/=2;
        temp=((mr_small)1<<bits);
        if (temp==nb)
        {
            fits=TRUE;
            break;
        }
        if (temp<nb || (bits%2)!=0) break;
    }
    if (fits)
    {
        mr_mip->apbase=nb;
        mr_mip->pack=MIRACL/bits;
        mr_mip->base=0;
        return 0;
    }
#endif
    mr_mip->apbase=nb;
    mr_mip->pack=1;
    mr_mip->base=nb;
#ifdef MR_SIMPLE_BASE
    return 0;
#else
    if (mr_mip->base==0) return 0;
    temp=MR_DIV(MAXBASE,nb);
    while (temp>=nb)
    {
        temp=MR_DIV(temp,nb);
        mr_mip->base*=nb;
        mr_mip->pack++;
    }
#ifdef MR_FP_ROUNDING
    mr_mip->inverse_base=mr_invert(mr_mip->base);
    return mr_mip->inverse_base;
#else
    return 0;
#endif
#endif
}

#ifdef MR_FLASH

BOOL fit(big x,big y,int f)
{ /* returns TRUE if x/y would fit flash format of length f */
    int n,d;
    n=(int)(x->len&(MR_OBITS));
    d=(int)(y->len&(MR_OBITS));
    if (n==1 && x->w[0]==1) n=0;
    if (d==1 && y->w[0]==1) d=0;
    if (n+d<=f) return TRUE;
    return FALSE;
}

#endif

int mr_lent(flash x)
{ /* return length of big or flash in words */
    mr_lentype lx;
    lx=(x->len&(MR_OBITS));
#ifdef MR_FLASH
    return (int)((lx&(MR_MSK))+((lx>>(MR_BTS))&(MR_MSK)));
#else
    return (int)lx;
#endif
}

void zero(flash x)
{ /* set big/flash number to zero */
    int i,n;
    mr_small *g;
    if (x==NULL) return;
#ifdef MR_FLASH
    n=mr_lent(x);
#else
    n=(x->len&MR_OBITS);
#endif
    g=x->w;

    for (i=0;i<n;i++)
        g[i]=0;

    x->len=0;
}

void uconvert(_MIPD_ unsigned int n ,big x)
{  /*  convert unsigned integer n to big number format  */
    int m;
#ifdef MR_FP
    mr_small dres;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    zero(x);
    if (n==0) return;
    
    m=0;
#ifndef MR_SIMPLE_BASE
    if (mr_mip->base==0)
    {
#endif
#ifndef MR_NOFULLWIDTH
#if MR_IBITS > MIRACL
        while (n>0)
        {
            x->w[m++]=(mr_small)(n%((mr_small)1<<(MIRACL)));
            n/=((mr_small)1<<(MIRACL));
        }
#else
        x->w[m++]=(mr_small)n;
#endif
#endif
#ifndef MR_SIMPLE_BASE
    }
    else while (n>0)
    {
        x->w[m++]=MR_REMAIN((mr_small)n,mr_mip->base);
		n=(unsigned int)((mr_small)n/mr_mip->base);
    }
#endif
    x->len=m;
}

void tconvert(_MIPD_ mr_utype n,big x)
{
	mr_lentype s;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (n==0) {zero(x); return;}
    s=0;
    if (n<0)
    {
        s=MR_MSBIT;
        n=(-n);
    }
	x->w[0]=n;
	x->len=1;
    x->len|=s;
}

void convert(_MIPD_ int n ,big x)
{  /*  convert signed integer n to big number format  */
    mr_lentype s;

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (n==0) {zero(x); return;}
    s=0;
    if (n<0)
    {
        s=MR_MSBIT;
        n=(-n);
    }
    uconvert(_MIPP_ (unsigned int)n,x);
    x->len|=s;
}

#ifndef MR_STATIC
#ifdef mr_dltype

void dlconv(_MIPD_ mr_dltype n,big x)
{ /* convert double length integer to big number format - rarely needed */
    int m;
    mr_lentype s;
#ifdef MR_FP
    mr_small dres;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    zero(x);
    if (n==0) return;
    s=0;
    if (n<0)
    {
        s=MR_MSBIT;
        n=(-n);
    }
    m=0;
#ifndef MR_SIMPLE_BASE
    if (mr_mip->base==0)
    {
#endif
#ifndef MR_NOFULLWIDTH
        while (n>0)
        {
            x->w[m++]=(mr_small)(n%((mr_dltype)1<<(MIRACL)));
            n/=((mr_dltype)1<<(MIRACL));
        }
#endif
#ifndef MR_SIMPLE_BASE
    }    
    else while (n>0)
    {
        x->w[m++]=(mr_small)MR_REMAIN(n,mr_mip->base);
        n/=mr_mip->base;
    }
#endif
    x->len=(m|s);
}

#endif

void ulgconv(_MIPD_ unsigned long n,big x)
{ /* convert unsigned long integer to big number format - rarely needed */
    int m;
#ifdef MR_FP
    mr_small dres;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    zero(x);
    if (n==0) return;

    m=0;
#ifndef MR_SIMPLE_BASE
    if (mr_mip->base==0)
    {
#endif
#ifndef MR_NOFULLWIDTH
#if MR_LBITS > MIRACL
        while (n>0)
        {
            x->w[m++]=(mr_small)(n%(1L<<(MIRACL)));
            n/=(1L<<(MIRACL));
        }
#else
        x->w[m++]=(mr_small)n;
#endif
#endif
#ifndef MR_SIMPLE_BASE
    }    
    else while (n>0)
    {
        x->w[m++]=MR_REMAIN(n,mr_mip->base);
		n=(unsigned long)((mr_small)n/mr_mip->base);
    }
#endif
    x->len=m;
}

void lgconv(_MIPD_ long n,big x)
{ /* convert signed long integer to big number format - rarely needed */
    mr_lentype s;

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (n==0) {zero(x); return;}
    s=0;
    if (n<0)
    {
        s=MR_MSBIT;
        n=(-n);
    }
    ulgconv(_MIPP_ (unsigned long)n,x);

    x->len|=s;
}

flash mirvar(_MIPD_ int iv)
{ /* initialize big/flash number */
    flash x;
    int align;
    char *ptr;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
 
    if (mr_mip->ERNUM) return NULL;
    MR_IN(23);  

    if (!(mr_mip->active))
    {
        mr_berror(_MIPP_ MR_ERR_NO_MIRSYS);
        MR_OUT  
        return NULL;
    }

/* OK, now I control alignment.... */

/* Allocate space for big, the length, the pointer, and the array */
/* Do it all in one memory allocation - this is quicker */
/* Ensure that the array has correct alignment */

    x=(big)mr_alloc(_MIPP_ mr_size(mr_mip->nib-1),1);
    if (x==NULL)
    {
        MR_OUT 
        return x;
    }
    
    ptr=(char *)&x->w;
    align=(unsigned long)(ptr+sizeof(mr_small *))%sizeof(mr_small);   

    x->w=(mr_small *)(ptr+sizeof(mr_small *)+sizeof(mr_small)-align);   

    if (iv!=0) convert(_MIPP_ iv,x);
    MR_OUT 
    return x;
}

#endif

flash mirvar_mem_variable(char *mem,int index,int sz)
{
    flash x;
    int align;
    char *ptr;
    int offset,r;

/* alignment */
    offset=0;
    r=(unsigned long)mem%MR_SL;
    if (r>0) offset=MR_SL-r;

    x=(big)&mem[offset+mr_size(sz)*index];
    ptr=(char *)&x->w;
    align=(unsigned long)(ptr+sizeof(mr_small *))%sizeof(mr_small);   
    x->w=(mr_small *)(ptr+sizeof(mr_small *)+sizeof(mr_small)-align);   

    return x;
}

flash mirvar_mem(_MIPD_ char *mem,int index)
{ /* initialize big/flash number from pre-allocated memory */
 
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
 
    if (mr_mip->ERNUM) return NULL;

    return mirvar_mem_variable(mem,index,mr_mip->nib-1);

}

void set_user_function(_MIPD_ BOOL (*user)(void))
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(111)

    if (!(mr_mip->active))
    {
        mr_berror(_MIPP_ MR_ERR_NO_MIRSYS);
        MR_OUT
        return;
    }

    mr_mip->user=user;

    MR_OUT
}

#ifndef MR_STATIC

#ifndef MR_SIMPLE_IO

void set_io_buffer_size(_MIPD_ int len)
{
    int i;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (len<0) return;
    MR_IN(142)
    for (i=0;i<mr_mip->IOBSIZ;i++) mr_mip->IOBUFF[i]=0;
    mr_free(mr_mip->IOBUFF);
    if (len==0) 
    {
        MR_OUT
        return;
    }
    mr_mip->IOBSIZ=len;
    mr_mip->IOBUFF=(char *)mr_alloc(_MIPP_ len+1,1);
    mr_mip->IOBUFF[0]='\0';
    MR_OUT
}
#endif

#endif

/* Initialise a big from ROM given its fixed length */

BOOL init_big_from_rom(big x,int len,const mr_small *rom,int romsize,int *romptr)
{
    int i;
    zero(x);
    x->len=len;
    for (i=0;i<len;i++)
    {
        if (*romptr>=romsize) return FALSE;
#ifdef MR_AVR
        x->w[i]=pgm_read_byte_near(&rom[*romptr]);
#else
        x->w[i]=rom[*romptr];
#endif
        (*romptr)++;
    }

    mr_lzero(x);
    return TRUE;
}

/* Initialise an elliptic curve point from ROM */

BOOL init_point_from_rom(epoint *P,int len,const mr_small *rom,int romsize,int *romptr)
{
    if (!init_big_from_rom(P->X,len,rom,romsize,romptr)) return FALSE;
    if (!init_big_from_rom(P->Y,len,rom,romsize,romptr)) return FALSE;
    P->marker=MR_EPOINT_NORMALIZED;
    return TRUE;
}

#ifdef MR_GENERIC_AND_STATIC
miracl *mirsys(miracl *mr_mip,int nd,mr_small nb)
#else
miracl *mirsys(int nd,mr_small nb)
#endif
{  /*  Initialize MIRACL system to   *
    *  use numbers to base nb, and   *
    *  nd digits or (-nd) bytes long */

/* In these cases mr_mip is passed as the first parameter */

#ifdef MR_GENERIC_AND_STATIC
	return mirsys_basic(mr_mip,nd,nb);
#endif

#ifdef MR_GENERIC_MT
#ifndef MR_STATIC
	miracl *mr_mip=mr_first_alloc();
    return mirsys_basic(mr_mip,nd,nb);
#endif
#endif
/* In these cases mr_mip is a "global" pointer and the mip itself is allocated from the heap. 
   In fact mr_mip (and mip) may be thread specific if some multi-threading scheme is implemented */
#ifndef MR_STATIC
 #ifdef MR_WINDOWS_MT
    miracl *mr_mip=mr_first_alloc();
    TlsSetValue(mr_key,mr_mip);
 #endif

 #ifdef MR_UNIX_MT
    miracl *mr_mip=mr_first_alloc(); 
    pthread_setspecific(mr_key,mr_mip);    
 #endif

 #ifdef MR_OPENMP_MT
    mr_mip=mr_first_alloc(); 
 #endif

 #ifndef MR_WINDOWS_MT
   #ifndef MR_UNIX_MT
     #ifndef MR_OPENMP_MT
       mr_mip=mr_first_alloc();
     #endif
   #endif
 #endif
#endif

#ifndef MR_GENERIC_MT
    mr_mip=get_mip();
#endif
    return mirsys_basic(mr_mip,nd,nb);
}

miracl *mirsys_basic(miracl *mr_mip,int nd,mr_small nb)
{
#ifndef MR_NO_RAND
    int i;
#endif
   
    mr_small b,nw;
#ifdef MR_FP
    mr_small dres;
#endif

    if (mr_mip==NULL) return NULL;

#ifndef MR_STRIPPED_DOWN
    mr_mip->depth=0;
    mr_mip->trace[0]=0;
    mr_mip->depth++;
    mr_mip->trace[mr_mip->depth]=29;
#endif           
                    /* digest hardware configuration */

#ifdef MR_NO_STANDARD_IO
    mr_mip->ERCON=TRUE;
#else
    mr_mip->ERCON=FALSE;
#endif
#ifndef MR_STATIC
    mr_mip->logN=0;
    mr_mip->degree=0;
    mr_mip->chin.NP=0;
#endif


    mr_mip->user=NULL;
    mr_mip->same=FALSE;
    mr_mip->first_one=FALSE;
    mr_mip->debug=FALSE;
	mr_mip->AA=0;
#ifndef MR_AFFINE_ONLY
    mr_mip->coord=MR_NOTSET;
#endif

#ifdef MR_NOFULLWIDTH
    if (nb==0)
    {
        mr_berror(_MIPP_ MR_ERR_BAD_BASE);
        MR_OUT
        return mr_mip;
    }
#endif

#ifndef MR_FP
#ifdef mr_dltype
#ifndef MR_NOFULLWIDTH
    if (sizeof(mr_dltype)<2*sizeof(mr_utype))
    { /* double length type, isn't */
        mr_berror(_MIPP_ MR_ERR_NOT_DOUBLE_LEN);
        MR_OUT
        return mr_mip;
    }
#endif
#endif
#endif

    if (nb==1 || nb>MAXBASE)
    {
        mr_berror(_MIPP_ MR_ERR_BAD_BASE);
        MR_OUT
        return mr_mip;
    }

#ifdef MR_FP_ROUNDING
    if (mr_setbase(_MIPP_ nb)==0)
    { /* unable in fact to control FP rounding */
        mr_berror(_MIPP_ MR_ERR_NO_ROUNDING);
        MR_OUT
        return mr_mip;
    }
#else
    mr_setbase(_MIPP_ nb);
#endif

    b=mr_mip->base;

#ifdef MR_SIMPLE_BASE
    if (b!=0)
    {
        mr_berror(_MIPP_ MR_ERR_BAD_BASE);
        MR_OUT
        return mr_mip;
    }
#endif

    mr_mip->lg2b=0;
    mr_mip->base2=1;
#ifndef MR_SIMPLE_BASE
    if (b==0)
    {
#endif
        mr_mip->lg2b=MIRACL;
        mr_mip->base2=0;
#ifndef MR_SIMPLE_BASE
    }
    else while (b>1)
    {
        b=MR_DIV(b,2);
        mr_mip->lg2b++;
        mr_mip->base2*=2;
    }
#endif

#ifdef MR_ALWAYS_BINARY
    if (mr_mip->base!=mr_mip->base2) 
    {
        mr_berror(_MIPP_ MR_ERR_NOT_BINARY);
        MR_OUT
        return mr_mip;
    }
#endif

/* calculate total space for bigs */
/*

 big -> |int len|small *ptr| alignment space | size in words +1| alignment up to multiple of 4 | 


*/
    if (nd>0) nw=MR_ROUNDUP(nd,mr_mip->pack);
    else      nw=MR_ROUNDUP(8*(-nd),mr_mip->lg2b);

    if (nw<1) nw=1;
    mr_mip->nib=(int)(nw+1);   /* add one extra word for small overflows */

#ifdef MR_STATIC
    if (nw>MR_STATIC)
    {
        mr_berror(_MIPP_ MR_ERR_TOO_BIG);
        MR_OUT
        return mr_mip;
    }
#endif

   /* mr_mip->nib=(int)(nw+1);    add one extra word for small overflows */     

#ifdef MR_FLASH
    mr_mip->workprec=mr_mip->nib;
    mr_mip->stprec=mr_mip->nib;
    while (mr_mip->stprec>2 && mr_mip->stprec>MR_FLASH/mr_mip->lg2b) 
        mr_mip->stprec=(mr_mip->stprec+1)/2;
    if (mr_mip->stprec<2) mr_mip->stprec=2;
   
#endif

#ifndef MR_DOUBLE_BIG
    mr_mip->check=ON;
#else
    mr_mip->check=OFF;
#endif

#ifndef MR_SIMPLE_BASE
#ifndef MR_SIMPLE_IO
    mr_mip->IOBASE=10;   /* defaults */
#endif
#endif
    mr_mip->ERNUM=0;
    
    mr_mip->NTRY=6;
    mr_mip->MONTY=ON;
#ifdef MR_FLASH
    mr_mip->EXACT=TRUE;
    mr_mip->RPOINT=OFF;
#endif
#ifndef MR_STRIPPED_DOWN
    mr_mip->TRACER=OFF;
#endif

#ifndef MR_SIMPLE_IO
    mr_mip->INPLEN=0;
    mr_mip->IOBSIZ=MR_DEFAULT_BUFFER_SIZE;
#endif

#ifdef MR_STATIC
    mr_mip->PRIMES=mr_small_primes;
#else
    mr_mip->PRIMES=NULL;
#ifndef MR_SIMPLE_IO
    mr_mip->IOBUFF=(char *)mr_alloc(_MIPP_ MR_DEFAULT_BUFFER_SIZE+1,1);
#endif
#endif
#ifndef MR_SIMPLE_IO
    mr_mip->IOBUFF[0]='\0';
#endif
    mr_mip->qnr=0;
    mr_mip->cnr=0;
    mr_mip->TWIST=0;
    mr_mip->pmod8=0;
	mr_mip->pmod9=0;

/* quick start for rng. irand(.) should be called first before serious use.. */

#ifndef MR_NO_RAND
    mr_mip->ira[0]=0x55555555;
    mr_mip->ira[1]=0x12345678;

    for (i=2;i<NK;i++) 
        mr_mip->ira[i]=mr_mip->ira[i-1]+mr_mip->ira[i-2]+0x1379BDF1;
    mr_mip->rndptr=NK;
    mr_mip->borrow=0;
#endif

    mr_mip->nib=2*mr_mip->nib+1;
#ifdef MR_FLASH
    if (mr_mip->nib!=(mr_mip->nib&(MR_MSK)))
#else
    if (mr_mip->nib!=(int)(mr_mip->nib&(MR_OBITS)))
#endif
    {
        mr_berror(_MIPP_ MR_ERR_TOO_BIG);
        mr_mip->nib=(mr_mip->nib-1)/2;
        MR_OUT
        return mr_mip;
    }
#ifndef MR_STATIC
    mr_mip->workspace=(char *)memalloc(_MIPP_ MR_SPACES);  /* grab workspace */
#else
    memset(mr_mip->workspace,0,MR_BIG_RESERVE(MR_SPACES));
#endif

    mr_mip->M=0;
    mr_mip->fin=FALSE;
    mr_mip->fout=FALSE;
    mr_mip->active=ON;
    
    mr_mip->nib=(mr_mip->nib-1)/2;

/* allocate memory for workspace variables */
   
#ifndef MR_DOUBLE_BIG

    mr_mip->w0=mirvar_mem(_MIPP_ mr_mip->workspace,0);  /* double length */
    mr_mip->w1=mirvar_mem(_MIPP_ mr_mip->workspace,2);
    mr_mip->w2=mirvar_mem(_MIPP_ mr_mip->workspace,3);
    mr_mip->w3=mirvar_mem(_MIPP_ mr_mip->workspace,4);
    mr_mip->w4=mirvar_mem(_MIPP_ mr_mip->workspace,5);
    mr_mip->w5=mirvar_mem(_MIPP_ mr_mip->workspace,6);  /* double length */
    mr_mip->w6=mirvar_mem(_MIPP_ mr_mip->workspace,8);  /* double length */
    mr_mip->w7=mirvar_mem(_MIPP_ mr_mip->workspace,10); /* double length */
    mr_mip->w8=mirvar_mem(_MIPP_ mr_mip->workspace,12);
    mr_mip->w9=mirvar_mem(_MIPP_ mr_mip->workspace,13);
    mr_mip->w10=mirvar_mem(_MIPP_ mr_mip->workspace,14);
    mr_mip->w11=mirvar_mem(_MIPP_ mr_mip->workspace,15);
    mr_mip->w12=mirvar_mem(_MIPP_ mr_mip->workspace,16);
    mr_mip->w13=mirvar_mem(_MIPP_ mr_mip->workspace,17);
    mr_mip->w14=mirvar_mem(_MIPP_ mr_mip->workspace,18);
    mr_mip->w15=mirvar_mem(_MIPP_ mr_mip->workspace,19);
    mr_mip->sru=mirvar_mem(_MIPP_ mr_mip->workspace,20);
    mr_mip->modulus=mirvar_mem(_MIPP_ mr_mip->workspace,21);
    mr_mip->pR=mirvar_mem(_MIPP_ mr_mip->workspace,22); /* double length */
    mr_mip->A=mirvar_mem(_MIPP_ mr_mip->workspace,24);
    mr_mip->B=mirvar_mem(_MIPP_ mr_mip->workspace,25);
    mr_mip->one=mirvar_mem(_MIPP_ mr_mip->workspace,26);
#ifdef MR_KCM
    mr_mip->big_ndash=mirvar_mem(_MIPP_ mr_mip->workspace,27);
    mr_mip->ws=mirvar_mem(_MIPP_ mr_mip->workspace,28);
    mr_mip->wt=mirvar_mem(_MIPP_ mr_mip->workspace,29); /* double length */
#endif
#ifdef MR_FLASH
#ifdef MR_KCM
    mr_mip->pi=mirvar_mem(_MIPP_ mr_mip->workspace,31);
#else
    mr_mip->pi=mirvar_mem(_MIPP_ mr_mip->workspace,27);
#endif
#endif

#else
/* w0-w7 are double normal length */
    mr_mip->w0=mirvar_mem(_MIPP_ mr_mip->workspace,0);  /* quad length */
    mr_mip->w1=mirvar_mem(_MIPP_ mr_mip->workspace,4);  /* double length */
    mr_mip->w2=mirvar_mem(_MIPP_ mr_mip->workspace,6);
    mr_mip->w3=mirvar_mem(_MIPP_ mr_mip->workspace,8);
    mr_mip->w4=mirvar_mem(_MIPP_ mr_mip->workspace,10);
    mr_mip->w5=mirvar_mem(_MIPP_ mr_mip->workspace,12);  /* quad length */
    mr_mip->w6=mirvar_mem(_MIPP_ mr_mip->workspace,16);  /* quad length */
    mr_mip->w7=mirvar_mem(_MIPP_ mr_mip->workspace,20);  /* quad length */
    mr_mip->w8=mirvar_mem(_MIPP_ mr_mip->workspace,24);

    mr_mip->w9=mirvar_mem(_MIPP_ mr_mip->workspace,25);
    mr_mip->w10=mirvar_mem(_MIPP_ mr_mip->workspace,26);
    mr_mip->w11=mirvar_mem(_MIPP_ mr_mip->workspace,27);
    mr_mip->w12=mirvar_mem(_MIPP_ mr_mip->workspace,28);
    mr_mip->w13=mirvar_mem(_MIPP_ mr_mip->workspace,29);
    mr_mip->w14=mirvar_mem(_MIPP_ mr_mip->workspace,30);
    mr_mip->w15=mirvar_mem(_MIPP_ mr_mip->workspace,31);
    mr_mip->sru=mirvar_mem(_MIPP_ mr_mip->workspace,32);
    mr_mip->modulus=mirvar_mem(_MIPP_ mr_mip->workspace,33);
    mr_mip->pR=mirvar_mem(_MIPP_ mr_mip->workspace,34); /* double length */
    mr_mip->A=mirvar_mem(_MIPP_ mr_mip->workspace,36);
    mr_mip->B=mirvar_mem(_MIPP_ mr_mip->workspace,37);
    mr_mip->one=mirvar_mem(_MIPP_ mr_mip->workspace,38);
#ifdef MR_KCM
    mr_mip->big_ndash=mirvar_mem(_MIPP_ mr_mip->workspace,39);
    mr_mip->ws=mirvar_mem(_MIPP_ mr_mip->workspace,40);
    mr_mip->wt=mirvar_mem(_MIPP_ mr_mip->workspace,41); /* double length */
#endif
#ifdef MR_FLASH
#ifdef MR_KCM
    mr_mip->pi=mirvar_mem(_MIPP_ mr_mip->workspace,43);
#else
    mr_mip->pi=mirvar_mem(_MIPP_ mr_mip->workspace,39);
#endif
#endif

#endif
    MR_OUT
    return mr_mip;
} 

#ifndef MR_STATIC

/* allocate space for a number of bigs from the heap */

void *memalloc(_MIPD_ int num)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    return mr_alloc(_MIPP_ mr_big_reserve(num,mr_mip->nib-1),1);
}

#endif

void memkill(_MIPD_ char *mem,int len)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mem==NULL) return;
    memset(mem,0,mr_big_reserve(len,mr_mip->nib-1));
#ifndef MR_STATIC
    mr_free(mem);
#endif
}

#ifndef MR_STATIC

void mirkill(big x)
{ /* kill a big/flash variable, that is set it to zero
     and free its memory */
    if (x==NULL) return;
    zero(x);
    mr_free(x);
}

#endif

void mirexit(_MIPDO_ )
{ /* clean up after miracl */

    int i;
#ifdef MR_WINDOWS_MT
    miracl *mr_mip=get_mip();
#endif
#ifdef MR_UNIX_MT
    miracl *mr_mip=get_mip();
#endif
#ifdef MR_OPENMP_MT
    miracl *mr_mip=get_mip();
#endif
    mr_mip->ERCON=FALSE;
    mr_mip->active=OFF;
    memkill(_MIPP_ mr_mip->workspace,MR_SPACES);
#ifndef MR_NO_RAND
    for (i=0;i<NK;i++) mr_mip->ira[i]=0L;
#endif
#ifndef MR_STATIC
#ifndef MR_SIMPLE_IO
    set_io_buffer_size(_MIPP_ 0);
#endif
    if (mr_mip->PRIMES!=NULL) mr_free(mr_mip->PRIMES);
#else
#ifndef MR_SIMPLE_IO
    for (i=0;i<=MR_DEFAULT_BUFFER_SIZE;i++)
        mr_mip->IOBUFF[i]=0;
#endif
#endif

#ifndef MR_STATIC
    mr_free(mr_mip);
#ifdef MR_WINDOWS_MT
	TlsSetValue(mr_key, NULL);		/* Thank you Thales */
#endif
#endif

#ifndef MR_GENERIC_MT
#ifndef MR_WINDOWS_MT
#ifndef MR_UNIX_MT
#ifndef MR_STATIC
    mr_mip=NULL;
#endif
#endif   
#endif   
#endif  
    
#ifdef MR_OPENMP_MT
    mr_mip=NULL;
#endif

}

int exsign(flash x)
{ /* extract sign of big/flash number */
    if ((x->len&(MR_MSBIT))==0) return PLUS;
    else                        return MINUS;    
}

void insign(int s,flash x)
{  /* assert sign of big/flash number */
    if (x->len==0) return;
    if (s<0) x->len|=MR_MSBIT;
    else     x->len&=MR_OBITS;
}   

void mr_lzero(big x)
{  /*  strip leading zeros from big number  */
    mr_lentype s;
    int m;
    s=(x->len&(MR_MSBIT));
    m=(int)(x->len&(MR_OBITS));
    while (m>0 && x->w[m-1]==0)
        m--;
    x->len=m;
    if (m>0) x->len|=s;
}

#ifndef MR_SIMPLE_IO

int getdig(_MIPD_ big x,int i)
{  /* extract a packed digit */
    int k;
    mr_small n;
#ifdef MR_FP
    mr_small dres;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    i--;
    n=x->w[i/mr_mip->pack];

    if (mr_mip->pack==1) return (int)n;
    k=i%mr_mip->pack;
    for (i=1;i<=k;i++)
        n=MR_DIV(n,mr_mip->apbase);  
    return (int)MR_REMAIN(n,mr_mip->apbase);
}

int numdig(_MIPD_ big x)
{  /* returns number of digits in x */
    int nd;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    if (x->len==0) return 0;

    nd=(int)(x->len&(MR_OBITS))*mr_mip->pack;
    while (getdig(_MIPP_ x,nd)==0)
        nd--;
    return nd;
} 

void putdig(_MIPD_ int n,big x,int i)
{  /* insert a digit into a packed word */
    int j,k,lx;
    mr_small m,p;
    mr_lentype s;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(26)

    s=(x->len&(MR_MSBIT));
    lx=(int)(x->len&(MR_OBITS));
    m=getdig(_MIPP_ x,i);
    p=n;
    i--;
    j=i/mr_mip->pack;
    k=i%mr_mip->pack;
    for (i=1;i<=k;i++)
    {
        m*=mr_mip->apbase;
        p*=mr_mip->apbase;
    }
    if (j>=mr_mip->nib && (mr_mip->check || j>=2*mr_mip->nib))
    {
        mr_berror(_MIPP_ MR_ERR_OVERFLOW);
        MR_OUT
        return;
    }

    x->w[j]=(x->w[j]-m)+p;
    if (j>=lx) x->len=((j+1)|s);
    mr_lzero(x);
    MR_OUT
}

#endif

#ifndef MR_FP

void mr_and(big x,big y,big z)
{ /* z= bitwise logical AND of x and y */
    int i,nx,ny,nz,nr;
    if (x==y) 
    {
        copy(x,z);
        return;
    }

#ifdef MR_FLASH
    nx=mr_lent(x);
    ny=mr_lent(y);
    nz=mr_lent(z);
#else
    ny=(y->len&(MR_OBITS));
    nx=(x->len&(MR_OBITS));
    nz=(z->len&(MR_OBITS));
#endif
    if (ny<nx) nr=ny;
    else       nr=nx;
    for (i=0;i<nr;i++)
        z->w[i]=x->w[i]&y->w[i];
    for (i=nr;i<nz;i++) 
        z->w[i]=0;
    z->len=nr;
}

void mr_xor(big x,big y,big z)
{ 
     int i,nx,ny,nz,nr;
     if (x==y)
     {
         copy(x,z);
         return;
     }

#ifdef MR_FLASH
     nx=mr_lent(x);
     ny=mr_lent(y);
     nz=mr_lent(z);
#else
     ny=(y->len&(MR_OBITS));
     nx=(x->len&(MR_OBITS));
     nz=(z->len&(MR_OBITS));
#endif
     if (ny<nx) nr=nx;
     else       nr=ny;

     for (i=0;i<nr;i++)
         z->w[i]=x->w[i]^y->w[i];
     for (i=nr;i<nz;i++)
         z->w[i]=0;
     z->len=nr;
}

#endif

void copy(flash x,flash y)
{  /* copy x to y: y=x  */
    int i,nx,ny;
    mr_small *gx,*gy;
    if (x==y || y==NULL) return;

    if (x==NULL)
    { 
        zero(y);
        return;
    }

#ifdef MR_FLASH    
    ny=mr_lent(y);
    nx=mr_lent(x);
#else
    ny=(y->len&(MR_OBITS));
    nx=(x->len&(MR_OBITS));
#endif

    gx=x->w;
    gy=y->w;

    for (i=nx;i<ny;i++)
        gy[i]=0;
    for (i=0;i<nx;i++)
        gy[i]=gx[i];
    y->len=x->len;

}

void negify(flash x,flash y)
{ /* negate a big/flash variable: y=-x */
    copy(x,y);
    if (y->len!=0) y->len^=MR_MSBIT;
}

void absol(flash x,flash y)
{ /* y=abs(x) */
    copy(x,y);
    y->len&=MR_OBITS;
}

BOOL mr_notint(flash x)
{ /* returns TRUE if x is Flash */
#ifdef MR_FLASH
    if ((((x->len&(MR_OBITS))>>(MR_BTS))&(MR_MSK))!=0) return TRUE;
#endif
    return FALSE;
}

void mr_shift(_MIPD_ big x,int n,big w)
{ /* set w=x.(mr_base^n) by shifting */
    mr_lentype s;
    int i,bl;
    mr_small *gw=w->w;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    copy(x,w);
    if (w->len==0 || n==0) return;
    MR_IN(33)

    if (mr_notint(w)) mr_berror(_MIPP_ MR_ERR_INT_OP);
    s=(w->len&(MR_MSBIT));
    bl=(int)(w->len&(MR_OBITS))+n;
    if (bl<=0)
    {
        zero(w);
        MR_OUT
        return;
    }
    if (bl>mr_mip->nib && mr_mip->check) mr_berror(_MIPP_ MR_ERR_OVERFLOW);
    if (mr_mip->ERNUM)
    {
        MR_OUT
        return;
    }
    if (n>0)
    {
        for (i=bl-1;i>=n;i--)
            gw[i]=gw[i-n];
        for (i=0;i<n;i++)
            gw[i]=0;
    }
    else
    {
        n=(-n);
        for (i=0;i<bl;i++)
            gw[i]=gw[i+n];
        for (i=0;i<n;i++)
            gw[bl+i]=0;
    }
    w->len=(bl|s);
    MR_OUT
}

int size(big x)
{  /*  get size of big number;  convert to *
    *  integer - if possible               */
    int n,m;
    mr_lentype s;
    if (x==NULL) return 0;
    s=(x->len&MR_MSBIT);
    m=(int)(x->len&MR_OBITS);
    if (m==0) return 0;
    if (m==1 && x->w[0]<(mr_small)MR_TOOBIG) n=(int)x->w[0];
    else                                     n=MR_TOOBIG;
    if (s==MR_MSBIT) return (-n);
    return n;
}

int mr_compare(big x,big y)
{  /* compare x and y: =1 if x>y  =-1 if x<y *
    *  =0 if x=y                             */
    int m,n,sig;
    mr_lentype sx,sy;
    if (x==y) return 0;
    sx=(x->len&MR_MSBIT);
    sy=(y->len&MR_MSBIT);
    if (sx==0) sig=PLUS;
    else       sig=MINUS;
    if (sx!=sy) return sig;
    m=(int)(x->len&MR_OBITS);
    n=(int)(y->len&MR_OBITS);
    if (m>n) return sig;
    if (m<n) return -sig;
    while (m>0)
    { /* check digit by digit */
        m--;  
        if (x->w[m]>y->w[m]) return sig;
        if (x->w[m]<y->w[m]) return -sig;
    }
    return 0;
}

#ifdef MR_FLASH

void fpack(_MIPD_ big n,big d,flash x)
{ /* create floating-slash number x=n/d from *
   * big integer numerator and denominator   */
    mr_lentype s;
    int i,ld,ln;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(31)

    ld=(int)(d->len&MR_OBITS);
    if (ld==0) mr_berror(_MIPP_ MR_ERR_FLASH_OVERFLOW);
    if (ld==1 && d->w[0]==1) ld=0;
    if (x==d) mr_berror(_MIPP_ MR_ERR_BAD_PARAMETERS);
    if (mr_notint(n) || mr_notint(d)) mr_berror(_MIPP_ MR_ERR_INT_OP);
    s=(n->len&MR_MSBIT);
    ln=(int)(n->len&MR_OBITS);
    if (ln==1 && n->w[0]==1) ln=0;
    if ((ld+ln>mr_mip->nib) && (mr_mip->check || ld+ln>2*mr_mip->nib)) 
        mr_berror(_MIPP_ MR_ERR_FLASH_OVERFLOW);
    if (mr_mip->ERNUM)
    {
       MR_OUT
       return;
    }
    copy(n,x);
    if (n->len==0)
    {
        MR_OUT
        return;
    }
    s^=(d->len&MR_MSBIT);
    if (ld==0)
    {
        if (x->len!=0) x->len|=s;
        MR_OUT
        return;
    }
    for (i=0;i<ld;i++)
        x->w[ln+i]=d->w[i];
    x->len=(s|(ln+((mr_lentype)ld<<MR_BTS)));
    MR_OUT
}

void numer(_MIPD_ flash x,big y)
{ /* extract numerator of x */
    int i,ln,ld;
    mr_lentype s,ly;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    if (mr_notint(x))
    {
        s=(x->len&MR_MSBIT);
        ly=(x->len&MR_OBITS);
        ln=(int)(ly&MR_MSK);
        if (ln==0)
        {
            if(s==MR_MSBIT) convert(_MIPP_ (-1),y);
            else            convert(_MIPP_ 1,y);
            return;
        }
        ld=(int)((ly>>MR_BTS)&MR_MSK);
        if (x!=y)
        {
            for (i=0;i<ln;i++) y->w[i]=x->w[i];
            for (i=ln;i<mr_lent(y);i++) y->w[i]=0;
        }
        else for (i=0;i<ld;i++) y->w[ln+i]=0;
        y->len=(ln|s);
    }
    else copy(x,y);
}

void denom(_MIPD_ flash x,big y)
{ /* extract denominator of x */
    int i,ln,ld;
    mr_lentype ly;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    if (!mr_notint(x))
    {
        convert(_MIPP_ 1,y);
        return;
    }
    ly=(x->len&MR_OBITS);
    ln=(int)(ly&MR_MSK);
    ld=(int)((ly>>MR_BTS)&MR_MSK);
    for (i=0;i<ld;i++)
        y->w[i]=x->w[ln+i];
    if (x==y) for (i=0;i<ln;i++) y->w[ld+i]=0;
    else for (i=ld;i<mr_lent(y);i++) y->w[i]=0;
    y->len=ld;
}

#endif

unsigned int igcd(unsigned int x,unsigned int y)
{ /* integer GCD, returns GCD of x and y */
    unsigned int r;
    if (y==0) return x;
    while ((r=x%y)!=0)
        x=y,y=r;
    return y;
}

unsigned long lgcd(unsigned long x,unsigned long y)
{ /* long GCD, returns GCD of x and y */
    unsigned long r;
    if (y==0) return x;
    while ((r=x%y)!=0)
        x=y,y=r;
    return y;
}

unsigned int isqrt(unsigned int num,unsigned int guess)
{ /* square root of an integer */
    unsigned int sqr;
    unsigned int oldguess=guess;
    if (num==0) return 0;
    if (num<4) return 1;
  
    for (;;)
    { /* Newtons iteration */
     /*   sqr=guess+(((num/guess)-guess)/2); */
        sqr=((num/guess)+guess)/2;
        if (sqr==guess || sqr==oldguess) 
        {
            if (sqr*sqr>num) sqr--;
            return sqr;
        }
        oldguess=guess;
        guess=sqr;
    }
}

unsigned long mr_lsqrt(unsigned long num,unsigned long guess)
{ /* square root of a long */
    unsigned long sqr;
    unsigned long oldguess=guess;
    if (num==0) return 0;
    if (num<4) return 1;
  
    for (;;)
    { /* Newtons iteration */
     /*   sqr=guess+(((num/guess)-guess)/2); */
        sqr=((num/guess)+guess)/2;
        if (sqr==guess || sqr==oldguess) 
        {
            if (sqr*sqr>num) sqr--;
            return sqr;
        }
        oldguess=guess;
        guess=sqr;
    }
}

mr_small sgcd(mr_small x,mr_small y)
{ /* integer GCD, returns GCD of x and y */
    mr_small r;
#ifdef MR_FP
    mr_small dres;
#endif
    if (y==(mr_small)0) return x;
    while ((r=MR_REMAIN(x,y))!=(mr_small)0)
        x=y,y=r;
    return y;
}

/* routines to support sliding-windows exponentiation *
 * in various contexts */

int mr_testbit(_MIPD_ big x,int n)
{ /* return value of n-th bit of big */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
#ifdef MR_FP
    mr_small m,a,dres;
    m=mr_shiftbits((mr_small)1,n%mr_mip->lg2b);

    a=x->w[n/mr_mip->lg2b];

    a=MR_DIV(a,m); 

    if ((MR_DIV(a,2.0)*2.0) != a) return 1;
#else
    if ((x->w[n/mr_mip->lg2b] & ((mr_small)1<<(n%mr_mip->lg2b))) >0) return 1;
#endif
    return 0;
}

void mr_addbit(_MIPD_ big x,int n)
{ /* add 2^n to positive x - where you know that bit is zero. Use with care! */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    mr_lentype m=n/mr_mip->lg2b;
    x->w[m]+=mr_shiftbits((mr_small)1,n%mr_mip->lg2b);
    if (x->len<m+1) x->len=m+1;
}

int recode(_MIPD_ big e,int t,int w,int i)
{ /* recode exponent for Comb method */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    int j,r;
    r=0;
    for (j=w-1;j>=0;j--)
    {
        r<<=1;
        r|=mr_testbit(_MIPP_ e,i+j*t);
    }
    return r;
}

int mr_window(_MIPD_ big x,int i,int *nbs,int * nzs,int window_size)
{ /* returns sliding window value, max. of 5 bits,         *
   * (Note from version 5.23 this can be changed by        *
   * setting parameter window_size. This can be            *
   * a useful space-saver) starting at i-th bit of big x.  *
   * nbs is number of bits processed, nzs is the number of *
   * additional trailing zeros detected. Returns valid bit *
   * pattern 1x..x1 with no two adjacent 0's. So 10101     *
   * will return 21 with nbs=5, nzs=0. 11001 will return 3,*
   * with nbs=2, nzs=2, having stopped after the first 11..*/
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    int j,r,w;
    w=window_size;

/* check for leading 0 bit */

    *nbs=1;
    *nzs=0;
    if (!mr_testbit(_MIPP_ x,i)) return 0;

/* adjust window size if not enough bits left */
   
    if (i-w+1<0) w=i+1;

    r=1;
    for (j=i-1;j>i-w;j--)
    { /* accumulate bits. Abort if two 0's in a row */
        (*nbs)++;
        r*=2;
        if (mr_testbit(_MIPP_ x,j)) r+=1;
        if (r%4==0)
        { /* oops - too many zeros - shorten window */
            r/=4;
            *nbs-=2;
            *nzs=2;
            break;
        }
    }
    if (r%2==0)
    { /* remove trailing 0 */
        r/=2;
        *nzs=1;
        (*nbs)--;
    }
    return r;
}

int mr_window2(_MIPD_ big x,big y,int i,int *nbs,int *nzs)
{ /* two bit window for double exponentiation */
    int r,w;
    BOOL a,b,c,d;
    w=2;
    *nbs=1;
    *nzs=0;

/* check for two leading 0's */
    a=mr_testbit(_MIPP_ x,i); b=mr_testbit(_MIPP_ y,i);

    if (!a && !b) return 0;
    if (i<1) w=1;

    if (a)
    {
        if (b) r=3;
        else   r=2;
    }
    else r=1;
    if (w==1) return r;

    c=mr_testbit(_MIPP_ x,i-1); d=mr_testbit(_MIPP_ y,i-1);

    if (!c && !d) 
    {
        *nzs=1;
        return r;
    }

    *nbs=2;
    r*=4;
    if (c)
    {
        if (d) r+=3;
        else   r+=2;
    }
    else r+=1;
    return r;
}

int mr_naf_window(_MIPD_ big x,big x3,int i,int *nbs,int *nzs,int store)
{ /* returns sliding window value, using fractional windows   *
   * where "store" precomputed values are precalulated and    *
   * stored. Scanning starts at the i-th bit of  x. nbs is    *
   * the number of bits processed. nzs is number of           *
   * additional trailing zeros detected. x and x3 (which is   *
   * 3*x) are combined to produce the NAF (non-adjacent       *
   * form). So if x=11011(27) and x3 is 1010001, the LSB is   *
   * ignored and the value 100T0T (32-4-1=27) processed,      *
   * where T is -1. Note x.P = (3x-x)/2.P. This value will    *
   * return +7, with nbs=4 and nzs=1, having stopped after    *
   * the first 4 bits. If it goes too far, it must backtrack  *
   * Note in an NAF non-zero elements are never side by side, *
   * so 10T10T won't happen. NOTE: return value n zero or     * 
   * odd, -21 <= n <= +21     */

    int nb,j,r,biggest;

 /* get first bit */
    nb=mr_testbit(_MIPP_ x3,i)-mr_testbit(_MIPP_ x,i);

    *nbs=1;
    *nzs=0;
    if (nb==0) return 0;
    if (i==0) return nb;

    biggest=2*store-1;

    if (nb>0) r=1;
    else      r=(-1);

    for (j=i-1;j>0;j--)
    {
        (*nbs)++;
        r*=2;
        nb=mr_testbit(_MIPP_ x3,j)-mr_testbit(_MIPP_ x,j);
        if (nb>0) r+=1;
        if (nb<0) r-=1;
        if (abs(r)>biggest) break;
    }

    if (r%2!=0 && j!=0)
    { /* backtrack */
        if (nb>0) r=(r-1)/2;
        if (nb<0) r=(r+1)/2;
        (*nbs)--;
    }
    
    while (r%2==0)
    { /* remove trailing zeros */
        r/=2;
        (*nzs)++;
        (*nbs)--;
    }     
    return r;
}

/* Some general purpose elliptic curve stuff */

BOOL point_at_infinity(epoint *p)
{
    if (p==NULL) return FALSE;
    if (p->marker==MR_EPOINT_INFINITY) return TRUE;
    return FALSE;
}

#ifndef MR_STATIC

epoint* epoint_init(_MIPDO_ )
{ /* initialise epoint to general point at infinity. */
    epoint *p;
    char *ptr;

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return NULL;

    MR_IN(96)

/* Create space for whole structure in one heap access */ 

    p=(epoint *)mr_alloc(_MIPP_ mr_esize(mr_mip->nib-1),1);

    ptr=(char *)p+sizeof(epoint);
    p->X=mirvar_mem(_MIPP_ ptr,0);
    p->Y=mirvar_mem(_MIPP_ ptr,1);
#ifndef MR_AFFINE_ONLY
    p->Z=mirvar_mem(_MIPP_ ptr,2);
#endif
    p->marker=MR_EPOINT_INFINITY;

    MR_OUT

    return p;
}

#endif

epoint* epoint_init_mem_variable(_MIPD_ char *mem,int index,int sz)
{
    epoint *p;
    char *ptr;
    int offset,r;

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    offset=0;
    r=(unsigned long)mem%MR_SL;
    if (r>0) offset=MR_SL-r;

#ifndef MR_AFFINE_ONLY
    if (mr_mip->coord==MR_AFFINE)
        p=(epoint *)&mem[offset+index*mr_esize_a(sz)];
    else
#endif
    p=(epoint *)&mem[offset+index*mr_esize(sz)];

    ptr=(char *)p+sizeof(epoint);
    p->X=mirvar_mem_variable(ptr,0,sz);
    p->Y=mirvar_mem_variable(ptr,1,sz);
#ifndef MR_AFFINE_ONLY
    if (mr_mip->coord!=MR_AFFINE) p->Z=mirvar_mem_variable(ptr,2,sz);
#endif
    p->marker=MR_EPOINT_INFINITY;
    return p;
}

epoint* epoint_init_mem(_MIPD_ char *mem,int index)
{ 
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return NULL;

    return epoint_init_mem_variable(_MIPP_ mem,index,mr_mip->nib-1);
}

#ifndef MR_STATIC

/* allocate space for a number of epoints from the heap */

void *ecp_memalloc(_MIPD_ int num)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

#ifndef MR_AFFINE_ONLY
    if (mr_mip->coord==MR_AFFINE)
        return mr_alloc(_MIPP_  mr_ecp_reserve_a(num,mr_mip->nib-1),1);
    else
#endif
        return mr_alloc(_MIPP_  mr_ecp_reserve(num,mr_mip->nib-1),1);
}

#endif

void ecp_memkill(_MIPD_ char *mem,int num)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    if (mem==NULL) return;

#ifndef MR_AFFINE_ONLY
    if (mr_mip->coord==MR_AFFINE)
        memset(mem,0,mr_ecp_reserve_a(num,mr_mip->nib-1));
    else
#endif
        memset(mem,0,mr_ecp_reserve(num,mr_mip->nib-1));


#ifndef MR_STATIC
    mr_free(mem);
#endif
}

#ifndef MR_STATIC

void epoint_free(epoint *p)
{ /* clean up point */
 
    if (p==NULL) return;
    zero(p->X);
    zero(p->Y);
#ifndef MR_AFFINE_ONLY
    if (p->marker==MR_EPOINT_GENERAL) zero(p->Z);
#endif
    mr_free(p);
}        

#endif
