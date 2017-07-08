
/***************************************************************************
                                                                           *
Copyright 2013 CertiVox UK Ltd.                                           *
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
 *   MIRACL F_p^2 support functions 
 *   mrzzn2.c
 */

#include <stdlib.h> 
#include <openssl/miracl.h>

#ifdef MR_COUNT_OPS
extern int fpmq,fpsq,fpaq; 
#endif

BOOL zzn2_iszero(zzn2 *x)
{
    if (size(x->a)==0 && size(x->b)==0) return TRUE;
    return FALSE;
}

BOOL zzn2_isunity(_MIPD_ zzn2 *x)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM || size(x->b)!=0) return FALSE;

    if (mr_compare(x->a,mr_mip->one)==0) return TRUE;
    return FALSE;

}

BOOL zzn2_compare(zzn2 *x,zzn2 *y)
{
    if (mr_compare(x->a,y->a)==0 && mr_compare(x->b,y->b)==0) return TRUE;
    return FALSE;
}

void zzn2_from_int(_MIPD_ int i,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(156)
    if (i==1) 
    {
        copy(mr_mip->one,w->a);
    }
    else
    {
        convert(_MIPP_ i,mr_mip->w1);
        nres(_MIPP_ mr_mip->w1,w->a);
    }
    zero(w->b);
    MR_OUT
}

void zzn2_from_ints(_MIPD_ int i,int j,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(168)
    convert(_MIPP_ i,mr_mip->w1);
    nres(_MIPP_ mr_mip->w1,w->a);
    convert(_MIPP_ j,mr_mip->w1);
    nres(_MIPP_ mr_mip->w1,w->b);

    MR_OUT
}

void zzn2_from_zzns(big x,big y,zzn2 *w)
{
    copy(x,w->a);
    copy(y,w->b);
}

void zzn2_from_bigs(_MIPD_ big x,big y, zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(166)
    nres(_MIPP_ x,w->a);
    nres(_MIPP_ y,w->b);
    MR_OUT
}

void zzn2_from_zzn(big x,zzn2 *w)
{
    copy(x,w->a);
    zero(w->b);
}

void zzn2_from_big(_MIPD_ big x, zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(167)
    nres(_MIPP_ x,w->a);
    zero(w->b);
    MR_OUT
}

void zzn2_copy(zzn2 *x,zzn2 *w)
{
    if (x==w) return;
    copy(x->a,w->a);
    copy(x->b,w->b);
}

void zzn2_zero(zzn2 *w)
{
    zero(w->a);
    zero(w->b);
}

void zzn2_negate(_MIPD_ zzn2 *x,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(157)
    zzn2_copy(x,w);
    nres_negate(_MIPP_ w->a,w->a);
    nres_negate(_MIPP_ w->b,w->b);
    MR_OUT
}

void zzn2_conj(_MIPD_ zzn2 *x,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    MR_IN(158)
    if (mr_mip->ERNUM) return;
    zzn2_copy(x,w);
    nres_negate(_MIPP_ w->b,w->b);
    MR_OUT
}

void zzn2_add(_MIPD_ zzn2 *x,zzn2 *y,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
#ifdef MR_COUNT_OPS
fpaq++; 
#endif
    MR_IN(159)
    nres_modadd(_MIPP_ x->a,y->a,w->a);
    nres_modadd(_MIPP_ x->b,y->b,w->b);
    MR_OUT
}
  
void zzn2_sadd(_MIPD_ zzn2 *x,big y,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(169)
    nres_modadd(_MIPP_ x->a,y,w->a);
    MR_OUT
}              

void zzn2_sub(_MIPD_ zzn2 *x,zzn2 *y,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
#ifdef MR_COUNT_OPS
fpaq++; 
#endif
    MR_IN(160)
    nres_modsub(_MIPP_ x->a,y->a,w->a);
    nres_modsub(_MIPP_ x->b,y->b,w->b);
    MR_OUT
}

void zzn2_ssub(_MIPD_ zzn2 *x,big y,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(170)
    nres_modsub(_MIPP_ x->a,y,w->a);
    MR_OUT
}

void zzn2_smul(_MIPD_ zzn2 *x,big y,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(161)
    if (size(x->a)!=0) nres_modmult(_MIPP_ x->a,y,w->a);
    else zero(w->a);
    if (size(x->b)!=0) nres_modmult(_MIPP_ x->b,y,w->b);
    else zero(w->b);
    MR_OUT
}

void zzn2_imul(_MIPD_ zzn2 *x,int y,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(152)
    if (size(x->a)!=0) nres_premult(_MIPP_ x->a,y,w->a);
    else zero(w->a);
    if (size(x->b)!=0) nres_premult(_MIPP_ x->b,y,w->b);
    else zero(w->b);
    MR_OUT
}

void zzn2_sqr(_MIPD_ zzn2 *x,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    if (mr_mip->ERNUM) return;
#ifdef MR_COUNT_OPS
fpsq++; 
#endif
    MR_IN(210)

	nres_complex(_MIPP_ x->a,x->b,w->a,w->b);

    MR_OUT
}    

void zzn2_mul(_MIPD_ zzn2 *x,zzn2 *y,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    if (mr_mip->ERNUM) return;
	if (x==y) {zzn2_sqr(_MIPP_ x,w); return; }
    MR_IN(162)
 /* Uses w1, w2, and w5 */

    if (zzn2_iszero(x) || zzn2_iszero(y)) zzn2_zero(w);
    else
    {
#ifdef MR_COUNT_OPS
fpmq++; 
#endif
#ifndef MR_NO_LAZY_REDUCTION 
        if (x->a->len!=0 && x->b->len!=0 && y->a->len!=0 && y->b->len!=0)
            nres_lazy(_MIPP_ x->a,x->b,y->a,y->b,w->a,w->b);
        else
        {
#endif
            nres_modmult(_MIPP_ x->a,y->a,mr_mip->w1);
            nres_modmult(_MIPP_ x->b,y->b,mr_mip->w2);
            nres_modadd(_MIPP_ x->a,x->b,mr_mip->w5);
            nres_modadd(_MIPP_ y->a,y->b,w->b);
            nres_modmult(_MIPP_ w->b,mr_mip->w5,w->b);
            nres_modsub(_MIPP_ w->b,mr_mip->w1,w->b);
            nres_modsub(_MIPP_ w->b,mr_mip->w2,w->b);
            nres_modsub(_MIPP_ mr_mip->w1,mr_mip->w2,w->a);
            if (mr_mip->qnr==-2)
                nres_modsub(_MIPP_ w->a,mr_mip->w2,w->a);
#ifndef MR_NO_LAZY_REDUCTION
        }
#endif
    }    
    MR_OUT
}


/*
void zzn2_print(_MIPD_ char *label, zzn2 *x)
{
    char s1[1024], s2[1024];
    big a, b;

#ifdef MR_STATIC
    char mem_big[MR_BIG_RESERVE(2)];   
 	memset(mem_big, 0, MR_BIG_RESERVE(2)); 
    a=mirvar_mem(_MIPP_ mem_big,0);
    b=mirvar_mem(_MIPP_ mem_big,1);
#else
    a = mirvar(_MIPP_  0); 
    b = mirvar(_MIPP_  0); 
#endif
    redc(_MIPP_ x->a, a); otstr(_MIPP_ a, s1);
    redc(_MIPP_ x->b, b); otstr(_MIPP_ b, s2);

    printf("%s: [%s,%s]\n", label, s1, s2);
#ifndef MR_STATIC
    mr_free(a); mr_free(b);
#endif
}

static void nres_print(_MIPD_ char *label, big x)
{
    char s[1024];
    big a;
#ifdef MR_STATIC
    char mem_big[MR_BIG_RESERVE(1)];     
 	memset(mem_big, 0, MR_BIG_RESERVE(1)); 
    a=mirvar_mem(_MIPP_ mem_big,0);
#else
    a = mirvar(_MIPP_  0); 
#endif

    redc(_MIPP_ x, a);
    otstr(_MIPP_ a, s);

    printf("%s: %s\n", label, s);
#ifndef MR_STATIC
    mr_free(a);
#endif
}

*/
void zzn2_inv(_MIPD_ zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(163)
    nres_modmult(_MIPP_ w->a,w->a,mr_mip->w1); 
    nres_modmult(_MIPP_ w->b,w->b,mr_mip->w2); 
    nres_modadd(_MIPP_ mr_mip->w1,mr_mip->w2,mr_mip->w1);

    if (mr_mip->qnr==-2)
        nres_modadd(_MIPP_ mr_mip->w1,mr_mip->w2,mr_mip->w1);
    redc(_MIPP_ mr_mip->w1,mr_mip->w6);
  
    invmodp(_MIPP_ mr_mip->w6,mr_mip->modulus,mr_mip->w6);

    nres(_MIPP_ mr_mip->w6,mr_mip->w6);

    nres_modmult(_MIPP_ w->a,mr_mip->w6,w->a);
    nres_negate(_MIPP_ mr_mip->w6,mr_mip->w6);
    nres_modmult(_MIPP_ w->b,mr_mip->w6,w->b);
    MR_OUT
}

/* divide zzn2 by 2 */

void zzn2_div2(_MIPD_ zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(173)

    nres_div2(_MIPP_ w->a,w->a);
    nres_div2(_MIPP_ w->b,w->b);

    MR_OUT
}

/* divide zzn2 by 3 */

void zzn2_div3(_MIPD_ zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(200)

    nres_div3(_MIPP_ w->a,w->a);
    nres_div3(_MIPP_ w->b,w->b);

    MR_OUT
}

/* divide zzn2 by 5 */

void zzn2_div5(_MIPD_ zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(209)

    nres_div5(_MIPP_ w->a,w->a);
    nres_div5(_MIPP_ w->b,w->b);

    MR_OUT
}

/* multiply zzn2 by i */

void zzn2_timesi(_MIPD_ zzn2 *u)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(164)
    copy(u->a,mr_mip->w1);
    nres_negate(_MIPP_ u->b,u->a);
    if (mr_mip->qnr==-2)
        nres_modadd(_MIPP_ u->a,u->a,u->a);

    copy(mr_mip->w1,u->b);
    MR_OUT
}

void zzn2_txx(_MIPD_ zzn2 *u)
{
  /* multiply w by t^2 where x^2-t is irreducible polynomial for ZZn4
  
   for p=5 mod 8 t=sqrt(sqrt(-2)), qnr=-2
   for p=3 mod 8 t=sqrt(1+sqrt(-1)), qnr=-1
   for p=7 mod 8 and p=2,3 mod 5 t=sqrt(2+sqrt(-1)), qnr=-1 */
    zzn2 t;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(196)  
        
    switch (mr_mip->pmod8)
    {
    case 5:
        zzn2_timesi(_MIPP_ u);
        break;
    case 3:
        t.a=mr_mip->w3;
        t.b=mr_mip->w4;
        zzn2_copy(u,&t);
        zzn2_timesi(_MIPP_ u);
        zzn2_add(_MIPP_ u,&t,u);
        break;
    case 7:
        t.a=mr_mip->w3;
        t.b=mr_mip->w4;
        zzn2_copy(u,&t);
        zzn2_timesi(_MIPP_ u);
        zzn2_add(_MIPP_ u,&t,u);
        zzn2_add(_MIPP_ u,&t,u); 
        break;
    default: break; 
    }
    MR_OUT
}

void zzn2_txd(_MIPD_ zzn2 *u)
{ /* divide w by t^2 where x^2-t is irreducible polynomial for ZZn4
  
   for p=5 mod 8 t=sqrt(sqrt(-2)), qnr=-2
   for p=3 mod 8 t=sqrt(1+sqrt(-1)), qnr=-1
   for p=7 mod 8 and p=2,3 mod 5 t=sqrt(2+sqrt(-1)), qnr=-1 */
    zzn2 t;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(197)  
    t.a=mr_mip->w3;
    t.b=mr_mip->w4;
    switch (mr_mip->pmod8)
    {
    case 5:
        copy(u->b,t.a);
        nres_div2(_MIPP_ u->a,t.b);
        nres_negate(_MIPP_ t.b,t.b);
        zzn2_copy(&t,u);
        break;
    case 3:
        nres_modadd(_MIPP_ u->a,u->b,t.a);
        nres_modsub(_MIPP_ u->b,u->a,t.b);
        zzn2_div2(_MIPP_ &t);
        zzn2_copy(&t,u);
        break;
    case 7:
        nres_modadd(_MIPP_ u->a,u->a,t.a);
        nres_modadd(_MIPP_ t.a,u->b,t.a);
        nres_modadd(_MIPP_ u->b,u->b,t.b);
        nres_modsub(_MIPP_ t.b,u->a,t.b);
        zzn2_div5(_MIPP_ &t);
        zzn2_copy(&t,u);  
/*
        nres_modadd(_MIPP_ u->a,u->b,t.a);
        nres_modadd(_MIPP_ t.a,u->b,t.a);
        nres_modsub(_MIPP_ u->b,u->a,t.b);
        zzn2_div3(_MIPP_ &t);
        zzn2_copy(&t,u);
*/
        break;
        default: break;
    }
 
    MR_OUT
}

/* find w[i]=1/x[i] mod n, for i=0 to m-1 *
   * x and w MUST be distinct             */

BOOL zzn2_multi_inverse(_MIPD_ int m,zzn2 *x,zzn2 *w)
{ 
    int i;
    zzn2 t1,t2;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (m==0) return TRUE;
    if (m<0) return FALSE;
    MR_IN(214)

    if (x==w)
    {
        mr_berror(_MIPP_ MR_ERR_BAD_PARAMETERS);
        MR_OUT
        return FALSE;
    }

    if (m==1)
    {
        zzn2_copy(&x[0],&w[0]);
        zzn2_inv(_MIPP_ &w[0]);

        MR_OUT
        return TRUE;
    }

    zzn2_from_int(_MIPP_ 1,&w[0]);
    zzn2_copy(&x[0],&w[1]);

    for (i=2;i<m;i++)
    {
        if (zzn2_isunity(_MIPP_ &x[i-1]))
            zzn2_copy(&w[i-1],&w[i]);
        else
            zzn2_mul(_MIPP_ &w[i-1],&x[i-1],&w[i]); 
    }

    t1.a=mr_mip->w8;
    t1.b=mr_mip->w9;
    t2.a=mr_mip->w10;
    t2.b=mr_mip->w11;

    zzn2_mul(_MIPP_ &w[m-1],&x[m-1],&t1); 
    if (zzn2_iszero(&t1))
    {
        mr_berror(_MIPP_ MR_ERR_DIV_BY_ZERO);
        MR_OUT
        return FALSE;
    }

    zzn2_inv(_MIPP_ &t1);

    zzn2_copy(&x[m-1],&t2);
    zzn2_mul(_MIPP_ &w[m-1],&t1,&w[m-1]);

    for (i=m-2;;i--)
    {
        if (i==0)
        {
            zzn2_mul(_MIPP_ &t2,&t1,&w[0]);
            break;
        }
        zzn2_mul(_MIPP_ &w[i],&t2,&w[i]);
        zzn2_mul(_MIPP_ &w[i],&t1,&w[i]);
        if (!zzn2_isunity(_MIPP_ &x[i])) zzn2_mul(_MIPP_ &t2,&x[i],&t2);
    }

    MR_OUT 
    return TRUE;   
}


/*
static void zzn2_print(_MIPD_ char *label, zzn2 *x)
{
    char s1[1024], s2[1024];
    big a, b;


    a = mirvar(_MIPP_  0); 
    b = mirvar(_MIPP_  0); 

    redc(_MIPP_ x->a, a); otstr(_MIPP_ a, s1);
    redc(_MIPP_ x->b, b); otstr(_MIPP_ b, s2);

    printf("%s: [%s,%s]\n", label, s1, s2);

    mr_free(a); mr_free(b);

}

static void nres_print(_MIPD_ char *label, big x)
{
    char s[1024];
    big a;

    a = mirvar(_MIPP_  0); 

    redc(_MIPP_ x, a);
    otstr(_MIPP_ a, s);

    printf("%s: %s\n", label, s);

    mr_free(a);
}

*/

/* Lucas-style ladder exponentiation - for ZZn4 exponentiation 

void zzn2_powl(_MIPD_ zzn2 *x,big e,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    int i,s;
    zzn2 t1,t3,t4;
    if (mr_mip->ERNUM) return;
    MR_IN(165)
    t1.a=mr_mip->w3;
    t1.b=mr_mip->w4;
    t3.a=mr_mip->w8;
    t3.b=mr_mip->w9;
    t4.a=mr_mip->w10;
    t4.b=mr_mip->w11;

    zzn2_from_int(_MIPP_ 1,&t1);

    s=size(e);
    if (s==0)
    {
        zzn2_copy(&t1,w);
        return;
    }
    zzn2_copy(x,w);
    if (s==1 || s==(-1)) return;

    i=logb2(_MIPP_ e)-1;

    zzn2_copy(w,&t3);
    zzn2_sqr(_MIPP_ w,&t4);
    zzn2_add(_MIPP_ &t4,&t4,&t4);
    zzn2_sub(_MIPP_ &t4,&t1,&t4);

    while (i-- && !mr_mip->ERNUM)
    {
        if (mr_testbit(_MIPP_ e,i))
        {
            zzn2_mul(_MIPP_ &t3,&t4,&t3);
            zzn2_add(_MIPP_ &t3,&t3,&t3);
            zzn2_sub(_MIPP_ &t3,w,&t3);
            zzn2_sqr(_MIPP_ &t4,&t4);
            zzn2_add(_MIPP_ &t4,&t4,&t4);
            zzn2_sub(_MIPP_ &t4,&t1,&t4);
        }
        else
        {
            zzn2_mul(_MIPP_ &t4,&t3,&t4);
            zzn2_add(_MIPP_ &t4,&t4,&t4);
            zzn2_sub(_MIPP_ &t4,w,&t4);
            zzn2_sqr(_MIPP_ &t3,&t3);
            zzn2_add(_MIPP_ &t3,&t3,&t3);
            zzn2_sub(_MIPP_ &t3,&t1,&t3);
        }

    }
    zzn2_copy(&t4,w);
    MR_OUT
}
*/
