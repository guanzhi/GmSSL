
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
 *   MIRACL arithmetic routines 3 - simple powers and roots
 *   mrarth3.c
 */

#include <stdlib.h> 
#include "miracl.h"

void expint(_MIPD_ int b,int n,big x)
{ /* sets x=b^n */
    unsigned int bit,un;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    convert(_MIPP_ 1,x);
    if (n==0) return;

    MR_IN(50)

    if (n<0)
    {
        mr_berror(_MIPP_ MR_ERR_NEG_POWER);
        MR_OUT
        return;
    }
    if (b==2) expb2(_MIPP_ n,x);
    else
    {
        bit=1;
        un=(unsigned int)n;
        while (un>=bit) bit<<=1;
        bit>>=1;
        while (bit>0)
        { /* ltr method */
            multiply(_MIPP_ x,x,x);
            if ((bit&un)!=0) premult(_MIPP_ x,b,x);
            bit>>=1;
        }
    }
    MR_OUT
}   

void power(_MIPD_ big x,long n,big z,big w)
{ /* raise big number to int power  w=x^n *
   * (mod z if z and w distinct)          */
    mr_small norm;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    copy(x,mr_mip->w5);
    zero(w);
    if(mr_mip->ERNUM || size(mr_mip->w5)==0) return;
    convert(_MIPP_ 1,w);
    if (n==0L) return;

    MR_IN(17)

    if (n<0L)
    {
        mr_berror(_MIPP_ MR_ERR_NEG_POWER);
        MR_OUT
        return;
    }

    if (w==z) forever
    { /* "Russian peasant" exponentiation */
        if (n%2!=0L) 
             multiply(_MIPP_ w,mr_mip->w5,w);
        n/=2L;
        if (mr_mip->ERNUM || n==0L) break;
        multiply(_MIPP_ mr_mip->w5,mr_mip->w5,mr_mip->w5);
    }
    else
    { 
        norm=normalise(_MIPP_ z,z);
        divide(_MIPP_ mr_mip->w5,z,z);
        forever
        {
            if (mr_mip->user!=NULL) (*mr_mip->user)();

            if (n%2!=0L) mad(_MIPP_ w,mr_mip->w5,mr_mip->w5,z,z,w);
            n/=2L;
            if (mr_mip->ERNUM || n==0L) break;
            mad(_MIPP_ mr_mip->w5,mr_mip->w5,mr_mip->w5,z,z,mr_mip->w5);
        }
        if (norm!=1)
        {
#ifdef MR_FP_ROUNDING
            mr_sdiv(_MIPP_ z,norm,mr_invert(norm),z);
#else
            mr_sdiv(_MIPP_ z,norm,z);
#endif
            divide(_MIPP_ w,z,z);
        }
    }

    MR_OUT
}

BOOL nroot(_MIPD_ big x,int n,big w)
{  /*  extract  lower approximation to nth root   *
    *  w=x^(1/n) returns TRUE for exact root      *
    *  uses Newtons method                        */
    int sx,dif,s,p,d,lg2,lgx,rem;
    BOOL full;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return FALSE;
    if (size(x)==0 || n==1)
    {
        copy(x,w);
        return TRUE;
    }

    MR_IN(16)

    if (n<1) mr_berror(_MIPP_ MR_ERR_BAD_ROOT);
    sx=exsign(x);
    if (n%2==0 && sx==MINUS) mr_berror(_MIPP_ MR_ERR_NEG_ROOT);
    if (mr_mip->ERNUM) 
    {
        MR_OUT
        return FALSE;
    }
    insign(PLUS,x);
    lgx=logb2(_MIPP_ x);
    if (n>=lgx)
    { /* root must be 1 */
        insign(sx,x);
        convert(_MIPP_ sx,w);
        MR_OUT
        if (lgx==1) return TRUE;
        else        return FALSE;
    }
    expb2(_MIPP_ 1+(lgx-1)/n,mr_mip->w2);           /* guess root as 2^(log2(x)/n) */
    s=(-(((int)x->len-1)/n)*n);
    mr_shift(_MIPP_ mr_mip->w2,s/n,mr_mip->w2);
    lg2=logb2(_MIPP_ mr_mip->w2)-1;
    full=FALSE;
    if (s==0) full=TRUE;
    d=0;
    p=1;
    while (!mr_mip->ERNUM)
    { /* Newtons method */
        copy(mr_mip->w2,mr_mip->w3);
        mr_shift(_MIPP_ x,s,mr_mip->w4);
        mr_mip->check=OFF;
        power(_MIPP_ mr_mip->w2,n-1,mr_mip->w6,mr_mip->w6);
        mr_mip->check=ON;
        divide(_MIPP_ mr_mip->w4,mr_mip->w6,mr_mip->w2);
        rem=size(mr_mip->w4);
        subtract(_MIPP_ mr_mip->w2,mr_mip->w3,mr_mip->w2);
        dif=size(mr_mip->w2);
        subdiv(_MIPP_ mr_mip->w2,n,mr_mip->w2);
        add(_MIPP_ mr_mip->w2,mr_mip->w3,mr_mip->w2);
        p*=2;
        if(p<lg2+d*mr_mip->lg2b) continue;
        if (full && mr_abs(dif)<n)
        { /* test for finished */
            while (dif<0)
            {
                rem=0;
                decr(_MIPP_ mr_mip->w2,1,mr_mip->w2);
                mr_mip->check=OFF;
                power(_MIPP_ mr_mip->w2,n,mr_mip->w6,mr_mip->w6);
                mr_mip->check=ON;
                dif=mr_compare(x,mr_mip->w6);
            }
            copy(mr_mip->w2,w);
            insign(sx,w);
            insign(sx,x);
            MR_OUT
            if (rem==0 && dif==0) return TRUE;
            else                  return FALSE;
        }
        else
        { /* adjust precision */
            d*=2;
            if (d==0) d=1;
            s+=d*n;
            if (s>=0)
            {
                d-=s/n;
                s=0;
                full=TRUE;
            }
            mr_shift(_MIPP_ mr_mip->w2,d,mr_mip->w2);
        }
        p/=2;
    }
    MR_OUT
    return FALSE;
}

