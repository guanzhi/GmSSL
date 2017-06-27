
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
 *   MIRACL method for modular square root
 *   mrsroot.c 
 *
 *   Siguna Mueller's O(lg(p)^3) algorithm, Designs Codes and Cryptography, 2004 
 * 
 *   This is a little slower for p=1 mod 4 primes, but its not time critical, and
 *   more importantly it doesn't pull in the large powmod code into elliptic curve programs
 *   It does require code from mrjack.c and mrlucas.c
 *
 *   If p=3 mod 4, then  sqrt(a)=a^[(p+1)/4] mod p. Note that for many elliptic curves
 *   (p+1)/4 has very low hamming weight.
 *
 *   (was sqrt(a) = V_{(p+1)/4}(a+1/a,1)/(1+1/a))
 *
 *   Mueller's method is also very simple, uses very little memory, and it works just fine for p=1 mod 8 primes
 *   (for example the "annoying" NIST modulus 2^224-2^96+1)
 *   Also doesn't waste time on non-squares, as a jacobi test is done first
 *
 *   If you know that the prime is 3 mod 4, and you know that x is almost certainly a QR
 *   then the jacobi-dependent code can be deleted with some space savings.
 * 
 *   NOTE - IF p IS NOT PRIME, THIS CODE WILL FAIL SILENTLY!
 *
 */

#include <stdlib.h>
#include "miracl.h"

BOOL nres_sqroot(_MIPD_ big x,big w)
{ /* w=sqrt(x) mod p. This depends on p being prime! */
    int t,js;
   
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return FALSE;

    copy(x,w);
    if (size(w)==0) return TRUE; 

    MR_IN(100)

    redc(_MIPP_ w,w);   /* get it back into normal form */

    if (size(w)==1) /* square root of 1 is 1 */
    {
        nres(_MIPP_ w,w);
        MR_OUT
        return TRUE;
    }

    if (size(w)==4) /* square root of 4 is 2 */
    {
        convert(_MIPP_ 2,w);
        nres(_MIPP_ w,w);
        MR_OUT
        return TRUE;
    }

    if (jack(_MIPP_ w,mr_mip->modulus)!=1) 
    { /* Jacobi test */ 
        zero(w);
        MR_OUT
        return FALSE;
    }

    js=mr_mip->pmod8%4-2;     /* 1 mod 4 or 3 mod 4 prime? */

    incr(_MIPP_ mr_mip->modulus,js,mr_mip->w10);
    subdiv(_MIPP_ mr_mip->w10,4,mr_mip->w10);    /* (p+/-1)/4 */

    if (js==1)
    { /* 3 mod 4 primes - do a quick and dirty sqrt(x)=x^(p+1)/4 mod p */
        nres(_MIPP_ w,mr_mip->w2);
        copy(mr_mip->one,w);
        forever
        { /* Simple Right-to-Left exponentiation */

            if (mr_mip->user!=NULL) (*mr_mip->user)();
            if (subdiv(_MIPP_ mr_mip->w10,2,mr_mip->w10)!=0)
                nres_modmult(_MIPP_ w,mr_mip->w2,w);
            if (mr_mip->ERNUM || size(mr_mip->w10)==0) break;
            nres_modmult(_MIPP_ mr_mip->w2,mr_mip->w2,mr_mip->w2);
        }
 
 /*     nres_moddiv(_MIPP_ mr_mip->one,w,mr_mip->w11); 
        nres_modadd(_MIPP_ mr_mip->w11,w,mr_mip->w3);  
        nres_lucas(_MIPP_ mr_mip->w3,mr_mip->w10,w,w);
        nres_modadd(_MIPP_ mr_mip->w11,mr_mip->one,mr_mip->w11); 
        nres_moddiv(_MIPP_ w,mr_mip->w11,w); */
    } 
    else
    { /* 1 mod 4 primes */
        for (t=1; ;t++)
        { /* t=1.5 on average */
            if (t==1) copy(w,mr_mip->w4);
            else
            {
                premult(_MIPP_ w,t,mr_mip->w4);
                divide(_MIPP_ mr_mip->w4,mr_mip->modulus,mr_mip->modulus);
                premult(_MIPP_ mr_mip->w4,t,mr_mip->w4);
                divide(_MIPP_ mr_mip->w4,mr_mip->modulus,mr_mip->modulus);
            }

            decr(_MIPP_ mr_mip->w4,4,mr_mip->w1);
            if (jack(_MIPP_ mr_mip->w1,mr_mip->modulus)==js) break;
            if (mr_mip->ERNUM) break;
        }
    
        decr(_MIPP_ mr_mip->w4,2,mr_mip->w3);
        nres(_MIPP_ mr_mip->w3,mr_mip->w3);
        nres_lucas(_MIPP_ mr_mip->w3,mr_mip->w10,w,w); /* heavy lifting done here */
        if (t!=1)
        {
            convert(_MIPP_ t,mr_mip->w11);
            nres(_MIPP_ mr_mip->w11,mr_mip->w11);
            nres_moddiv(_MIPP_ w,mr_mip->w11,w);
        }
    }
    
    MR_OUT
    return TRUE;
}

BOOL sqroot(_MIPD_ big x,big p,big w)
{ /* w = sqrt(x) mod p */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return FALSE;

    MR_IN(101)

    if (subdivisible(_MIPP_ p,2))
    { /* p must be odd */
        zero(w);
        MR_OUT
        return FALSE;
    }

    prepare_monty(_MIPP_ p);
    nres(_MIPP_ x,w);
    if (nres_sqroot(_MIPP_ w,w))
    {
        redc(_MIPP_ w,w);
        MR_OUT
        return TRUE;
    }

    zero(w);
    MR_OUT
    return FALSE;
}
