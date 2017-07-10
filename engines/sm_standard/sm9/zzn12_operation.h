/* ====================================================================
 * Copyright (c) 2016 The GmSSL Project.  All rights reserved.
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
 * ====================================================================
 */

#ifndef HEADER_ZZN12_OPERATION_H
#define HEADER_ZZN12_OPERATION_H


#include "miracl.h"


#ifdef __cplusplus
extern "C"{
#endif

miracl* mip;
zzn2 X; //Frobniues constant
typedef struct
{
    zzn4 a, b, c;
    BOOL unitary; // "unitary property means that fast squaring can be used, and inversions are just conjugates
    BOOL miller;  // "miller" property means that arithmetic on this instance can ignore multiplications
                  // or divisions by constants - as instance will eventually be raised to (p-1).
} zzn12;


static void zzn12_init(zzn12 *x)
{
    x->a.a.a = mirvar(0);
    x->a.a.b = mirvar(0);

    x->a.b.a = mirvar(0);
    x->a.b.b = mirvar(0);

    x->a.unitary = FALSE;
    

    x->b.a.a = mirvar(0);
    x->b.a.b = mirvar(0);

    x->b.b.a = mirvar(0);
    x->b.b.b = mirvar(0);
    
    x->b.unitary = FALSE;
    
    
    x->c.a.a = mirvar(0);
    x->c.a.b = mirvar(0);
    
    x->c.b.a = mirvar(0);
    x->c.b.b = mirvar(0);
    
    x->c.unitary = FALSE;
    
    
    x->miller = FALSE;
    x->unitary = FALSE;
}


static void zzn12_copy(zzn12 *x, zzn12 *y)
{
    zzn4_copy(&x->a, &y->a);
    zzn4_copy(&x->b, &y->b);
    zzn4_copy(&x->c, &y->c);
    
    y->miller = x->miller;
    y->unitary = x->unitary;
}


static void zzn12_mul(zzn12 x, zzn12 y, zzn12 *z)
{
    // Karatsuba
    zzn4 Z0, Z1, Z2, Z3, T0, T1;
    BOOL zero_c, zero_b;
    
    Z0.a.a = mirvar(0);
    Z0.a.b = mirvar(0);
    
    Z0.b.a = mirvar(0);
    Z0.b.b = mirvar(0);
    
    Z0.unitary = FALSE;
    
    
    Z1.a.a = mirvar(0);
    Z1.a.b = mirvar(0);
    
    Z1.b.a = mirvar(0);
    Z1.b.b = mirvar(0);
    
    Z1.unitary = FALSE;
    
    
    Z2.a.a = mirvar(0);
    Z2.a.b = mirvar(0);
    
    Z2.b.a = mirvar(0);
    Z2.b.b = mirvar(0);
    
    Z2.unitary = FALSE;
    
    
    Z3.a.a = mirvar(0);
    Z3.a.b = mirvar(0);
    
    Z3.b.a = mirvar(0);
    Z3.b.b = mirvar(0);
    
    Z3.unitary = FALSE;
    
    
    T0.a.a = mirvar(0);
    T0.a.b = mirvar(0);
    
    T0.b.a = mirvar(0);
    T0.b.b = mirvar(0);
    
    T0.unitary = FALSE;
    
    
    T1.a.a = mirvar(0);
    T1.a.b = mirvar(0);
    
    T1.b.a = mirvar(0);
    T1.b.b = mirvar(0);
    
    T1.unitary = FALSE;
    
    
    zzn12_copy(&x, z);
    if(zzn4_compare(&x.a, &y.a) && zzn4_compare(&x.a, &y.a) && zzn4_compare(&x.a, &y.a))
    {
        if(x.unitary == TRUE)
        {
            zzn4_copy(&x.a, &Z0);
            zzn4_mul(&x.a, &x.a, &z->a);
            zzn4_copy(&z->a, &Z3);
            zzn4_add(&z->a, &z->a, &z->a);
            zzn4_add(&z->a, &Z3, &z->a);
            zzn4_conj(&Z0, &Z0); 
            zzn4_add(&Z0, &Z0, &Z0);
            zzn4_sub(&z->a, &Z0, &z->a);
            zzn4_copy(&x.c, &Z1);
            zzn4_mul(&Z1, &Z1, &Z1);
            zzn4_tx(&Z1);
            zzn4_copy(&Z1, &Z3);
            zzn4_add(&Z1, &Z1, &Z1);
            zzn4_add(&Z1, &Z3, &Z1);
            zzn4_copy(&x.b, &Z2);
            zzn4_mul(&Z2, &Z2, &Z2);
            zzn4_copy(&Z2, &Z3);
            zzn4_add(&Z2, &Z2, &Z2);
            zzn4_add(&Z2, &Z3, &Z2);
            zzn4_conj(&x.b, &z->b);
            zzn4_add(&z->b, &z->b, &z->b);
            zzn4_conj(&x.c, &z->c);
            zzn4_add(&z->c, &z->c, &z->c);
            zzn4_negate(&z->c, &z->c);
            zzn4_add(&z->b, &Z1, &z->b);
            zzn4_add(&z->c, &Z2, &z->c);
        }
        else
        {
            if(!x.miller)
            {   // Chung-Hasan SQR2
                zzn4_copy(&x.a, &Z0);
                zzn4_mul(&Z0, &Z0, &Z0);
                zzn4_mul(&x.b, &x.c, &Z1);
                zzn4_add(&Z1, &Z1, &Z1);
                zzn4_copy(&x.c, &Z2);
                zzn4_mul(&Z2, &Z2, &Z2);
                zzn4_mul(&x.a, &x.b, &Z3);
                zzn4_add(&Z3, &Z3, &Z3);
                zzn4_add(&x.a, &x.b, &z->c);
                zzn4_add(&z->c, &x.c, &z->c);
                zzn4_mul(&z->c, &z->c, &z->c);
                zzn4_tx(&Z1);
                zzn4_add(&Z0, &Z1, &z->a);
                zzn4_tx(&Z2);
                zzn4_add(&Z3, &Z2, &z->b);
                zzn4_add(&Z0, &Z1, &T0);
                zzn4_add(&T0, &Z2, &T0);
                zzn4_add(&T0, &Z3, &T0);
                zzn4_sub(&z->c, &T0, &z->c);
            }
            else
            {   // Chung-Hasan SQR3 - actually calculate 2x^2 !
                // Slightly dangerous - but works as will be raised to p^{k/2}-1
                // which wipes out the 2.
                zzn4_copy(&x.a, &Z0);
                zzn4_mul(&Z0, &Z0, &Z0);    // a0^2 = S0
                zzn4_copy(&x.c, &Z2);
                zzn4_mul(&Z2, &x.b, &Z2);
                zzn4_add(&Z2, &Z2, &Z2);    // 2a1.a2 = S3
                zzn4_copy(&x.c, &Z3);
                zzn4_mul(&Z3, &Z3, &Z3);      // a2^2 = S4
                zzn4_add(&x.c, &x.a, &z->c);    // a0+a2
                zzn4_copy(&x.b, &Z1);
                zzn4_add(&Z1, &z->c, &Z1);
                zzn4_mul(&Z1, &Z1, &Z1);    // (a0+a1+a2)^2 =S1
                zzn4_sub(&z->c, &x.b, &z->c);
                zzn4_mul(&z->c, &z->c, &z->c);  // (a0-a1+a2)^2 =S2
                zzn4_add(&Z2, &Z2, &Z2);
                zzn4_add(&Z0, &Z0, &Z0);
                zzn4_add(&Z3, &Z3, &Z3);
                zzn4_sub(&Z1, &z->c, &T0);
                zzn4_sub(&T0, &Z2, &T0);
                zzn4_sub(&Z1, &Z0, &T1);
                zzn4_sub(&T1, &Z3, &T1);
                zzn4_add(&z->c, &T1, &z->c);
                zzn4_tx(&Z3);
                zzn4_add(&T0, &Z3, &z->b);
                zzn4_tx(&Z2);
                zzn4_add(&Z0, &Z2, &z->a);
            }
        }
    }
    else
    {
        // Karatsuba
        zero_b = zzn4_iszero(&y.b);
        zero_c = zzn4_iszero(&y.c);
        
        zzn4_mul(&x.a, &y.a, &Z0); //9
        if(!zero_b) 
            zzn4_mul(&x.b, &y.b, &Z2); //+6
        
        zzn4_add(&x.a, &x.b, &T0);
        zzn4_add(&y.a, &y.b, &T1);
        zzn4_mul(&T0, &T1, &Z1); //+9
        zzn4_sub(&Z1, &Z0, &Z1);
        if(!zero_b) 
            zzn4_sub(&Z1, &Z2, &Z1);
        
        zzn4_add(&x.b, &x.c, &T0);
        zzn4_add(&y.b, &y.c, &T1);
        zzn4_mul(&T0, &T1, &Z3);//+6
        if(!zero_b) 
            zzn4_sub(&Z3, &Z2, &Z3);
        
        zzn4_add(&x.a, &x.c, &T0);
        zzn4_add(&y.a, &y.c, &T1);
        zzn4_mul(&T0, &T1, &T0);//+9=39 for "special case"
        if(!zero_b) 
            zzn4_add(&Z2, &T0, &Z2);
        else 
            zzn4_copy(&T0, &Z2);
        
        zzn4_sub(&Z2, &Z0, &Z2);
        zzn4_copy(&Z1, &z->b);
        if(!zero_c)
        { 
            // exploit special form of BN curve line function
            zzn4_mul(&x.c, &y.c, &T0);
            zzn4_sub(&Z2, &T0, &Z2);
            zzn4_sub(&Z3, &T0, &Z3);
            zzn4_tx(&T0);
            zzn4_add(&z->b, &T0, &z->b);
        }

        zzn4_tx(&Z3);
        zzn4_add(&Z0, &Z3, &z->a);
        zzn4_copy(&Z2, &z->c);
        if(!y.unitary) 
            z->unitary = FALSE;
    }
}


static void zzn12_conj(zzn12 *x, zzn12 *y)
{
    zzn4_conj(&x->a, &y->a);
    zzn4_conj(&x->b, &y->b);
    zzn4_negate(&y->b, &y->b);
    zzn4_conj(&x->c, &y->c);
    y->miller = x->miller;
    y->unitary = x->unitary;
}


static zzn12 zzn12_inverse(zzn12 w)
{
    zzn4 tmp1, tmp2;
    zzn12 res;

    tmp1.a.a = mirvar(0);
    tmp1.a.b = mirvar(0);
    
    tmp1.b.a = mirvar(0);
    tmp1.b.b = mirvar(0);
    
    tmp1.unitary = FALSE;
   
   
    tmp2.a.a = mirvar(0);
    tmp2.a.b = mirvar(0);
    
    tmp2.b.a = mirvar(0);
    tmp2.b.b = mirvar(0);
    
    tmp2.unitary = FALSE;
    
    
    zzn12_init(&res);
    
    if(w.unitary)
    {
        zzn12_conj(&w, &res);
        return res;
    }   
    //res.a=w.a*w.a-tx(w.b*w.c);
    zzn4_mul(&w.a, &w.a, &res.a);
    zzn4_mul(&w.b, &w.c, &res.b);
    zzn4_tx(&res.b);
    zzn4_sub(&res.a, &res.b, &res.a);
    
    //res.b=tx(w.c*w.c)-w.a*w.b;
    zzn4_mul(&w.c, &w.c, &res.c);
    zzn4_tx(&res.c);
    zzn4_mul(&w.a, &w.b, &res.b);
    zzn4_sub(&res.c, &res.b, &res.b);
    
    //res.c=w.b*w.b-w.a*w.c;
    zzn4_mul(&w.b, &w.b, &res.c);
    zzn4_mul(&w.a, &w.c, &tmp1);
    zzn4_sub(&res.c, &tmp1, &res.c);
    
    //tmp1=tx(w.b*res.c)+w.a*res.a+tx(w.c*res.b);
    zzn4_mul(&w.b, &res.c, &tmp1);
    zzn4_tx(&tmp1);
    zzn4_mul(&w.a, &res.a, &tmp2);
    zzn4_add(&tmp1, &tmp2, &tmp1);
    zzn4_mul(&w.c, &res.b, &tmp2);
    zzn4_tx(&tmp2);
    zzn4_add(&tmp1, &tmp2, &tmp1);
    
    zzn4_inv(&tmp1);
    zzn4_mul(&res.a, &tmp1, &res.a);
    zzn4_mul(&res.b, &tmp1, &res.b);
    zzn4_mul(&res.c, &tmp1, &res.c);
    return res;
}


static void zzn12_powq(zzn2 F, zzn12 *y)
{
    zzn2 X2, X3;
    X2.a = mirvar(0);
    X2.b = mirvar(0);
    
    X3.a = mirvar(0);
    X3.b = mirvar(0);
    zzn2_mul(&F, &F, &X2);
    zzn2_mul(&X2, &F, &X3);
    
    zzn4_powq(&X3, &y->a);
    zzn4_powq(&X3, &y->b);
    zzn4_powq(&X3, &y->c);
    zzn4_smul(&y->b, &X, &y->b);
    zzn4_smul(&y->c, &X2, &y->c);
}


static void zzn12_div(zzn12 x, zzn12 y, zzn12 *z)
{
    y=zzn12_inverse(y);
    zzn12_mul(x, y, z);
}


static zzn12 zzn12_pow(zzn12 x, big k)
{
    big zero, tmp, tmp1;
    int nb, i;
    BOOL invert_it;
    zzn12 res;
    
    zero = mirvar(0);
    tmp = mirvar(0);
    tmp1 = mirvar(0);
    
    zzn12_init(&res);
    copy(k, tmp1);
    invert_it = FALSE;
    
    if(mr_compare(tmp1, zero) == 0)
    {
        tmp = get_mip()->one;
        zzn4_from_big(tmp, &res.a);
        return res;
    }
    if(mr_compare(tmp1, zero) < 0)
    {
        negify(tmp1, tmp1);
        invert_it = TRUE;
    }
    nb = logb2(k);
    zzn12_copy(&x, &res);
    if(nb > 1)
        for(i = nb - 2; i >= 0; i--)
        {
            zzn12_mul(res, res, &res);
            if(mr_testbit(k, i)) 
                zzn12_mul(res, x, &res);
        }
    if(invert_it) 
        res = zzn12_inverse(res);
    return res;
}

#ifdef __cplusplus
}
#endif

#endif
