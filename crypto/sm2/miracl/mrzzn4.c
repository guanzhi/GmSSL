
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
 *   MIRACL F_p^4 support functions 
 *   mrzzn4.c
 */

#include <stdlib.h> 
#include <openssl/miracl.h>

#define FUNC_BASE 226

BOOL zzn4_iszero(zzn4 *x)
{
    if (zzn2_iszero(&(x->a)) && zzn2_iszero(&(x->b))) return TRUE;
    return FALSE;
}

BOOL zzn4_isunity(_MIPD_ zzn4 *x)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM || !zzn2_iszero(&(x->b))) return FALSE;

    if (zzn2_isunity(_MIPP_ &x->a)) return TRUE;
    return FALSE;
}

BOOL zzn4_compare(zzn4 *x,zzn4 *y)
{
    if (zzn2_compare(&(x->a),&(y->a)) && zzn2_compare(&(x->b),&(y->b))) return TRUE;
    return FALSE;
}

void zzn4_from_int(_MIPD_ int i,zzn4 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(FUNC_BASE+0)
    if (i==1) 
    {
        copy(mr_mip->one,w->a.a);
		w->unitary=TRUE;
    }
    else
    {
        convert(_MIPP_ i,mr_mip->w1);
        nres(_MIPP_ mr_mip->w1,(w->a).a);
		w->unitary=FALSE;
    }
    zero((w->a).b);
	zero((w->b).a);
	zero((w->b).b);

    MR_OUT
}

void zzn4_copy(zzn4 *x,zzn4 *w)
{
    if (x==w) return;
    zzn2_copy(&(x->a),&(w->a));
    zzn2_copy(&(x->b),&(w->b));
	w->unitary=x->unitary;
}

void zzn4_zero(zzn4 *w)
{
    zzn2_zero(&(w->a));
    zzn2_zero(&(w->b));
	w->unitary=FALSE;
}

void zzn4_from_zzn2s(zzn2 *x,zzn2 *y,zzn4 *w)
{
    zzn2_copy(x,&(w->a));
    zzn2_copy(y,&(w->b));
	w->unitary=FALSE;
}

void zzn4_from_zzn2(zzn2 *x,zzn4 *w)
{
    zzn2_copy(x,&(w->a));
    zzn2_zero(&(w->b));
	w->unitary=FALSE;
}

void zzn4_from_zzn2h(zzn2 *x,zzn4 *w)
{
    zzn2_copy(x,&(w->b));
    zzn2_zero(&(w->a));
	w->unitary=FALSE;
}

void zzn4_from_zzn(big x,zzn4 *w)
{
	zzn2_from_zzn(x,&(w->a));
	zzn2_zero(&(w->b));
	w->unitary=FALSE;
}

void zzn4_from_big(_MIPD_ big x, zzn4 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(FUNC_BASE+16)
	zzn2_from_big(_MIPP_ x,&(w->a));
    zzn2_zero(&(w->b));
    MR_OUT
}

void zzn4_negate(_MIPD_ zzn4 *x,zzn4 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(FUNC_BASE+1)
    zzn4_copy(x,w);
    zzn2_negate(_MIPP_ &(w->a),&(w->a));
    zzn2_negate(_MIPP_ &(w->b),&(w->b));
    MR_OUT
}

void zzn4_conj(_MIPD_ zzn4 *x,zzn4 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    MR_IN(FUNC_BASE+2)
    if (mr_mip->ERNUM) return;
    zzn4_copy(x,w);
    zzn2_negate(_MIPP_ &(w->b),&(w->b));
    MR_OUT
}

void zzn4_add(_MIPD_ zzn4 *x,zzn4 *y,zzn4 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(FUNC_BASE+3)
    zzn2_add(_MIPP_ &(x->a),&(y->a),&(w->a));
    zzn2_add(_MIPP_ &(x->b),&(y->b),&(w->b));
	w->unitary=FALSE;
    MR_OUT
}
  
void zzn4_sadd(_MIPD_ zzn4 *x,zzn2 *y,zzn4 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(FUNC_BASE+4)
    zzn2_add(_MIPP_ &(x->a),y,&(w->a));
	w->unitary=FALSE;
    MR_OUT
} 
	
void zzn4_sub(_MIPD_ zzn4 *x,zzn4 *y,zzn4 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(FUNC_BASE+5)
    zzn2_sub(_MIPP_ &(x->a),&(y->a),&(w->a));
    zzn2_sub(_MIPP_ &(x->b),&(y->b),&(w->b));
	w->unitary=FALSE;

    MR_OUT
}

void zzn4_ssub(_MIPD_ zzn4 *x,zzn2 *y,zzn4 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(FUNC_BASE+6)
    zzn2_sub(_MIPP_ &(x->a),y,&(w->a));
	w->unitary=FALSE;

    MR_OUT
}

void zzn4_smul(_MIPD_ zzn4 *x,zzn2 *y,zzn4 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(FUNC_BASE+7)
	if (!zzn2_iszero(&(x->a))) zzn2_mul(_MIPP_ &(x->a),y,&(w->a));
	else zzn2_zero(&(w->a));
	if (!zzn2_iszero(&(x->b))) zzn2_mul(_MIPP_ &(x->b),y,&(w->b));
	else zzn2_zero(&(w->b));
	w->unitary=FALSE;

    MR_OUT
}

void zzn4_lmul(_MIPD_ zzn4 *x,big y,zzn4 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(FUNC_BASE+15)

	if (!zzn2_iszero(&(x->a))) zzn2_smul(_MIPP_ &(x->a),y,&(w->a));
	else zzn2_zero(&(w->a));
	if (!zzn2_iszero(&(x->b))) zzn2_smul(_MIPP_ &(x->b),y,&(w->b));
	else zzn2_zero(&(w->b));
	w->unitary=FALSE;

    MR_OUT
}


void zzn4_imul(_MIPD_ zzn4 *x,int y,zzn4 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(FUNC_BASE+14)
	zzn2_imul(_MIPP_ &(x->a),y,&(w->a));
	zzn2_imul(_MIPP_ &(x->b),y,&(w->b));

    MR_OUT
}

void zzn4_sqr(_MIPD_ zzn4 *x,zzn4 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    zzn2 t1,t2;
    if (mr_mip->ERNUM) return;

    MR_IN(FUNC_BASE+8)

    t1.a=mr_mip->w10;
    t1.b=mr_mip->w11;
    t2.a=mr_mip->w8;
    t2.b=mr_mip->w9;

    zzn4_copy(x,w);
    if (x->unitary)
    { /* this is a lot faster.. - see Lenstra & Stam */
        zzn2_mul(_MIPP_ &(w->b),&(w->b),&t1);
        zzn2_add(_MIPP_ &(w->b),&(w->a),&(w->b));
        zzn2_mul(_MIPP_ &(w->b),&(w->b),&(w->b));
        zzn2_sub(_MIPP_ &(w->b),&t1,&(w->b));
        zzn2_txx(_MIPP_ &t1);
        zzn2_copy(&t1,&(w->a));
        zzn2_sub(_MIPP_ &(w->b),&(w->a),&(w->b));
        zzn2_add(_MIPP_ &(w->a),&(w->a),&(w->a));
        zzn2_sadd(_MIPP_ &(w->a),mr_mip->one,&(w->a));
        zzn2_ssub(_MIPP_ &(w->b),mr_mip->one,&(w->b));
    }
    else
    {
        zzn2_copy(&(w->b),&t2); // t2=b;
        zzn2_add(_MIPP_ &(w->a),&t2,&t1); // t1=a+b

        zzn2_txx(_MIPP_ &t2);      
        zzn2_add(_MIPP_ &t2,&(w->a),&t2); // t2=a+txx(b)

        zzn2_mul(_MIPP_ &(w->b),&(w->a),&(w->b)); // b*=a
        zzn2_mul(_MIPP_ &t1,&t2,&(w->a)); // a=t1*t2

        zzn2_copy(&(w->b),&t2); //t2=b
        zzn2_sub(_MIPP_ &(w->a),&t2,&(w->a)); //a-=b      
        zzn2_txx(_MIPP_ &t2); // t2=txx(b)
        zzn2_sub(_MIPP_ &(w->a),&t2,&(w->a)); // a-=txx(b);
        zzn2_add(_MIPP_ &(w->b),&(w->b),&(w->b)); // b+=b;

    }

    MR_OUT
}    

void zzn4_mul(_MIPD_ zzn4 *x,zzn4 *y,zzn4 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    zzn2 t1,t2,t3;
    if (mr_mip->ERNUM) return;
	if (x==y) {zzn4_sqr(_MIPP_ x,w); return; }
    MR_IN(FUNC_BASE+9)

    t1.a=mr_mip->w12;
    t1.b=mr_mip->w13;
    t2.a=mr_mip->w8;
    t2.b=mr_mip->w9;
    t3.a=mr_mip->w10;
    t3.b=mr_mip->w11;
    zzn2_copy(&(x->a),&t1);
    zzn2_copy(&(x->b),&t2);
    zzn2_mul(_MIPP_ &t1,&(y->a),&t1);   /* t1= x->a * y->a */
    zzn2_mul(_MIPP_ &t2,&(y->b),&t2);   /* t2 = x->b * y->b */
    zzn2_copy(&(y->a),&t3);
    zzn2_add(_MIPP_ &t3,&(y->b),&t3);   /* y->a + y->b */

    zzn2_add(_MIPP_ &(x->b),&(x->a),&(w->b)); /* x->a + x->b */
    zzn2_mul(_MIPP_ &(w->b),&t3,&(w->b));     /* t3= (x->a + x->b)*(y->a + y->b) */
    zzn2_sub(_MIPP_ &(w->b),&t1,&(w->b));
    zzn2_sub(_MIPP_ &(w->b),&t2,&(w->b));     /*  w->b = t3-(t1+t2) */
    zzn2_copy(&t1,&(w->a));
    zzn2_txx(_MIPP_ &t2);
    zzn2_add(_MIPP_ &(w->a),&t2,&(w->a));	/* w->a = t1+tx(t2) */
    if (x->unitary && y->unitary) w->unitary=TRUE;
    else w->unitary=FALSE;

    MR_OUT
}

void zzn4_inv(_MIPD_ zzn4 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
	zzn2 t1,t2;
    if (mr_mip->ERNUM) return;
    if (w->unitary)
    {
        zzn4_conj(_MIPP_ w,w);
        return;
    }
	MR_IN(FUNC_BASE+10)

    t1.a=mr_mip->w8;
    t1.b=mr_mip->w9;
    t2.a=mr_mip->w10;
    t2.b=mr_mip->w11; 
    zzn2_mul(_MIPP_ &(w->a),&(w->a),&t1);
    zzn2_mul(_MIPP_ &(w->b),&(w->b),&t2);
    zzn2_txx(_MIPP_ &t2);
    zzn2_sub(_MIPP_ &t1,&t2,&t1);
    zzn2_inv(_MIPP_ &t1);
    zzn2_mul(_MIPP_ &(w->a),&t1,&(w->a));
    zzn2_negate(_MIPP_ &t1,&t1);
    zzn2_mul(_MIPP_ &(w->b),&t1,&(w->b));

	MR_OUT
}

/* divide zzn4 by 2 */

void zzn4_div2(_MIPD_ zzn4 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(FUNC_BASE+11)

    zzn2_div2(_MIPP_ &(w->a));
    zzn2_div2(_MIPP_ &(w->b));
	w->unitary=FALSE;

    MR_OUT
}

void zzn4_powq(_MIPD_ zzn2 *fr,zzn4 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
	MR_IN(FUNC_BASE+12)
	zzn2_conj(_MIPP_ &(w->a),&(w->a));
    zzn2_conj(_MIPP_ &(w->b),&(w->b));
	zzn2_mul(_MIPP_ &(w->b),fr,&(w->b));
	MR_OUT
}

void zzn4_tx(_MIPD_ zzn4* w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
	zzn2 t;	
	MR_IN(FUNC_BASE+13)

    t.a=mr_mip->w8;
    t.b=mr_mip->w9;
	zzn2_copy(&(w->b),&t);
	zzn2_txx(_MIPP_ &t);
	zzn2_copy(&(w->a),&(w->b));
	zzn2_copy(&t,&(w->a));

	MR_OUT
}
