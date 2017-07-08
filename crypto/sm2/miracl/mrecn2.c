
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
 *   MIRACL E(F_p^2) support functions 
 *   mrecn2.c
 */

#include <stdlib.h> 
#include <openssl/miracl.h>
#ifdef MR_STATIC
#include <string.h>
#endif

#ifndef MR_EDWARDS

BOOL ecn2_iszero(ecn2 *a)
{
    if (a->marker==MR_EPOINT_INFINITY) return TRUE;
    return FALSE;
}

void ecn2_copy(ecn2 *a,ecn2 *b)
{
    zzn2_copy(&(a->x),&(b->x));
    zzn2_copy(&(a->y),&(b->y));
#ifndef MR_AFFINE_ONLY
    if (a->marker==MR_EPOINT_GENERAL)  zzn2_copy(&(a->z),&(b->z));
#endif
    b->marker=a->marker;
}

void ecn2_zero(ecn2 *a)
{
    zzn2_zero(&(a->x)); zzn2_zero(&(a->y)); 
#ifndef MR_AFFINE_ONLY
    if (a->marker==MR_EPOINT_GENERAL) zzn2_zero(&(a->z));
#endif
    a->marker=MR_EPOINT_INFINITY;
}

BOOL ecn2_compare(_MIPD_ ecn2 *a,ecn2 *b)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return FALSE;

    MR_IN(193)
    ecn2_norm(_MIPP_ a);
    ecn2_norm(_MIPP_ b);
    MR_OUT
    if (zzn2_compare(&(a->x),&(b->x)) && zzn2_compare(&(a->y),&(b->y)) && a->marker==b->marker) return TRUE;
    return FALSE;
}

void ecn2_norm(_MIPD_ ecn2 *a)
{
    zzn2 t;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
#ifndef MR_AFFINE_ONLY
    if (mr_mip->ERNUM) return;
    if (a->marker!=MR_EPOINT_GENERAL) return;

    MR_IN(194)

    zzn2_inv(_MIPP_ &(a->z));

    t.a=mr_mip->w3;
    t.b=mr_mip->w4;
    zzn2_copy(&(a->z),&t);

    zzn2_sqr(_MIPP_ &(a->z),&(a->z));
    zzn2_mul(_MIPP_ &(a->x),&(a->z),&(a->x));
    zzn2_mul(_MIPP_ &(a->z),&t,&(a->z));
    zzn2_mul(_MIPP_ &(a->y),&(a->z),&(a->y));
    zzn2_from_zzn(mr_mip->one,&(a->z));
    a->marker=MR_EPOINT_NORMALIZED;

    MR_OUT
#endif
}

void ecn2_get(_MIPD_ ecn2 *e,zzn2 *x,zzn2 *y,zzn2 *z)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    
    zzn2_copy(&(e->x),x);
    zzn2_copy(&(e->y),y);
#ifndef MR_AFFINE_ONLY
    if (e->marker==MR_EPOINT_GENERAL) zzn2_copy(&(e->z),z);
    else                              zzn2_from_zzn(mr_mip->one,z);
#endif
}

void ecn2_getxy(ecn2 *e,zzn2 *x,zzn2 *y)
{
    zzn2_copy(&(e->x),x);
    zzn2_copy(&(e->y),y);
}

void ecn2_getx(ecn2 *e,zzn2 *x)
{
    zzn2_copy(&(e->x),x);
}

void ecn2_psi(_MIPD_ zzn2 *psi,ecn2 *P)
{ /* apply GLS morphism to P */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    MR_IN(212)
    ecn2_norm(_MIPP_ P);
    zzn2_conj(_MIPP_ &(P->x),&(P->x));
    zzn2_conj(_MIPP_ &(P->y),&(P->y));
    zzn2_mul(_MIPP_ &(P->x),&psi[0],&(P->x));
    zzn2_mul(_MIPP_ &(P->y),&psi[1],&(P->y));

    MR_OUT
}

#ifndef MR_AFFINE_ONLY
void ecn2_getz(_MIPD_ ecn2 *e,zzn2 *z)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    if (e->marker==MR_EPOINT_GENERAL) zzn2_copy(&(e->z),z);
    else                              zzn2_from_zzn(mr_mip->one,z);
}
#endif

void ecn2_rhs(_MIPD_ zzn2 *x,zzn2 *rhs)
{ /* calculate RHS of elliptic curve equation */
    int twist;
    zzn2 A,B;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    twist=mr_mip->TWIST;

    MR_IN(202)

    A.a=mr_mip->w10;
    A.b=mr_mip->w11;
    B.a=mr_mip->w12;
    B.b=mr_mip->w13;

    if (mr_abs(mr_mip->Asize)<MR_TOOBIG) zzn2_from_int(_MIPP_ mr_mip->Asize,&A);
    else zzn2_from_zzn(mr_mip->A,&A);

    if (mr_abs(mr_mip->Bsize)<MR_TOOBIG) zzn2_from_int(_MIPP_ mr_mip->Bsize,&B);
    else zzn2_from_zzn(mr_mip->B,&B);
  
    if (twist)
    { /* assume its the quartic or sextic twist, if such is possible */
		if (twist==MR_QUARTIC_M)
		{
			zzn2_mul(_MIPP_ &A,x,&B);
			zzn2_txx(_MIPP_ &B);
		}
		if (twist==MR_QUARTIC_D)
		{
			zzn2_mul(_MIPP_ &A,x,&B);
			zzn2_txd(_MIPP_ &B);
		}
		if (twist==MR_SEXTIC_M)
		{
			zzn2_txx(_MIPP_ &B);
		}
		if (twist==MR_SEXTIC_D)
		{
			zzn2_txd(_MIPP_ &B);
		}
		if (twist==MR_QUADRATIC)
		{
			zzn2_txx(_MIPP_ &B);
            zzn2_txx(_MIPP_ &B);
            zzn2_txx(_MIPP_ &B);

            zzn2_mul(_MIPP_ &A,x,&A);
            zzn2_txx(_MIPP_ &A);
            zzn2_txx(_MIPP_ &A);
            zzn2_add(_MIPP_ &B,&A,&B);

		}
/*
        if (mr_mip->Asize==0 || mr_mip->Bsize==0)
        {
            if (mr_mip->Asize==0)
            { // CM Discriminant D=3 - its the sextic twist (Hope I got the right one!). This works for BN curves 
                zzn2_txd(_MIPP_ &B);
            }
            if (mr_mip->Bsize==0)
            { // CM Discriminant D=1 - its the quartic twist. 
                zzn2_mul(_MIPP_ &A,x,&B);
				zzn2_txx(_MIPP_ &B);
            }
        }
        else
        { // its the quadratic twist 

            zzn2_txx(_MIPP_ &B);
            zzn2_txx(_MIPP_ &B);
            zzn2_txx(_MIPP_ &B);

            zzn2_mul(_MIPP_ &A,x,&A);
            zzn2_txx(_MIPP_ &A);
            zzn2_txx(_MIPP_ &A);
            zzn2_add(_MIPP_ &B,&A,&B);

        }
*/
    }
    else
    {
        zzn2_mul(_MIPP_ &A,x,&A);
        zzn2_add(_MIPP_ &B,&A,&B);
    }

    zzn2_sqr(_MIPP_ x,&A);
    zzn2_mul(_MIPP_ &A,x,&A);
    zzn2_add(_MIPP_ &B,&A,rhs);

    MR_OUT
}

BOOL ecn2_set(_MIPD_ zzn2 *x,zzn2 *y,ecn2 *e)
{
    zzn2 lhs,rhs;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return FALSE;

    MR_IN(195)

    lhs.a=mr_mip->w10;
    lhs.b=mr_mip->w11;
    rhs.a=mr_mip->w12;
    rhs.b=mr_mip->w13;

    ecn2_rhs(_MIPP_ x,&rhs);

    zzn2_sqr(_MIPP_ y,&lhs);

    if (!zzn2_compare(&lhs,&rhs))
    {
        MR_OUT
        return FALSE;
    }

    zzn2_copy(x,&(e->x));
    zzn2_copy(y,&(e->y));

    e->marker=MR_EPOINT_NORMALIZED;

    MR_OUT
    return TRUE;
}

#ifndef MR_NOSUPPORT_COMPRESSION


BOOL ecn2_setx(_MIPD_ zzn2 *x,ecn2 *e)
{
    zzn2 rhs;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return FALSE;

    MR_IN(201)

    rhs.a=mr_mip->w12;
    rhs.b=mr_mip->w13;

    ecn2_rhs(_MIPP_ x,&rhs);
    if (!zzn2_iszero(&rhs))
    {
		if (!zzn2_qr(_MIPP_ &rhs))
		{
            MR_OUT
            return FALSE;
		}
        zzn2_sqrt(_MIPP_ &rhs,&rhs); 
    }

    zzn2_copy(x,&(e->x));
    zzn2_copy(&rhs,&(e->y));

    e->marker=MR_EPOINT_NORMALIZED;

    MR_OUT
    return TRUE;
}

#endif

#ifndef MR_AFFINE_ONLY
void ecn2_setxyz(_MIPD_ zzn2 *x,zzn2 *y,zzn2 *z,ecn2 *e)
{
    zzn2_copy(x,&(e->x));
    zzn2_copy(y,&(e->y));
    zzn2_copy(z,&(e->z));


	if (zzn2_isunity(_MIPP_ z)) e->marker=MR_EPOINT_NORMALIZED;
    else e->marker=MR_EPOINT_GENERAL;
}
#endif

/* Normalise an array of points of length m<MR_MAX_M_T_S - requires a zzn2 workspace array of length m */

BOOL ecn2_multi_norm(_MIPD_ int m,zzn2 *work,ecn2 *p)
{ 

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
 
#ifndef MR_AFFINE_ONLY
    int i;
    zzn2 one,t;
    zzn2 w[MR_MAX_M_T_S];
    if (mr_mip->coord==MR_AFFINE) return TRUE;
    if (mr_mip->ERNUM) return FALSE;   
    if (m>MR_MAX_M_T_S) return FALSE;

    MR_IN(215)

    one.a=mr_mip->w12;
    one.b=mr_mip->w13;
    t.a=mr_mip->w14;
    t.b=mr_mip->w15;

    zzn2_from_int(_MIPP_ 1,&one);

    for (i=0;i<m;i++)
    {
        if (p[i].marker==MR_EPOINT_NORMALIZED) w[i]=one;
        else w[i]=p[i].z;
    }
  
    if (!zzn2_multi_inverse(_MIPP_ m,w,work)) 
    {
       MR_OUT
       return FALSE;
    }

    for (i=0;i<m;i++)
    {
        p[i].marker=MR_EPOINT_NORMALIZED;
        if (!zzn2_isunity(_MIPP_ &work[i]))
        {
            zzn2_sqr(_MIPP_ &work[i],&t);
            zzn2_mul(_MIPP_ &(p[i].x),&t,&(p[i].x));    
            zzn2_mul(_MIPP_ &t,&work[i],&t);
            zzn2_mul(_MIPP_ &(p[i].y),&t,&(p[i].y));  
        }
    }    
    MR_OUT
#endif
    return TRUE;   
}

void ecn2_negate(_MIPD_ ecn2 *u,ecn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    ecn2_copy(u,w);
    if (w->marker!=MR_EPOINT_INFINITY)
        zzn2_negate(_MIPP_ &(w->y),&(w->y));
}

BOOL ecn2_add2(_MIPD_ ecn2 *Q,ecn2 *P,zzn2 *lam,zzn2 *ex1)
{
    BOOL Doubling;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    Doubling=ecn2_add3(_MIPP_ Q,P,lam,ex1,NULL);

    return Doubling;
}

BOOL ecn2_add1(_MIPD_ ecn2 *Q,ecn2 *P,zzn2 *lam)
{
    BOOL Doubling;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    Doubling=ecn2_add3(_MIPP_ Q,P,lam,NULL,NULL);

    return Doubling;
}

BOOL ecn2_add(_MIPD_ ecn2 *Q,ecn2 *P)
{
    BOOL Doubling;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    zzn2 lam;

    lam.a = mr_mip->w14;
    lam.b = mr_mip->w15;

    Doubling=ecn2_add3(_MIPP_ Q,P,&lam,NULL,NULL);

    return Doubling;
}

BOOL ecn2_sub(_MIPD_ ecn2 *Q,ecn2 *P)
{
    BOOL Doubling;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    zzn2 lam;

    lam.a = mr_mip->w14;
    lam.b = mr_mip->w15;

    ecn2_negate(_MIPP_ Q,Q);

    Doubling=ecn2_add3(_MIPP_ Q,P,&lam,NULL,NULL);

    ecn2_negate(_MIPP_ Q,Q);

    return Doubling;
}

BOOL ecn2_add_sub(_MIPD_ ecn2 *P,ecn2 *Q,ecn2 *PP,ecn2 *PM)
{ /* PP=P+Q, PM=P-Q. Assumes P and Q are both normalized, and P!=Q */
 #ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    zzn2 t1,t2,lam;

    if (mr_mip->ERNUM) return FALSE;

    if (P->marker==MR_EPOINT_GENERAL || Q->marker==MR_EPOINT_GENERAL)
    { /* Sorry, some restrictions.. */
        mr_berror(_MIPP_ MR_ERR_BAD_PARAMETERS);
        MR_OUT
        return FALSE;
    }

    if (zzn2_compare(&(P->x),&(Q->x)))
    { /* P=Q or P=-Q - shouldn't happen */
        ecn2_copy(P,PP);
        ecn2_add(_MIPP_ Q,PP);
        ecn2_copy(P,PM);
        ecn2_sub(_MIPP_ Q,PM);

        MR_OUT
        return TRUE;
    }

    t1.a = mr_mip->w8;
    t1.b = mr_mip->w9; 
    t2.a = mr_mip->w10; 
    t2.b = mr_mip->w11; 
    lam.a = mr_mip->w12; 
    lam.b = mr_mip->w13;    

    zzn2_copy(&(P->x),&t2);
    zzn2_sub(_MIPP_ &t2,&(Q->x),&t2);
    zzn2_inv(_MIPP_ &t2);   /* only one inverse required */
    zzn2_add(_MIPP_ &(P->x),&(Q->x),&(PP->x));
    zzn2_copy(&(PP->x),&(PM->x));

    zzn2_copy(&(P->y),&t1);
    zzn2_sub(_MIPP_ &t1,&(Q->y),&t1);
    zzn2_copy(&t1,&lam);
    zzn2_mul(_MIPP_ &lam,&t2,&lam);
    zzn2_copy(&lam,&t1);
    zzn2_sqr(_MIPP_ &t1,&t1);
    zzn2_sub(_MIPP_ &t1,&(PP->x),&(PP->x));
    zzn2_copy(&(Q->x),&(PP->y));
    zzn2_sub(_MIPP_ &(PP->y),&(PP->x),&(PP->y));
    zzn2_mul(_MIPP_ &(PP->y),&lam,&(PP->y));
    zzn2_sub(_MIPP_ &(PP->y),&(Q->y),&(PP->y));

    zzn2_copy(&(P->y),&t1);
    zzn2_add(_MIPP_ &t1,&(Q->y),&t1);
    zzn2_copy(&t1,&lam);
    zzn2_mul(_MIPP_ &lam,&t2,&lam);
    zzn2_copy(&lam,&t1);
    zzn2_sqr(_MIPP_ &t1,&t1);
    zzn2_sub(_MIPP_ &t1,&(PM->x),&(PM->x));
    zzn2_copy(&(Q->x),&(PM->y));
    zzn2_sub(_MIPP_ &(PM->y),&(PM->x),&(PM->y));
    zzn2_mul(_MIPP_ &(PM->y),&lam,&(PM->y));
    zzn2_add(_MIPP_ &(PM->y),&(Q->y),&(PM->y));

    PP->marker=MR_EPOINT_NORMALIZED;
    PM->marker=MR_EPOINT_NORMALIZED;

    return TRUE;
}

BOOL ecn2_add3(_MIPD_ ecn2 *Q,ecn2 *P,zzn2 *lam,zzn2 *ex1,zzn2 *ex2)
{ /* P+=Q */
    BOOL Doubling=FALSE;
    int twist;
    int iA;
    zzn2 t1,t2,t3;
    zzn2 Yzzz;
 
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    t1.a = mr_mip->w8;
    t1.b = mr_mip->w9; 
    t2.a = mr_mip->w10; 
    t2.b = mr_mip->w11; 
    t3.a = mr_mip->w12; 
    t3.b = mr_mip->w13; 
    Yzzz.a = mr_mip->w3;
    Yzzz.b = mr_mip->w4;

    twist=mr_mip->TWIST;
    if (mr_mip->ERNUM) return FALSE;

    if (P->marker==MR_EPOINT_INFINITY)
    {
        ecn2_copy(Q,P);
        return Doubling;
    }
    if (Q->marker==MR_EPOINT_INFINITY) return Doubling;

    MR_IN(205)

    if (Q!=P && Q->marker==MR_EPOINT_GENERAL)
    { /* Sorry, this code is optimized for mixed addition only */
        mr_berror(_MIPP_ MR_ERR_BAD_PARAMETERS);
        MR_OUT
        return Doubling;
    }
#ifndef MR_AFFINE_ONLY
    if (mr_mip->coord==MR_AFFINE)
    {
#endif
        if (!zzn2_compare(&(P->x),&(Q->x)))
        {
            zzn2_copy(&(P->y),&t1);
            zzn2_sub(_MIPP_ &t1,&(Q->y),&t1);
            zzn2_copy(&(P->x),&t2);
            zzn2_sub(_MIPP_ &t2,&(Q->x),&t2);
            zzn2_copy(&t1,lam);
            zzn2_inv(_MIPP_ &t2);
            zzn2_mul(_MIPP_ lam,&t2,lam);

            zzn2_add(_MIPP_ &(P->x),&(Q->x),&(P->x));
            zzn2_copy(lam,&t1);
            zzn2_sqr(_MIPP_ &t1,&t1);
            zzn2_sub(_MIPP_ &t1,&(P->x),&(P->x));
           
            zzn2_copy(&(Q->x),&(P->y));
            zzn2_sub(_MIPP_ &(P->y),&(P->x),&(P->y));
            zzn2_mul(_MIPP_ &(P->y),lam,&(P->y));
            zzn2_sub(_MIPP_ &(P->y),&(Q->y),&(P->y));
        }
        else
        {   
            if (!zzn2_compare(&(P->y),&(Q->y)) || zzn2_iszero(&(P->y)))
            {
                ecn2_zero(P);
                zzn2_from_int(_MIPP_ 1,lam);
                MR_OUT
                return Doubling;
            }
            zzn2_copy(&(P->x),&t1);
            zzn2_copy(&(P->x),&t2);
            zzn2_copy(&(P->x),lam);
            zzn2_sqr(_MIPP_ lam,lam);
            zzn2_add(_MIPP_ lam,lam,&t3);
            zzn2_add(_MIPP_ lam,&t3,lam);

            if (mr_abs(mr_mip->Asize)<MR_TOOBIG) zzn2_from_int(_MIPP_ mr_mip->Asize,&t3);
            else zzn2_from_zzn(mr_mip->A,&t3);
        
            if (twist)
            {
				if (twist==MR_QUARTIC_M)
				{
					zzn2_txx(_MIPP_ &t3);
				}
				if (twist==MR_QUARTIC_D)
				{
					zzn2_txd(_MIPP_ &t3);
				}
				if (twist==MR_QUADRATIC)
				{
					zzn2_txx(_MIPP_ &t3);
					zzn2_txx(_MIPP_ &t3);
				}
/*
				if (mr_mip->Bsize==0)
				{ // assume its the quartic twist 
					zzn2_txx(_MIPP_ &t3);
				}
				else
				{
					zzn2_txx(_MIPP_ &t3);
					zzn2_txx(_MIPP_ &t3);
				}
*/
            }
            zzn2_add(_MIPP_ lam,&t3,lam);
            zzn2_add(_MIPP_ &(P->y),&(P->y),&t3);
            zzn2_inv(_MIPP_ &t3);
            zzn2_mul(_MIPP_ lam,&t3,lam);

            zzn2_add(_MIPP_ &t2,&(P->x),&t2);
            zzn2_copy(lam,&(P->x));
            zzn2_sqr(_MIPP_ &(P->x),&(P->x));
            zzn2_sub(_MIPP_ &(P->x),&t2,&(P->x));
            zzn2_sub(_MIPP_ &t1,&(P->x),&t1);
            zzn2_mul(_MIPP_ &t1,lam,&t1);
            zzn2_sub(_MIPP_ &t1,&(P->y),&(P->y));
        }

        P->marker=MR_EPOINT_NORMALIZED;
        MR_OUT
        return Doubling;
#ifndef MR_AFFINE_ONLY
    }

    if (Q==P) Doubling=TRUE;

    zzn2_copy(&(Q->x),&t3);
    zzn2_copy(&(Q->y),&Yzzz);

    if (!Doubling)
    {
        if (P->marker!=MR_EPOINT_NORMALIZED)
        {
            zzn2_sqr(_MIPP_ &(P->z),&t1); /* 1S */
            zzn2_mul(_MIPP_ &t3,&t1,&t3);         /* 1M */
            zzn2_mul(_MIPP_ &t1,&(P->z),&t1);     /* 1M */
            zzn2_mul(_MIPP_ &Yzzz,&t1,&Yzzz);     /* 1M */
        }
        if (zzn2_compare(&t3,&(P->x)))
        {
            if (!zzn2_compare(&Yzzz,&(P->y)) || zzn2_iszero(&(P->y)))
            {
                ecn2_zero(P);
                zzn2_from_int(_MIPP_ 1,lam);
                MR_OUT
                return Doubling;
            }
            else Doubling=TRUE;
        }
    }
    if (!Doubling)
    { /* Addition */
        zzn2_sub(_MIPP_ &t3,&(P->x),&t3);
        zzn2_sub(_MIPP_ &Yzzz,&(P->y),lam);
        if (P->marker==MR_EPOINT_NORMALIZED) zzn2_copy(&t3,&(P->z));
        else zzn2_mul(_MIPP_ &(P->z),&t3,&(P->z)); /* 1M */
        zzn2_sqr(_MIPP_ &t3,&t1);                  /* 1S */
        zzn2_mul(_MIPP_ &t1,&t3,&Yzzz);            /* 1M */
        zzn2_mul(_MIPP_ &t1,&(P->x),&t1);          /* 1M */
        zzn2_copy(&t1,&t3);
        zzn2_add(_MIPP_ &t3,&t3,&t3);
        zzn2_sqr(_MIPP_ lam,&(P->x));              /* 1S */
        zzn2_sub(_MIPP_ &(P->x),&t3,&(P->x));
        zzn2_sub(_MIPP_ &(P->x),&Yzzz,&(P->x));
        zzn2_sub(_MIPP_ &t1,&(P->x),&t1);
        zzn2_mul(_MIPP_ &t1,lam,&t1);              /* 1M */
        zzn2_mul(_MIPP_ &Yzzz,&(P->y),&Yzzz);      /* 1M */
        zzn2_sub(_MIPP_ &t1,&Yzzz,&(P->y));

/*
        zzn2_sub(_MIPP_ &(P->x),&t3,&t1);     
        zzn2_sub(_MIPP_ &(P->y),&Yzzz,lam); 
        if (P->marker==MR_EPOINT_NORMALIZED) zzn2_copy(&t1,&(P->z));
        else zzn2_mul(_MIPP_ &(P->z),&t1,&(P->z)); 
        zzn2_sqr(_MIPP_ &t1,&t2);             
        zzn2_add(_MIPP_ &(P->x),&t3,&t3);     
        zzn2_mul(_MIPP_ &t3,&t2,&t3);         
        zzn2_sqr(_MIPP_ lam,&(P->x));        
        zzn2_sub(_MIPP_ &(P->x),&t3,&(P->x));

        zzn2_mul(_MIPP_ &t2,&t1,&t2);         
        zzn2_add(_MIPP_ &(P->x),&(P->x),&t1);
        zzn2_sub(_MIPP_ &t3,&t1,&t3);
        zzn2_mul(_MIPP_ &t3,lam,&t3);         

        zzn2_add(_MIPP_ &(P->y),&Yzzz,&t1);

        zzn2_mul(_MIPP_ &t2,&t1,&t2);         
        zzn2_sub(_MIPP_ &t3,&t2,&(P->y));
        zzn2_div2(_MIPP_ &(P->y));
*/
    }
    else
    { /* doubling */
        zzn2_sqr(_MIPP_ &(P->y),&t3);  /* 1S */

        iA=mr_mip->Asize;
        if (iA!=0)
        {
            if (P->marker==MR_EPOINT_NORMALIZED) zzn2_from_int(_MIPP_ 1,&t1);
            else zzn2_sqr(_MIPP_ &(P->z),&t1);  /* 1S */
            if (ex2!=NULL) zzn2_copy(&t1,ex2);

            if (iA==-3 && twist<=MR_QUADRATIC)
            {
                if (twist==MR_QUADRATIC) zzn2_txx(_MIPP_ &t1); /* quadratic twist */
                zzn2_sub(_MIPP_ &(P->x),&t1,lam);
                zzn2_add(_MIPP_ &t1,&(P->x),&t1);
                zzn2_mul(_MIPP_ lam,&t1,lam);        /* 1M */
                zzn2_add(_MIPP_ lam,lam,&t2);
                zzn2_add(_MIPP_ lam,&t2,lam);
            }
            else
            {
                zzn2_sqr(_MIPP_ &(P->x),lam);  /* 1S */
                zzn2_add(_MIPP_ lam,lam,&t2);         
                zzn2_add(_MIPP_ lam,&t2,lam);      
          
                if (twist==MR_QUADRATIC) zzn2_txx(_MIPP_ &t1);    /* quadratic twist */
                zzn2_sqr(_MIPP_ &t1,&t1);          /* 1S */ 
				if (twist==MR_QUARTIC_M) zzn2_txx(_MIPP_ &t1);    /* quartic twist */ 
				if (twist==MR_QUARTIC_D) zzn2_txd(_MIPP_ &t1);    /* quartic twist */ 
                if (iA!=1)
                { /* optimized for iA=1 case */
                    if (iA<MR_TOOBIG) zzn2_imul(_MIPP_ &t1,iA,&t1);
                    else zzn2_smul(_MIPP_ &t1,mr_mip->A,&t1);
                }
                zzn2_add(_MIPP_ lam,&t1,lam);
            }
        }
        else
        {
            zzn2_sqr(_MIPP_ &(P->x),lam);  /* 1S */
            zzn2_add(_MIPP_ lam,lam,&t2);
            zzn2_add(_MIPP_ lam,&t2,lam);
        }
        zzn2_mul(_MIPP_ &(P->x),&t3,&t1);    /* 1M */
        zzn2_add(_MIPP_ &t1,&t1,&t1);
        zzn2_add(_MIPP_ &t1,&t1,&t1);
        zzn2_sqr(_MIPP_ lam,&(P->x));        /* 1S */
        zzn2_add(_MIPP_ &t1,&t1,&t2);
        zzn2_sub(_MIPP_ &(P->x),&t2,&(P->x));
        if (P->marker==MR_EPOINT_NORMALIZED) zzn2_copy(&(P->y),&(P->z));
        else zzn2_mul(_MIPP_ &(P->z),&(P->y),&(P->z));   /* 1M */
        zzn2_add(_MIPP_ &(P->z),&(P->z),&(P->z));
        zzn2_add(_MIPP_ &t3,&t3,&t3);
        if (ex1!=NULL) zzn2_copy(&t3,ex1);
        zzn2_sqr(_MIPP_ &t3,&t3);                  /* 1S */
        zzn2_add(_MIPP_ &t3,&t3,&t3);
        zzn2_sub(_MIPP_ &t1,&(P->x),&t1);
        zzn2_mul(_MIPP_ lam,&t1,&(P->y));          /* 1M */  
        zzn2_sub(_MIPP_ &(P->y),&t3,&(P->y));
    }

    P->marker=MR_EPOINT_GENERAL;
    MR_OUT
    return Doubling;
#endif
}

/* Dahmen, Okeya and Schepers "Affine Precomputation with Sole Inversion in Elliptic Curve Cryptography" */
/* Precomputes table into T. Assumes first P has been copied to P[0], then calculates 3P, 5P, 7P etc. into T */

#define MR_PRE_2 (14+4*MR_ECC_STORE_N2)

static void ecn2_pre(_MIPD_ int sz,BOOL norm,ecn2 *PT)
{
    int twist;
    int i,j;
    zzn2 A,B,C,D,E,T,W;

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

#ifndef MR_STATIC
    zzn2 *d=(zzn2 *)mr_alloc(_MIPP_ sz,sizeof(zzn2));
    zzn2 *e=(zzn2 *)mr_alloc(_MIPP_ sz,sizeof(zzn2));
    char *mem = (char *)memalloc(_MIPP_ 14+4*sz);
#else
    zzn2 d[MR_ECC_STORE_N2],e[MR_ECC_STORE_N2];
    char mem[MR_BIG_RESERVE(MR_PRE_2)];       
 	memset(mem, 0, MR_BIG_RESERVE(MR_PRE_2));   
#endif

    twist=mr_mip->TWIST;
    j=0;

    A.a= mirvar_mem(_MIPP_ mem, j++);
    A.b= mirvar_mem(_MIPP_ mem, j++);
    B.a= mirvar_mem(_MIPP_ mem, j++);
    B.b= mirvar_mem(_MIPP_ mem, j++);
    C.a= mirvar_mem(_MIPP_ mem, j++);
    C.b= mirvar_mem(_MIPP_ mem, j++);
    D.a= mirvar_mem(_MIPP_ mem, j++);
    D.b= mirvar_mem(_MIPP_ mem, j++);
    E.a= mirvar_mem(_MIPP_ mem, j++);
    E.b= mirvar_mem(_MIPP_ mem, j++);
    T.a= mirvar_mem(_MIPP_ mem, j++);
    T.b= mirvar_mem(_MIPP_ mem, j++);
    W.a= mirvar_mem(_MIPP_ mem, j++);
    W.b= mirvar_mem(_MIPP_ mem, j++);

    for (i=0;i<sz;i++)
    {
        d[i].a= mirvar_mem(_MIPP_ mem, j++);
        d[i].b= mirvar_mem(_MIPP_ mem, j++);
        e[i].a= mirvar_mem(_MIPP_ mem, j++);
        e[i].b= mirvar_mem(_MIPP_ mem, j++);
    }

    zzn2_add(_MIPP_ &(PT[0].y),&(PT[0].y),&d[0]);   /* 1. d_0=2.y */
    zzn2_sqr(_MIPP_ &d[0],&C);                      /* 2. C=d_0^2 */

    zzn2_sqr(_MIPP_ &(PT[0].x),&T);
    zzn2_add(_MIPP_ &T,&T,&A);
    zzn2_add(_MIPP_ &T,&A,&T);
           
    if (mr_abs(mr_mip->Asize)<MR_TOOBIG) zzn2_from_int(_MIPP_ mr_mip->Asize,&A);
    else zzn2_from_zzn(mr_mip->A,&A);
        
    if (twist)
    {
		if (twist==MR_QUARTIC_M)
		{
			zzn2_txx(_MIPP_ &A);
		}
		if (twist==MR_QUARTIC_D)
		{
			zzn2_txd(_MIPP_ &A);
		}
		if (twist==MR_QUADRATIC)
		{
			zzn2_txx(_MIPP_ &A);
			zzn2_txx(_MIPP_ &A);
		}
/*
		if (mr_mip->Bsize==0)
		{ // assume its the quartic twist 
			zzn2_txx(_MIPP_ &A);
		}
		else
		{
			zzn2_txx(_MIPP_ &A);
			zzn2_txx(_MIPP_ &A);
		}
*/
    }
    zzn2_add(_MIPP_ &A,&T,&A);             /* 3. A=3x^2+a */
    zzn2_copy(&A,&W);

    zzn2_add(_MIPP_ &C,&C,&B);
    zzn2_add(_MIPP_ &B,&C,&B);
    zzn2_mul(_MIPP_ &B,&(PT[0].x),&B);     /* 4. B=3C.x */

    zzn2_sqr(_MIPP_ &A,&d[1]);
    zzn2_sub(_MIPP_ &d[1],&B,&d[1]);       /* 5. d_1=A^2-B */

    zzn2_sqr(_MIPP_ &d[1],&E);             /* 6. E=d_1^2 */
    
    zzn2_mul(_MIPP_ &B,&E,&B);             /* 7. B=E.B */

    zzn2_sqr(_MIPP_ &C,&C);                /* 8. C=C^2 */

    zzn2_mul(_MIPP_ &E,&d[1],&D);          /* 9. D=E.d_1 */

    zzn2_mul(_MIPP_ &A,&d[1],&A);
    zzn2_add(_MIPP_ &A,&C,&A);
    zzn2_negate(_MIPP_ &A,&A);             /* 10. A=-d_1*A-C */

    zzn2_add(_MIPP_ &D,&D,&T);
    zzn2_sqr(_MIPP_ &A,&d[2]);
    zzn2_sub(_MIPP_ &d[2],&T,&d[2]);
    zzn2_sub(_MIPP_ &d[2],&B,&d[2]);       /* 11. d_2=A^2-2D-B */

    if (sz>3)
    {
        zzn2_sqr(_MIPP_ &d[2],&E);             /* 12. E=d_2^2 */

        zzn2_add(_MIPP_ &T,&D,&T);
        zzn2_add(_MIPP_ &T,&B,&T);
        zzn2_mul(_MIPP_ &T,&E,&B);             /* 13. B=E(B+3D) */
        
        zzn2_add(_MIPP_ &A,&A,&T);
        zzn2_add(_MIPP_ &C,&T,&C);
        zzn2_mul(_MIPP_ &C,&D,&C);             /* 14. C=D(2A+C) */

        zzn2_mul(_MIPP_ &d[2],&E,&D);          /* 15. D=E.d_2 */

        zzn2_mul(_MIPP_ &A,&d[2],&A);
        zzn2_add(_MIPP_ &A,&C,&A);
        zzn2_negate(_MIPP_ &A,&A);             /* 16. A=-d_2*A-C */

 
        zzn2_sqr(_MIPP_ &A,&d[3]);
        zzn2_sub(_MIPP_ &d[3],&D,&d[3]);
        zzn2_sub(_MIPP_ &d[3],&B,&d[3]);       /* 17. d_3=A^2-D-B */

        for (i=4;i<sz;i++)
        {
            zzn2_sqr(_MIPP_ &d[i-1],&E);       /* 19. E=d(i-1)^2 */
            zzn2_mul(_MIPP_ &B,&E,&B);         /* 20. B=E.B */
            zzn2_mul(_MIPP_ &C,&D,&C);         /* 21. C=D.C */
            zzn2_mul(_MIPP_ &E,&d[i-1],&D);    /* 22. D=E.d(i-1) */

            zzn2_mul(_MIPP_ &A,&d[i-1],&A);
            zzn2_add(_MIPP_ &A,&C,&A);
            zzn2_negate(_MIPP_ &A,&A);         /* 23. A=-d(i-1)*A-C */

            zzn2_sqr(_MIPP_ &A,&d[i]);
            zzn2_sub(_MIPP_ &d[i],&D,&d[i]);
            zzn2_sub(_MIPP_ &d[i],&B,&d[i]);   /* 24. d(i)=A^2-D-B */
        }
    }

    zzn2_copy(&d[0],&e[0]);
    for (i=1;i<sz;i++)
        zzn2_mul(_MIPP_ &e[i-1],&d[i],&e[i]);
       
    zzn2_copy(&e[sz-1],&A);
    zzn2_inv(_MIPP_ &A);

    for (i=sz-1;i>0;i--)
    {
        zzn2_copy(&d[i],&B);
        zzn2_mul(_MIPP_ &e[i-1],&A,&d[i]);  
        zzn2_mul(_MIPP_ &A,&B,&A);
    }
    zzn2_copy(&A,&d[0]);

    for (i=1;i<sz;i++)
    {
        zzn2_sqr(_MIPP_ &e[i-1],&T);
        zzn2_mul(_MIPP_ &d[i],&T,&d[i]); /** */
    }

    zzn2_mul(_MIPP_ &W,&d[0],&W);
    zzn2_sqr(_MIPP_ &W,&A);
    zzn2_sub(_MIPP_ &A,&(PT[0].x),&A);
    zzn2_sub(_MIPP_ &A,&(PT[0].x),&A);
    zzn2_sub(_MIPP_ &(PT[0].x),&A,&B);
    zzn2_mul(_MIPP_ &B,&W,&B);
    zzn2_sub(_MIPP_ &B,&(PT[0].y),&B);

    zzn2_sub(_MIPP_ &B,&(PT[0].y),&T);
    zzn2_mul(_MIPP_ &T,&d[1],&T);

    zzn2_sqr(_MIPP_ &T,&(PT[1].x));
    zzn2_sub(_MIPP_ &(PT[1].x),&A,&(PT[1].x));
    zzn2_sub(_MIPP_ &(PT[1].x),&(PT[0].x),&(PT[1].x));

    zzn2_sub(_MIPP_ &A,&(PT[1].x),&(PT[1].y));
    zzn2_mul(_MIPP_ &(PT[1].y),&T,&(PT[1].y));
    zzn2_sub(_MIPP_ &(PT[1].y),&B,&(PT[1].y));

    for (i=2;i<sz;i++)
    {
        zzn2_sub(_MIPP_ &(PT[i-1].y),&B,&T);
        zzn2_mul(_MIPP_ &T,&d[i],&T);

        zzn2_sqr(_MIPP_ &T,&(PT[i].x));
        zzn2_sub(_MIPP_ &(PT[i].x),&A,&(PT[i].x));
        zzn2_sub(_MIPP_ &(PT[i].x),&(PT[i-1].x),&(PT[i].x));

        zzn2_sub(_MIPP_ &A,&(PT[i].x),&(PT[i].y));
        zzn2_mul(_MIPP_ &(PT[i].y),&T,&(PT[i].y));
        zzn2_sub(_MIPP_ &(PT[i].y),&B,&(PT[i].y));
    }
    for (i=0;i<sz;i++) PT[i].marker=MR_EPOINT_NORMALIZED;

#ifndef MR_STATIC
    memkill(_MIPP_ mem, 14+4*sz);
    mr_free(d); mr_free(e);
#else
    memset(mem, 0, MR_BIG_RESERVE(MR_PRE_2));
#endif
}

#ifndef MR_DOUBLE_BIG
#define MR_MUL_RESERVE (1+4*MR_ECC_STORE_N2)
#else
#define MR_MUL_RESERVE (2+4*MR_ECC_STORE_N2)
#endif

int ecn2_mul(_MIPD_ big k,ecn2 *P)
{
    int i,j,nb,n,nbs,nzs,nadds;
	BOOL neg;
    big h;
    ecn2 T[MR_ECC_STORE_N2];
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

#ifndef MR_STATIC
    char *mem = (char *)memalloc(_MIPP_ MR_MUL_RESERVE);
#else
    char mem[MR_BIG_RESERVE(MR_MUL_RESERVE)];
    memset(mem, 0, MR_BIG_RESERVE(MR_MUL_RESERVE));
#endif

    j=0;
#ifndef MR_DOUBLE_BIG
    h=mirvar_mem(_MIPP_ mem, j++);
#else
    h=mirvar_mem(_MIPP_ mem, j); j+=2;
#endif
    for (i=0;i<MR_ECC_STORE_N2;i++)
    {
        T[i].x.a= mirvar_mem(_MIPP_ mem, j++);
        T[i].x.b= mirvar_mem(_MIPP_ mem, j++);
        T[i].y.a= mirvar_mem(_MIPP_ mem, j++);
        T[i].y.b= mirvar_mem(_MIPP_ mem, j++);
    }

    MR_IN(207)

    ecn2_norm(_MIPP_ P);

	nadds=0;
  
	neg=FALSE;
	if (size(k)<0)
	{
		negify(k,k);
		ecn2_negate(_MIPP_ P,&T[0]);
		neg=TRUE;
	}
	else ecn2_copy(P,&T[0]);
		
	premult(_MIPP_ k,3,h);
    
	nb=logb2(_MIPP_ h);
    ecn2_pre(_MIPP_ MR_ECC_STORE_N2,TRUE,T);

    ecn2_zero(P);

    for (i=nb-1;i>=1;)
    {
        if (mr_mip->user!=NULL) (*mr_mip->user)();
        n=mr_naf_window(_MIPP_ k,h,i,&nbs,&nzs,MR_ECC_STORE_N2);
 
        for (j=0;j<nbs;j++) ecn2_add(_MIPP_ P,P);
       
        if (n>0) {nadds++; ecn2_add(_MIPP_ &T[n/2],P);}
        if (n<0) {nadds++; ecn2_sub(_MIPP_ &T[(-n)/2],P);}
        i-=nbs;
        if (nzs)
        {
            for (j=0;j<nzs;j++) ecn2_add(_MIPP_ P,P);
            i-=nzs;
        }
    }
	if (neg) negify(k,k);

    ecn2_norm(_MIPP_ P);
    MR_OUT

#ifndef MR_STATIC
    memkill(_MIPP_ mem, MR_MUL_RESERVE);
#else
    memset(mem, 0, MR_BIG_RESERVE(MR_MUL_RESERVE));
#endif
	return nadds;
}

/* Double addition, using Joint Sparse Form */
/* R=aP+bQ */

#ifndef MR_NO_ECC_MULTIADD

#define MR_MUL2_JSF_RESERVE 20

int ecn2_mul2_jsf(_MIPD_ big a,ecn2 *P,big b,ecn2 *Q,ecn2 *R)
{
    int e1,h1,e2,h2,bb,nadds;
    ecn2 P1,P2,PS,PD;
    big c,d,e,f;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

#ifndef MR_STATIC
    char *mem = (char *)memalloc(_MIPP_ MR_MUL2_JSF_RESERVE);
#else
    char mem[MR_BIG_RESERVE(MR_MUL2_JSF_RESERVE)];
    memset(mem, 0, MR_BIG_RESERVE(MR_MUL2_JSF_RESERVE));
#endif

    c = mirvar_mem(_MIPP_ mem, 0);
    d = mirvar_mem(_MIPP_ mem, 1);
    e = mirvar_mem(_MIPP_ mem, 2);
    f = mirvar_mem(_MIPP_ mem, 3);
    P1.x.a= mirvar_mem(_MIPP_ mem, 4);
    P1.x.b= mirvar_mem(_MIPP_ mem, 5);
    P1.y.a= mirvar_mem(_MIPP_ mem, 6);
    P1.y.b= mirvar_mem(_MIPP_ mem, 7);
    P2.x.a= mirvar_mem(_MIPP_ mem, 8);
    P2.x.b= mirvar_mem(_MIPP_ mem, 9);
    P2.y.a= mirvar_mem(_MIPP_ mem, 10);
    P2.y.b= mirvar_mem(_MIPP_ mem, 11);
    PS.x.a= mirvar_mem(_MIPP_ mem, 12);
    PS.x.b= mirvar_mem(_MIPP_ mem, 13);
    PS.y.a= mirvar_mem(_MIPP_ mem, 14);
    PS.y.b= mirvar_mem(_MIPP_ mem, 15);
    PD.x.a= mirvar_mem(_MIPP_ mem, 16);
    PD.x.b= mirvar_mem(_MIPP_ mem, 17);
    PD.y.a= mirvar_mem(_MIPP_ mem, 18);
    PD.y.b= mirvar_mem(_MIPP_ mem, 19);

    MR_IN(206)

    ecn2_norm(_MIPP_ Q); 
    ecn2_copy(Q,&P2); 

    copy(b,d);
    if (size(d)<0) 
    {
        negify(d,d);
        ecn2_negate(_MIPP_ &P2,&P2);
    }

    ecn2_norm(_MIPP_ P); 
    ecn2_copy(P,&P1); 

    copy(a,c);
    if (size(c)<0) 
    {
        negify(c,c);
        ecn2_negate(_MIPP_ &P1,&P1);
    }

    mr_jsf(_MIPP_ d,c,e,d,f,c);   /* calculate joint sparse form */
 
    if (mr_compare(e,f)>0) bb=logb2(_MIPP_ e)-1;
    else                   bb=logb2(_MIPP_ f)-1;

    ecn2_add_sub(_MIPP_ &P1,&P2,&PS,&PD);
    ecn2_zero(R);
	nadds=0;
   
    while (bb>=0) 
    { /* add/subtract method */
        if (mr_mip->user!=NULL) (*mr_mip->user)();
        ecn2_add(_MIPP_ R,R);
        e1=h1=e2=h2=0;

        if (mr_testbit(_MIPP_ d,bb)) e2=1;
        if (mr_testbit(_MIPP_ e,bb)) h2=1;
        if (mr_testbit(_MIPP_ c,bb)) e1=1;
        if (mr_testbit(_MIPP_ f,bb)) h1=1;

        if (e1!=h1)
        {
            if (e2==h2)
            {
                if (h1==1) {ecn2_add(_MIPP_ &P1,R); nadds++;}
                else       {ecn2_sub(_MIPP_ &P1,R); nadds++;}
            }
            else
            {
                if (h1==1)
                {
                    if (h2==1) {ecn2_add(_MIPP_ &PS,R); nadds++;}
                    else       {ecn2_add(_MIPP_ &PD,R); nadds++;}
                }
                else
                {
                    if (h2==1) {ecn2_sub(_MIPP_ &PD,R); nadds++;}
                    else       {ecn2_sub(_MIPP_ &PS,R); nadds++;}
                }
            }
        }
        else if (e2!=h2)
        {
            if (h2==1) {ecn2_add(_MIPP_ &P2,R); nadds++;}
            else       {ecn2_sub(_MIPP_ &P2,R); nadds++;}
        }
        bb-=1;
    }
    ecn2_norm(_MIPP_ R); 

    MR_OUT
#ifndef MR_STATIC
    memkill(_MIPP_ mem, MR_MUL2_JSF_RESERVE);
#else
    memset(mem, 0, MR_BIG_RESERVE(MR_MUL2_JSF_RESERVE));
#endif
	return nadds;

}

/* General purpose multi-exponentiation engine, using inter-leaving algorithm. Calculate aP+bQ+cR+dS...
   Inputs are divided into two groups of sizes wa<4 and wb<4. For the first group if the points are fixed the 
   first precomputed Table Ta[] may be taken from ROM. For the second group if the points are variable Tb[j] will
   have to computed online. Each group has its own precomputed store size, sza (=8?) and szb (=20?) respectively. 
   The values a,b,c.. are provided in ma[] and mb[], and 3.a,3.b,3.c (as required by the NAF) are provided in 
   ma3[] and mb3[]. If only one group is required, set wb=0 and pass NULL pointers.
   */

int ecn2_muln_engine(_MIPD_ int wa,int sza,int wb,int szb,big *ma,big *ma3,big *mb,big *mb3,ecn2 *Ta,ecn2 *Tb,ecn2 *R)
{ /* general purpose interleaving algorithm engine for multi-exp */
    int i,j,tba[4],pba[4],na[4],sa[4],tbb[4],pbb[4],nb[4],sb[4],nbits,nbs,nzs;
    int nadds;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    ecn2_zero(R);

    nbits=0;
    for (i=0;i<wa;i++) {sa[i]=exsign(ma[i]); tba[i]=0; j=logb2(_MIPP_ ma3[i]); if (j>nbits) nbits=j; }
    for (i=0;i<wb;i++) {sb[i]=exsign(mb[i]); tbb[i]=0; j=logb2(_MIPP_ mb3[i]); if (j>nbits) nbits=j; }
    
    nadds=0;
    for (i=nbits-1;i>=1;i--)
    {
        if (mr_mip->user!=NULL) (*mr_mip->user)();
        if (R->marker!=MR_EPOINT_INFINITY) ecn2_add(_MIPP_ R,R);
        for (j=0;j<wa;j++)
        { /* deal with the first group */
            if (tba[j]==0)
            {
                na[j]=mr_naf_window(_MIPP_ ma[j],ma3[j],i,&nbs,&nzs,sza);
                tba[j]=nbs+nzs;
                pba[j]=nbs;
            }
            tba[j]--;  pba[j]--; 
            if (pba[j]==0)
            {
                if (sa[j]==PLUS)
                {
                    if (na[j]>0) {ecn2_add(_MIPP_ &Ta[j*sza+na[j]/2],R); nadds++;}
                    if (na[j]<0) {ecn2_sub(_MIPP_ &Ta[j*sza+(-na[j])/2],R); nadds++;}
                }
                else
                {
                    if (na[j]>0) {ecn2_sub(_MIPP_ &Ta[j*sza+na[j]/2],R); nadds++;}
                    if (na[j]<0) {ecn2_add(_MIPP_ &Ta[j*sza+(-na[j])/2],R); nadds++;}
                }
            }         
        }
        for (j=0;j<wb;j++)
        { /* deal with the second group */
            if (tbb[j]==0)
            {
                nb[j]=mr_naf_window(_MIPP_ mb[j],mb3[j],i,&nbs,&nzs,szb);
                tbb[j]=nbs+nzs;
                pbb[j]=nbs;
            }
            tbb[j]--;  pbb[j]--; 
            if (pbb[j]==0)
            {
                if (sb[j]==PLUS)
                {
                    if (nb[j]>0) {ecn2_add(_MIPP_ &Tb[j*szb+nb[j]/2],R);  nadds++;}
                    if (nb[j]<0) {ecn2_sub(_MIPP_ &Tb[j*szb+(-nb[j])/2],R);  nadds++;}
                }
                else
                {
                    if (nb[j]>0) {ecn2_sub(_MIPP_ &Tb[j*szb+nb[j]/2],R);  nadds++;}
                    if (nb[j]<0) {ecn2_add(_MIPP_ &Tb[j*szb+(-nb[j])/2],R);  nadds++;}
                }
            }         
        }
    }
    ecn2_norm(_MIPP_ R);  
    return nadds;
}

/* Routines to support Galbraith, Lin, Scott (GLS) method for ECC */
/* requires an endomorphism psi */

/* *********************** */

/* Precompute T - first half from i.P, second half from i.psi(P) */ 

void ecn2_precomp_gls(_MIPD_ int sz,BOOL norm,ecn2 *P,zzn2 *psi,ecn2 *T)
{
    int i,j;

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    j=0;

    MR_IN(219)

    ecn2_norm(_MIPP_ P);
    ecn2_copy(P,&T[0]);
    
    ecn2_pre(_MIPP_ sz,norm,T); /* precompute table */

    for (i=sz;i<sz+sz;i++)
    {
        ecn2_copy(&T[i-sz],&T[i]);
        ecn2_psi(_MIPP_ psi,&T[i]);
    }

    MR_OUT
}

#ifndef MR_NO_ECC_MULTIADD

/* Calculate a[0].P+a[1].psi(P) using interleaving method */

#define MR_MUL2_GLS_RESERVE (2+2*MR_ECC_STORE_N2*4)

int ecn2_mul2_gls(_MIPD_ big *a,ecn2 *P,zzn2 *psi,ecn2 *R)
{
    int i,j,nadds;
    ecn2 T[2*MR_ECC_STORE_N2];
    big a3[2];
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

#ifndef MR_STATIC
    char *mem = (char *)memalloc(_MIPP_ MR_MUL2_GLS_RESERVE);
#else
    char mem[MR_BIG_RESERVE(MR_MUL2_GLS_RESERVE)];       
 	memset(mem, 0, MR_BIG_RESERVE(MR_MUL2_GLS_RESERVE));   
#endif

    for (j=i=0;i<2;i++)
        a3[i]=mirvar_mem(_MIPP_ mem, j++);

    for (i=0;i<2*MR_ECC_STORE_N2;i++)
    {
        T[i].x.a=mirvar_mem(_MIPP_  mem, j++);
        T[i].x.b=mirvar_mem(_MIPP_  mem, j++);
        T[i].y.a=mirvar_mem(_MIPP_  mem, j++);
        T[i].y.b=mirvar_mem(_MIPP_  mem, j++);       
        T[i].marker=MR_EPOINT_INFINITY;
    }
    MR_IN(220)

    ecn2_precomp_gls(_MIPP_ MR_ECC_STORE_N2,TRUE,P,psi,T);

    for (i=0;i<2;i++) premult(_MIPP_ a[i],3,a3[i]); /* calculate for NAF */

    nadds=ecn2_muln_engine(_MIPP_ 0,0,2,MR_ECC_STORE_N2,NULL,NULL,a,a3,NULL,T,R);

    ecn2_norm(_MIPP_ R);

    MR_OUT

#ifndef MR_STATIC
    memkill(_MIPP_ mem, MR_MUL2_GLS_RESERVE);
#else
    memset(mem, 0, MR_BIG_RESERVE(MR_MUL2_GLS_RESERVE));
#endif
    return nadds;
}

/* Calculates a[0]*P+a[1]*psi(P) + b[0]*Q+b[1]*psi(Q) 
   where P is fixed, and precomputations are already done off-line into FT
   using ecn2_precomp_gls. Useful for signature verification */

#define MR_MUL4_GLS_V_RESERVE (4+2*MR_ECC_STORE_N2*4)

int ecn2_mul4_gls_v(_MIPD_ big *a,int ns,ecn2 *FT,big *b,ecn2 *Q,zzn2 *psi,ecn2 *R)
{ 
    int i,j,nadds;
    ecn2 VT[2*MR_ECC_STORE_N2];
    big a3[2],b3[2];
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

#ifndef MR_STATIC
    char *mem = (char *)memalloc(_MIPP_ MR_MUL4_GLS_V_RESERVE);
#else
    char mem[MR_BIG_RESERVE(MR_MUL4_GLS_V_RESERVE)];       
 	memset(mem, 0, MR_BIG_RESERVE(MR_MUL4_GLS_V_RESERVE));   
#endif
    j=0;
    for (i=0;i<2;i++)
    {
        a3[i]=mirvar_mem(_MIPP_ mem, j++);
        b3[i]=mirvar_mem(_MIPP_ mem, j++);
    }
    for (i=0;i<2*MR_ECC_STORE_N2;i++)
    {
        VT[i].x.a=mirvar_mem(_MIPP_  mem, j++);
        VT[i].x.b=mirvar_mem(_MIPP_  mem, j++);
        VT[i].y.a=mirvar_mem(_MIPP_  mem, j++);
        VT[i].y.b=mirvar_mem(_MIPP_  mem, j++);       
        VT[i].marker=MR_EPOINT_INFINITY;
    }

    MR_IN(217)

    ecn2_precomp_gls(_MIPP_ MR_ECC_STORE_N2,TRUE,Q,psi,VT); /* precompute for the variable points */
    for (i=0;i<2;i++)
    { /* needed for NAF */
        premult(_MIPP_ a[i],3,a3[i]);
        premult(_MIPP_ b[i],3,b3[i]);
    }
    nadds=ecn2_muln_engine(_MIPP_ 2,ns,2,MR_ECC_STORE_N2,a,a3,b,b3,FT,VT,R);
    ecn2_norm(_MIPP_ R);

    MR_OUT

#ifndef MR_STATIC
    memkill(_MIPP_ mem, MR_MUL4_GLS_V_RESERVE);
#else
    memset(mem, 0, MR_BIG_RESERVE(MR_MUL4_GLS_V_RESERVE));
#endif
    return nadds;
}

/* Calculate a.P+b.Q using interleaving method. P is fixed and FT is precomputed from it */

void ecn2_precomp(_MIPD_ int sz,BOOL norm,ecn2 *P,ecn2 *T)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    MR_IN(216)

    ecn2_norm(_MIPP_ P);
    ecn2_copy(P,&T[0]);
    ecn2_pre(_MIPP_ sz,norm,T); 

    MR_OUT
}

#ifndef MR_DOUBLE_BIG
#define MR_MUL2_RESERVE (2+2*MR_ECC_STORE_N2*4)
#else
#define MR_MUL2_RESERVE (4+2*MR_ECC_STORE_N2*4)
#endif

int ecn2_mul2(_MIPD_ big a,int ns,ecn2 *FT,big b,ecn2 *Q,ecn2 *R)
{
    int i,j,nadds;
    ecn2 T[2*MR_ECC_STORE_N2];
    big a3,b3;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

#ifndef MR_STATIC
    char *mem = (char *)memalloc(_MIPP_ MR_MUL2_RESERVE);
#else
    char mem[MR_BIG_RESERVE(MR_MUL2_RESERVE)];       
 	memset(mem, 0, MR_BIG_RESERVE(MR_MUL2_RESERVE));   
#endif

    j=0;
#ifndef MR_DOUBLE_BIG
    a3=mirvar_mem(_MIPP_ mem, j++);
	b3=mirvar_mem(_MIPP_ mem, j++);
#else
    a3=mirvar_mem(_MIPP_ mem, j); j+=2;
	b3=mirvar_mem(_MIPP_ mem, j); j+=2;
#endif    
    for (i=0;i<2*MR_ECC_STORE_N2;i++)
    {
        T[i].x.a=mirvar_mem(_MIPP_  mem, j++);
        T[i].x.b=mirvar_mem(_MIPP_  mem, j++);
        T[i].y.a=mirvar_mem(_MIPP_  mem, j++);
        T[i].y.b=mirvar_mem(_MIPP_  mem, j++);       
        T[i].marker=MR_EPOINT_INFINITY;
    }

    MR_IN(218)

    ecn2_precomp(_MIPP_ MR_ECC_STORE_N2,TRUE,Q,T);

    premult(_MIPP_ a,3,a3); 
	premult(_MIPP_ b,3,b3); 

    nadds=ecn2_muln_engine(_MIPP_ 1,ns,1,MR_ECC_STORE_N2,&a,&a3,&b,&b3,FT,T,R);

    ecn2_norm(_MIPP_ R);

    MR_OUT

#ifndef MR_STATIC
    memkill(_MIPP_ mem, MR_MUL2_RESERVE);
#else
    memset(mem, 0, MR_BIG_RESERVE(MR_MUL2_RESERVE));
#endif
    return nadds;
}
#endif
#endif

#ifndef MR_STATIC

BOOL ecn2_brick_init(_MIPD_ ebrick *B,zzn2 *x,zzn2 *y,big a,big b,big n,int window,int nb)
{ /* Uses Montgomery arithmetic internally              *
   * (x,y) is the fixed base                            *
   * a,b and n are parameters and modulus of the curve  *
   * window is the window size in bits and              *
   * nb is the maximum number of bits in the multiplier */
    int i,j,k,t,bp,len,bptr,is;
    ecn2 *table;
    ecn2 w;

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    if (nb<2 || window<1 || window>nb || mr_mip->ERNUM) return FALSE;

    t=MR_ROUNDUP(nb,window);

    if (t<2) return FALSE;

    MR_IN(221)

#ifndef MR_ALWAYS_BINARY
    if (mr_mip->base != mr_mip->base2)
    {
        mr_berror(_MIPP_ MR_ERR_NOT_SUPPORTED);
        MR_OUT
        return FALSE;
    }
#endif

    B->window=window;
    B->max=nb;
    table=(ecn2 *)mr_alloc(_MIPP_ (1<<window),sizeof(ecn2));
    if (table==NULL)
    {
        mr_berror(_MIPP_ MR_ERR_OUT_OF_MEMORY);   
        MR_OUT
        return FALSE;
    }
    B->a=mirvar(_MIPP_ 0);
    B->b=mirvar(_MIPP_ 0);
    B->n=mirvar(_MIPP_ 0);
    copy(a,B->a);
    copy(b,B->b);
    copy(n,B->n);

    ecurve_init(_MIPP_ a,b,n,MR_AFFINE);
    mr_mip->TWIST=MR_QUADRATIC;

    w.x.a=mirvar(_MIPP_ 0);
    w.x.b=mirvar(_MIPP_ 0);
    w.y.a=mirvar(_MIPP_ 0);
    w.y.b=mirvar(_MIPP_ 0);
    w.marker=MR_EPOINT_INFINITY;
    ecn2_set(_MIPP_ x,y,&w);

    table[0].x.a=mirvar(_MIPP_ 0);
    table[0].x.b=mirvar(_MIPP_ 0);
    table[0].y.a=mirvar(_MIPP_ 0);
    table[0].y.b=mirvar(_MIPP_ 0);
    table[0].marker=MR_EPOINT_INFINITY;
    table[1].x.a=mirvar(_MIPP_ 0);
    table[1].x.b=mirvar(_MIPP_ 0);
    table[1].y.a=mirvar(_MIPP_ 0);
    table[1].y.b=mirvar(_MIPP_ 0);
    table[1].marker=MR_EPOINT_INFINITY;

    ecn2_copy(&w,&table[1]);
    for (j=0;j<t;j++)
        ecn2_add(_MIPP_ &w,&w);

    k=1;
    for (i=2;i<(1<<window);i++)
    {
        table[i].x.a=mirvar(_MIPP_ 0);
        table[i].x.b=mirvar(_MIPP_ 0);
        table[i].y.a=mirvar(_MIPP_ 0);
        table[i].y.b=mirvar(_MIPP_ 0);
        table[i].marker=MR_EPOINT_INFINITY;
        if (i==(1<<k))
        {
            k++;
            ecn2_copy(&w,&table[i]);
            
            for (j=0;j<t;j++)
                ecn2_add(_MIPP_ &w,&w);
            continue;
        }
        bp=1;
        for (j=0;j<k;j++)
        {
            if (i&bp)
			{
				is=1<<j;
                ecn2_add(_MIPP_ &table[is],&table[i]);
			}
            bp<<=1;
        }
    }
    mr_free(w.x.a);
    mr_free(w.x.b);
    mr_free(w.y.a);
    mr_free(w.y.b);

/* create the table */

    len=n->len;
    bptr=0;
    B->table=(mr_small *)mr_alloc(_MIPP_ 4*len*(1<<window),sizeof(mr_small));

    for (i=0;i<(1<<window);i++)
    {
        for (j=0;j<len;j++) B->table[bptr++]=table[i].x.a->w[j];
        for (j=0;j<len;j++) B->table[bptr++]=table[i].x.b->w[j];

        for (j=0;j<len;j++) B->table[bptr++]=table[i].y.a->w[j];
        for (j=0;j<len;j++) B->table[bptr++]=table[i].y.b->w[j];

        mr_free(table[i].x.a);
        mr_free(table[i].x.b);
        mr_free(table[i].y.a);
        mr_free(table[i].y.b);
    }
        
    mr_free(table);  

    MR_OUT
    return TRUE;
}

void ecn2_brick_end(ebrick *B)
{
    mirkill(B->n);
    mirkill(B->b);
    mirkill(B->a);
    mr_free(B->table);  
}

#else

/* use precomputated table in ROM */

void ecn2_brick_init(ebrick *B,const mr_small* rom,big a,big b,big n,int window,int nb)
{
    B->table=rom;
    B->a=a; /* just pass a pointer */
    B->b=b;
    B->n=n;
    B->window=window;  /* 2^4=16  stored values */
    B->max=nb;
}

#endif

/*
void ecn2_mul_brick(_MIPD_ ebrick *B,big e,zzn2 *x,zzn2 *y)
{
    int i,j,t,len,maxsize,promptr;
    ecn2 w,z;
 
#ifdef MR_STATIC
    char mem[MR_BIG_RESERVE(10)];
#else
    char *mem;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    if (size(e)<0) mr_berror(_MIPP_ MR_ERR_NEG_POWER);
    t=MR_ROUNDUP(B->max,B->window);
    
    MR_IN(116)

#ifndef MR_ALWAYS_BINARY
    if (mr_mip->base != mr_mip->base2)
    {
        mr_berror(_MIPP_ MR_ERR_NOT_SUPPORTED);
        MR_OUT
        return;
    }
#endif

    if (logb2(_MIPP_ e) > B->max)
    {
        mr_berror(_MIPP_ MR_ERR_EXP_TOO_BIG);
        MR_OUT
        return;
    }

    ecurve_init(_MIPP_ B->a,B->b,B->n,MR_BEST);
    mr_mip->TWIST=MR_QUADRATIC;
  
#ifdef MR_STATIC
    memset(mem,0,MR_BIG_RESERVE(10));
#else
    mem=memalloc(_MIPP_ 10);
#endif

    w.x.a=mirvar_mem(_MIPP_  mem, 0);
    w.x.b=mirvar_mem(_MIPP_  mem, 1);
    w.y.a=mirvar_mem(_MIPP_  mem, 2);
    w.y.b=mirvar_mem(_MIPP_  mem, 3);  
    w.z.a=mirvar_mem(_MIPP_  mem, 4);
    w.z.b=mirvar_mem(_MIPP_  mem, 5);      
    w.marker=MR_EPOINT_INFINITY;
    z.x.a=mirvar_mem(_MIPP_  mem, 6);
    z.x.b=mirvar_mem(_MIPP_  mem, 7);
    z.y.a=mirvar_mem(_MIPP_  mem, 8);
    z.y.b=mirvar_mem(_MIPP_  mem, 9);       
    z.marker=MR_EPOINT_INFINITY;

    len=B->n->len;
    maxsize=4*(1<<B->window)*len;

    for (i=t-1;i>=0;i--)
    {
        j=recode(_MIPP_ e,t,B->window,i);
        ecn2_add(_MIPP_ &w,&w);
        if (j>0)
        {
            promptr=4*j*len;
            init_big_from_rom(z.x.a,len,B->table,maxsize,&promptr);
            init_big_from_rom(z.x.b,len,B->table,maxsize,&promptr);
            init_big_from_rom(z.y.a,len,B->table,maxsize,&promptr);
            init_big_from_rom(z.y.b,len,B->table,maxsize,&promptr);
            z.marker=MR_EPOINT_NORMALIZED;
            ecn2_add(_MIPP_ &z,&w);
        }
    }
    ecn2_norm(_MIPP_ &w);
    ecn2_getxy(&w,x,y);
#ifndef MR_STATIC
    memkill(_MIPP_ mem,10);
#else
    memset(mem,0,MR_BIG_RESERVE(10));
#endif
    MR_OUT
}
*/

void ecn2_mul_brick_gls(_MIPD_ ebrick *B,big *e,zzn2 *psi,zzn2 *x,zzn2 *y)
{
    int i,j,k,t,len,maxsize,promptr,se[2];
    ecn2 w,z;
 
#ifdef MR_STATIC
    char mem[MR_BIG_RESERVE(10)];
#else
    char *mem;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    for (k=0;k<2;k++) se[k]=exsign(e[k]);

    t=MR_ROUNDUP(B->max,B->window);
    
    MR_IN(222)

#ifndef MR_ALWAYS_BINARY
    if (mr_mip->base != mr_mip->base2)
    {
        mr_berror(_MIPP_ MR_ERR_NOT_SUPPORTED);
        MR_OUT
        return;
    }
#endif

    if (logb2(_MIPP_ e[0])>B->max || logb2(_MIPP_ e[1])>B->max)
    {
        mr_berror(_MIPP_ MR_ERR_EXP_TOO_BIG);
        MR_OUT
        return;
    }

    ecurve_init(_MIPP_ B->a,B->b,B->n,MR_BEST);
    mr_mip->TWIST=MR_QUADRATIC;
  
#ifdef MR_STATIC
    memset(mem,0,MR_BIG_RESERVE(10));
#else
    mem=(char *)memalloc(_MIPP_ 10);
#endif

    z.x.a=mirvar_mem(_MIPP_  mem, 0);
    z.x.b=mirvar_mem(_MIPP_  mem, 1);
    z.y.a=mirvar_mem(_MIPP_  mem, 2);
    z.y.b=mirvar_mem(_MIPP_  mem, 3);       
    z.marker=MR_EPOINT_INFINITY;

    w.x.a=mirvar_mem(_MIPP_  mem, 4);
    w.x.b=mirvar_mem(_MIPP_  mem, 5);
    w.y.a=mirvar_mem(_MIPP_  mem, 6);
    w.y.b=mirvar_mem(_MIPP_  mem, 7);  
#ifndef MR_AFFINE_ONLY
    w.z.a=mirvar_mem(_MIPP_  mem, 8);
    w.z.b=mirvar_mem(_MIPP_  mem, 9); 
#endif    
    w.marker=MR_EPOINT_INFINITY;

    len=B->n->len;
    maxsize=4*(1<<B->window)*len;

    for (i=t-1;i>=0;i--)
    {
        ecn2_add(_MIPP_ &w,&w);
        for (k=0;k<2;k++)
        {
            j=recode(_MIPP_ e[k],t,B->window,i);
            if (j>0)
            {
                promptr=4*j*len;
                init_big_from_rom(z.x.a,len,B->table,maxsize,&promptr);
                init_big_from_rom(z.x.b,len,B->table,maxsize,&promptr);
                init_big_from_rom(z.y.a,len,B->table,maxsize,&promptr);
                init_big_from_rom(z.y.b,len,B->table,maxsize,&promptr);
                z.marker=MR_EPOINT_NORMALIZED;
                if (k==1) ecn2_psi(_MIPP_ psi,&z);
                if (se[k]==PLUS) ecn2_add(_MIPP_ &z,&w);
                else             ecn2_sub(_MIPP_ &z,&w);
            }
        }      
    }
    ecn2_norm(_MIPP_ &w);
    ecn2_getxy(&w,x,y);
#ifndef MR_STATIC
    memkill(_MIPP_ mem,10);
#else
    memset(mem,0,MR_BIG_RESERVE(10));
#endif
    MR_OUT
}

#else

/* Now for curves in Inverted Twisted Edwards Form */

BOOL ecn2_iszero(ecn2 *a)
{
    if (a->marker==MR_EPOINT_INFINITY) return TRUE;
    return FALSE;
}

void ecn2_copy(ecn2 *a,ecn2 *b)
{
    zzn2_copy(&(a->x),&(b->x));
    zzn2_copy(&(a->y),&(b->y));
    if (a->marker==MR_EPOINT_GENERAL)  zzn2_copy(&(a->z),&(b->z));
    b->marker=a->marker;
}

void ecn2_zero(ecn2 *a)
{
    zzn2_zero(&(a->x));
    zzn2_zero(&(a->y)); 
    if (a->marker==MR_EPOINT_GENERAL) zzn2_zero(&(a->z)); 
    a->marker=MR_EPOINT_INFINITY;
}

BOOL ecn2_compare(_MIPD_ ecn2 *a,ecn2 *b)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return FALSE;

    MR_IN(193)
    ecn2_norm(_MIPP_ a);
    ecn2_norm(_MIPP_ b);
    MR_OUT
    if (zzn2_compare(&(a->x),&(b->x)) && zzn2_compare(&(a->y),&(b->y)) && a->marker==b->marker) return TRUE;
    return FALSE;
}

void ecn2_norm(_MIPD_ ecn2 *a)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    if (mr_mip->ERNUM) return;
    if (a->marker!=MR_EPOINT_GENERAL) return;

    MR_IN(194)
    
    zzn2_inv(_MIPP_ &(a->z));

    zzn2_mul(_MIPP_ &(a->x),&(a->z),&(a->x));
    zzn2_mul(_MIPP_ &(a->y),&(a->z),&(a->y));
    zzn2_from_zzn(mr_mip->one,&(a->z));
    a->marker=MR_EPOINT_NORMALIZED;

    MR_OUT

}

void ecn2_get(_MIPD_ ecn2 *e,zzn2 *x,zzn2 *y,zzn2 *z)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    
    zzn2_copy(&(e->x),x);
    zzn2_copy(&(e->y),y);
    if (e->marker==MR_EPOINT_GENERAL) zzn2_copy(&(e->z),z);
    else                              zzn2_from_zzn(mr_mip->one,z);
}

void ecn2_getxy(ecn2 *e,zzn2 *x,zzn2 *y)
{
    zzn2_copy(&(e->x),x);
    zzn2_copy(&(e->y),y);
}

void ecn2_getx(ecn2 *e,zzn2 *x)
{
    zzn2_copy(&(e->x),x);
}

void ecn2_getz(_MIPD_ ecn2 *e,zzn2 *z)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (e->marker==MR_EPOINT_GENERAL) zzn2_copy(&(e->z),z);
    else                              zzn2_from_zzn(mr_mip->one,z);
}

void ecn2_psi(_MIPD_ zzn2 *psi,ecn2 *P)
{ /* apply GLS morphism to P */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    MR_IN(212)
    zzn2_conj(_MIPP_ &(P->x),&(P->x));
    zzn2_conj(_MIPP_ &(P->y),&(P->y));
	if (P->marker==MR_EPOINT_GENERAL)
		zzn2_conj(_MIPP_ &(P->z),&(P->z));
    zzn2_mul(_MIPP_ &(P->x),&psi[0],&(P->x));

    MR_OUT
}
/*
static void out_zzn2(zzn2 *x)
{
	redc(x->a,x->a);
	redc(x->b,x->b);
	cotnum(x->a,stdout);
	cotnum(x->b,stdout);
	nres(x->a,x->a);
	nres(x->b,x->b);
}
*/

/* find RHS=(x^2-B)/(x^2-A) */

void ecn2_rhs(_MIPD_ zzn2 *x,zzn2 *rhs)
{ /* calculate RHS of elliptic curve equation */
    int twist;
    zzn2 A,B;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    twist=mr_mip->TWIST;

    MR_IN(202)

    A.a=mr_mip->w8;
    A.b=mr_mip->w9;
    B.a=mr_mip->w10;
    B.b=mr_mip->w11;

    zzn2_from_zzn(mr_mip->A,&A);
    zzn2_from_zzn(mr_mip->B,&B);
  
    if (twist==MR_QUADRATIC)
    { /* quadratic twist */
        zzn2_txx(_MIPP_ &A);
        zzn2_txx(_MIPP_ &B);
    }

    zzn2_sqr(_MIPP_ x,rhs);

    zzn2_sub(_MIPP_ rhs,&B,&B);

    zzn2_sub(_MIPP_ rhs,&A,&A);

    zzn2_inv(_MIPP_ &A);
    zzn2_mul(_MIPP_ &A,&B,rhs);

    MR_OUT
}

BOOL ecn2_set(_MIPD_ zzn2 *x,zzn2 *y,ecn2 *e)
{
    zzn2 lhs,rhs;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return FALSE;

    MR_IN(195)

    lhs.a=mr_mip->w12;
    lhs.b=mr_mip->w13;
    rhs.a=mr_mip->w14;
    rhs.b=mr_mip->w15;

    ecn2_rhs(_MIPP_ x,&rhs);

    zzn2_sqr(_MIPP_ y,&lhs);

    if (!zzn2_compare(&lhs,&rhs))
    {
        MR_OUT
        return FALSE;
    }

    zzn2_copy(x,&(e->x));
    zzn2_copy(y,&(e->y));

    e->marker=MR_EPOINT_NORMALIZED;

    MR_OUT
    return TRUE;
}

#ifndef MR_NOSUPPORT_COMPRESSION

BOOL ecn2_setx(_MIPD_ zzn2 *x,ecn2 *e)
{
    zzn2 rhs;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return FALSE;

    MR_IN(201)

    rhs.a=mr_mip->w12;
    rhs.b=mr_mip->w13;

    ecn2_rhs(_MIPP_ x,&rhs);

    if (!zzn2_iszero(&rhs))
    {
		if (!zzn2_qr(_MIPP_ &rhs))
		{
            MR_OUT
            return FALSE;
		}
        zzn2_sqrt(_MIPP_ &rhs,&rhs); 
    }

    zzn2_copy(x,&(e->x));
    zzn2_copy(&rhs,&(e->y));

    e->marker=MR_EPOINT_NORMALIZED;

    MR_OUT
    return TRUE;
}

#endif

void ecn2_setxyz(zzn2 *x,zzn2 *y,zzn2 *z,ecn2 *e)
{
    zzn2_copy(x,&(e->x));
    zzn2_copy(y,&(e->y));
    zzn2_copy(z,&(e->z));
    e->marker=MR_EPOINT_GENERAL;
}

/* Normalise an array of points of length m<MR_MAX_M_T_S - requires a zzn2 workspace array of length m */

BOOL ecn2_multi_norm(_MIPD_ int m,zzn2 *work,ecn2 *p)
{ 

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
 
    int i;
	zzn2 one;
    zzn2 w[MR_MAX_M_T_S];
    if (mr_mip->ERNUM) return FALSE;   
    if (m>MR_MAX_M_T_S) return FALSE;

    MR_IN(215)
    
	one.a=mr_mip->w12;
    one.b=mr_mip->w13;

	zzn2_from_zzn(mr_mip->one,&one);

    for (i=0;i<m;i++)
	{
		if (p[i].marker==MR_EPOINT_NORMALIZED) w[i]=one;
        else w[i]=p[i].z;
	}

    if (!zzn2_multi_inverse(_MIPP_ m,w,work)) 
    {
       MR_OUT
       return FALSE;
    }

    for (i=0;i<m;i++)
    {
        p[i].marker=MR_EPOINT_NORMALIZED;
        zzn2_mul(_MIPP_ &(p[i].x),&work[i],&(p[i].x));    
        zzn2_mul(_MIPP_ &(p[i].y),&work[i],&(p[i].y));  
		zzn2_from_zzn(mr_mip->one,&(p[i].z));
    }    
    MR_OUT

    return TRUE;   
}

BOOL ecn2_add(_MIPD_ ecn2 *Q,ecn2 *P)
{ /* P+=Q */
    BOOL Doubling=FALSE;
    int twist;
    zzn2 t2,t3,t4;
 
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
 
    t2.a = mr_mip->w8; 
    t2.b = mr_mip->w9; 
    t3.a = mr_mip->w10; 
    t3.b = mr_mip->w11;
    t4.a = mr_mip->w12;
    t4.b = mr_mip->w13;

    twist=mr_mip->TWIST;
    if (mr_mip->ERNUM) return FALSE;

    if (P->marker==MR_EPOINT_INFINITY)
    {
        ecn2_copy(Q,P);
        return Doubling;
    }
    if (Q->marker==MR_EPOINT_INFINITY) return Doubling;

    if (Q==P)
    {
        Doubling=TRUE;
        if (P->marker==MR_EPOINT_INFINITY) 
        { /* 2 times infinity == infinity ! */
            return Doubling;
        }
    }

    MR_IN(205)

    if (!Doubling)
    { /* Addition */
        zzn2_add(_MIPP_ &(Q->x),&(Q->y),&t2);
        zzn2_add(_MIPP_ &(P->x),&(P->y),&t4);
        zzn2_mul(_MIPP_ &t4,&t2,&t4);          /* I = t4 = (x1+y1)(x2+y2) */
        if (Q->marker!=MR_EPOINT_NORMALIZED)
        {
            if (P->marker==MR_EPOINT_NORMALIZED)
                zzn2_copy(&(Q->z),&(P->z));
            else
                zzn2_mul(_MIPP_ &(Q->z),&(P->z),&(P->z));  /* Z = z1*z2 */
        }  
        else
        {
            if (P->marker==MR_EPOINT_NORMALIZED)
                zzn2_from_zzn(mr_mip->one,&(P->z));
        }
        zzn2_sqr(_MIPP_ &(P->z),&t2);    /* P->z = z1.z2 */
        if (mr_abs(mr_mip->Bsize)==MR_TOOBIG)
            zzn2_smul(_MIPP_ &t2,mr_mip->B,&t2);
        else
            zzn2_imul(_MIPP_ &t2,mr_mip->Bsize,&t2);
        if (twist==MR_QUADRATIC) zzn2_txx(_MIPP_ &t2);              /* B = t2 = d*A^2 */
        zzn2_mul(_MIPP_ &(P->x),&(Q->x),&(P->x));     /* X = x1*x2 */
        zzn2_mul(_MIPP_ &(P->y),&(Q->y),&(P->y));     /* Y = y1*y2 */
        zzn2_sub(_MIPP_ &t4,&(P->x),&t4);
        zzn2_sub(_MIPP_ &t4,&(P->y),&t4);             /* I = (x1+y1)(x2+y2)-X-Y */ 
        zzn2_mul(_MIPP_ &(P->x),&(P->y),&t3);         /* E = t3 = X*Y */
        if (mr_abs(mr_mip->Asize)==MR_TOOBIG)
            zzn2_smul(_MIPP_ &(P->y),mr_mip->A,&(P->y));
        else
            zzn2_imul(_MIPP_ &(P->y),mr_mip->Asize,&(P->y));
        if (twist==MR_QUADRATIC) zzn2_txx(_MIPP_ &(P->y));         /* Y=aY */
        zzn2_sub(_MIPP_ &(P->x),&(P->y),&(P->x));    /* X=X-aY */
        zzn2_mul(_MIPP_ &(P->z),&(P->x),&(P->z));
        zzn2_mul(_MIPP_ &(P->z),&t4,&(P->z));
        zzn2_sub(_MIPP_ &t3,&t2,&(P->y));
        zzn2_mul(_MIPP_ &(P->y),&t4,&(P->y));
        zzn2_add(_MIPP_ &t3,&t2,&t4);
        zzn2_mul(_MIPP_ &(P->x),&t4,&(P->x));
    }
    else
    { /* doubling */
        zzn2_add(_MIPP_ &(P->x),&(P->y),&t2);
        zzn2_sqr(_MIPP_ &t2,&t2);
        zzn2_sqr(_MIPP_ &(P->x),&(P->x));
        zzn2_sqr(_MIPP_ &(P->y),&(P->y));
        zzn2_sub(_MIPP_ &t2,&(P->x),&t2);
        zzn2_sub(_MIPP_ &t2,&(P->y),&t2);   /* E=(X+Y)^2-X^2-Y^2 */

        if (P->marker!=MR_EPOINT_NORMALIZED)
            zzn2_sqr(_MIPP_ &(P->z),&(P->z));
        else
            zzn2_from_zzn(mr_mip->one,&(P->z));

        zzn2_add(_MIPP_ &(P->z),&(P->z),&(P->z));
        if (mr_abs(mr_mip->Bsize)==MR_TOOBIG)
            zzn2_smul(_MIPP_ &(P->z),mr_mip->B,&(P->z));
        else
            zzn2_imul(_MIPP_ &(P->z),mr_mip->Bsize,&(P->z));
        if (twist==MR_QUADRATIC) zzn2_txx(_MIPP_ &(P->z));
        if (mr_abs(mr_mip->Asize)==MR_TOOBIG)
            zzn2_smul(_MIPP_ &(P->y),mr_mip->A,&(P->y));
        else
            zzn2_imul(_MIPP_ &(P->y),mr_mip->Asize,&(P->y));
        if (twist==MR_QUADRATIC) zzn2_txx(_MIPP_ &(P->y));
        zzn2_add(_MIPP_ &(P->x),&(P->y),&t3);
        zzn2_sub(_MIPP_ &(P->x),&(P->y),&t4);
        zzn2_mul(_MIPP_ &t3,&t4,&(P->x));

        zzn2_sub(_MIPP_ &t3,&(P->z),&t3);
        zzn2_mul(_MIPP_ &t2,&t3,&(P->y));
        zzn2_mul(_MIPP_ &t2,&t4,&(P->z));
    }

    if (zzn2_iszero(&(P->z)))
    {
        zzn2_from_zzn(mr_mip->one,&(P->x));
        zzn2_zero(&(P->y));
        P->marker=MR_EPOINT_INFINITY;
    }
    else P->marker=MR_EPOINT_GENERAL;
   
    MR_OUT
    return Doubling;
}

void ecn2_negate(_MIPD_ ecn2 *u,ecn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    ecn2_copy(u,w);
    if (w->marker!=MR_EPOINT_INFINITY)
        zzn2_negate(_MIPP_ &(w->x),&(w->x));
}


BOOL ecn2_sub(_MIPD_ ecn2 *Q,ecn2 *P)
{
    BOOL Doubling;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    zzn2 lam;

    lam.a = mr_mip->w14;
    lam.b = mr_mip->w15;

    ecn2_negate(_MIPP_ Q,Q);

    Doubling=ecn2_add(_MIPP_ Q,P);

    ecn2_negate(_MIPP_ Q,Q);

    return Doubling;
}

/*

BOOL ecn2_add_sub(_MIPD_ ecn2 *P,ecn2 *Q,ecn2 *PP,ecn2 *PM)
{  PP=P+Q, PM=P-Q. Assumes P and Q are both normalized, and P!=Q 
 #ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    zzn2 t1,t2,lam;

    if (mr_mip->ERNUM) return FALSE;

    PP->marker=MR_EPOINT_NORMALIZED;
    PM->marker=MR_EPOINT_NORMALIZED;

    return TRUE;
}

*/

/* Precomputation of  3P, 5P, 7P etc. into PT. Assume PT[0] contains P */

#define MR_PRE_2 (6+2*MR_ECC_STORE_N2)

static void ecn2_pre(_MIPD_ int sz,BOOL norm,ecn2 *PT)
{
    int i,j;
    ecn2 P2;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

#ifndef MR_STATIC
	zzn2 *work=(zzn2 *)mr_alloc(_MIPP_ sz,sizeof(zzn2));
    char *mem = memalloc(_MIPP_ 6+2*sz);
#else
	zzn2 work[MR_ECC_STORE_N2];
    char mem[MR_BIG_RESERVE(MR_PRE_2)];
    memset(mem, 0, MR_BIG_RESERVE(MR_PRE_2));
#endif
    j=0;
    P2.x.a=mirvar_mem(_MIPP_ mem, j++);
    P2.x.b=mirvar_mem(_MIPP_ mem, j++);
    P2.y.a=mirvar_mem(_MIPP_ mem, j++);
    P2.y.b=mirvar_mem(_MIPP_ mem, j++);
    P2.z.a=mirvar_mem(_MIPP_ mem, j++);
    P2.z.b=mirvar_mem(_MIPP_ mem, j++);

    for (i=0;i<sz;i++)
    {
        work[i].a= mirvar_mem(_MIPP_ mem, j++);
        work[i].b= mirvar_mem(_MIPP_ mem, j++);
    }

    ecn2_copy(&PT[0],&P2);
    ecn2_add(_MIPP_ &P2,&P2);
    for (i=1;i<sz;i++)
    {
        ecn2_copy(&PT[i-1],&PT[i]);
        ecn2_add(_MIPP_ &P2,&PT[i]);
		
    }
	if (norm) ecn2_multi_norm(_MIPP_ sz,work,PT);

#ifndef MR_STATIC
    memkill(_MIPP_ mem, 6+2*sz);
	mr_free(work);
#else
    memset(mem, 0, MR_BIG_RESERVE(MR_PRE_2));
#endif
}

#ifndef MR_DOUBLE_BIG
#define MR_MUL_RESERVE (1+6*MR_ECC_STORE_N2)
#else
#define MR_MUL_RESERVE (2+6*MR_ECC_STORE_N2)
#endif

int ecn2_mul(_MIPD_ big k,ecn2 *P)
{
    int i,j,nb,n,nbs,nzs,nadds;
    big h;
	BOOL neg;
    ecn2 T[MR_ECC_STORE_N2];
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

#ifndef MR_STATIC
    char *mem = memalloc(_MIPP_ MR_MUL_RESERVE);
#else
    char mem[MR_BIG_RESERVE(MR_MUL_RESERVE)];
    memset(mem, 0, MR_BIG_RESERVE(MR_MUL_RESERVE));
#endif

    j=0;
#ifndef MR_DOUBLE_BIG
    h=mirvar_mem(_MIPP_ mem, j++);
#else
    h=mirvar_mem(_MIPP_ mem, j); j+=2;
#endif
    for (i=0;i<MR_ECC_STORE_N2;i++)
    {
        T[i].x.a= mirvar_mem(_MIPP_ mem, j++);
        T[i].x.b= mirvar_mem(_MIPP_ mem, j++);
        T[i].y.a= mirvar_mem(_MIPP_ mem, j++);
        T[i].y.b= mirvar_mem(_MIPP_ mem, j++);
        T[i].z.a= mirvar_mem(_MIPP_ mem, j++);
        T[i].z.b= mirvar_mem(_MIPP_ mem, j++);
    }

    MR_IN(207)

    ecn2_norm(_MIPP_ P);

	nadds=0;

	neg=FALSE;
	if (size(k)<0)
	{
		negify(k,k);
		ecn2_negate(_MIPP_ P,&T[0]);
		neg=TRUE;
	}
	else ecn2_copy(P,&T[0]);

    premult(_MIPP_ k,3,h);

    ecn2_pre(_MIPP_ MR_ECC_STORE_N2,FALSE,T);
    nb=logb2(_MIPP_ h);

    ecn2_zero(P);

    for (i=nb-1;i>=1;)
    {
        if (mr_mip->user!=NULL) (*mr_mip->user)();
        n=mr_naf_window(_MIPP_ k,h,i,&nbs,&nzs,MR_ECC_STORE_N2);
 
        for (j=0;j<nbs;j++) ecn2_add(_MIPP_ P,P);
       
        if (n>0) {nadds++; ecn2_add(_MIPP_ &T[n/2],P);}
        if (n<0) {nadds++; ecn2_sub(_MIPP_ &T[(-n)/2],P);}
        i-=nbs;
        if (nzs)
        {
            for (j=0;j<nzs;j++) ecn2_add(_MIPP_ P,P);
            i-=nzs;
        }
    }
	if (neg) negify(k,k);

    ecn2_norm(_MIPP_ P);
    MR_OUT

#ifndef MR_STATIC
    memkill(_MIPP_ mem, MR_MUL_RESERVE);
#else
    memset(mem, 0, MR_BIG_RESERVE(MR_MUL_RESERVE));
#endif
	return nadds;
}

/* Double addition, using Joint Sparse Form */
/* R=aP+bQ */

#define MR_MUL2_JSF_RESERVE 24

int ecn2_mul2_jsf(_MIPD_ big a,ecn2 *P,big b,ecn2 *Q,ecn2 *R)
{
    int e1,h1,e2,h2,bb,nadds;
    ecn2 P1,P2,PS,PD;
    big c,d,e,f;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

#ifndef MR_STATIC
    char *mem = memalloc(_MIPP_ MR_MUL2_JSF_RESERVE);
#else
    char mem[MR_BIG_RESERVE(MR_MUL2_JSF_RESERVE)];
    memset(mem, 0, MR_BIG_RESERVE(MR_MUL2_JSF_RESERVE));
#endif

    c = mirvar_mem(_MIPP_ mem, 0);
    d = mirvar_mem(_MIPP_ mem, 1);
    e = mirvar_mem(_MIPP_ mem, 2);
    f = mirvar_mem(_MIPP_ mem, 3);
    P1.x.a= mirvar_mem(_MIPP_ mem, 4);
    P1.x.b= mirvar_mem(_MIPP_ mem, 5);
    P1.y.a= mirvar_mem(_MIPP_ mem, 6);
    P1.y.b= mirvar_mem(_MIPP_ mem, 7);
    P2.x.a= mirvar_mem(_MIPP_ mem, 8);
    P2.x.b= mirvar_mem(_MIPP_ mem, 9);
    P2.y.a= mirvar_mem(_MIPP_ mem, 10);
    P2.y.b= mirvar_mem(_MIPP_ mem, 11);
    PS.x.a= mirvar_mem(_MIPP_ mem, 12);
    PS.x.b= mirvar_mem(_MIPP_ mem, 13);
    PS.y.a= mirvar_mem(_MIPP_ mem, 14);
    PS.y.b= mirvar_mem(_MIPP_ mem, 15);
    PS.z.a= mirvar_mem(_MIPP_ mem, 16);
    PS.z.b= mirvar_mem(_MIPP_ mem, 17);
    PD.x.a= mirvar_mem(_MIPP_ mem, 18);
    PD.x.b= mirvar_mem(_MIPP_ mem, 19);
    PD.y.a= mirvar_mem(_MIPP_ mem, 20);
    PD.y.b= mirvar_mem(_MIPP_ mem, 21);
    PD.z.a= mirvar_mem(_MIPP_ mem, 22);
    PD.z.b= mirvar_mem(_MIPP_ mem, 23);

    MR_IN(206)

    ecn2_norm(_MIPP_ Q); 
    ecn2_copy(Q,&P2); 

    copy(b,d);
    if (size(d)<0) 
    {
        negify(d,d);
        ecn2_negate(_MIPP_ &P2,&P2);
    }

    ecn2_norm(_MIPP_ P); 
    ecn2_copy(P,&P1); 

    copy(a,c);
    if (size(c)<0) 
    {
        negify(c,c);
        ecn2_negate(_MIPP_ &P1,&P1);
    }

    mr_jsf(_MIPP_ d,c,e,d,f,c);   /* calculate joint sparse form */
 
    if (mr_compare(e,f)>0) bb=logb2(_MIPP_ e)-1;
    else                bb=logb2(_MIPP_ f)-1;

    /*ecn2_add_sub(_MIPP_ &P1,&P2,&PS,&PD);*/

    ecn2_copy(&P1,&PS);
    ecn2_copy(&P1,&PD);
    ecn2_add(_MIPP_ &P2,&PS);
    ecn2_sub(_MIPP_ &P2,&PD);

    ecn2_zero(R);
	nadds=0;
   
    while (bb>=0) 
    { /* add/subtract method */
        if (mr_mip->user!=NULL) (*mr_mip->user)();
        ecn2_add(_MIPP_ R,R);
        e1=h1=e2=h2=0;

        if (mr_testbit(_MIPP_ d,bb)) e2=1;
        if (mr_testbit(_MIPP_ e,bb)) h2=1;
        if (mr_testbit(_MIPP_ c,bb)) e1=1;
        if (mr_testbit(_MIPP_ f,bb)) h1=1;

        if (e1!=h1)
        {
            if (e2==h2)
            {
                if (h1==1) {ecn2_add(_MIPP_ &P1,R); nadds++;}
                else       {ecn2_sub(_MIPP_ &P1,R); nadds++;}
            }
            else
            {
                if (h1==1)
                {
                    if (h2==1) {ecn2_add(_MIPP_ &PS,R); nadds++;}
                    else       {ecn2_add(_MIPP_ &PD,R); nadds++;}
                }
                else
                {
                    if (h2==1) {ecn2_sub(_MIPP_ &PD,R); nadds++;}
                    else       {ecn2_sub(_MIPP_ &PS,R); nadds++;}
                }
            }
        }
        else if (e2!=h2)
        {
            if (h2==1) {ecn2_add(_MIPP_ &P2,R); nadds++;}
            else       {ecn2_sub(_MIPP_ &P2,R); nadds++;}
        }
        bb-=1;
    }
    ecn2_norm(_MIPP_ R); 

    MR_OUT
#ifndef MR_STATIC
    memkill(_MIPP_ mem, MR_MUL2_JSF_RESERVE);
#else
    memset(mem, 0, MR_BIG_RESERVE(MR_MUL2_JSF_RESERVE));
#endif
	return nadds;

}

/* General purpose multi-exponentiation engine, using inter-leaving algorithm. Calculate aP+bQ+cR+dS...
   Inputs are divided into two groups of sizes wa<4 and wb<4. For the first group if the points are fixed the 
   first precomputed Table Ta[] may be taken from ROM. For the second group if the points are variable Tb[j] will
   have to computed online. Each group has its own precomputed store size, sza (=8?) and szb (=20?) respectively. 
   The values a,b,c.. are provided in ma[] and mb[], and 3.a,3.b,3.c (as required by the NAF) are provided in 
   ma3[] and mb3[]. If only one group is required, set wb=0 and pass NULL pointers.
   */

int ecn2_muln_engine(_MIPD_ int wa,int sza,int wb,int szb,big *ma,big *ma3,big *mb,big *mb3,ecn2 *Ta,ecn2 *Tb,ecn2 *R)
{ /* general purpose interleaving algorithm engine for multi-exp */
    int i,j,tba[4],pba[4],na[4],sa[4],tbb[4],pbb[4],nb[4],sb[4],nbits,nbs,nzs;
    int nadds;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    ecn2_zero(R);

    nbits=0;
    for (i=0;i<wa;i++) {sa[i]=exsign(ma[i]); tba[i]=0; j=logb2(_MIPP_ ma3[i]); if (j>nbits) nbits=j; }
    for (i=0;i<wb;i++) {sb[i]=exsign(mb[i]); tbb[i]=0; j=logb2(_MIPP_ mb3[i]); if (j>nbits) nbits=j; }
    
    nadds=0;
    for (i=nbits-1;i>=1;i--)
    {
        if (mr_mip->user!=NULL) (*mr_mip->user)();
        if (R->marker!=MR_EPOINT_INFINITY) ecn2_add(_MIPP_ R,R);
        for (j=0;j<wa;j++)
        { /* deal with the first group */
            if (tba[j]==0)
            {
                na[j]=mr_naf_window(_MIPP_ ma[j],ma3[j],i,&nbs,&nzs,sza);
                tba[j]=nbs+nzs;
                pba[j]=nbs;
            }
            tba[j]--;  pba[j]--; 
            if (pba[j]==0)
            {
                if (sa[j]==PLUS)
                {
                    if (na[j]>0) {ecn2_add(_MIPP_ &Ta[j*sza+na[j]/2],R); nadds++;}
                    if (na[j]<0) {ecn2_sub(_MIPP_ &Ta[j*sza+(-na[j])/2],R); nadds++;}
                }
                else
                {
                    if (na[j]>0) {ecn2_sub(_MIPP_ &Ta[j*sza+na[j]/2],R); nadds++;}
                    if (na[j]<0) {ecn2_add(_MIPP_ &Ta[j*sza+(-na[j])/2],R); nadds++;}
                }
            }         
        }
        for (j=0;j<wb;j++)
        { /* deal with the second group */
            if (tbb[j]==0)
            {
                nb[j]=mr_naf_window(_MIPP_ mb[j],mb3[j],i,&nbs,&nzs,szb);
                tbb[j]=nbs+nzs;
                pbb[j]=nbs;
            }
            tbb[j]--;  pbb[j]--; 
            if (pbb[j]==0)
            {
                if (sb[j]==PLUS)
                {
                    if (nb[j]>0) {ecn2_add(_MIPP_ &Tb[j*szb+nb[j]/2],R);  nadds++;}
                    if (nb[j]<0) {ecn2_sub(_MIPP_ &Tb[j*szb+(-nb[j])/2],R);  nadds++;}
                }
                else
                {
                    if (nb[j]>0) {ecn2_sub(_MIPP_ &Tb[j*szb+nb[j]/2],R);  nadds++;}
                    if (nb[j]<0) {ecn2_add(_MIPP_ &Tb[j*szb+(-nb[j])/2],R);  nadds++;}
                }
            }         
        }
    }
    ecn2_norm(_MIPP_ R);  
    return nadds;
}

/* Routines to support Galbraith, Lin, Scott (GLS) method for ECC */
/* requires an endomorphism psi */

/* *********************** */

/* Precompute T - first half from i.P, second half from i.psi(P) */
/* norm=TRUE if the table is to be normalised - which it should be */
/* if it is to be calculated off-line */

void ecn2_precomp_gls(_MIPD_ int sz,BOOL norm,ecn2 *P,zzn2 *psi,ecn2 *T)
{
    int i,j;

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    j=0;

    MR_IN(219)

    ecn2_norm(_MIPP_ P);
    ecn2_copy(P,&T[0]);

    ecn2_pre(_MIPP_ sz,norm,T); /* precompute table */
    for (i=sz;i<sz+sz;i++)
    {
        ecn2_copy(&T[i-sz],&T[i]);
        ecn2_psi(_MIPP_ psi,&T[i]);
    }

    MR_OUT
}

/* Calculate a[0].P+a[1].psi(P) using interleaving method */

#define MR_MUL2_GLS_RESERVE (2+2*MR_ECC_STORE_N2*6)

int ecn2_mul2_gls(_MIPD_ big *a,ecn2 *P,zzn2 *psi,ecn2 *R)
{
    int i,j,nadds;
    ecn2 T[2*MR_ECC_STORE_N2];
    big a3[2];
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

#ifndef MR_STATIC
    char *mem = memalloc(_MIPP_ MR_MUL2_GLS_RESERVE);
#else
    char mem[MR_BIG_RESERVE(MR_MUL2_GLS_RESERVE)];       
 	memset(mem, 0, MR_BIG_RESERVE(MR_MUL2_GLS_RESERVE));   
#endif

    for (j=i=0;i<2;i++)
        a3[i]=mirvar_mem(_MIPP_ mem, j++);

    for (i=0;i<2*MR_ECC_STORE_N2;i++)
    {
        T[i].x.a=mirvar_mem(_MIPP_  mem, j++);
        T[i].x.b=mirvar_mem(_MIPP_  mem, j++);
        T[i].y.a=mirvar_mem(_MIPP_  mem, j++);
        T[i].y.b=mirvar_mem(_MIPP_  mem, j++);  
        T[i].z.a=mirvar_mem(_MIPP_  mem, j++);
        T[i].z.b=mirvar_mem(_MIPP_  mem, j++);          
        T[i].marker=MR_EPOINT_INFINITY;
    }
    MR_IN(220)

    ecn2_precomp_gls(_MIPP_ MR_ECC_STORE_N2,FALSE,P,psi,T);

    for (i=0;i<2;i++) premult(_MIPP_ a[i],3,a3[i]); /* calculate for NAF */

    nadds=ecn2_muln_engine(_MIPP_ 0,0,2,MR_ECC_STORE_N2,NULL,NULL,a,a3,NULL,T,R);

    ecn2_norm(_MIPP_ R);

    MR_OUT

#ifndef MR_STATIC
    memkill(_MIPP_ mem, MR_MUL2_GLS_RESERVE);
#else
    memset(mem, 0, MR_BIG_RESERVE(MR_MUL2_GLS_RESERVE));
#endif
    return nadds;
}

/* Calculates a[0]*P+a[1]*psi(P) + b[0]*Q+b[1]*psi(Q) 
   where P is fixed, and precomputations are already done off-line into FT
   using ecn2_precomp_gls. Useful for signature verification */

#define MR_MUL4_GLS_V_RESERVE (4+2*MR_ECC_STORE_N2*6)

int ecn2_mul4_gls_v(_MIPD_ big *a,int ns,ecn2 *FT,big *b,ecn2 *Q,zzn2 *psi,ecn2 *R)
{ 
    int i,j,nadds;
    ecn2 VT[2*MR_ECC_STORE_N2];
    big a3[2],b3[2];
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

#ifndef MR_STATIC
    char *mem = memalloc(_MIPP_ MR_MUL4_GLS_V_RESERVE);
#else
    char mem[MR_BIG_RESERVE(MR_MUL4_GLS_V_RESERVE)];       
 	memset(mem, 0, MR_BIG_RESERVE(MR_MUL4_GLS_V_RESERVE));   
#endif
    j=0;
    for (i=0;i<2;i++)
    {
        a3[i]=mirvar_mem(_MIPP_ mem, j++);
        b3[i]=mirvar_mem(_MIPP_ mem, j++);
    }
    for (i=0;i<2*MR_ECC_STORE_N2;i++)
    {
        VT[i].x.a=mirvar_mem(_MIPP_  mem, j++);
        VT[i].x.b=mirvar_mem(_MIPP_  mem, j++);
        VT[i].y.a=mirvar_mem(_MIPP_  mem, j++);
        VT[i].y.b=mirvar_mem(_MIPP_  mem, j++);  
        VT[i].z.a=mirvar_mem(_MIPP_  mem, j++);
        VT[i].z.b=mirvar_mem(_MIPP_  mem, j++);         
        VT[i].marker=MR_EPOINT_INFINITY;
    }

    MR_IN(217)

    ecn2_precomp_gls(_MIPP_ MR_ECC_STORE_N2,FALSE,Q,psi,VT); /* precompute for the variable points */
    for (i=0;i<2;i++)
    { /* needed for NAF */
        premult(_MIPP_ a[i],3,a3[i]);
        premult(_MIPP_ b[i],3,b3[i]);
    }
    nadds=ecn2_muln_engine(_MIPP_ 2,ns,2,MR_ECC_STORE_N2,a,a3,b,b3,FT,VT,R);
    ecn2_norm(_MIPP_ R);

    MR_OUT

#ifndef MR_STATIC
    memkill(_MIPP_ mem, MR_MUL4_GLS_V_RESERVE);
#else
    memset(mem, 0, MR_BIG_RESERVE(MR_MUL4_GLS_V_RESERVE));
#endif
    return nadds;
}

/* Calculate a.P+b.Q using interleaving method. P is fixed and T is precomputed from it */

void ecn2_precomp(_MIPD_ int sz,BOOL norm,ecn2 *P,ecn2 *T)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    MR_IN(216)

    ecn2_norm(_MIPP_ P);
    ecn2_copy(P,&T[0]);
    ecn2_pre(_MIPP_ sz,norm,T); 

    MR_OUT
}

#ifndef MR_DOUBLE_BIG
#define MR_MUL2_RESERVE (2+2*MR_ECC_STORE_N2*6)
#else
#define MR_MUL2_RESERVE (4+2*MR_ECC_STORE_N2*6)
#endif

int ecn2_mul2(_MIPD_ big a,int ns,ecn2 *FT,big b,ecn2 *Q,ecn2 *R)
{
    int i,j,nadds;
    ecn2 T[2*MR_ECC_STORE_N2];
    big a3,b3;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

#ifndef MR_STATIC
    char *mem = memalloc(_MIPP_ MR_MUL2_RESERVE);
#else
    char mem[MR_BIG_RESERVE(MR_MUL2_RESERVE)];       
 	memset(mem, 0, MR_BIG_RESERVE(MR_MUL2_RESERVE));   
#endif

    j=0;
#ifndef MR_DOUBLE_BIG
    a3=mirvar_mem(_MIPP_ mem, j++);
	b3=mirvar_mem(_MIPP_ mem, j++);
#else
    a3=mirvar_mem(_MIPP_ mem, j); j+=2;
	b3=mirvar_mem(_MIPP_ mem, j); j+=2;
#endif    
    for (i=0;i<2*MR_ECC_STORE_N2;i++)
    {
        T[i].x.a=mirvar_mem(_MIPP_  mem, j++);
        T[i].x.b=mirvar_mem(_MIPP_  mem, j++);
        T[i].y.a=mirvar_mem(_MIPP_  mem, j++);
        T[i].y.b=mirvar_mem(_MIPP_  mem, j++); 
        T[i].z.a=mirvar_mem(_MIPP_  mem, j++);
        T[i].z.b=mirvar_mem(_MIPP_  mem, j++);        
        T[i].marker=MR_EPOINT_INFINITY;
    }

    MR_IN(218)

    ecn2_precomp(_MIPP_ MR_ECC_STORE_N2,FALSE,Q,T);

    premult(_MIPP_ a,3,a3); 
	premult(_MIPP_ b,3,b3); 

    nadds=ecn2_muln_engine(_MIPP_ 1,ns,1,MR_ECC_STORE_N2,&a,&a3,&b,&b3,FT,T,R);

    ecn2_norm(_MIPP_ R);

    MR_OUT

#ifndef MR_STATIC
    memkill(_MIPP_ mem, MR_MUL2_RESERVE);
#else
    memset(mem, 0, MR_BIG_RESERVE(MR_MUL2_RESERVE));
#endif
    return nadds;
}


#ifndef MR_STATIC

BOOL ecn2_brick_init(_MIPD_ ebrick *B,zzn2 *x,zzn2 *y,big a,big b,big n,int window,int nb)
{ /* Uses Montgomery arithmetic internally              *
   * (x,y) is the fixed base                            *
   * a,b and n are parameters and modulus of the curve  *
   * window is the window size in bits and              *
   * nb is the maximum number of bits in the multiplier */
    int i,j,k,t,bp,len,bptr;
    ecn2 *table;
    ecn2 w;

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (nb<2 || window<1 || window>nb || mr_mip->ERNUM) return FALSE;

    t=MR_ROUNDUP(nb,window);
    if (t<2) return FALSE;

    MR_IN(221)

#ifndef MR_ALWAYS_BINARY
    if (mr_mip->base != mr_mip->base2)
    {
        mr_berror(_MIPP_ MR_ERR_NOT_SUPPORTED);
        MR_OUT
        return FALSE;
    }
#endif

    B->window=window;
    B->max=nb;
    table=mr_alloc(_MIPP_ (1<<window),sizeof(ecn2));
    if (table==NULL)
    {
        mr_berror(_MIPP_ MR_ERR_OUT_OF_MEMORY);   
        MR_OUT
        return FALSE;
    }
    B->a=mirvar(_MIPP_ 0);
    B->b=mirvar(_MIPP_ 0);
    B->n=mirvar(_MIPP_ 0);
    copy(a,B->a);
    copy(b,B->b);
    copy(n,B->n);

    ecurve_init(_MIPP_ a,b,n,MR_BEST);
    mr_mip->TWIST=MR_QUADRATIC;

    w.x.a=mirvar(_MIPP_ 0);
    w.x.b=mirvar(_MIPP_ 0);
    w.y.a=mirvar(_MIPP_ 0);
    w.y.b=mirvar(_MIPP_ 0);
    w.z.a=mirvar(_MIPP_ 0);
    w.z.b=mirvar(_MIPP_ 0);

    w.marker=MR_EPOINT_INFINITY;
    ecn2_set(_MIPP_ x,y,&w);

    table[0].x.a=mirvar(_MIPP_ 0);
    table[0].x.b=mirvar(_MIPP_ 0);
    table[0].y.a=mirvar(_MIPP_ 0);
    table[0].y.b=mirvar(_MIPP_ 0);
    table[0].z.a=mirvar(_MIPP_ 0);
    table[0].z.b=mirvar(_MIPP_ 0);
    table[0].marker=MR_EPOINT_INFINITY;
    table[1].x.a=mirvar(_MIPP_ 0);
    table[1].x.b=mirvar(_MIPP_ 0);
    table[1].y.a=mirvar(_MIPP_ 0);
    table[1].y.b=mirvar(_MIPP_ 0);
    table[1].z.a=mirvar(_MIPP_ 0);
    table[1].z.b=mirvar(_MIPP_ 0);
    table[1].marker=MR_EPOINT_INFINITY;

    ecn2_copy(&w,&table[1]);
    for (j=0;j<t;j++)
        ecn2_add(_MIPP_ &w,&w);

    k=1;
    for (i=2;i<(1<<window);i++)
    {
        table[i].x.a=mirvar(_MIPP_ 0);
        table[i].x.b=mirvar(_MIPP_ 0);
        table[i].y.a=mirvar(_MIPP_ 0);
        table[i].y.b=mirvar(_MIPP_ 0);
        table[i].z.a=mirvar(_MIPP_ 0);
        table[i].z.b=mirvar(_MIPP_ 0);
        table[i].marker=MR_EPOINT_INFINITY;
        if (i==(1<<k))
        {
            k++;
			ecn2_norm(_MIPP_ &w);
            ecn2_copy(&w,&table[i]);
            
            for (j=0;j<t;j++)
                ecn2_add(_MIPP_ &w,&w);
            continue;
        }
        bp=1;
        for (j=0;j<k;j++)
        {
            if (i&bp)
                ecn2_add(_MIPP_ &table[1<<j],&table[i]);
            bp<<=1;
        }
        ecn2_norm(_MIPP_ &table[i]);
    }
    mr_free(w.x.a);
    mr_free(w.x.b);
    mr_free(w.y.a);
    mr_free(w.y.b);
    mr_free(w.z.a);
    mr_free(w.z.b);

/* create the table */

    len=n->len;
    bptr=0;
    B->table=mr_alloc(_MIPP_ 4*len*(1<<window),sizeof(mr_small));

    for (i=0;i<(1<<window);i++)
    {
        for (j=0;j<len;j++) B->table[bptr++]=table[i].x.a->w[j];
        for (j=0;j<len;j++) B->table[bptr++]=table[i].x.b->w[j];

        for (j=0;j<len;j++) B->table[bptr++]=table[i].y.a->w[j];
        for (j=0;j<len;j++) B->table[bptr++]=table[i].y.b->w[j];

        mr_free(table[i].x.a);
        mr_free(table[i].x.b);
        mr_free(table[i].y.a);
        mr_free(table[i].y.b);
        mr_free(table[i].z.a);
        mr_free(table[i].z.b);
    }
        
    mr_free(table);  

    MR_OUT
    return TRUE;
}

void ecn2_brick_end(ebrick *B)
{
    mirkill(B->n);
    mirkill(B->b);
    mirkill(B->a);
    mr_free(B->table);  
}

#else

/* use precomputated table in ROM */

void ecn2_brick_init(ebrick *B,const mr_small* rom,big a,big b,big n,int window,int nb)
{
    B->table=rom;
    B->a=a; /* just pass a pointer */
    B->b=b;
    B->n=n;
    B->window=window;  /* 2^4=16  stored values */
    B->max=nb;
}

#endif

/*
void ecn2_mul_brick(_MIPD_ ebrick *B,big e,zzn2 *x,zzn2 *y)
{
    int i,j,t,len,maxsize,promptr;
    ecn2 w,z;
 
#ifdef MR_STATIC
    char mem[MR_BIG_RESERVE(10)];
#else
    char *mem;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    if (size(e)<0) mr_berror(_MIPP_ MR_ERR_NEG_POWER);
    t=MR_ROUNDUP(B->max,B->window);
    
    MR_IN(116)

#ifndef MR_ALWAYS_BINARY
    if (mr_mip->base != mr_mip->base2)
    {
        mr_berror(_MIPP_ MR_ERR_NOT_SUPPORTED);
        MR_OUT
        return;
    }
#endif

    if (logb2(_MIPP_ e) > B->max)
    {
        mr_berror(_MIPP_ MR_ERR_EXP_TOO_BIG);
        MR_OUT
        return;
    }

    ecurve_init(_MIPP_ B->a,B->b,B->n,MR_BEST);
    mr_mip->TWIST=MR_QUADRATIC;
  
#ifdef MR_STATIC
    memset(mem,0,MR_BIG_RESERVE(10));
#else
    mem=memalloc(_MIPP_ 10);
#endif

    w.x.a=mirvar_mem(_MIPP_  mem, 0);
    w.x.b=mirvar_mem(_MIPP_  mem, 1);
    w.y.a=mirvar_mem(_MIPP_  mem, 2);
    w.y.b=mirvar_mem(_MIPP_  mem, 3);  
    w.z.a=mirvar_mem(_MIPP_  mem, 4);
    w.z.b=mirvar_mem(_MIPP_  mem, 5);      
    w.marker=MR_EPOINT_INFINITY;
    z.x.a=mirvar_mem(_MIPP_  mem, 6);
    z.x.b=mirvar_mem(_MIPP_  mem, 7);
    z.y.a=mirvar_mem(_MIPP_  mem, 8);
    z.y.b=mirvar_mem(_MIPP_  mem, 9);       
    z.marker=MR_EPOINT_INFINITY;

    len=B->n->len;
    maxsize=4*(1<<B->window)*len;

    for (i=t-1;i>=0;i--)
    {
        j=recode(_MIPP_ e,t,B->window,i);
        ecn2_add(_MIPP_ &w,&w);
        if (j>0)
        {
            promptr=4*j*len;
            init_big_from_rom(z.x.a,len,B->table,maxsize,&promptr);
            init_big_from_rom(z.x.b,len,B->table,maxsize,&promptr);
            init_big_from_rom(z.y.a,len,B->table,maxsize,&promptr);
            init_big_from_rom(z.y.b,len,B->table,maxsize,&promptr);
            z.marker=MR_EPOINT_NORMALIZED;
            ecn2_add(_MIPP_ &z,&w);
        }
    }
    ecn2_norm(_MIPP_ &w);
    ecn2_getxy(&w,x,y);
#ifndef MR_STATIC
    memkill(_MIPP_ mem,10);
#else
    memset(mem,0,MR_BIG_RESERVE(10));
#endif
    MR_OUT
}
*/

void ecn2_mul_brick_gls(_MIPD_ ebrick *B,big *e,zzn2 *psi,zzn2 *x,zzn2 *y)
{
    int i,j,k,t,len,maxsize,promptr,se[2];
    ecn2 w,z;
 
#ifdef MR_STATIC
    char mem[MR_BIG_RESERVE(10)];
#else
    char *mem;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    for (k=0;k<2;k++) se[k]=exsign(e[k]);

    t=MR_ROUNDUP(B->max,B->window);
    
    MR_IN(222)

#ifndef MR_ALWAYS_BINARY
    if (mr_mip->base != mr_mip->base2)
    {
        mr_berror(_MIPP_ MR_ERR_NOT_SUPPORTED);
        MR_OUT
        return;
    }
#endif

    if (logb2(_MIPP_ e[0])>B->max || logb2(_MIPP_ e[1])>B->max)
    {
        mr_berror(_MIPP_ MR_ERR_EXP_TOO_BIG);
        MR_OUT
        return;
    }

    ecurve_init(_MIPP_ B->a,B->b,B->n,MR_BEST);
    mr_mip->TWIST=MR_QUADRATIC;
  
#ifdef MR_STATIC
    memset(mem,0,MR_BIG_RESERVE(10));
#else
    mem=memalloc(_MIPP_ 10);
#endif

    z.x.a=mirvar_mem(_MIPP_  mem, 0);
    z.x.b=mirvar_mem(_MIPP_  mem, 1);
    z.y.a=mirvar_mem(_MIPP_  mem, 2);
    z.y.b=mirvar_mem(_MIPP_  mem, 3);       
    z.marker=MR_EPOINT_INFINITY;

    w.x.a=mirvar_mem(_MIPP_  mem, 4);
    w.x.b=mirvar_mem(_MIPP_  mem, 5);
    w.y.a=mirvar_mem(_MIPP_  mem, 6);
    w.y.b=mirvar_mem(_MIPP_  mem, 7);  
    w.z.a=mirvar_mem(_MIPP_  mem, 8);
    w.z.b=mirvar_mem(_MIPP_  mem, 9); 
    w.marker=MR_EPOINT_INFINITY;

    len=B->n->len;
    maxsize=4*(1<<B->window)*len;

    for (i=t-1;i>=0;i--)
    {
        ecn2_add(_MIPP_ &w,&w);
        for (k=0;k<2;k++)
        {
            j=recode(_MIPP_ e[k],t,B->window,i);
            if (j>0)
            {
                promptr=4*j*len;
                init_big_from_rom(z.x.a,len,B->table,maxsize,&promptr);
                init_big_from_rom(z.x.b,len,B->table,maxsize,&promptr);
                init_big_from_rom(z.y.a,len,B->table,maxsize,&promptr);
                init_big_from_rom(z.y.b,len,B->table,maxsize,&promptr);
                z.marker=MR_EPOINT_NORMALIZED;
                if (k==1) ecn2_psi(_MIPP_ psi,&z);
                if (se[k]==PLUS) ecn2_add(_MIPP_ &z,&w);
                else             ecn2_sub(_MIPP_ &z,&w);
            }
        }      
    }
    ecn2_norm(_MIPP_ &w);
    ecn2_getxy(&w,x,y);
#ifndef MR_STATIC
    memkill(_MIPP_ mem,10);
#else
    memset(mem,0,MR_BIG_RESERVE(10));
#endif
    MR_OUT
}

#endif

#ifndef MR_NO_ECC_MULTIADD

void ecn2_mult4(_MIPD_ big *e,ecn2 *P,ecn2 *R)
{ /* R=e[0]*P[0]+e[1]*P[1]+ .... e[n-1]*P[n-1]   */
    int i,j,k,l,nb,ea,c;
    ecn2 G[16];
	zzn2 work[16];
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
#ifndef MR_STATIC
	char *mem=(char *)memalloc(_MIPP_ 120);
#else
    char mem[MR_BIG_RESERVE(120)];       
 	memset(mem, 0, MR_BIG_RESERVE(120));   
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(243)

	l=0;
	for (k=1;k<16;k++)
	{
		G[k].x.a=mirvar_mem(_MIPP_  mem, l++);
		G[k].x.b=mirvar_mem(_MIPP_  mem, l++);
		G[k].y.a=mirvar_mem(_MIPP_  mem, l++);
		G[k].y.b=mirvar_mem(_MIPP_  mem, l++); 
		G[k].z.a=mirvar_mem(_MIPP_  mem, l++);
		G[k].z.b=mirvar_mem(_MIPP_  mem, l++);        
		G[k].marker=MR_EPOINT_INFINITY;	

		i=k; j=1; c=0; while (i>=(2*j)) {j*=2; c++;}
		if (i>j) ecn2_copy(&G[i-j],&G[k]);
		ecn2_add(_MIPP_ &P[c],&G[k]);
	}

	for (i=0;i<15;i++)
	{
		work[i].a=mirvar_mem(_MIPP_  mem, l++);  
		work[i].b=mirvar_mem(_MIPP_  mem, l++);  
	}

	ecn2_multi_norm(_MIPP_ 15,work,&G[1]);

    nb=0;
    for (j=0;j<4;j++) if ((k=logb2(_MIPP_ e[j])) > nb) nb=k;

	ecn2_zero(R);

#ifndef MR_ALWAYS_BINARY
    if (mr_mip->base==mr_mip->base2)
    {
#endif
        for (i=nb-1;i>=0;i--)
        {
            if (mr_mip->user!=NULL) (*mr_mip->user)();
            ea=0;
            k=1;
            for (j=0;j<4;j++)
            {
                if (mr_testbit(_MIPP_ e[j],i)) ea+=k;
                k<<=1;
            }
            ecn2_add(_MIPP_ R,R);
            if (ea!=0) ecn2_add(_MIPP_ &G[ea],R);
        }    
#ifndef MR_ALWAYS_BINARY
    }
    else mr_berror(_MIPP_ MR_ERR_NOT_SUPPORTED);
#endif
#ifndef MR_STATIC
    memkill(_MIPP_ mem,120);
#else
 	memset(mem, 0, MR_BIG_RESERVE(120));  
#endif

    MR_OUT
}

#ifndef MR_STATIC

void ecn2_multn(_MIPD_ int n,big *e,ecn2 *P,ecn2 *R)
{ /* R=e[0]*P[0]+e[1]*P[1]+ .... e[n-1]*P[n-1]   */
    int i,j,k,l,nb,ea,c;
	int m=1<<n;
    ecn2 *G;
	zzn2 *work;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
	char *mem=(char *)memalloc(_MIPP_ 8*(m-1));
    if (mr_mip->ERNUM) return;

    MR_IN(223)

    G=   (ecn2 *)mr_alloc(_MIPP_ m,sizeof(ecn2));
	work=(zzn2 *)mr_alloc(_MIPP_ m,sizeof(zzn2));

	l=0;
	for (k=1;k<m;k++)
	{
		G[k].x.a=mirvar_mem(_MIPP_  mem, l++);
		G[k].x.b=mirvar_mem(_MIPP_  mem, l++);
		G[k].y.a=mirvar_mem(_MIPP_  mem, l++);
		G[k].y.b=mirvar_mem(_MIPP_  mem, l++); 
		G[k].z.a=mirvar_mem(_MIPP_  mem, l++);
		G[k].z.b=mirvar_mem(_MIPP_  mem, l++);        
		G[k].marker=MR_EPOINT_INFINITY;	

		i=k; j=1; c=0; while (i>=(2*j)) {j*=2; c++;}
		if (i>j) ecn2_copy(&G[i-j],&G[k]);
		ecn2_add(_MIPP_ &P[c],&G[k]);
	}

	for (i=0;i<m-1;i++)
	{
		work[i].a=mirvar_mem(_MIPP_  mem, l++);  
		work[i].b=mirvar_mem(_MIPP_  mem, l++);  
	}

	ecn2_multi_norm(_MIPP_ m-1,work,&G[1]);

    nb=0;
    for (j=0;j<n;j++) if ((k=logb2(_MIPP_ e[j])) > nb) nb=k;

	ecn2_zero(R);

#ifndef MR_ALWAYS_BINARY
    if (mr_mip->base==mr_mip->base2)
    {
#endif
        for (i=nb-1;i>=0;i--)
        {
            if (mr_mip->user!=NULL) (*mr_mip->user)();
            ea=0;
            k=1;
            for (j=0;j<n;j++)
            {
                if (mr_testbit(_MIPP_ e[j],i)) ea+=k;
                k<<=1;
            }
            ecn2_add(_MIPP_ R,R);
            if (ea!=0) ecn2_add(_MIPP_ &G[ea],R);
        }    
#ifndef MR_ALWAYS_BINARY
    }
    else mr_berror(_MIPP_ MR_ERR_NOT_SUPPORTED);
#endif

    memkill(_MIPP_ mem,8*(m-1));
	mr_free(work);
    mr_free(G);
    MR_OUT
}

#endif
#endif
