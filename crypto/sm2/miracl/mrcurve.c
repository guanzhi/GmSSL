
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
 *   MIRACL elliptic curve routines
 *   mrcurve.c
 *
 *   Assumes Weierstrass equation y^2 = x^3 + Ax + B
 *   See IEEE P1363 Draft Standard 
 *
 *   (See below for Edwards coordinates implementation)
 *
 *   Uses Montgomery's representation internally
 *
 *   Works particularly well with fixed length Comba multiplier
 *   e.g. #define MR_COMBA 5 for 5x32 = 160 bit modulus
 *        on 32-bit computer
 *
 */

#include <stdlib.h> 
#include "miracl.h"
#ifdef MR_STATIC
#include <string.h>
#endif

#ifndef MR_EDWARDS

static void epoint_getrhs(_MIPD_ big x,big y)
{ /* x and y must be different */

  /* find x^3+Ax+B */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    nres_modmult(_MIPP_ x,x,y);

    nres_modmult(_MIPP_ y,x,y);
    if (mr_abs(mr_mip->Asize)==MR_TOOBIG)
        nres_modmult(_MIPP_ x,mr_mip->A,mr_mip->w1);
    else
        nres_premult(_MIPP_ x,mr_mip->Asize,mr_mip->w1);
    nres_modadd(_MIPP_ y,mr_mip->w1,y);
    if (mr_abs(mr_mip->Bsize)==MR_TOOBIG)
        nres_modadd(_MIPP_ y,mr_mip->B,y);
    else
    {
        convert(_MIPP_ mr_mip->Bsize,mr_mip->w1);
        nres(_MIPP_ mr_mip->w1,mr_mip->w1);
        nres_modadd(_MIPP_ y,mr_mip->w1,y);
    }
}

#ifndef MR_NOSUPPORT_COMPRESSION

BOOL epoint_x(_MIPD_ big x)
{ /* test if x is associated with a point on the   *
   * currently active curve                        */
    int j;

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return FALSE;

    MR_IN(147)
    
    if (x==NULL) return FALSE;

    nres(_MIPP_ x,mr_mip->w2);
    epoint_getrhs(_MIPP_ mr_mip->w2,mr_mip->w3);

    if (size(mr_mip->w3)==0)
    {
        MR_OUT
        return TRUE;
    }

    redc(_MIPP_ mr_mip->w3,mr_mip->w4);
    j=jack(_MIPP_ mr_mip->w4,mr_mip->modulus);

    MR_OUT
    if (j==1) return TRUE;
    return FALSE;
}

#endif

BOOL epoint_set(_MIPD_ big x,big y,int cb,epoint *p)
{ /* initialise a point on active ecurve            *
   * if x or y == NULL, set to point at infinity    *
   * if x==y, a y co-ordinate is calculated - if    *
   * possible - and cb suggests LSB 0/1  of y       *
   * (which "decompresses" y). Otherwise, check     *
   * validity of given (x,y) point, ignoring cb.    *
   * Returns TRUE for valid point, otherwise FALSE. */
  
    BOOL valid;

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return FALSE;

    MR_IN(97)

    if (x==NULL || y==NULL)
    {
        copy(mr_mip->one,p->X);
        copy(mr_mip->one,p->Y);
        p->marker=MR_EPOINT_INFINITY;
        MR_OUT
        return TRUE;
    }

/* find x^3+Ax+B */

    nres(_MIPP_ x,p->X);

    epoint_getrhs(_MIPP_ p->X,mr_mip->w3);

    valid=FALSE;

    if (x!=y)
    { /* compare with y^2 */
        nres(_MIPP_ y,p->Y);
        nres_modmult(_MIPP_ p->Y,p->Y,mr_mip->w1);
        
        if (mr_compare(mr_mip->w1,mr_mip->w3)==0) valid=TRUE;
    }
    else
    { /* no y supplied - calculate one. Find square root */
#ifndef MR_NOSUPPORT_COMPRESSION

        valid=nres_sqroot(_MIPP_ mr_mip->w3,p->Y);
    /* check LSB - have we got the right root? */
        redc(_MIPP_ p->Y,mr_mip->w1);
        if (remain(_MIPP_ mr_mip->w1,2)!=cb) 
            mr_psub(_MIPP_ mr_mip->modulus,p->Y,p->Y);

#else
    mr_berror(_MIPP_ MR_ERR_NOT_SUPPORTED);
    MR_OUT
    return FALSE;
#endif
    } 
    if (valid)
    {
        p->marker=MR_EPOINT_NORMALIZED;
        MR_OUT
        return TRUE;
    }

    MR_OUT
    return FALSE;
}

#ifndef MR_STATIC

void epoint_getxyz(_MIPD_ epoint *p,big x,big y,big z)
{ /* get (x,y,z) coordinates */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    MR_IN(143)
    convert(_MIPP_ 1,mr_mip->w1);
    if (p->marker==MR_EPOINT_INFINITY)
    {
#ifndef MR_AFFINE_ONLY
        if (mr_mip->coord==MR_AFFINE)
        { /* (0,1) or (0,0) = O */
#endif
            if (x!=NULL) zero(x);
            if (mr_mip->Bsize==0)
            {
                if (y!=NULL) copy(mr_mip->w1,y);
            }
            else
            {
                if (y!=NULL) zero(y);
            }
#ifndef MR_AFFINE_ONLY 
        }
        if (mr_mip->coord==MR_PROJECTIVE)
        { /* (1,1,0) = O */
            if (x!=NULL) copy(mr_mip->w1,x);
            if (y!=NULL) copy(mr_mip->w1,y);
        }
#endif
        if (z!=NULL) zero(z);
        MR_OUT
        return;
    }
    if (x!=NULL) redc(_MIPP_ p->X,x);
    if (y!=NULL) redc(_MIPP_ p->Y,y);
#ifndef MR_AFFINE_ONLY
    if (mr_mip->coord==MR_AFFINE)
    {
#endif
        if (z!=NULL) zero(z);
#ifndef MR_AFFINE_ONLY
    }

    if (mr_mip->coord==MR_PROJECTIVE)
    {
        if (z!=NULL) 
        {
            if (p->marker!=MR_EPOINT_GENERAL) copy(mr_mip->w1,z);
            else redc(_MIPP_ p->Z,z);
        }
    }
#endif
    MR_OUT
    return;
}

#endif

int epoint_get(_MIPD_ epoint* p,big x,big y)
{ /* Get point co-ordinates in affine, normal form       *
   * (converted from projective, Montgomery form)        *
   * if x==y, supplies x only. Return value is Least     *
   * Significant Bit of y (useful for point compression) */

    int lsb;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    if (p->marker==MR_EPOINT_INFINITY)
    {
        zero(x);
        zero(y);
        return 0;
    }
    if (mr_mip->ERNUM) return 0;

    MR_IN(98)

    if (!epoint_norm(_MIPP_ p)) 
    { /* not possible ! */
        MR_OUT
        return (-1);
    }

    redc(_MIPP_ p->X,x);
    redc(_MIPP_ p->Y,mr_mip->w1);

    if (x!=y) copy(mr_mip->w1,y);
    lsb=remain(_MIPP_ mr_mip->w1,2); 
    MR_OUT
    return lsb;
}

BOOL epoint_norm(_MIPD_ epoint *p)
{ /* normalise a point */
    
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

#ifndef MR_AFFINE_ONLY

    if (mr_mip->coord==MR_AFFINE) return TRUE;
    if (p->marker!=MR_EPOINT_GENERAL) return TRUE;

    if (mr_mip->ERNUM) return FALSE;

    MR_IN(117)

    copy(mr_mip->one,mr_mip->w8);

    if (nres_moddiv(_MIPP_ mr_mip->w8,p->Z,mr_mip->w8)>1) /* 1/Z  */
    {
        epoint_set(_MIPP_ NULL,NULL,0,p);
        mr_berror(_MIPP_ MR_ERR_COMPOSITE_MODULUS); 
        MR_OUT
        return FALSE;
    }
    
    nres_modmult(_MIPP_ mr_mip->w8,mr_mip->w8,mr_mip->w1);/* 1/ZZ */
    nres_modmult(_MIPP_ p->X,mr_mip->w1,p->X);            /* X/ZZ */
    nres_modmult(_MIPP_ mr_mip->w1,mr_mip->w8,mr_mip->w1);/* 1/ZZZ */
    nres_modmult(_MIPP_ p->Y,mr_mip->w1,p->Y);            /* Y/ZZZ */

    copy(mr_mip->one,p->Z);
   
    p->marker=MR_EPOINT_NORMALIZED;
    MR_OUT

#endif

    return TRUE;
}

BOOL epoint_multi_norm(_MIPD_ int m,big *work,epoint **p)
{ /* Normalise an array of points of length m<MR_MAX_M_T_S - requires a workspace array of length m */

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
 
#ifndef MR_AFFINE_ONLY
    int i;
	BOOL inf=FALSE;
    big w[MR_MAX_M_T_S];
    if (mr_mip->coord==MR_AFFINE) return TRUE;
    if (mr_mip->ERNUM) return FALSE;   
    if (m>MR_MAX_M_T_S) return FALSE;

    MR_IN(190)

    for (i=0;i<m;i++)
    {
        if (p[i]->marker==MR_EPOINT_NORMALIZED) w[i]=mr_mip->one;
        else w[i]=p[i]->Z;
		if (p[i]->marker==MR_EPOINT_INFINITY) {inf=TRUE; break;} /* whoops, one of them is point at infinity */
    }

	if (inf)
	{
		for (i=0;i<m;i++) epoint_norm(_MIPP_ p[i]);
		MR_OUT
		return TRUE;
	}  

    if (!nres_multi_inverse(_MIPP_ m,w,work)) 
    {
       MR_OUT
       return FALSE;
    }

    for (i=0;i<m;i++)
    {
        copy(mr_mip->one,p[i]->Z);
        p[i]->marker=MR_EPOINT_NORMALIZED;
        nres_modmult(_MIPP_ work[i],work[i],mr_mip->w1);
        nres_modmult(_MIPP_ p[i]->X,mr_mip->w1,p[i]->X);    /* X/ZZ */
        nres_modmult(_MIPP_ mr_mip->w1,work[i],mr_mip->w1);
        nres_modmult(_MIPP_ p[i]->Y,mr_mip->w1,p[i]->Y);    /* Y/ZZZ */
    }    
    MR_OUT
#endif
    return TRUE;   
}

/* adds b+=a, d+=c, and slopes in s1 and s2 */

#ifndef MR_NO_ECC_MULTIADD
#ifndef MR_STATIC

void ecurve_double_add(_MIPD_ epoint *a,epoint*b,epoint *c,epoint *d,big *s1,big *s2)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;    

    MR_IN(144);

#ifndef MR_AFFINE_ONLY

    if (mr_mip->coord==MR_AFFINE)
    {
#endif
        if (a->marker==MR_EPOINT_INFINITY || size(a->Y)==0)
        {
            *s1=NULL;
            ecurve_add(_MIPP_ c,d);
            *s2=mr_mip->w8;
            MR_OUT
            return;
        }
        if (b->marker==MR_EPOINT_INFINITY || size(b->Y)==0)
        {
            *s1=NULL;
            epoint_copy(a,b);
            ecurve_add(_MIPP_ c,d);
            *s2=mr_mip->w8;
            MR_OUT
            return;
        }
        if (c->marker==MR_EPOINT_INFINITY || size(c->Y)==0)
        {
            ecurve_add(_MIPP_ a,b);
            *s1=mr_mip->w8;
            *s2=NULL;
            MR_OUT
            return;
        }
        if (d->marker==MR_EPOINT_INFINITY || size(d->Y)==0)
        {
            epoint_copy(c,d);
            ecurve_add(_MIPP_ a,b);
            *s1=mr_mip->w8;
            *s2=NULL;
            MR_OUT
            return;
        }

        if (a==b || (mr_compare(a->X,b->X)==0 && mr_compare(a->Y,b->Y)==0))
        {
            nres_modmult(_MIPP_ a->X,a->X,mr_mip->w8);
            nres_premult(_MIPP_ mr_mip->w8,3,mr_mip->w8); /* 3x^2 */
            if (mr_abs(mr_mip->Asize)==MR_TOOBIG)
                nres_modadd(_MIPP_ mr_mip->w8,mr_mip->A,mr_mip->w8);
            else
            {
                convert(_MIPP_ mr_mip->Asize,mr_mip->w2);
                nres(_MIPP_ mr_mip->w2,mr_mip->w2);
                nres_modadd(_MIPP_ mr_mip->w8,mr_mip->w2,mr_mip->w8);
            }
            nres_premult(_MIPP_ a->Y,2,mr_mip->w10);
        }
        else
        {
            if (mr_compare(a->X,b->X)==0)
            {
                epoint_set(_MIPP_ NULL,NULL,0,b);
                *s1=NULL;
                ecurve_add(_MIPP_ c,d);
                *s2=mr_mip->w8;
                MR_OUT
                return;
            }
            nres_modsub(_MIPP_ a->Y,b->Y,mr_mip->w8);
            nres_modsub(_MIPP_ a->X,b->X,mr_mip->w10);
        }

        if (c==d || (mr_compare(c->X,d->X)==0 && mr_compare(c->Y,d->Y)==0))
        {
            nres_modmult(_MIPP_ c->X,c->X,mr_mip->w9);
            nres_premult(_MIPP_ mr_mip->w9,3,mr_mip->w9); /* 3x^2 */
            if (mr_abs(mr_mip->Asize)==MR_TOOBIG)
                nres_modadd(_MIPP_ mr_mip->w9,mr_mip->A,mr_mip->w9);
            else
            {
                convert(_MIPP_ mr_mip->Asize,mr_mip->w2);
                nres(_MIPP_ mr_mip->w2,mr_mip->w2);
                nres_modadd(_MIPP_ mr_mip->w9,mr_mip->w2,mr_mip->w9);
            }
            nres_premult(_MIPP_ c->Y,2,mr_mip->w11);
        }
        else
        {
            if (mr_compare(c->X,d->X)==0)
            {
                epoint_set(_MIPP_ NULL,NULL,0,d);
                *s2=NULL;
                ecurve_add(_MIPP_ a,b);
                *s1=mr_mip->w8;
                MR_OUT
                return;
            }
            nres_modsub(_MIPP_ c->Y,d->Y,mr_mip->w9);
            nres_modsub(_MIPP_ c->X,d->X,mr_mip->w11);
        }

        nres_double_inverse(_MIPP_ mr_mip->w10,mr_mip->w10,mr_mip->w11,mr_mip->w11);
        nres_modmult(_MIPP_ mr_mip->w8,mr_mip->w10,mr_mip->w8);
        nres_modmult(_MIPP_ mr_mip->w9,mr_mip->w11,mr_mip->w9);

        nres_modmult(_MIPP_ mr_mip->w8,mr_mip->w8,mr_mip->w2); /* m^2 */
        nres_modsub(_MIPP_ mr_mip->w2,a->X,mr_mip->w1);
        nres_modsub(_MIPP_ mr_mip->w1,b->X,mr_mip->w1);

        nres_modsub(_MIPP_ b->X,mr_mip->w1,mr_mip->w2);
        nres_modmult(_MIPP_ mr_mip->w2,mr_mip->w8,mr_mip->w2);
        nres_modsub(_MIPP_ mr_mip->w2,b->Y,b->Y);
        copy(mr_mip->w1,b->X);
        b->marker=MR_EPOINT_GENERAL;

        nres_modmult(_MIPP_ mr_mip->w9,mr_mip->w9,mr_mip->w2); /* m^2 */
        nres_modsub(_MIPP_ mr_mip->w2,c->X,mr_mip->w1);
        nres_modsub(_MIPP_ mr_mip->w1,d->X,mr_mip->w1);

        nres_modsub(_MIPP_ d->X,mr_mip->w1,mr_mip->w2);
        nres_modmult(_MIPP_ mr_mip->w2,mr_mip->w9,mr_mip->w2);
        nres_modsub(_MIPP_ mr_mip->w2,d->Y,d->Y);
        copy(mr_mip->w1,d->X);
        d->marker=MR_EPOINT_GENERAL;

        *s1=mr_mip->w8;
        *s2=mr_mip->w9;
#ifndef MR_AFFINE_ONLY
    }
    else
    { /* no speed-up */
        ecurve_add(_MIPP_ a,b);
        copy(mr_mip->w8,mr_mip->w9);
        *s1=mr_mip->w9;
        ecurve_add(_MIPP_ c,d);
        *s2=mr_mip->w8;
    }
#endif
    MR_OUT
}

void ecurve_multi_add(_MIPD_ int m,epoint **x,epoint**w)
{ /* adds m points together simultaneously, w[i]+=x[i] */
    int i,*flag;
    big *A,*B,*C;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;    

    MR_IN(122)
#ifndef MR_AFFINE_ONLY
    if (mr_mip->coord==MR_AFFINE)
    { /* this can be done faster */
#endif
        A=(big *)mr_alloc(_MIPP_ m,sizeof(big));
        B=(big *)mr_alloc(_MIPP_ m,sizeof(big));
        C=(big *)mr_alloc(_MIPP_ m,sizeof(big));
        flag=(int *)mr_alloc(_MIPP_ m,sizeof(int));

        copy(mr_mip->one,mr_mip->w3);

        for (i=0;i<m;i++)
        {
            A[i]=mirvar(_MIPP_ 0);
            B[i]=mirvar(_MIPP_ 0);
            C[i]=mirvar(_MIPP_ 0);
            flag[i]=0;
            if (mr_compare(x[i]->X,w[i]->X)==0 && mr_compare(x[i]->Y,w[i]->Y)==0) 
            { /* doubling */
                if (x[i]->marker==MR_EPOINT_INFINITY || size(x[i]->Y)==0)
                {
                    flag[i]=1;       /* result is infinity */
                    copy(mr_mip->w3,B[i]);
                    continue;    
                }
                nres_modmult(_MIPP_ x[i]->X,x[i]->X,A[i]);
                nres_premult(_MIPP_ A[i],3,A[i]);  /* 3*x^2 */
                if (mr_abs(mr_mip->Asize) == MR_TOOBIG)
                    nres_modadd(_MIPP_ A[i],mr_mip->A,A[i]);
                else
                {
                    convert(_MIPP_ mr_mip->Asize,mr_mip->w2);
                    nres(_MIPP_ mr_mip->w2,mr_mip->w2);
                    nres_modadd(_MIPP_ A[i],mr_mip->w2,A[i]);
                }                                       /* 3*x^2+A */
                nres_premult(_MIPP_ x[i]->Y,2,B[i]);
            }
            else
            {
                if (x[i]->marker==MR_EPOINT_INFINITY)
                {
                    flag[i]=2;              /* w[i] unchanged */
                    copy(mr_mip->w3,B[i]);
                    continue;
                }
                if (w[i]->marker==MR_EPOINT_INFINITY)
                {
                    flag[i]=3;              /* w[i] = x[i] */
                    copy(mr_mip->w3,B[i]);
                    continue;
                }
                nres_modsub(_MIPP_ x[i]->X,w[i]->X,B[i]);
                if (size(B[i])==0)
                { /* point at infinity */
                    flag[i]=1;       /* result is infinity */
                    copy(mr_mip->w3,B[i]);
                    continue;    
                }
                nres_modsub(_MIPP_ x[i]->Y,w[i]->Y,A[i]);
            }   
        }
        nres_multi_inverse(_MIPP_ m,B,C);  /* only one inversion needed */
        for (i=0;i<m;i++)
        {
            if (flag[i]==1)
            { /* point at infinity */
                epoint_set(_MIPP_ NULL,NULL,0,w[i]);
                continue;
            }
            if (flag[i]==2)
            {
                continue;
            }
            if (flag[i]==3)
            {
                epoint_copy(x[i],w[i]);
                continue;
            }
            nres_modmult(_MIPP_ A[i],C[i],mr_mip->w8);

            nres_modmult(_MIPP_ mr_mip->w8,mr_mip->w8,mr_mip->w2); /* m^2 */
            nres_modsub(_MIPP_ mr_mip->w2,x[i]->X,mr_mip->w1);
            nres_modsub(_MIPP_ mr_mip->w1,w[i]->X,mr_mip->w1);
       
            nres_modsub(_MIPP_ w[i]->X,mr_mip->w1,mr_mip->w2);
            nres_modmult(_MIPP_ mr_mip->w2,mr_mip->w8,mr_mip->w2);
            nres_modsub(_MIPP_ mr_mip->w2,w[i]->Y,w[i]->Y);
            copy(mr_mip->w1,w[i]->X);
            w[i]->marker=MR_EPOINT_NORMALIZED;

            mr_free(C[i]);
            mr_free(B[i]);
            mr_free(A[i]);
        }
        mr_free(flag);
        mr_free(C); mr_free(B); mr_free(A);
#ifndef MR_AFFINE_ONLY
    }
    else
    { /* no speed-up */
        for (i=0;i<m;i++) ecurve_add(_MIPP_ x[i],w[i]);
    }
#endif
    MR_OUT  
}

#endif
#endif

void ecurve_double(_MIPD_ epoint *p)
{ /* double epoint on active ecurve */

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    if (p->marker==MR_EPOINT_INFINITY) 
    { /* 2 times infinity == infinity ! */
        return;
    }

#ifndef MR_AFFINE_ONLY
    if (mr_mip->coord==MR_AFFINE)
    { /* 2 sqrs, 1 mul, 1 div */
#endif
        if (size(p->Y)==0) 
        { /* set to point at infinity */
            epoint_set(_MIPP_ NULL,NULL,0,p);
            return;
        }
 
        nres_modmult(_MIPP_ p->X,p->X,mr_mip->w8);    /* w8=x^2   */
        nres_premult(_MIPP_ mr_mip->w8,3,mr_mip->w8); /* w8=3*x^2 */
        if (mr_abs(mr_mip->Asize) == MR_TOOBIG)
            nres_modadd(_MIPP_ mr_mip->w8,mr_mip->A,mr_mip->w8);
        else
        {
            convert(_MIPP_ mr_mip->Asize,mr_mip->w2);
            nres(_MIPP_ mr_mip->w2,mr_mip->w2);
            nres_modadd(_MIPP_ mr_mip->w8,mr_mip->w2,mr_mip->w8);
        }                                     /* w8=3*x^2+A */
        nres_premult(_MIPP_ p->Y,2,mr_mip->w6);      /* w6=2y */
        if (nres_moddiv(_MIPP_ mr_mip->w8,mr_mip->w6,mr_mip->w8)>1) 
        {
            epoint_set(_MIPP_ NULL,NULL,0,p);
            mr_berror(_MIPP_ MR_ERR_COMPOSITE_MODULUS); 
            return;
        }

/* w8 is slope m on exit */

        nres_modmult(_MIPP_ mr_mip->w8,mr_mip->w8,mr_mip->w2); /* w2=m^2 */
        nres_premult(_MIPP_ p->X,2,mr_mip->w1);
        nres_modsub(_MIPP_ mr_mip->w2,mr_mip->w1,mr_mip->w1); /* w1=m^2-2x */
        
        nres_modsub(_MIPP_ p->X,mr_mip->w1,mr_mip->w2);
        nres_modmult(_MIPP_ mr_mip->w2,mr_mip->w8,mr_mip->w2);
        nres_modsub(_MIPP_ mr_mip->w2,p->Y,p->Y);
        copy(mr_mip->w1,p->X);
        
        return;    
#ifndef MR_AFFINE_ONLY
    }

    if (size(p->Y)==0)
    { /* set to point at infinity */
        epoint_set(_MIPP_ NULL,NULL,0,p);
        return;
    }
 
    convert(_MIPP_ 1,mr_mip->w1);
    if (mr_abs(mr_mip->Asize) < MR_TOOBIG)
    {
        if (mr_mip->Asize!=0)
        {
            if (p->marker==MR_EPOINT_NORMALIZED)
				nres(_MIPP_ mr_mip->w1,mr_mip->w6);
            else nres_modmult(_MIPP_ p->Z,p->Z,mr_mip->w6);
        }

        if (mr_mip->Asize==(-3))
        { /* a is -3. Goody. 4 sqrs, 4 muls */
            nres_modsub(_MIPP_ p->X,mr_mip->w6,mr_mip->w3);
            nres_modadd(_MIPP_ p->X,mr_mip->w6,mr_mip->w8);
            nres_modmult(_MIPP_ mr_mip->w3,mr_mip->w8,mr_mip->w3);
            nres_modadd(_MIPP_ mr_mip->w3,mr_mip->w3,mr_mip->w8);
            nres_modadd(_MIPP_ mr_mip->w8,mr_mip->w3,mr_mip->w8);
        }
        else
        { /* a is small */
            if (mr_mip->Asize!=0)
            { /* a is non zero! */
                nres_modmult(_MIPP_ mr_mip->w6,mr_mip->w6,mr_mip->w3);
                nres_premult(_MIPP_ mr_mip->w3,mr_mip->Asize,mr_mip->w3);
            }
            nres_modmult(_MIPP_ p->X,p->X,mr_mip->w1);
            nres_modadd(_MIPP_ mr_mip->w1,mr_mip->w1,mr_mip->w8);
            nres_modadd(_MIPP_ mr_mip->w8,mr_mip->w1,mr_mip->w8);
            if (mr_mip->Asize!=0) nres_modadd(_MIPP_ mr_mip->w8,mr_mip->w3,mr_mip->w8);
        }
    }
    else
    { /* a is not special */
        if (p->marker==MR_EPOINT_NORMALIZED) nres(_MIPP_ mr_mip->w1,mr_mip->w6);
        else nres_modmult(_MIPP_ p->Z,p->Z,mr_mip->w6);

        nres_modmult(_MIPP_ mr_mip->w6,mr_mip->w6,mr_mip->w3);
        nres_modmult(_MIPP_ mr_mip->w3,mr_mip->A,mr_mip->w3);
        nres_modmult(_MIPP_ p->X,p->X,mr_mip->w1);
        nres_modadd(_MIPP_ mr_mip->w1,mr_mip->w1,mr_mip->w8);
        nres_modadd(_MIPP_ mr_mip->w8,mr_mip->w1,mr_mip->w8);
        nres_modadd(_MIPP_ mr_mip->w8,mr_mip->w3,mr_mip->w8);        
    }

/* w8 contains numerator of slope 3x^2+A.z^4  *
 * denominator is now placed in Z             */

    nres_modmult(_MIPP_ p->Y,p->Y,mr_mip->w2);
    nres_modmult(_MIPP_ p->X,mr_mip->w2,mr_mip->w3);
    nres_modadd(_MIPP_ mr_mip->w3,mr_mip->w3,mr_mip->w3);
    nres_modadd(_MIPP_ mr_mip->w3,mr_mip->w3,mr_mip->w3);
    nres_modmult(_MIPP_ mr_mip->w8,mr_mip->w8,p->X);
    nres_modsub(_MIPP_ p->X,mr_mip->w3,p->X);
    nres_modsub(_MIPP_ p->X,mr_mip->w3,p->X);
    
    if (p->marker==MR_EPOINT_NORMALIZED)
        copy(p->Y,p->Z);
    else nres_modmult(_MIPP_ p->Z,p->Y,p->Z);
    nres_modadd(_MIPP_ p->Z,p->Z,p->Z);

    nres_modadd(_MIPP_ mr_mip->w2,mr_mip->w2,mr_mip->w7);
    nres_modmult(_MIPP_ mr_mip->w7,mr_mip->w7,mr_mip->w2);
    nres_modadd(_MIPP_ mr_mip->w2,mr_mip->w2,mr_mip->w2);
    nres_modsub(_MIPP_ mr_mip->w3,p->X,mr_mip->w3);
    nres_modmult(_MIPP_ mr_mip->w8,mr_mip->w3,p->Y);
    nres_modsub(_MIPP_ p->Y,mr_mip->w2,p->Y);

/* alternative method
    nres_modadd(_MIPP_ p->Y,p->Y,mr_mip->w2);  

    if (p->marker==MR_EPOINT_NORMALIZED)
        copy(mr_mip->w2,p->Z);

    else nres_modmult(_MIPP_ mr_mip->w2,p->Z,p->Z);

    nres_modmult(_MIPP_ mr_mip->w2,mr_mip->w2,mr_mip->w2); 
    nres_modmult(_MIPP_ p->X,mr_mip->w2,mr_mip->w3);
    nres_modadd(_MIPP_ mr_mip->w3,mr_mip->w3,p->X);
    nres_modmult(_MIPP_ mr_mip->w8,mr_mip->w8,mr_mip->w1);
    nres_modsub(_MIPP_ mr_mip->w1,p->X,p->X);
    nres_modmult(_MIPP_ mr_mip->w2,mr_mip->w2,mr_mip->w2);

    if (remain(_MIPP_ mr_mip->w2,2)!=0)
        mr_padd(_MIPP_ mr_mip->w2,mr_mip->modulus,mr_mip->w2);
    subdiv(_MIPP_ mr_mip->w2,2,mr_mip->w2);

    nres_modsub(_MIPP_ mr_mip->w3,p->X,mr_mip->w3);
    nres_modmult(_MIPP_ mr_mip->w3,mr_mip->w8,mr_mip->w3);
    nres_modsub(_MIPP_ mr_mip->w3,mr_mip->w2,p->Y);
*/

/* 

Observe that when finished w8 contains the line slope, w7 has 2y^2 and w6 has z^2 
This is useful for calculating line functions in pairings  

*/

    p->marker=MR_EPOINT_GENERAL;
    return;
#endif
}
   
static BOOL ecurve_padd(_MIPD_ epoint *p,epoint *pa)
{ /* primitive add two epoints on the active ecurve - pa+=p;   *
   * note that if p is normalized, its Z coordinate isn't used */
 
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
#ifndef MR_AFFINE_ONLY
    if (mr_mip->coord==MR_AFFINE)
    {  /* 1 sqr, 1 mul, 1 div */
#endif
        nres_modsub(_MIPP_ p->Y,pa->Y,mr_mip->w8);
        nres_modsub(_MIPP_ p->X,pa->X,mr_mip->w6);
        if (size(mr_mip->w6)==0) 
        { /* divide by 0 */
            if (size(mr_mip->w8)==0) 
            { /* should have doubled ! */
                return FALSE; 
            }
            else
            { /* point at infinity */
                epoint_set(_MIPP_ NULL,NULL,0,pa);
                return TRUE;
            }
        }
        if (nres_moddiv(_MIPP_ mr_mip->w8,mr_mip->w6,mr_mip->w8)>1)
        {
            epoint_set(_MIPP_ NULL,NULL,0,pa);
            mr_berror(_MIPP_ MR_ERR_COMPOSITE_MODULUS);
            return TRUE;
        }

        nres_modmult(_MIPP_ mr_mip->w8,mr_mip->w8,mr_mip->w2); /* w2=m^2 */
        nres_modsub(_MIPP_ mr_mip->w2,p->X,mr_mip->w1); /* w1=m^2-x1-x2 */
        nres_modsub(_MIPP_ mr_mip->w1,pa->X,mr_mip->w1);
        

        nres_modsub(_MIPP_ pa->X,mr_mip->w1,mr_mip->w2);
        nres_modmult(_MIPP_ mr_mip->w2,mr_mip->w8,mr_mip->w2);
        nres_modsub(_MIPP_ mr_mip->w2,pa->Y,pa->Y);
        copy(mr_mip->w1,pa->X);

        pa->marker=MR_EPOINT_NORMALIZED;
        return TRUE;
#ifndef MR_AFFINE_ONLY
    }

    if (p->marker!=MR_EPOINT_NORMALIZED)    
    {
        nres_modmult(_MIPP_ p->Z,p->Z,mr_mip->w6);
        nres_modmult(_MIPP_ pa->X,mr_mip->w6,mr_mip->w1);
        nres_modmult(_MIPP_ mr_mip->w6,p->Z,mr_mip->w6);
        nres_modmult(_MIPP_ pa->Y,mr_mip->w6,mr_mip->w8);
    }
    else
    {
        copy(pa->X,mr_mip->w1);
        copy(pa->Y,mr_mip->w8);
    }
    if (pa->marker==MR_EPOINT_NORMALIZED)
        copy(mr_mip->one,mr_mip->w6);
    
    else nres_modmult(_MIPP_ pa->Z,pa->Z,mr_mip->w6);
    nres_modmult(_MIPP_ p->X,mr_mip->w6,mr_mip->w4);
    if (pa->marker!=MR_EPOINT_NORMALIZED) 
        nres_modmult(_MIPP_ mr_mip->w6,pa->Z,mr_mip->w6);
    nres_modmult(_MIPP_ p->Y,mr_mip->w6,mr_mip->w5);
    nres_modsub(_MIPP_ mr_mip->w1,mr_mip->w4,mr_mip->w1);
    nres_modsub(_MIPP_ mr_mip->w8,mr_mip->w5,mr_mip->w8);

/* w8 contains the numerator of the slope */

    if (size(mr_mip->w1)==0)
    {
        if (size(mr_mip->w8)==0)
        { /* should have doubled ! */
           return FALSE; 
        }
        else
        { /* point at infinity */
            epoint_set(_MIPP_ NULL,NULL,0,pa);
            return TRUE;
        }
    }
    nres_modadd(_MIPP_ mr_mip->w4,mr_mip->w4,mr_mip->w6);
    nres_modadd(_MIPP_ mr_mip->w1,mr_mip->w6,mr_mip->w4);
    nres_modadd(_MIPP_ mr_mip->w5,mr_mip->w5,mr_mip->w6);
    nres_modadd(_MIPP_ mr_mip->w8,mr_mip->w6,mr_mip->w5);
    
    if (p->marker!=MR_EPOINT_NORMALIZED)
    { 
        if (pa->marker!=MR_EPOINT_NORMALIZED) 
            nres_modmult(_MIPP_ pa->Z,p->Z,mr_mip->w3);
        else
            copy(p->Z,mr_mip->w3);
        nres_modmult(_MIPP_ mr_mip->w3,mr_mip->w1,pa->Z);
    }
    else
    {
        if (pa->marker!=MR_EPOINT_NORMALIZED)
            nres_modmult(_MIPP_ pa->Z,mr_mip->w1,pa->Z);
        else
            copy(mr_mip->w1,pa->Z);
    }
    nres_modmult(_MIPP_ mr_mip->w1,mr_mip->w1,mr_mip->w6);
    nres_modmult(_MIPP_ mr_mip->w1,mr_mip->w6,mr_mip->w1);
    nres_modmult(_MIPP_ mr_mip->w6,mr_mip->w4,mr_mip->w6);
    nres_modmult(_MIPP_ mr_mip->w8,mr_mip->w8,mr_mip->w4);

    nres_modsub(_MIPP_ mr_mip->w4,mr_mip->w6,pa->X);
    nres_modsub(_MIPP_ mr_mip->w6,pa->X,mr_mip->w6);
    nres_modsub(_MIPP_ mr_mip->w6,pa->X,mr_mip->w6);
    nres_modmult(_MIPP_ mr_mip->w8,mr_mip->w6,mr_mip->w2);
    nres_modmult(_MIPP_ mr_mip->w1,mr_mip->w5,mr_mip->w1);
    nres_modsub(_MIPP_ mr_mip->w2,mr_mip->w1,mr_mip->w5);

/* divide by 2 */

    nres_div2(_MIPP_ mr_mip->w5,pa->Y);

    pa->marker=MR_EPOINT_GENERAL;
    return TRUE;      
#endif
}

void epoint_copy(epoint *a,epoint *b)
{   
    if (a==b || b==NULL) return;

    copy(a->X,b->X);
    copy(a->Y,b->Y);
#ifndef MR_AFFINE_ONLY
    if (a->marker==MR_EPOINT_GENERAL) copy(a->Z,b->Z);
#endif
    b->marker=a->marker;
    return;
}

BOOL epoint_comp(_MIPD_ epoint *a,epoint *b)
{
    BOOL result;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return FALSE;
    if (a==b) return TRUE;
    if (a->marker==MR_EPOINT_INFINITY)
    {
        if (b->marker==MR_EPOINT_INFINITY) return TRUE;
        else return FALSE;
    }
    if (b->marker==MR_EPOINT_INFINITY)
        return FALSE;
    
#ifndef MR_AFFINE_ONLY
    if (mr_mip->coord==MR_AFFINE)
    {
#endif
        if (mr_compare(a->X,b->X)==0 && mr_compare(a->Y,b->Y)==0) result=TRUE;
        else result=FALSE;
        return result;
#ifndef MR_AFFINE_ONLY
    }

    if (mr_mip->coord==MR_PROJECTIVE)
    {
        MR_IN(105)
        if (a->marker!=MR_EPOINT_GENERAL) 
            copy(mr_mip->one,mr_mip->w1);
        else copy(a->Z,mr_mip->w1);

        if (b->marker!=MR_EPOINT_GENERAL) 
            copy(mr_mip->one,mr_mip->w2);
        else copy(b->Z,mr_mip->w2);

        nres_modmult(_MIPP_ mr_mip->w1,mr_mip->w1,mr_mip->w3); /* Za*Za */
        nres_modmult(_MIPP_ mr_mip->w2,mr_mip->w2,mr_mip->w4); /* Zb*Zb */

        nres_modmult(_MIPP_ a->X,mr_mip->w4,mr_mip->w5); /* Xa*Zb*Zb */
        nres_modmult(_MIPP_ b->X,mr_mip->w3,mr_mip->w6); /* Xb*Za*Za */

        if (mr_compare(mr_mip->w5,mr_mip->w6)!=0) result=FALSE;
        else
        {
            nres_modmult(_MIPP_ mr_mip->w1,mr_mip->w3,mr_mip->w3);
            nres_modmult(_MIPP_ mr_mip->w2,mr_mip->w4,mr_mip->w4);

            nres_modmult(_MIPP_ a->Y,mr_mip->w4,mr_mip->w5);
            nres_modmult(_MIPP_ b->Y,mr_mip->w3,mr_mip->w6);

            if (mr_compare(mr_mip->w5,mr_mip->w6)!=0) result=FALSE;
            else result=TRUE;
        }
        MR_OUT
        return result;
    }
    return FALSE;
#endif
}

int ecurve_add(_MIPD_ epoint *p,epoint *pa)
{  /* pa=pa+p; */
   /* An ephemeral pointer to the line slope is returned */

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return MR_OVER;

    MR_IN(94)

    if (p==pa) 
    {
        ecurve_double(_MIPP_ pa);
        MR_OUT
        if (pa->marker==MR_EPOINT_INFINITY) return MR_OVER;
        return MR_DOUBLE;
    }
    if (pa->marker==MR_EPOINT_INFINITY)
    {
        epoint_copy(p,pa);
        MR_OUT 
        return MR_ADD;
    }
    if (p->marker==MR_EPOINT_INFINITY) 
    {
        MR_OUT
        return MR_ADD;
    }

    if (!ecurve_padd(_MIPP_ p,pa))
    {    
        ecurve_double(_MIPP_ pa);
        MR_OUT
        return MR_DOUBLE;
    }
    MR_OUT
    if (pa->marker==MR_EPOINT_INFINITY) return MR_OVER;
    return MR_ADD;
}

void epoint_negate(_MIPD_ epoint *p)
{ /* negate a point */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    if (p->marker==MR_EPOINT_INFINITY) return;

    MR_IN(121)
    if (size(p->Y)!=0) mr_psub(_MIPP_ mr_mip->modulus,p->Y,p->Y);
    MR_OUT
}

int ecurve_sub(_MIPD_ epoint *p,epoint *pa)
{
    int r;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return MR_OVER;

    MR_IN(104)

    if (p==pa)
    {
        epoint_set(_MIPP_ NULL,NULL,0,pa);
        MR_OUT
        return MR_OVER;
    } 
    if (p->marker==MR_EPOINT_INFINITY) 
    {
        MR_OUT
        return MR_ADD;
    }

    epoint_negate(_MIPP_ p);
    r=ecurve_add(_MIPP_ p,pa);
    epoint_negate(_MIPP_ p);

    MR_OUT
    return r;
}

int ecurve_mult(_MIPD_ big e,epoint *pa,epoint *pt)
{ /* pt=e*pa; */
    int i,j,n,nb,nbs,nzs,nadds;
    epoint *table[MR_ECC_STORE_N];
#ifndef MR_AFFINE_ONLY
    big work[MR_ECC_STORE_N];
#endif

#ifdef MR_STATIC
    char mem[MR_ECP_RESERVE(MR_ECC_STORE_N)];  
#ifndef MR_AFFINE_ONLY
    char mem1[MR_BIG_RESERVE(MR_ECC_STORE_N)];
#endif
#else
    char *mem;
#ifndef MR_AFFINE_ONLY
    char *mem1;
#endif
#endif

#ifndef MR_ALWAYS_BINARY
    epoint *p;
    int ce,ch;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return 0;

    MR_IN(95)
    if (size(e)==0) 
    { /* multiplied by 0 */
        epoint_set(_MIPP_ NULL,NULL,0,pt);
        MR_OUT
        return 0;
    }
    copy(e,mr_mip->w9);
/*    epoint_norm(_MIPP_ pa); */
    epoint_copy(pa,pt);

    if (size(mr_mip->w9)<0)
    { /* pt = -pt */
        negify(mr_mip->w9,mr_mip->w9);
        epoint_negate(_MIPP_ pt);
    }

    if (size(mr_mip->w9)==1)
    { 
        MR_OUT
        return 0;
    }

    premult(_MIPP_ mr_mip->w9,3,mr_mip->w10);      /* h=3*e */

#ifndef MR_STATIC
#ifndef MR_ALWAYS_BINARY
    if (mr_mip->base==mr_mip->base2)
    {
#endif
#endif

#ifdef  MR_STATIC
        memset(mem,0,MR_ECP_RESERVE(MR_ECC_STORE_N));
#ifndef MR_AFFINE_ONLY
        memset(mem1,0,MR_BIG_RESERVE(MR_ECC_STORE_N));
#endif
#else
        mem=(char *)ecp_memalloc(_MIPP_ MR_ECC_STORE_N);
#ifndef MR_AFFINE_ONLY
        mem1=(char *)memalloc(_MIPP_ MR_ECC_STORE_N);
#endif
#endif

        for (i=0;i<=MR_ECC_STORE_N-1;i++)
        {
            table[i]=epoint_init_mem(_MIPP_ mem,i);
#ifndef MR_AFFINE_ONLY
            work[i]=mirvar_mem(_MIPP_ mem1,i);
#endif
        }

        epoint_copy(pt,table[0]);
        epoint_copy(table[0],table[MR_ECC_STORE_N-1]);
        ecurve_double(_MIPP_ table[MR_ECC_STORE_N-1]);
     /*   epoint_norm(_MIPP_ table[MR_ECC_STORE_N-1]); */

        for (i=1;i<MR_ECC_STORE_N-1;i++)
        { /* precomputation */
            epoint_copy(table[i-1],table[i]);
            ecurve_add(_MIPP_ table[MR_ECC_STORE_N-1],table[i]);
        }
        ecurve_add(_MIPP_ table[MR_ECC_STORE_N-2],table[MR_ECC_STORE_N-1]);

#ifndef MR_AFFINE_ONLY
        epoint_multi_norm(_MIPP_ MR_ECC_STORE_N,work,table);
#endif

        nb=logb2(_MIPP_ mr_mip->w10);
        nadds=0;
        epoint_set(_MIPP_ NULL,NULL,0,pt);
        for (i=nb-1;i>=1;)
        { /* add/subtract */
            if (mr_mip->user!=NULL) (*mr_mip->user)();
            n=mr_naf_window(_MIPP_ mr_mip->w9,mr_mip->w10,i,&nbs,&nzs,MR_ECC_STORE_N);
            for (j=0;j<nbs;j++)
                ecurve_double(_MIPP_ pt);
            if (n>0) {ecurve_add(_MIPP_ table[n/2],pt); nadds++;}
            if (n<0) {ecurve_sub(_MIPP_ table[(-n)/2],pt); nadds++;}
            i-=nbs;
            if (nzs)
            {
                for (j=0;j<nzs;j++) ecurve_double(_MIPP_ pt);
                i-=nzs;
            }
        }

        ecp_memkill(_MIPP_ mem,MR_ECC_STORE_N);
#ifndef MR_AFFINE_ONLY
        memkill(_MIPP_ mem1,MR_ECC_STORE_N);
#endif

#ifndef MR_STATIC
#ifndef MR_ALWAYS_BINARY
    }
    else
    { 
        mem=(char *)ecp_memalloc(_MIPP_ 1);
        p=epoint_init_mem(_MIPP_ mem,0);
        epoint_norm(_MIPP_ pt);
        epoint_copy(pt,p);

        nadds=0;
        expb2(_MIPP_ logb2(_MIPP_ mr_mip->w10)-1,mr_mip->w11);
        mr_psub(_MIPP_ mr_mip->w10,mr_mip->w11,mr_mip->w10);
        subdiv(_MIPP_ mr_mip->w11,2,mr_mip->w11);
        while (size(mr_mip->w11) > 1)
        { /* add/subtract method */
            if (mr_mip->user!=NULL) (*mr_mip->user)();

            ecurve_double(_MIPP_ pt);
            ce=mr_compare(mr_mip->w9,mr_mip->w11); /* e(i)=1? */
            ch=mr_compare(mr_mip->w10,mr_mip->w11); /* h(i)=1? */
            if (ch>=0) 
            {  /* h(i)=1 */
                if (ce<0) {ecurve_add(_MIPP_ p,pt); nadds++;}
                mr_psub(_MIPP_ mr_mip->w10,mr_mip->w11,mr_mip->w10);
            }
            if (ce>=0) 
            {  /* e(i)=1 */
                if (ch<0) {ecurve_sub(_MIPP_ p,pt); nadds++;}
                mr_psub(_MIPP_ mr_mip->w9,mr_mip->w11,mr_mip->w9);  
            }
            subdiv(_MIPP_ mr_mip->w11,2,mr_mip->w11);
        }
        ecp_memkill(_MIPP_ mem,1);
    }
#endif
#endif
    MR_OUT
    return nadds;
}

#ifndef MR_NO_ECC_MULTIADD
#ifndef MR_STATIC

void ecurve_multn(_MIPD_ int n,big *y,epoint **x,epoint *w)
{ /* pt=e[o]*p[0]+e[1]*p[1]+ .... e[n-1]*p[n-1]   */
    int i,j,k,m,nb,ea;
    epoint **G;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(114)

    m=1<<n;
    G=(epoint **)mr_alloc(_MIPP_ m,sizeof(epoint*));

    for (i=0,k=1;i<n;i++)
    {
        for (j=0; j < (1<<i) ;j++)
        {
            G[k]=epoint_init(_MIPPO_ );
            epoint_copy(x[i],G[k]);
            if (j!=0) ecurve_add(_MIPP_ G[j],G[k]);
            k++;
        }
    }

    nb=0;
    for (j=0;j<n;j++) if ((k=logb2(_MIPP_ y[j])) > nb) nb=k;

    epoint_set(_MIPP_ NULL,NULL,0,w);            /* w=0 */
    
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
                if (mr_testbit(_MIPP_ y[j],i)) ea+=k;
                k<<=1;
            }
            ecurve_double(_MIPP_ w);
            if (ea!=0) ecurve_add(_MIPP_ G[ea],w);
        }    
#ifndef MR_ALWAYS_BINARY
    }
    else mr_berror(_MIPP_ MR_ERR_NOT_SUPPORTED);
#endif

    for (i=1;i<m;i++) epoint_free(G[i]);
    mr_free(G);
    MR_OUT
}

#endif

/* PP=P+Q, PM=P-Q. Assumes P and Q are both normalized, and P!=Q */

static BOOL ecurve_add_sub(_MIPD_ epoint *P,epoint *Q,epoint *PP,epoint *PM)
{ 
 #ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    big t1,t2,lam;

    if (mr_mip->ERNUM) return FALSE;

    if (P->marker==MR_EPOINT_GENERAL || Q->marker==MR_EPOINT_GENERAL)
    { 
        mr_berror(_MIPP_ MR_ERR_BAD_PARAMETERS);
        MR_OUT
        return FALSE;
    }

    if (mr_compare(P->X,Q->X)==0)
    { /* P=Q or P=-Q - shouldn't happen */
        epoint_copy(P,PP);
        ecurve_add(_MIPP_ Q,PP);
        epoint_copy(P,PM);
        ecurve_sub(_MIPP_ Q,PM);

        MR_OUT
        return TRUE;
    }

    t1= mr_mip->w10;
    t2= mr_mip->w11; 
    lam = mr_mip->w13;   

    copy(P->X,t2);
    nres_modsub(_MIPP_ t2,Q->X,t2);

    redc(_MIPP_ t2,t2);
    invmodp(_MIPP_ t2,mr_mip->modulus,t2);
    nres(_MIPP_ t2,t2);
    
    nres_modadd(_MIPP_ P->X,Q->X,PP->X);
    copy(PP->X,PM->X);

    copy(P->Y,t1);
    nres_modsub(_MIPP_ t1,Q->Y,t1);
    copy(t1,lam);
    nres_modmult(_MIPP_ lam,t2,lam);
    copy(lam,t1);
    nres_modmult(_MIPP_ t1,t1,t1);
    nres_modsub(_MIPP_ t1,PP->X,PP->X);
    copy(Q->X,PP->Y);
    nres_modsub(_MIPP_ PP->Y,PP->X,PP->Y);
    nres_modmult(_MIPP_ PP->Y,lam,PP->Y);
    nres_modsub(_MIPP_ PP->Y,Q->Y,PP->Y);

    copy(P->Y,t1);
    nres_modadd(_MIPP_ t1,Q->Y,t1);
    copy(t1,lam);
    nres_modmult(_MIPP_ lam,t2,lam);
    copy(lam,t1);
    nres_modmult(_MIPP_ t1,t1,t1);
    nres_modsub(_MIPP_ t1,PM->X,PM->X);
    copy(Q->X,PM->Y);
    nres_modsub(_MIPP_ PM->Y,PM->X,PM->Y);
    nres_modmult(_MIPP_ PM->Y,lam,PM->Y);
    nres_modadd(_MIPP_ PM->Y,Q->Y,PM->Y);

    PP->marker=MR_EPOINT_NORMALIZED;
    PM->marker=MR_EPOINT_NORMALIZED;

    return TRUE;
}

void ecurve_mult2(_MIPD_ big e,epoint *p,big ea,epoint *pa,epoint *pt)
{ /* pt=e*p+ea*pa; */
    int e1,h1,e2,h2,bb;
    epoint *p1,*p2,*ps[2];
#ifdef MR_STATIC
    char mem[MR_ECP_RESERVE(4)];
#else
    char *mem;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    if (mr_mip->ERNUM) return;

    MR_IN(103)

    if (size(e)==0) 
    {
        ecurve_mult(_MIPP_ ea,pa,pt);
        MR_OUT
        return;
    }
#ifdef MR_STATIC
    memset(mem,0,MR_ECP_RESERVE(4));
#else
    mem=(char *)ecp_memalloc(_MIPP_ 4);
#endif
    p2=epoint_init_mem(_MIPP_ mem,0);
    p1=epoint_init_mem(_MIPP_ mem,1);
    ps[0]=epoint_init_mem(_MIPP_ mem,2);
    ps[1]=epoint_init_mem(_MIPP_ mem,3);

    epoint_norm(_MIPP_ pa);
    epoint_copy(pa,p2);
    copy(ea,mr_mip->w9);
    if (size(mr_mip->w9)<0)
    { /* p2 = -p2 */
        negify(mr_mip->w9,mr_mip->w9);
        epoint_negate(_MIPP_ p2);
    }

    epoint_norm(_MIPP_ p);
    epoint_copy(p,p1);
    copy(e,mr_mip->w12);
    if (size(mr_mip->w12)<0)
    { /* p1= -p1 */
        negify(mr_mip->w12,mr_mip->w12);
        epoint_negate(_MIPP_ p1);
    }


    epoint_set(_MIPP_ NULL,NULL,0,pt);            /* pt=0 */
    ecurve_add_sub(_MIPP_ p1,p2,ps[0],ps[1]);     /* only one inversion! ps[0]=p1+p2, ps[1]=p1-p2 */

    mr_jsf(_MIPP_ mr_mip->w9,mr_mip->w12,mr_mip->w10,mr_mip->w9,mr_mip->w13,mr_mip->w12);
  
/*    To use a simple NAF instead, substitute this for the JSF 
        premult(_MIPP_ mr_mip->w9,3,mr_mip->w10);      3*ea  
        premult(_MIPP_ mr_mip->w12,3,mr_mip->w13);     3*e  
*/ 

#ifndef MR_ALWAYS_BINARY
    if (mr_mip->base==mr_mip->base2)
    {
#endif
        if (mr_compare(mr_mip->w10,mr_mip->w13)>=0) bb=logb2(_MIPP_ mr_mip->w10)-1;
        else                                        bb=logb2(_MIPP_ mr_mip->w13)-1;

        while (bb>=0) /* for the simple NAF, this should be 1 */
        {
            if (mr_mip->user!=NULL) (*mr_mip->user)();
            ecurve_double(_MIPP_ pt);

            e1=h1=e2=h2=0;
            if (mr_testbit(_MIPP_ mr_mip->w9,bb)) e2=1;
            if (mr_testbit(_MIPP_ mr_mip->w10,bb)) h2=1;
            if (mr_testbit(_MIPP_ mr_mip->w12,bb)) e1=1;
            if (mr_testbit(_MIPP_ mr_mip->w13,bb)) h1=1;

            if (e1!=h1)
            {
                if (e2==h2)
                {
                    if (h1==1) ecurve_add(_MIPP_ p1,pt);
                    else       ecurve_sub(_MIPP_ p1,pt);
                }
                else
                {
                    if (h1==1)
                    {
                        if (h2==1) ecurve_add(_MIPP_ ps[0],pt);
                        else       ecurve_add(_MIPP_ ps[1],pt);
                    }
                    else
                    {
                        if (h2==1) ecurve_sub(_MIPP_ ps[1],pt);
                        else       ecurve_sub(_MIPP_ ps[0],pt);
                    }
                }
            }
            else if (e2!=h2)
            {
                if (h2==1) ecurve_add(_MIPP_ p2,pt);
                else       ecurve_sub(_MIPP_ p2,pt);
            }
            bb-=1;
        }
#ifndef MR_ALWAYS_BINARY
    }
    else
    {
         if (mr_compare(mr_mip->w10,mr_mip->w13)>=0)
              expb2(_MIPP_ logb2(_MIPP_ mr_mip->w10)-1,mr_mip->w11);
         else expb2(_MIPP_ logb2(_MIPP_ mr_mip->w13)-1,mr_mip->w11);

        while (size(mr_mip->w11) > 0)    /* for the NAF, this should be 1 */
        { /* add/subtract method */
            if (mr_mip->user!=NULL) (*mr_mip->user)();

            ecurve_double(_MIPP_ pt);

            e1=h1=e2=h2=0;
            if (mr_compare(mr_mip->w9,mr_mip->w11)>=0)
            { /* e1(i)=1? */
                e2=1;  
                mr_psub(_MIPP_ mr_mip->w9,mr_mip->w11,mr_mip->w9);
            }
            if (mr_compare(mr_mip->w10,mr_mip->w11)>=0)
            { /* h1(i)=1? */
                h2=1;  
                mr_psub(_MIPP_ mr_mip->w10,mr_mip->w11,mr_mip->w10);
            } 
            if (mr_compare(mr_mip->w12,mr_mip->w11)>=0)
            { /* e2(i)=1? */
                e1=1;   
                mr_psub(_MIPP_ mr_mip->w12,mr_mip->w11,mr_mip->w12);
            }
            if (mr_compare(mr_mip->w13,mr_mip->w11)>=0) 
            { /* h2(i)=1? */
                h1=1;  
                mr_psub(_MIPP_ mr_mip->w13,mr_mip->w11,mr_mip->w13);
            }

            if (e1!=h1)
            {
                if (e2==h2)
                {
                    if (h1==1) ecurve_add(_MIPP_ p1,pt);
                    else       ecurve_sub(_MIPP_ p1,pt);
                }
                else
                {
                    if (h1==1)
                    {
                        if (h2==1) ecurve_add(_MIPP_ ps[0],pt);
                        else       ecurve_add(_MIPP_ ps[1],pt);
                    }
                    else
                    {
                        if (h2==1) ecurve_sub(_MIPP_ ps[1],pt);
                        else       ecurve_sub(_MIPP_ ps[0],pt);
                    }
                }
            }
            else if (e2!=h2)
            {
                if (h2==1) ecurve_add(_MIPP_ p2,pt);
                else       ecurve_sub(_MIPP_ p2,pt);
            }

            subdiv(_MIPP_ mr_mip->w11,2,mr_mip->w11);
        }
    }
#endif
    ecp_memkill(_MIPP_ mem,4);
    MR_OUT
}

#endif

#else

/*   Twisted Inverted Edwards curves 

 *   Assumes Twisted Inverted Edward's equation x^2+Ay^2 = x^2.y^2 + B
 *   Assumes points are not of order 2 or 4
*/

static void epoint_getrhs(_MIPD_ big x,big y)
{ 
  /* find RHS=(x^2-B)/(x^2-A) */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
 
    nres_modmult(_MIPP_ x,x,mr_mip->w6);
    nres_modsub(_MIPP_ mr_mip->w6,mr_mip->B,y);  
    nres_modsub(_MIPP_ mr_mip->w6,mr_mip->A,mr_mip->w6);

    nres_moddiv(_MIPP_ y,mr_mip->w6,y);
}

#ifndef MR_NOSUPPORT_COMPRESSION

BOOL epoint_x(_MIPD_ big x)
{ /* test if x is associated with a point on the   *
   * currently active curve                        */
    int j;

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return FALSE;

    MR_IN(147)
    
    if (x==NULL) return FALSE;

    nres(_MIPP_ x,mr_mip->w2);
    epoint_getrhs(_MIPP_ mr_mip->w2,mr_mip->w7);

    if (size(mr_mip->w7)==0)
    {
        MR_OUT
        return TRUE;
    }

    redc(_MIPP_ mr_mip->w7,mr_mip->w4);
    j=jack(_MIPP_ mr_mip->w4,mr_mip->modulus);

    MR_OUT
    if (j==1) return TRUE;
    return FALSE;
}

#endif

BOOL epoint_set(_MIPD_ big x,big y,int cb,epoint *p)
{ /* initialise a point on active ecurve            *
   * if x or y == NULL, set to point at infinity    *
   * if x==y, a y co-ordinate is calculated - if    *
   * possible - and cb suggests LSB 0/1  of y       *
   * (which "decompresses" y). Otherwise, check     *
   * validity of given (x,y) point, ignoring cb.    *
   * Returns TRUE for valid point, otherwise FALSE. */
  
    BOOL valid;

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return FALSE;

    MR_IN(97)

    if (x==NULL || y==NULL)
    {
        copy(mr_mip->one,p->X);
        zero(p->Y); 
        p->marker=MR_EPOINT_INFINITY;
        MR_OUT
        return TRUE;
    }

    valid=FALSE;
	nres(_MIPP_ x,p->X);
	if (x!=y)
	{ /* Check directly that x^2+Ay^2 == x^2.y^2+B */
		nres(_MIPP_ y,p->Y);
		nres_modmult(_MIPP_ p->X,p->X,mr_mip->w1);
		nres_modmult(_MIPP_ p->Y,p->Y,mr_mip->w2);
		nres_modmult(_MIPP_ mr_mip->w1,mr_mip->w2,mr_mip->w3);
		nres_modadd(_MIPP_ mr_mip->w3,mr_mip->B,mr_mip->w3);


		if (mr_abs(mr_mip->Asize)==MR_TOOBIG)
			nres_modmult(_MIPP_ mr_mip->w2,mr_mip->A,mr_mip->w2);
		else
			nres_premult(_MIPP_ mr_mip->w2,mr_mip->Asize,mr_mip->w2);   
		nres_modadd(_MIPP_ mr_mip->w2,mr_mip->w1,mr_mip->w2);
		if (mr_compare(mr_mip->w2,mr_mip->w3)==0) valid=TRUE;
	}
	else
	{ /* find RHS */
		epoint_getrhs(_MIPP_ p->X,mr_mip->w7);
     /* no y supplied - calculate one. Find square root */
#ifndef MR_NOSUPPORT_COMPRESSION
        valid=nres_sqroot(_MIPP_ mr_mip->w7,p->Y);
    /* check LSB - have we got the right root? */
        redc(_MIPP_ p->Y,mr_mip->w1);
        if (remain(_MIPP_ mr_mip->w1,2)!=cb) 
            mr_psub(_MIPP_ mr_mip->modulus,p->Y,p->Y);

#else
		mr_berror(_MIPP_ MR_ERR_NOT_SUPPORTED);
		MR_OUT
		return FALSE;
#endif
    } 
    if (valid)
    {
        p->marker=MR_EPOINT_NORMALIZED;
        MR_OUT
        return TRUE;
    }

    MR_OUT
    return FALSE;
}

#ifndef MR_STATIC

void epoint_getxyz(_MIPD_ epoint *p,big x,big y,big z)
{ /* get (x,y,z) coordinates */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    MR_IN(143)
    convert(_MIPP_ 1,mr_mip->w1);
    if (p->marker==MR_EPOINT_INFINITY)
    {
        if (x!=NULL) copy(mr_mip->w1,x);
        if (y!=NULL) zero(y);
        if (z!=NULL) zero(z);
        MR_OUT
        return;
    }
    if (x!=NULL) redc(_MIPP_ p->X,x);
    if (y!=NULL) redc(_MIPP_ p->Y,y);
    if (z!=NULL) redc(_MIPP_ p->Z,z);

    MR_OUT
    return;
}

#endif

int epoint_get(_MIPD_ epoint* p,big x,big y)
{ /* Get point co-ordinates in affine, normal form       *
   * (converted from projective, Montgomery form)        *
   * if x==y, supplies x only. Return value is Least     *
   * Significant Bit of y (useful for point compression) */

    int lsb;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    if (p->marker==MR_EPOINT_INFINITY)
    {
        zero(y);
        convert(_MIPP_ 1,x);
        return 0;
    }
    if (mr_mip->ERNUM) return 0;

    MR_IN(98)

    if (!epoint_norm(_MIPP_ p)) 
    { /* not possible ! */
        MR_OUT
        return (-1);
    }

    redc(_MIPP_ p->X,x);
    redc(_MIPP_ p->Y,mr_mip->w1);

    if (x!=y) copy(mr_mip->w1,y);
    lsb=remain(_MIPP_ mr_mip->w1,2); 
    MR_OUT
    return lsb;
}

BOOL epoint_norm(_MIPD_ epoint *p)
{ /* normalise a point */
    
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    if (p->marker!=MR_EPOINT_GENERAL) return TRUE;

    if (mr_mip->ERNUM) return FALSE;

    MR_IN(117)

    copy(mr_mip->one,mr_mip->w8);

    if (nres_moddiv(_MIPP_ mr_mip->w8,p->Z,mr_mip->w8)>1) /* 1/Z  */
    {
        epoint_set(_MIPP_ NULL,NULL,0,p);
        mr_berror(_MIPP_ MR_ERR_COMPOSITE_MODULUS); 
        MR_OUT
        return FALSE;
    }
    
    nres_modmult(_MIPP_ p->X,mr_mip->w8,p->X);            /* X/Z */
    nres_modmult(_MIPP_ p->Y,mr_mip->w8,p->Y);            /* Y/Z */

    copy(mr_mip->one,p->Z);
   
    p->marker=MR_EPOINT_NORMALIZED;
    MR_OUT

    return TRUE;
}

void ecurve_double(_MIPD_ epoint *p)
{ /* double epoint on active ecurve */

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    if (p->marker==MR_EPOINT_INFINITY) 
    { /* 2 times infinity == infinity ! */
        return;
    }
    nres_modadd(_MIPP_ p->X,p->Y,mr_mip->w1);

    nres_modmult(_MIPP_ p->X,p->X,p->X);                 /* A=X1^2        */
    nres_modmult(_MIPP_ p->Y,p->Y,p->Y);                 /* B=Y1^2        */
    nres_modmult(_MIPP_ mr_mip->w1,mr_mip->w1,mr_mip->w1);          /* (X+Y)^2       */
    nres_modsub(_MIPP_ mr_mip->w1,p->X,mr_mip->w1);
    nres_modsub(_MIPP_ mr_mip->w1,p->Y,mr_mip->w1);           /* E=(X+Y)^2-A-B   */

    if (mr_abs(mr_mip->Asize)==MR_TOOBIG)                      /* U = aB        */
        nres_modmult(_MIPP_ p->Y,mr_mip->A,p->Y);
    else
        nres_premult(_MIPP_ p->Y,mr_mip->Asize,p->Y);   

    if (p->marker!=MR_EPOINT_NORMALIZED)
        nres_modmult(_MIPP_ p->Z,p->Z,p->Z);
    else
        copy(mr_mip->one,p->Z);

    nres_modadd(_MIPP_ p->Z,p->Z,p->Z);
    if (mr_abs(mr_mip->Bsize)==MR_TOOBIG)                           /* 2dZ^2 */
        nres_modmult(_MIPP_ p->Z,mr_mip->B,p->Z);
    else
        nres_premult(_MIPP_ p->Z,mr_mip->Bsize,p->Z);  
  
    nres_modadd(_MIPP_ p->X,p->Y,mr_mip->w2);           /* C=A+U         */
    nres_modsub(_MIPP_ p->X,p->Y,mr_mip->w3);           /* D=A-U         */

    nres_modmult(_MIPP_ mr_mip->w2,mr_mip->w3,p->X);                /* X=C.D */

    nres_modsub(_MIPP_ mr_mip->w2,p->Z,mr_mip->w2);           /* C-2dZ^2 */
    nres_modmult(_MIPP_ mr_mip->w2,mr_mip->w1,p->Y);                /* Y=E.(C-2dZ^2) */
    nres_modmult(_MIPP_ mr_mip->w3,mr_mip->w1,p->Z);                /* Z=D.E */

    p->marker=MR_EPOINT_GENERAL;
    return;
}
   
static BOOL ecurve_padd(_MIPD_ epoint *p,epoint *pa)
{ /* primitive add two epoints on the active ecurve - pa+=p;   *
   * note that if p is normalized, its Z coordinate isn't used */
 
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    if (p->marker==MR_EPOINT_INFINITY) return TRUE;
    if (pa->marker==MR_EPOINT_INFINITY)
    {
        epoint_copy(p,pa);
        return TRUE;
    }

    nres_modadd(_MIPP_ p->X,p->Y,mr_mip->w1);
    nres_modadd(_MIPP_ pa->X,pa->Y,mr_mip->w2);
    nres_modmult(_MIPP_ mr_mip->w1,mr_mip->w2,mr_mip->w1);  /* I=(X1+Y1)(X2+Y2) */
    if (p->marker!=MR_EPOINT_NORMALIZED) 
    {
        if (pa->marker==MR_EPOINT_NORMALIZED)
            copy(p->Z,pa->Z);
        else nres_modmult(_MIPP_ p->Z,pa->Z,pa->Z);    /* z = A = Z1*Z2 */
    }
    else
    {
        if (pa->marker==MR_EPOINT_NORMALIZED) copy(mr_mip->one,pa->Z);
    }

    nres_modmult(_MIPP_ pa->Z,pa->Z,mr_mip->w2);       /* w2 = B = dA^2   */
    if (mr_abs(mr_mip->Bsize)==MR_TOOBIG)                   
        nres_modmult(_MIPP_ mr_mip->w2,mr_mip->B,mr_mip->w2);
    else
        nres_premult(_MIPP_ mr_mip->w2,mr_mip->Bsize,mr_mip->w2);
    nres_modmult(_MIPP_ p->X,pa->X,pa->X);             /* x = C = X1*X2 */
    nres_modmult(_MIPP_ p->Y,pa->Y,pa->Y);             /* y = D = Y1*Y2 */
    nres_modmult(_MIPP_ pa->X,pa->Y,mr_mip->w3);       /* w3 = E = C*D     */

    nres_modsub(_MIPP_ mr_mip->w1,pa->X,mr_mip->w1);
    nres_modsub(_MIPP_ mr_mip->w1,pa->Y,mr_mip->w1);   /* I=(X1+Y1)(X2+Y2)-C-D =X1*Y2+Y1*X2 */

    if (mr_abs(mr_mip->Asize)==MR_TOOBIG)                   /*   */
        nres_modmult(_MIPP_ pa->Y,mr_mip->A,pa->Y);
    else
        nres_premult(_MIPP_ pa->Y,mr_mip->Asize,pa->Y);
    nres_modsub(_MIPP_ pa->X,pa->Y,pa->X);   /* X = H = C-aD */

    nres_modmult(_MIPP_ pa->Z,pa->X,pa->Z);
    nres_modmult(_MIPP_ pa->Z,mr_mip->w1,pa->Z);

    nres_modsub(_MIPP_ mr_mip->w3,mr_mip->w2,pa->Y);
    nres_modmult(_MIPP_ pa->Y,mr_mip->w1,pa->Y);

    nres_modadd(_MIPP_ mr_mip->w3,mr_mip->w2,mr_mip->w3);
    nres_modmult(_MIPP_ pa->X,mr_mip->w3,pa->X);

    if (size(pa->Z)==0)
    {
        copy(mr_mip->one,pa->X);
        zero(pa->Y);
        pa->marker=MR_EPOINT_INFINITY;
    }
    else pa->marker=MR_EPOINT_GENERAL;

    return TRUE;      
}

void epoint_copy(epoint *a,epoint *b)
{   
    if (a==b || b==NULL) return;

    copy(a->X,b->X);
    copy(a->Y,b->Y);
    copy(a->Z,b->Z);

    b->marker=a->marker;
    return;
}

BOOL epoint_comp(_MIPD_ epoint *a,epoint *b)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return FALSE;
    if (a==b) return TRUE;
    if (a->marker==MR_EPOINT_INFINITY)
    {
        if (b->marker==MR_EPOINT_INFINITY) return TRUE;
        else return FALSE;
    }
    if (b->marker==MR_EPOINT_INFINITY)
        return FALSE;
    
    MR_IN(105)
    copy(a->Z,mr_mip->w1);
    copy(b->Z,mr_mip->w2);

    nres_modmult(_MIPP_ a->X,b->Z,mr_mip->w1);
    nres_modmult(_MIPP_ b->X,a->Z,mr_mip->w2);

    if (mr_compare(mr_mip->w1,mr_mip->w2)!=0) 
    {
        MR_OUT
        return FALSE;
    }

    nres_modmult(_MIPP_ a->Y,b->Z,mr_mip->w1);
    nres_modmult(_MIPP_ b->Y,a->Z,mr_mip->w2);

    if (mr_compare(mr_mip->w1,mr_mip->w2)!=0) 
    {
        MR_OUT
        return FALSE;
    }
    MR_OUT
    return TRUE;
 
}

int ecurve_add(_MIPD_ epoint *p,epoint *pa)
{  /* pa=pa+p; */

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return MR_OVER;

    MR_IN(94)

    if (p==pa) 
    {
        ecurve_double(_MIPP_ pa);
        MR_OUT
        if (pa->marker==MR_EPOINT_INFINITY) return MR_OVER;
        return MR_DOUBLE;
    }
    if (pa->marker==MR_EPOINT_INFINITY)
    {
        epoint_copy(p,pa);
        MR_OUT 
        return MR_ADD;
    }
    if (p->marker==MR_EPOINT_INFINITY) 
    {
        MR_OUT
        return MR_ADD;
    }

    if (!ecurve_padd(_MIPP_ p,pa))
    {    
        ecurve_double(_MIPP_ pa);
        MR_OUT
        return MR_DOUBLE;
    }
    MR_OUT
    if (pa->marker==MR_EPOINT_INFINITY) return MR_OVER;
    return MR_ADD;
}

void epoint_negate(_MIPD_ epoint *p)
{ /* negate a point */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    if (p->marker==MR_EPOINT_INFINITY) return;

    MR_IN(121)
    if (size(p->X)!=0) mr_psub(_MIPP_ mr_mip->modulus,p->X,p->X);
    MR_OUT
}

int ecurve_sub(_MIPD_ epoint *p,epoint *pa)
{
    int r;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return MR_OVER;

    MR_IN(104)

    if (p==pa)
    {
        epoint_set(_MIPP_ NULL,NULL,0,pa);
        MR_OUT
        return MR_OVER;
    } 
    if (p->marker==MR_EPOINT_INFINITY) 
    {
        MR_OUT
        return MR_ADD;
    }

    epoint_negate(_MIPP_ p);
    r=ecurve_add(_MIPP_ p,pa);
    epoint_negate(_MIPP_ p);

    MR_OUT
    return r;
}

int ecurve_mult(_MIPD_ big e,epoint *pa,epoint *pt)
{ /* pt=e*pa; */
    int i,j,n,nb,nbs,nzs,nadds;
    epoint *table[MR_ECC_STORE_N];

#ifdef MR_STATIC
    char mem[MR_ECP_RESERVE(MR_ECC_STORE_N)];  
#else
    char *mem;
#endif

#ifndef MR_ALWAYS_BINARY
    epoint *p;
    int ce,ch;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return 0;

    MR_IN(95)
    if (size(e)==0) 
    { /* multiplied by 0 */
        epoint_set(_MIPP_ NULL,NULL,0,pt);
        MR_OUT
        return 0;
    }
    copy(e,mr_mip->w9);
    epoint_copy(pa,pt);

    if (size(mr_mip->w9)<0)
    { /* pt = -pt */
        negify(mr_mip->w9,mr_mip->w9);
        epoint_negate(_MIPP_ pt);
    }

    if (size(mr_mip->w9)==1)
    { 
        MR_OUT
        return 0;
    }

    premult(_MIPP_ mr_mip->w9,3,mr_mip->w10);      /* h=3*e */

#ifndef MR_STATIC
#ifndef MR_ALWAYS_BINARY
    if (mr_mip->base==mr_mip->base2)
    {
#endif
#endif

#ifdef  MR_STATIC
        memset(mem,0,MR_ECP_RESERVE(MR_ECC_STORE_N));
#else
        mem=(char *)ecp_memalloc(_MIPP_ MR_ECC_STORE_N);
#endif

        for (i=0;i<=MR_ECC_STORE_N-1;i++)
            table[i]=epoint_init_mem(_MIPP_ mem,i);

        epoint_copy(pt,table[0]);
        epoint_copy(table[0],table[MR_ECC_STORE_N-1]);
        ecurve_double(_MIPP_ table[MR_ECC_STORE_N-1]);

        for (i=1;i<MR_ECC_STORE_N-1;i++)
        { /* precomputation */
            epoint_copy(table[i-1],table[i]);
            ecurve_add(_MIPP_ table[MR_ECC_STORE_N-1],table[i]);
        }
        ecurve_add(_MIPP_ table[MR_ECC_STORE_N-2],table[MR_ECC_STORE_N-1]);

        nb=logb2(_MIPP_ mr_mip->w10);
        nadds=0;
        epoint_set(_MIPP_ NULL,NULL,0,pt);
        for (i=nb-1;i>=1;)
        { /* add/subtract */
            if (mr_mip->user!=NULL) (*mr_mip->user)();
            n=mr_naf_window(_MIPP_ mr_mip->w9,mr_mip->w10,i,&nbs,&nzs,MR_ECC_STORE_N);
            for (j=0;j<nbs;j++)
                ecurve_double(_MIPP_ pt);
            if (n>0) {ecurve_add(_MIPP_ table[n/2],pt); nadds++;}
            if (n<0) {ecurve_sub(_MIPP_ table[(-n)/2],pt); nadds++;}
            i-=nbs;
            if (nzs)
            {
                for (j=0;j<nzs;j++) ecurve_double(_MIPP_ pt);
                i-=nzs;
            }
        }

        ecp_memkill(_MIPP_ mem,MR_ECC_STORE_N);


#ifndef MR_STATIC
#ifndef MR_ALWAYS_BINARY
    }
    else
    { 
        mem=ecp_memalloc(_MIPP_ 1);
        p=epoint_init_mem(_MIPP_ mem,0);
        epoint_copy(pt,p);

        nadds=0;
        expb2(_MIPP_ logb2(_MIPP_ mr_mip->w10)-1,mr_mip->w11);
        mr_psub(_MIPP_ mr_mip->w10,mr_mip->w11,mr_mip->w10);
        subdiv(_MIPP_ mr_mip->w11,2,mr_mip->w11);
        while (size(mr_mip->w11) > 1)
        { /* add/subtract method */
            if (mr_mip->user!=NULL) (*mr_mip->user)();

            ecurve_double(_MIPP_ pt);
            ce=mr_compare(mr_mip->w9,mr_mip->w11); /* e(i)=1? */
            ch=mr_compare(mr_mip->w10,mr_mip->w11); /* h(i)=1? */
            if (ch>=0) 
            {  /* h(i)=1 */
                if (ce<0) {ecurve_add(_MIPP_ p,pt); nadds++;}
                mr_psub(_MIPP_ mr_mip->w10,mr_mip->w11,mr_mip->w10);
            }
            if (ce>=0) 
            {  /* e(i)=1 */
                if (ch<0) {ecurve_sub(_MIPP_ p,pt); nadds++;}
                mr_psub(_MIPP_ mr_mip->w9,mr_mip->w11,mr_mip->w9);  
            }
            subdiv(_MIPP_ mr_mip->w11,2,mr_mip->w11);
        }
        ecp_memkill(_MIPP_ mem,1);
    }
#endif
#endif
    MR_OUT
    return nadds;
}

#ifndef MR_NO_ECC_MULTIADD
#ifndef MR_STATIC

void ecurve_multn(_MIPD_ int n,big *y,epoint **x,epoint *w)
{ /* pt=e[0]*p[0]+e[1]*p[1]+ .... e[n-1]*p[n-1]   */
    int i,j,k,m,nb,ea;
    epoint **G;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(114)

    m=1<<n;
    G=(epoint **)mr_alloc(_MIPP_ m,sizeof(epoint*));

    for (i=0,k=1;i<n;i++)
    {
        for (j=0; j < (1<<i) ;j++)
        {
            G[k]=epoint_init(_MIPPO_ );
            epoint_copy(x[i],G[k]);
            if (j!=0) ecurve_add(_MIPP_ G[j],G[k]);
            k++;
        }
    }

    nb=0;
    for (j=0;j<n;j++) if ((k=logb2(_MIPP_ y[j])) > nb) nb=k;

    epoint_set(_MIPP_ NULL,NULL,0,w);            /* w=0 */
    
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
                if (mr_testbit(_MIPP_ y[j],i)) ea+=k;
                k<<=1;
            }
            ecurve_double(_MIPP_ w);
            if (ea!=0) ecurve_add(_MIPP_ G[ea],w);
        }    
#ifndef MR_ALWAYS_BINARY
    }
    else mr_berror(_MIPP_ MR_ERR_NOT_SUPPORTED);
#endif

    for (i=1;i<m;i++) epoint_free(G[i]);
    mr_free(G);
    MR_OUT
}

#endif

/* PP=P+Q, PM=P-Q. */

static BOOL ecurve_add_sub(_MIPD_ epoint *P,epoint *Q,epoint *PP,epoint *PM)
{ 
 #ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
   
    if (P->marker==MR_EPOINT_NORMALIZED)
    {
        if (Q->marker==MR_EPOINT_NORMALIZED)
            copy(mr_mip->one,mr_mip->w1);
        else copy(Q->Z,mr_mip->w1);
    }
    else 
    {
        if (Q->marker==MR_EPOINT_NORMALIZED)
            copy(P->Z,mr_mip->w1);
        else nres_modmult(_MIPP_ P->Z,Q->Z,mr_mip->w1);         /* w1 = A = Z1*Z2 */
    }
    nres_modmult(_MIPP_ mr_mip->w1,mr_mip->w1,mr_mip->w2);      /* w2 = B = dA^2   */
    if (mr_abs(mr_mip->Bsize)==MR_TOOBIG)                   
        nres_modmult(_MIPP_ mr_mip->w2,mr_mip->B,mr_mip->w2);
    else
        nres_premult(_MIPP_ mr_mip->w2,mr_mip->Bsize,mr_mip->w2);
    nres_modmult(_MIPP_ P->X,Q->X,mr_mip->w3);              /* w3 = C = X1*X2 */
    nres_modmult(_MIPP_ P->Y,Q->Y,mr_mip->w4);              /* w4 = D = Y1*Y2 */
    nres_modmult(_MIPP_ mr_mip->w3,mr_mip->w4,mr_mip->w5);  /* w5 = E = C*D     */
    nres_modmult(_MIPP_ P->X,Q->Y,mr_mip->w7);              /* w7 = F = X1.Y2 */
    nres_modmult(_MIPP_ Q->X,P->Y,mr_mip->w8);              /* w8 = G = X2.Y1 */

    if (mr_abs(mr_mip->Asize)==MR_TOOBIG)                   /* w4 = aD */
        nres_modmult(_MIPP_ mr_mip->w4,mr_mip->A,mr_mip->w4);
    else
        nres_premult(_MIPP_ mr_mip->w4,mr_mip->Asize,mr_mip->w4);

/* P+Q */

    nres_modsub(_MIPP_ mr_mip->w3,mr_mip->w4,mr_mip->w6);   /* w6 = H = C-aD */
    nres_modadd(_MIPP_ mr_mip->w7,mr_mip->w8,PP->Z);        /* X1*Y2+X2*Y1   */
    nres_modadd(_MIPP_ mr_mip->w5,mr_mip->w2,PP->X);
    nres_modmult(_MIPP_ PP->X,mr_mip->w6,PP->X);
    nres_modsub(_MIPP_ mr_mip->w5,mr_mip->w2,PP->Y);
    nres_modmult(_MIPP_ PP->Y,PP->Z,PP->Y);
    nres_modmult(_MIPP_ PP->Z,mr_mip->w6,PP->Z);
    nres_modmult(_MIPP_ PP->Z,mr_mip->w1,PP->Z);

    if (size(PP->Z)==0)
    {
        copy(mr_mip->one,PP->X);
        zero(PP->Y);
        PP->marker=MR_EPOINT_INFINITY;
    }
    else PP->marker=MR_EPOINT_GENERAL;

/* P-Q */

    nres_modadd(_MIPP_ mr_mip->w3,mr_mip->w4,mr_mip->w6);  /* w6 = C+aD */
    nres_modsub(_MIPP_ mr_mip->w8,mr_mip->w7,PM->Z);       /* X2*Y1-X1*Y2 */
    nres_modsub(_MIPP_ mr_mip->w5,mr_mip->w2,PM->X);
    nres_modmult(_MIPP_ PM->X,mr_mip->w6,PM->X);
    nres_modadd(_MIPP_ mr_mip->w5,mr_mip->w2,PM->Y);
    nres_modmult(_MIPP_ PM->Y,PM->Z,PM->Y);
    nres_modmult(_MIPP_ PM->Z,mr_mip->w6,PM->Z);
    nres_modmult(_MIPP_ PM->Z,mr_mip->w1,PM->Z);

    if (size(PM->Z)==0)
    {
        copy(mr_mip->one,PM->X);
        zero(PM->Y);
        PM->marker=MR_EPOINT_INFINITY;
    }
    else PM->marker=MR_EPOINT_GENERAL;

    return TRUE;
}

void ecurve_mult2(_MIPD_ big e,epoint *p,big ea,epoint *pa,epoint *pt)
{ /* pt=e*p+ea*pa; */
    int e1,h1,e2,h2,bb;
    epoint *p1,*p2,*ps[2];
#ifdef MR_STATIC
    char mem[MR_ECP_RESERVE(4)];
#else
    char *mem;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    if (mr_mip->ERNUM) return;

    MR_IN(103)

    if (size(e)==0) 
    {
        ecurve_mult(_MIPP_ ea,pa,pt);
        MR_OUT
        return;
    }
#ifdef MR_STATIC
    memset(mem,0,MR_ECP_RESERVE(4));
#else
    mem=ecp_memalloc(_MIPP_ 4);
#endif
    p2=epoint_init_mem(_MIPP_ mem,0);
    p1=epoint_init_mem(_MIPP_ mem,1);
    ps[0]=epoint_init_mem(_MIPP_ mem,2);
    ps[1]=epoint_init_mem(_MIPP_ mem,3);

    epoint_copy(pa,p2);
    copy(ea,mr_mip->w9);
    if (size(mr_mip->w9)<0)
    { /* p2 = -p2 */
        negify(mr_mip->w9,mr_mip->w9);
        epoint_negate(_MIPP_ p2);
    }

    epoint_copy(p,p1);
    copy(e,mr_mip->w12);
    if (size(mr_mip->w12)<0)
    { /* p1= -p1 */
        negify(mr_mip->w12,mr_mip->w12);
        epoint_negate(_MIPP_ p1);
    }

    epoint_set(_MIPP_ NULL,NULL,0,pt);            /* pt=0 */ 
    ecurve_add_sub(_MIPP_ p1,p2,ps[0],ps[1]);     /* ps[0]=p1+p2, ps[1]=p1-p2 */

    mr_jsf(_MIPP_ mr_mip->w9,mr_mip->w12,mr_mip->w10,mr_mip->w9,mr_mip->w13,mr_mip->w12);
  
/*    To use a simple NAF instead, substitute this for the JSF 
        premult(_MIPP_ mr_mip->w9,3,mr_mip->w10);      3*ea  
        premult(_MIPP_ mr_mip->w12,3,mr_mip->w13);     3*e  
*/ 

#ifndef MR_ALWAYS_BINARY
    if (mr_mip->base==mr_mip->base2)
    {
#endif
        if (mr_compare(mr_mip->w10,mr_mip->w13)>=0) bb=logb2(_MIPP_ mr_mip->w10)-1;
        else                                        bb=logb2(_MIPP_ mr_mip->w13)-1;

        while (bb>=0) /* for the simple NAF, this should be 1 */
        {
            if (mr_mip->user!=NULL) (*mr_mip->user)();
            ecurve_double(_MIPP_ pt);

            e1=h1=e2=h2=0;
            if (mr_testbit(_MIPP_ mr_mip->w9,bb)) e2=1;
            if (mr_testbit(_MIPP_ mr_mip->w10,bb)) h2=1;
            if (mr_testbit(_MIPP_ mr_mip->w12,bb)) e1=1;
            if (mr_testbit(_MIPP_ mr_mip->w13,bb)) h1=1;

            if (e1!=h1)
            {
                if (e2==h2)
                {
                    if (h1==1) ecurve_add(_MIPP_ p1,pt);
                    else       ecurve_sub(_MIPP_ p1,pt);
                }
                else
                {
                    if (h1==1)
                    {
                        if (h2==1) ecurve_add(_MIPP_ ps[0],pt);
                        else       ecurve_add(_MIPP_ ps[1],pt);
                    }
                    else
                    {
                        if (h2==1) ecurve_sub(_MIPP_ ps[1],pt);
                        else       ecurve_sub(_MIPP_ ps[0],pt);
                    }
                }
            }
            else if (e2!=h2)
            {
                if (h2==1) ecurve_add(_MIPP_ p2,pt);
                else       ecurve_sub(_MIPP_ p2,pt);
            }
            bb-=1;
        }
#ifndef MR_ALWAYS_BINARY
    }
    else
    {
         if (mr_compare(mr_mip->w10,mr_mip->w13)>=0)
              expb2(_MIPP_ logb2(_MIPP_ mr_mip->w10)-1,mr_mip->w11);
         else expb2(_MIPP_ logb2(_MIPP_ mr_mip->w13)-1,mr_mip->w11);

        while (size(mr_mip->w11) > 0)    /* for the NAF, this should be 1 */
        { /* add/subtract method */
            if (mr_mip->user!=NULL) (*mr_mip->user)();

            ecurve_double(_MIPP_ pt);

            e1=h1=e2=h2=0;
            if (mr_compare(mr_mip->w9,mr_mip->w11)>=0)
            { /* e1(i)=1? */
                e2=1;  
                mr_psub(_MIPP_ mr_mip->w9,mr_mip->w11,mr_mip->w9);
            }
            if (mr_compare(mr_mip->w10,mr_mip->w11)>=0)
            { /* h1(i)=1? */
                h2=1;  
                mr_psub(_MIPP_ mr_mip->w10,mr_mip->w11,mr_mip->w10);
            } 
            if (mr_compare(mr_mip->w12,mr_mip->w11)>=0)
            { /* e2(i)=1? */
                e1=1;   
                mr_psub(_MIPP_ mr_mip->w12,mr_mip->w11,mr_mip->w12);
            }
            if (mr_compare(mr_mip->w13,mr_mip->w11)>=0) 
            { /* h2(i)=1? */
                h1=1;  
                mr_psub(_MIPP_ mr_mip->w13,mr_mip->w11,mr_mip->w13);
            }

            if (e1!=h1)
            {
                if (e2==h2)
                {
                    if (h1==1) ecurve_add(_MIPP_ p1,pt);
                    else       ecurve_sub(_MIPP_ p1,pt);
                }
                else
                {
                    if (h1==1)
                    {
                        if (h2==1) ecurve_add(_MIPP_ ps[0],pt);
                        else       ecurve_add(_MIPP_ ps[1],pt);
                    }
                    else
                    {
                        if (h2==1) ecurve_sub(_MIPP_ ps[1],pt);
                        else       ecurve_sub(_MIPP_ ps[0],pt);
                    }
                }
            }
            else if (e2!=h2)
            {
                if (h2==1) ecurve_add(_MIPP_ p2,pt);
                else       ecurve_sub(_MIPP_ p2,pt);
            }

            subdiv(_MIPP_ mr_mip->w11,2,mr_mip->w11);
        }
    }
#endif
    ecp_memkill(_MIPP_ mem,4);
    MR_OUT
}

#endif

#endif
