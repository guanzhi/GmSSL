
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
 *   mrzzn2b.c
 */

#include <stdlib.h> 
#include <openssl/miracl.h>

BOOL zzn2_qr(_MIPD_ zzn2 *u)
{
    int j;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    if (mr_mip->ERNUM) return FALSE;
    if (zzn2_iszero(u)) return TRUE;
    if (size(u->b)==0) return TRUE;

    if (mr_mip->qnr==-1 && size(u->a)==0) return TRUE;
    

    MR_IN(203)  

    nres_modmult(_MIPP_ u->b,u->b,mr_mip->w1);
    if (mr_mip->qnr==-2) nres_modadd(_MIPP_ mr_mip->w1,mr_mip->w1,mr_mip->w1);
    nres_modmult(_MIPP_ u->a,u->a,mr_mip->w2);
    nres_modadd(_MIPP_ mr_mip->w1,mr_mip->w2,mr_mip->w1);
    redc(_MIPP_ mr_mip->w1,mr_mip->w1); 
    j=jack(_MIPP_ mr_mip->w1,mr_mip->modulus);

    MR_OUT
    if (j==1) return TRUE; 
    return FALSE; 
}

BOOL zzn2_sqrt(_MIPD_ zzn2 *u,zzn2 *w)
{ /* sqrt(a+ib) = sqrt(a+sqrt(a*a-n*b*b)/2)+ib/(2*sqrt(a+sqrt(a*a-n*b*b)/2))
     where i*i=n */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return FALSE;

    zzn2_copy(u,w);
    if (zzn2_iszero(w)) return TRUE;

    MR_IN(204)  

    if (size(w->b)==0)
    {
        if (!nres_sqroot(_MIPP_ w->a,mr_mip->w15))
        {
            nres_negate(_MIPP_ w->a,w->b);
            zero(w->a);
            if (mr_mip->qnr==-2) nres_div2(_MIPP_ w->b,w->b); 
            nres_sqroot(_MIPP_ w->b,w->b);    
        }
        else
            copy(mr_mip->w15,w->a);

        MR_OUT
        return TRUE;
    }

    if (mr_mip->qnr==-1 && size(w->a)==0)
    {
        nres_div2(_MIPP_ w->b,w->b);
        if (nres_sqroot(_MIPP_ w->b,mr_mip->w15))
        {
            copy(mr_mip->w15,w->b);
            copy(w->b,w->a);
        }
        else
        {
            nres_negate(_MIPP_ w->b,w->b);
            nres_sqroot(_MIPP_ w->b,w->b);
            nres_negate(_MIPP_ w->b,w->a);
        }

        MR_OUT
        return TRUE;
    }

    nres_modmult(_MIPP_ w->b,w->b,mr_mip->w7);
    if (mr_mip->qnr==-2) nres_modadd(_MIPP_ mr_mip->w7,mr_mip->w7,mr_mip->w7);
    nres_modmult(_MIPP_ w->a,w->a,mr_mip->w1);
    nres_modadd(_MIPP_ mr_mip->w7,mr_mip->w1,mr_mip->w7);

    if (!nres_sqroot(_MIPP_ mr_mip->w7,mr_mip->w7)) /* s=w7 */
    {
        zzn2_zero(w);
        MR_OUT
        return FALSE;
    }

    nres_modadd(_MIPP_ w->a,mr_mip->w7,mr_mip->w15);
    nres_div2(_MIPP_ mr_mip->w15,mr_mip->w15);

    if (!nres_sqroot(_MIPP_ mr_mip->w15,mr_mip->w15))
    {

        nres_modsub(_MIPP_ w->a,mr_mip->w7,mr_mip->w15);
        nres_div2(_MIPP_ mr_mip->w15,mr_mip->w15);
        if (!nres_sqroot(_MIPP_ mr_mip->w15,mr_mip->w15))
        {
            zzn2_zero(w);
            MR_OUT
            return FALSE;
        }
    }

    copy(mr_mip->w15,w->a);
    nres_modadd(_MIPP_ mr_mip->w15,mr_mip->w15,mr_mip->w15);
    nres_moddiv(_MIPP_ w->b,mr_mip->w15,w->b);

    MR_OUT
    return TRUE;
}

/* y=1/x, z=1/w 

BOOL zzn2_double_inverse(_MIPD_ zzn2 *x,zzn2 *y,zzn2 *w,zzn2 *z)
{
    zzn2 t1,t2;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    MR_IN(214)

    t1.a=mr_mip->w8;
    t1.b=mr_mip->w9;  
    t2.a=mr_mip->w10;
    t2.b=mr_mip->w11;

    zzn2_mul(_MIPP_ x,w,&t1);
    if (zzn2_iszero(_MIPP_ &t1))
    {
        mr_berror(_MIPP_ MR_ERR_DIV_BY_ZERO);
        MR_OUT
        return FALSE;
    }
    zzn2_inv(_MIPP_ &t1);
    
    zzn2_mul(_MIPP_ &w,&t1,&t2);
    zzn2_mul(_MIPP_ &x,&t1,&z);
    zzn2_copy(&t2,&y);

    MR_OUT
    return TRUE;

}
*/

