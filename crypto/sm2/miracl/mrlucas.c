
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
 *   MIRACL methods for evaluating lucas V function
 *   mrlucas.c (Postl's algorithm)
 */

#include <stdlib.h>
#include "miracl.h"

void nres_lucas(_MIPD_ big p,big r,big vp,big v)
{
    int i,nb;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(107)

    if (size(r)==0) 
    {
        zero(vp);
        convert(_MIPP_ 2,v);
        nres(_MIPP_ v,v);
        MR_OUT
        return;
    }
    if (size(r)==1 || size(r)==(-1))
    { /* note - sign of r doesn't matter */
        convert(_MIPP_ 2,vp);
        nres(_MIPP_ vp,vp);
        copy(p,v);
        MR_OUT
        return;
    }

    copy(p,mr_mip->w3);
    
    convert(_MIPP_ 2,mr_mip->w4);
    nres(_MIPP_ mr_mip->w4,mr_mip->w4);     /* w4=2 */

    copy(mr_mip->w4,mr_mip->w8);
    copy(mr_mip->w3,mr_mip->w9);

    copy(r,mr_mip->w1);
    insign(PLUS,mr_mip->w1);         
    decr(_MIPP_ mr_mip->w1,1,mr_mip->w1);

#ifndef MR_ALWAYS_BINARY
    if (mr_mip->base==mr_mip->base2)
    {
#endif
        nb=logb2(_MIPP_ mr_mip->w1);
        for (i=nb-1;i>=0;i--)
        {
            if (mr_mip->user!=NULL) (*mr_mip->user)();

            if (mr_testbit(_MIPP_ mr_mip->w1,i))
            {
                nres_modmult(_MIPP_ mr_mip->w8,mr_mip->w9,mr_mip->w8);
                nres_modsub(_MIPP_ mr_mip->w8,mr_mip->w3,mr_mip->w8);
                nres_modmult(_MIPP_ mr_mip->w9,mr_mip->w9,mr_mip->w9);
                nres_modsub(_MIPP_ mr_mip->w9,mr_mip->w4,mr_mip->w9);

            }
            else
            {
                nres_modmult(_MIPP_ mr_mip->w9,mr_mip->w8,mr_mip->w9);
                nres_modsub(_MIPP_ mr_mip->w9,mr_mip->w3,mr_mip->w9);
                nres_modmult(_MIPP_ mr_mip->w8,mr_mip->w8,mr_mip->w8);
                nres_modsub(_MIPP_ mr_mip->w8,mr_mip->w4,mr_mip->w8);
            }  
        }

#ifndef MR_ALWAYS_BINARY
    }
    else
    {
        expb2(_MIPP_ logb2(_MIPP_ mr_mip->w1)-1,mr_mip->w2);                                                                                                   

        while (!mr_mip->ERNUM && size(mr_mip->w2)!=0)
        { /* use binary method */
            if (mr_compare(mr_mip->w1,mr_mip->w2)>=0)
            { /* vp=v*vp-p, v=v*v-2 */ 
                nres_modmult(_MIPP_ mr_mip->w8,mr_mip->w9,mr_mip->w8);
                nres_modsub(_MIPP_ mr_mip->w8,mr_mip->w3,mr_mip->w8);
                nres_modmult(_MIPP_ mr_mip->w9,mr_mip->w9,mr_mip->w9);
                nres_modsub(_MIPP_ mr_mip->w9,mr_mip->w4,mr_mip->w9);
                subtract(_MIPP_ mr_mip->w1,mr_mip->w2,mr_mip->w1);
            }
            else
            { /* v=v*vp-p, vp=vp*vp-2 */
                nres_modmult(_MIPP_ mr_mip->w9,mr_mip->w8,mr_mip->w9);
                nres_modsub(_MIPP_ mr_mip->w9,mr_mip->w3,mr_mip->w9);
                nres_modmult(_MIPP_ mr_mip->w8,mr_mip->w8,mr_mip->w8);
                nres_modsub(_MIPP_ mr_mip->w8,mr_mip->w4,mr_mip->w8);
            }
            subdiv(_MIPP_ mr_mip->w2,2,mr_mip->w2);
        }
    }
#endif

    copy(mr_mip->w9,v);
    if (v!=vp) copy(mr_mip->w8,vp);
    MR_OUT

}

void lucas(_MIPD_ big p,big r,big n,big vp,big v)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(108)
    prepare_monty(_MIPP_ n);
    nres(_MIPP_ p,mr_mip->w3);
    nres_lucas(_MIPP_ mr_mip->w3,r,mr_mip->w8,mr_mip->w9);
    redc(_MIPP_ mr_mip->w9,v);
    if (v!=vp) redc(_MIPP_ mr_mip->w8,vp);
    MR_OUT
}

