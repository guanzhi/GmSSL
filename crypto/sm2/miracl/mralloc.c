
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
 *   MIRACL memory allocation routines 
 *   mralloc.c
 *
 *   MIRACL C Memory allocation/deallocation
 *   Can be replaced with special user-defined routines
 *   Default is to standard system routines
 *
 *   NOTE: uses calloc() which initialises memory to Zero, so make sure
 *   any substituted routine does the same!
 */

#include "miracl.h"
#include <stdlib.h>

#ifndef MR_STATIC

miracl *mr_first_alloc()
{
    return (miracl *)calloc(1,sizeof(miracl));
}

void *mr_alloc(_MIPD_ int num,int size)
{
    char *p; 
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    if (mr_mip==NULL) 
    {
        p=(char *)calloc(num,size);
        return (void *)p;
    }
 
    if (mr_mip->ERNUM) return NULL;

    p=(char *)calloc(num,size);
    if (p==NULL) mr_berror(_MIPP_ MR_ERR_OUT_OF_MEMORY);
    return (void *)p;

}

void mr_free(void *addr)
{
    if (addr==NULL) return;
    free(addr);
    return;
}

#endif
