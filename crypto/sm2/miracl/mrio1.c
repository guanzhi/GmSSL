
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
 *   MIRACL I/O routines 1. 
 *   mrio1.c
 */

#include <openssl/miracl.h>

#ifndef MR_SIMPLE_IO

int instr(_MIPD_ flash x,char *string)
{  /*  input a big number       *
    *  returns length in digits */
    int i,ipt,n,s,e,pads;
	BOOL first_after_pad;
    int ch,lc;
#ifdef MR_FLASH
    BOOL frac;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return 0;

    MR_IN(76)

    if (mr_mip->apbase==0 || mr_mip->apbase>256)
    {
        mr_berror(_MIPP_ MR_ERR_BASE_TOO_BIG);
        MR_OUT
        return 0;
    }

    if (!mr_mip->active)
    {
        mr_berror(_MIPP_ MR_ERR_NO_MIRSYS);
        MR_OUT
        return 0;
    }

    zero(x);
    if (mr_mip->fin) string=mr_mip->IOBUFF;
    if (mr_mip->INPLEN==0)
    { /* inputting ASCII bytes */

#ifndef MR_NO_FILE_IO

        if (mr_mip->fin)
        { /* read in characters */
            i=0;
            do
            {
                ch=fgetc(mr_mip->infile);
                if (ch==EOF) break;
                string[i++]=ch;

                if (i>=mr_mip->IOBSIZ)
                {
                    mr_berror(_MIPP_ MR_ERR_IO_OVERFLOW);
                    MR_OUT
                    return 0;
                }
            } while (ch!='\n' && ch!='\0'); 
            string[i]='\0';
        }

#endif
        forever
        { /*  get input length  */
            ch=(unsigned char)string[mr_mip->INPLEN];
            if (ch=='\0') break;
            if (mr_mip->apbase<=60 && ch=='\n') break;
            mr_mip->INPLEN++;
            if (string==mr_mip->IOBUFF && mr_mip->INPLEN>=mr_mip->IOBSIZ)
            {
                mr_berror(_MIPP_ MR_ERR_IO_OVERFLOW);
                MR_OUT
                return 0;
            }
        }
    }
    else
    { /* inputting BINARY bytes */
        if (string==mr_mip->IOBUFF && mr_mip->INPLEN>=mr_mip->IOBSIZ)
        {
            mr_berror(_MIPP_ MR_ERR_IO_OVERFLOW);
            MR_OUT
            return 0;
        }

#ifndef MR_NO_FILE_IO

        if (mr_mip->fin) for(i=0;i<mr_mip->INPLEN;i++) 
        {
            if ((ch=fgetc(mr_mip->infile))==EOF)
            {
                mr_mip->INPLEN=i;
                break;
            }
            string[i]=MR_TOBYTE(ch);
        }

#endif

    }
    n=0;
    s=PLUS;
    e=0;
#ifdef MR_FLASH
    frac=FALSE;
#endif
    if (mr_mip->INPLEN>0 && mr_mip->apbase<=60)
    { /* skip leading blanks and check sign */
#ifdef MR_FLASH
        if (string[mr_mip->INPLEN-1]=='/') mr_mip->INPLEN--;
#endif
        while (string[e]==' ') e++;
        if (string[e]=='-')
        { /* check sign */
             s=MINUS;
             e++;
        }
        if (string[e]=='+') e++;
    }

	pads=0; first_after_pad=TRUE;
    for (i=mr_mip->INPLEN-1;i>=e;i--)
    {
        ch=(unsigned char)string[i];
        if (mr_mip->apbase<=60 || mr_mip->apbase==64)
        { /* check for slash or dot and convert character to number */
#ifdef MR_FLASH
            if (mr_mip->apbase<=60 && !frac)
            {
                if (ch=='/')
                {
                    frac=TRUE;
                    copy(x,mr_mip->w0);
                    zero(x);    
                    n=0;
                    continue;
                }
                if (ch=='.')
                {
                    frac=TRUE;
                    zero(mr_mip->w0);
                    putdig(_MIPP_ 1,mr_mip->w0,n+1);
                    continue;
                }
            }
#endif
            ch+=80;
            if (mr_mip->apbase==64)
            { /* base64 */
                if (ch<=112) continue; /* ignore white space */
                if (ch>144 && ch<171) ch-=145;
                if (ch>176 && ch<203) ch-=151;
                if (ch>127 && ch<138) ch-=76;
                if (ch==123) ch=62;
                if (ch==127) ch=63;
                if (ch==141) {pads++; continue;} /* pads '=' */
            }
            else
            {
                if (ch>127 && ch<138) ch-=128;
                if (ch>144 && ch<171) ch-=135;
                if (mr_mip->apbase<=16)
                {
                    if (ch>176 && ch<203) ch-=167;
                }
                else
                {
                    if (ch>176 && ch<203) ch-=141;
                }
            }
        }
         
        if ((mr_small)ch>=mr_mip->apbase || pads>2)
        {
            mr_berror(_MIPP_ MR_ERR_BAD_FORMAT);
            MR_OUT
            return 0;
        }
       
		if (pads && first_after_pad)
		{ /* there was padding, so adjust */
			lc=ch>>(2*pads);
			first_after_pad=FALSE;
			continue;
		}

		n++;
		if (pads)
		{
			putdig(_MIPP_ 0x3f&((ch<<(6-2*pads))|lc),x,n);
			lc=(ch>>(2*pads));
			continue;
		}
		
        putdig(_MIPP_ ch,x,n);
    }

	if (pads && lc>0)
		putdig(_MIPP_ lc,x,++n);
	
    ipt=mr_mip->INPLEN;
    mr_mip->INPLEN=0;
    insign(s,x);
    mr_lzero(x);
#ifdef MR_FLASH
    mr_lzero(mr_mip->w0);
    if (frac) fpack(_MIPP_ x,mr_mip->w0,x);
#endif
    MR_OUT
    return ipt;
}

int otstr(_MIPD_ flash x,char *string)
{  /*  output a big number  */
    int s,i,n,ch,rp,nd,m;
    BOOL check;
#ifdef MR_FLASH
    int nw,dw;
#endif
    mr_lentype lx;
    BOOL done;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return 0;

    MR_IN(75)
    if (mr_mip->apbase==0 || mr_mip->apbase>256)
    {
        mr_berror(_MIPP_ MR_ERR_BASE_TOO_BIG);
        MR_OUT
        return 0;
    }

    if (!mr_mip->active)
    {
        mr_berror(_MIPP_ MR_ERR_NO_MIRSYS);
        MR_OUT
        return 0;
    }
    n=0;
    s=exsign(x);
    insign(PLUS,x);
    lx = x->len;
    if (lx==0 && mr_mip->apbase<=60)
    {

#ifndef MR_NO_FILE_IO

        if (!mr_mip->fout)
        {
            string[0]='0';
            string[1]='\0';
        }
        else
        {
            fputc('0',mr_mip->otfile);
            fputc('\n',mr_mip->otfile);
        }
#else
        string[0]='0';
        string[1]='\0';

#endif
        MR_OUT
        return 1;
    }
    rp=0;
    if (s==MINUS && mr_mip->apbase<=60)
    {
#ifndef MR_NO_FILE_IO
        if (!mr_mip->fout) string[n]='-';
        else fputc('-',mr_mip->otfile);
#else
        string[n]='-';
#endif
        n++;
    }
#ifdef MR_FLASH
    done=FALSE;
    numer(_MIPP_ x,mr_mip->w6);
    if (mr_mip->RPOINT)
    { /* output with radix point */
        denom(_MIPP_ x,mr_mip->w5);
        if (size(mr_mip->w5)>1)
        { /* multiply up numerator to get full precision in *
           * the output. Remember position of radix point.  */
            nw=(int)(lx&MR_MSK);
            dw=(int)((lx>>MR_BTS)&MR_MSK);
            if (nw==0) nw++;
            check=mr_mip->check;
            mr_mip->check=OFF;
            if (nw>dw) mr_shift(_MIPP_ mr_mip->w5,nw-dw,mr_mip->w5);
            if (dw>nw) mr_shift(_MIPP_ mr_mip->w6,dw-nw,mr_mip->w6);
            nd=mr_mip->nib;
            if (mr_compare(mr_mip->w6,mr_mip->w5)>=0) nd--;
            copy(mr_mip->w6,mr_mip->w0);
            if (((int)mr_mip->w0->len+nd)>2*mr_mip->nib) nd=2*mr_mip->nib-(int)mr_mip->w0->len;
            mr_shift(_MIPP_ mr_mip->w0,nd,mr_mip->w0);
            divide(_MIPP_ mr_mip->w0,mr_mip->w5,mr_mip->w6);
            mr_mip->check=check;
            rp=mr_mip->pack*(nd+dw-nw);
        }
    }
#else
    copy(x,mr_mip->w6);
    done=TRUE;
#endif

    forever
    {
        nd=numdig(_MIPP_ mr_mip->w6);
        m=nd;
		if (mr_mip->apbase==64)
		{ /* add leading zeros to base64 */
			while (m%4!=0) m++;
		}
        if (rp>m) m=rp;
        for (i=m;i>0;i--)
        { 
            if (!mr_mip->fout && string==mr_mip->IOBUFF && n>=mr_mip->IOBSIZ-5)
            {
                mr_berror(_MIPP_ MR_ERR_IO_OVERFLOW);
                MR_OUT
                return n;
            }
#ifdef MR_FLASH
            if (i==rp && mr_mip->apbase<=60)
            {
#ifndef MR_NO_FILE_IO
                if (!mr_mip->fout) string[n]='.';
                else fputc('.',mr_mip->otfile);
#else
                string[n]='.';
#endif
                n++;
            }
#endif
            if (i>nd && mr_mip->apbase!=64) ch='0';
            else
            {
                ch=getdig(_MIPP_ mr_mip->w6,i);
                check=mr_mip->check;
                mr_mip->check=OFF;
                putdig(_MIPP_ 0,mr_mip->w6,i);
              /*  mr_mip->check=mr_mip->check; Nasty stupid bug! */
				mr_mip->check=check;
                if (mr_mip->apbase<=60)
                { /* convert number to character */
                    ch+=48;
                    if (ch>=58) ch+=7;
                    if (ch>=91) ch+=6;
                }
                if (mr_mip->apbase==64)
                {
                    if (ch<26) ch+=65;
                    if (ch>=26 && ch<52) ch+=71;
                    if (ch>=52 && ch<62) ch-=4;
                    if (ch==62) ch='+';
                    if (ch==63) ch='/';
                }
            }
            if (i<rp && mr_mip->apbase<=60 && ch=='0' && size(mr_mip->w6)==0) break;
#ifndef MR_NO_FILE_IO
            if (!mr_mip->fout) string[n]=MR_TOBYTE(ch);
            else fputc(MR_TOBYTE(ch),mr_mip->otfile);
#else
            string[n]=MR_TOBYTE(ch); 
#endif
            n++;
        }
        if (done) break;
#ifdef MR_FLASH
        if (mr_mip->RPOINT) break;
        denom(_MIPP_ x,mr_mip->w6);
        if (size(mr_mip->w6)==1) break;
        if (mr_mip->apbase<=60)
        {
#ifndef MR_NO_FILE_IO
            if (!mr_mip->fout) string[n]='/';
            else fputc('/',mr_mip->otfile);
#else
            string[n]='/';
#endif
            n++;
        }
        done=TRUE;
#endif
    }
/*
    if (mr_mip->apbase==64)
    {  
        while (n%3!=0) 
        {
#ifndef MR_NO_FILE_IO
            if (!mr_mip->fout) string[n]='=';
            else fputc('=',mr_mip->otfile);
#else
            string[n]='=';
#endif
            n++;
        }

    }
*/
/* Append a trailing 0 - it may be printable ascii text */    

#ifndef MR_NO_FILE_IO
    if (!mr_mip->fout) string[n]='\0';
    else if (mr_mip->apbase<=60 || mr_mip->apbase==64) fputc('\n',mr_mip->otfile);
#else
    string[n]='\0';
#endif
    insign(s,x);
    MR_OUT
    return n;
}

#ifndef MR_NO_FILE_IO

int innum(_MIPD_ flash x,FILE *filep)
{ /* convert from string to flash x */
    int n;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return 0;

    MR_IN(1)

    mr_mip->infile=filep;
    mr_mip->fin=TRUE;
    n=instr(_MIPP_ x,NULL);
    mr_mip->fin=FALSE;

    MR_OUT
    return n;
}

int otnum(_MIPD_ flash x,FILE *filep)
{ /* convert flash to string */
    int n;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return 0;

    MR_IN(2)

    mr_mip->otfile=filep;
    mr_mip->fout=TRUE;
    n=otstr(_MIPP_ x,NULL);
    mr_mip->fout=FALSE;

    MR_OUT
    return n;
}

#endif

#else

#ifndef MR_FLASH
#ifndef MR_NO_STANDARD_IO
#ifndef MR_FP

int otnum(_MIPD_ flash x,FILE *filep)
{ /* support crude hex output only */
    int i,j,ch,n;
    BOOL leading=TRUE;
    mr_small w;
    n=0;
    if (size(x)<0) fputc('-',filep);
    for (i=(x->len&MR_OBITS)-1;i>=0;i--)
    {
        w=x->w[i];
        for (j=MIRACL-4;j>=0;j-=4)
        {
            ch=48+((w>>j)&0xF);
            if (ch==48 && leading) continue;
            leading=FALSE;
            if (ch>=58) ch+=7;
            fputc(MR_TOBYTE(ch),filep);
            n++;
        }
    }
    fputc('\n',filep);
    return n;
}

#endif
#endif
#endif

#endif
