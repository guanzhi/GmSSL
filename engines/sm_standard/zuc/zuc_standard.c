/* ====================================================================
 * Copyright (c) 2015 - 2016 The GmSSL Project.  All rights reserved.
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

#include "zuc_standard.h"
#include "zuc.h"

/************************************************************
Function:     add_mod
Description:  calculate a+b mod 2^31-1
Calls:
Called By:    lfsr_with_init_mode
Input:        a,b: uint32_t(32bit)
Output:
Return:       c, c=a+b mod 2^31-1
Others:
************************************************************/
uint32_t add_mod(uint32_t a, uint32_t b)
{
    uint32_t c = a + b;
    if (c >> 31)
    {
        c = (c & 0x7fffffff) + 1;
    }
    return c;
}


/************************************************************
Function:     pow_mod
Description:  calculate x*2^k mod 2^31-1
Calls:        Called By: lfsr_with_init_mode
Input:        x: input
              k: exponential
Output:
Return:       x*2^k mod 2^31-1
Others:
************************************************************/
uint32_t pow_mod(uint32_t x, uint32_t k)
{
    return (((x << k) | (x >> (31 - k))) & 0x7fffffff);
}


/************************************************************
Function:     l1
Description:  linear transformation l1
Calls:
Called By:    f
Input:        X: input
Output:
Return:       X^(X<<< 2)^(X<<<10)^(X<<<18)^(X<<<24)
Others:
************************************************************/
uint32_t l1(uint32_t X)
{
    return X ^ ZUC_ROTL32(X, 2) ^ ZUC_ROTL32(X, 10) ^ ZUC_ROTL32(X, 18) ^ ZUC_ROTL32(X, 24);
}


/************************************************************
Function:     l2
Description:  linear transformation l2
Calls:
Called By:    f
Input:        X: input
Output:
Return:       X^(X<<< 8)^(X<<<14)^(X<<<22)^(X<<<30)
Others:
************************************************************/
uint32_t l2(uint32_t X)
{
    return X ^ ZUC_ROTL32(X, 8) ^ ZUC_ROTL32(X, 14) ^ ZUC_ROTL32(X, 22) ^ ZUC_ROTL32(X, 30);
}


/************************************************************
Function:     bit_value
Description:  test if the value of M at the position i equals 0
Calls:
Called By:    zuc_integrity
Input:        M: message
              i: the position i
Output:
Return:       0:the value of M at the position i equals 0
              1:the value of M at the position i equals 1
Others:
************************************************************/
unsigned char bit_value(uint32_t M[], uint32_t i)
{
    int j, k;
    j = i >> 5;
    k = i & 0x1f;
    if (M[j] & (0x1 << (31 - k)))
        return 1;
    else
        return 0;
}


/************************************************************
Function:     get_word
Description:  get a 32bit word ki from bit strings k[i],k[i+1]...,namely
ki=k[i]||k[i+1]||…||k[i+31]
Calls:
Called By:    zuc_integrity
Input:        k[]:
              i: the position i
Output:
Return:       ki=k[i]||k[i+1]||…||k[i+31]
Others:
************************************************************/
uint32_t get_word(uint32_t k[], uint32_t i)             
{
    int j, m;
    uint32_t word;
    j = i >> 5;
    m = i & 0x1f;
    if (m == 0)
        word = k[j];
    else
        word = (k[j] << m) | (k[j + 1] >> (32 - m));
    return word;
}


/************************************************************
Function:     lfsr_with_init_mode
Description:  Initialisation mode,refresh the current state of LFSR
Calls:        add_mod,pow_mod
Called By:    zuc_standard_init
Input:        LFSR_S:current state of LFSR
              u:u=W>>1
Output:       Null
Return:       Null
Others:
************************************************************/
void lfsr_with_init_mode(uint32_t LFSR_S[], uint32_t u)
{
    uint32_t v = LFSR_S[0], i;
    v = add_mod(v, pow_mod(LFSR_S[15], 15));
    v = add_mod(v, pow_mod(LFSR_S[13], 17));
    v = add_mod(v, pow_mod(LFSR_S[10], 21));
    v = add_mod(v, pow_mod(LFSR_S[4] , 20));
    v = add_mod(v, pow_mod(LFSR_S[0] , 8));

    for (i = 0; i < 15; i++)
    {
        LFSR_S[i] = LFSR_S[i + 1];
    }
    LFSR_S[15] = add_mod(v, u);

    if (!LFSR_S[15])
    {
        LFSR_S[15] = 0x7fffffff;
    }
};


/************************************************************
Function:     lfsr_with_work_mode
Description:  working mode,refresh the current state of LFSR
Calls:        add_mod,pow_mod
Called By:    zuc_standard_work
Input:        LFSR_S:current state of LFSR
Output:       Null
Return:       Null
Others:
************************************************************/
void lfsr_with_work_mode(uint32_t LFSR_S[])
{
    uint32_t v = LFSR_S[0], i;
    v = add_mod(v, pow_mod(LFSR_S[15], 15));
    v = add_mod(v, pow_mod(LFSR_S[13], 17));
    v = add_mod(v, pow_mod(LFSR_S[10], 21));
    v = add_mod(v, pow_mod(LFSR_S[4] , 20));
    v = add_mod(v, pow_mod(LFSR_S[0] , 8));

    for (i = 0; i < 15; i++)
    {
        LFSR_S[i] = LFSR_S[i + 1];
    }
    LFSR_S[15] = v;

    if (!LFSR_S[15])
    {
        LFSR_S[15] = 0x7fffffff;
    }
};


/************************************************************
Function:     br
Description:  Bit Reconstruction
Calls:
Called By:    zuc_standard_init,zuc_standard_work
Input:        LFSR_S:current state of LFSR
Output:       BR_X[]:achieve X0,X1,X2,X3
Return:       Null
Others:
************************************************************/
void br(uint32_t LFSR_S[], uint32_t BR_X[])
{
    BR_X[0] = ((LFSR_S[15] & 0x7fff8000) << 1) | (LFSR_S[14] & 0x0000ffff);
    BR_X[1] = ((LFSR_S[11] & 0x0000ffff) << 16) | ((LFSR_S[9] & 0x7fff8000) >> 15);
    BR_X[2] = ((LFSR_S[7] & 0x0000ffff) << 16) | ((LFSR_S[5] & 0x7fff8000) >> 15);
    BR_X[3] = ((LFSR_S[2] & 0x0000ffff) << 16) | ((LFSR_S[0] & 0x7fff8000) >> 15);
}


/************************************************************
Function:     f
Description:  nonlinear function
Calls:
Called By:    zuc_standard_init,zuc_standard_work
Input:        BR_X[]:words X0,X1,X2,X3 from br
              F_R[]:F_R[0]=R1,F_R[1]=R2
Output:
Return:       W
Others:
************************************************************/
uint32_t f(uint32_t BR_X[], uint32_t F_R[])
{
    uint32_t W, W1, W2;

    W = (BR_X[0] ^ F_R[0]) + F_R[1];
    W1 = F_R[0] + BR_X[1];
    W2 = F_R[1] ^ BR_X[2];
    F_R[0] = l1((W1 << 16) | (W2 >> 16));
    F_R[0] = (ZUC_S0[(F_R[0] >> 24) & 0xFF]) << 24
             | (ZUC_S1[(F_R[0] >> 16) & 0xFF]) << 16
             | (ZUC_S0[(F_R[0] >> 8)  & 0xFF]) << 8
             | (ZUC_S1[F_R[0] & 0xFF]);
    F_R[1] = l2((W2 << 16) | (W1 >> 16));
    F_R[1] = (ZUC_S0[(F_R[1] >> 24) & 0xFF]) << 24
             | (ZUC_S1[(F_R[1] >> 16) & 0xFF]) << 16
             | (ZUC_S0[(F_R[1] >> 8)  & 0xFF]) << 8
             | (ZUC_S1[F_R[1] & 0xFF]);

    return W;
};

/************************************************************
Function:     zuc_standard_init
Description:  Initialisation process of ZUC
Calls:        ZUC_LINK_TO_S,br,f,lfsr_with_init_mode
Called By:    zuc_genkeystream
Input:        k:initial key
              iv:initial vector
Output:       LFSR_S[]:the state of LFSR after initialisation:s0,s1,s2,..s15
              BR_X[] : the current value:X0,X1,X2,X3
              F_R[]:the current value:R1,R2,F_R[0]=R1,F_R[1]=R2
Return:       Null
Others:
************************************************************/
void zuc_standard_init(unsigned char k[], unsigned char iv[], uint32_t LFSR_S[], uint32_t
              BR_X[], uint32_t F_R[])
{
    unsigned char count = 32;
    int i;

    //loading key to the LFSR s0,s1,s2....s15
    printf("\ninitial state of LFSR: S[0]-S[15]\n");
    for (i = 0; i < 16; i++)
    {
        LFSR_S[i] = ZUC_LINK_TO_S(k[i], ZUC_D[i], iv[i]);
        printf("%08x  ", LFSR_S[i]);
    }

    F_R[0] = 0x00;  //R1
    F_R[1] = 0x00;  //R2

    while (count)         //32 times
    {
        uint32_t W;
        br( LFSR_S, BR_X); //BitReconstruction
        W = f(BR_X, F_R);  //nonlinear function
        lfsr_with_init_mode(LFSR_S, W >> 1);
        count--;
    }
}

/************************************************************
Function:     zuc_standard_work
Description:  working stage of ZUC
Calls:        br,f,lfsr_with_work_mode
Called By:    zuc_genkeystream
Input:        LFSR_S[]:the state of LFSR after initialisation:s0,s1,s2,..s15
              BR_X[] : X0,X1,X2,X3
              F_R[]:R1,R2
Output:       pKeyStream[]:key stream
              KeyStreamLen:the length of KeyStream,exporting 32bit for a beat
Return:       Null
Others:
************************************************************/
void zuc_standard_work(uint32_t LFSR_S[], uint32_t BR_X[], uint32_t F_R[], uint32_t
              pKeyStream[], int KeyStreamLen)
{
    int i = 0;
    br(LFSR_S, BR_X);
    f(BR_X, F_R);
    lfsr_with_work_mode(LFSR_S);

    while (i < KeyStreamLen)
    {
        br( LFSR_S, BR_X);
        pKeyStream[i] = f(BR_X, F_R) ^ BR_X[3];
        lfsr_with_work_mode(LFSR_S);
        i++;
    }
}

/****************************************************************
Function:       zuc_genkeystream
Description:    generate key stream
Calls:          zuc_standard_init,zuc_standard_work
Called By:      ZUC_SelfCheck
Input:          k[]           //initial key,128bit
                iv[]          //initial iv,128bit
                KeyStreamLen  //the byte length of KeyStream,exporting 32bit for a beat
Output:         KeyStream[]   // key strem to be outputed
Return:         null
Others:
****************************************************************/
void zuc_genkeystream(unsigned char k[], unsigned char iv[], uint32_t KeyStream[], int
                      KeyStreamLen)
{

    uint32_t LFSR_S[16]; //LFSR state s0,s1,s2,...s15
    uint32_t BR_X[4];    //Bit Reconstruction X0,X1,X2,X3
    uint32_t F_R[2];     //R1,R2,variables of nonlinear function f
    int i;

    //Initialisation
    zuc_standard_init(k, iv, LFSR_S, BR_X, F_R);
    printf("\nstate of LFSR after executing initialization: S[0]-S[15]\n");
    for (i = 0; i < 16; i++)
    {
        printf("%08x  ", LFSR_S[i]);
    }
    printf("\ninternal state of Finite State Machine:\n");
    printf("R1=%08x\n", F_R[0]);
    printf("R2=%08x\n", F_R[1]);

    //Working
    zuc_standard_work(LFSR_S, BR_X, F_R, KeyStream, KeyStreamLen);
}


/****************************************************************
Function:       zuc_confidentiality
Description:    the ZUC-based condifentiality algorithm
Calls:          zuc_genkeystream
Called By:      ZUC_SelfCheck
Input:          CK[]           //initial key,128bit,uesed to gain the key of ZUC KeyStream
generation algorithm
                COUNT          //128bit
                BEARER         //5bit,bearing layer identification,
                DIRECTION      //1bit
                IBS[]          //input bit stream,
                LENGTH         //the bit length of IBS
Output:         OBS[]          //output bit stream,
Return:         null
Others:
****************************************************************/
void zuc_confidentiality(unsigned char CK[], uint32_t COUNT, unsigned char BEARER, unsigned
                         char DIRECTION, uint32_t IBS[], int LENGTH, uint32_t OBS[])

{
    uint32_t *k;
    int L, i, t;
    unsigned char iv[16];

    //generate vector iv1,iv2,...iv15
    iv[0] = (unsigned char)(COUNT >> 24);
    iv[1] = (unsigned char)((COUNT >> 16) & 0xff);
    iv[2] = (unsigned char)((COUNT >> 8) & 0xff);
    iv[3] = (unsigned char)(COUNT & 0xff);
    iv[4] = (((BEARER << 3) | (DIRECTION << 2)) & 0xfc);
    iv[5] = 0x00;
    iv[6] = 0x00;
    iv[7] = 0x00;
    iv[8] = iv[0];
    iv[9] = iv[1];
    iv[10] = iv[2];
    iv[11] = iv[3];
    iv[12] = iv[4];
    iv[13] = iv[5];
    iv[14] = iv[6];
    iv[15] = iv[7];

    //L,the length of key stream,taking 32bit as a unit
    L = (LENGTH + 31) / 32;
    k = malloc(sizeof(uint32_t) * L);

    //generate key stream k
    zuc_genkeystream(CK, iv, k, L);  //generate key stream

    //OBS=IBS^k
    for (i = 0; i < L; i++)
    {
        OBS[i] = IBS[i] ^ k[i];
    }
    t = LENGTH % 32;
    if (t)
    {
        OBS[L - 1] = ((OBS[L - 1] >> (32 - t)) << (32 - t));
    }
    free(k);
}

/****************************************************************
Function:       zuc_integrity
Description:    the ZUC-based integrity algorithm
Calls:          zuc_genkeystream,bit_value,get_word
Called By:      ZUC_SelfCheck
Input:          IK[]           //integrity key,128bit,uesed to gain the key of ZUC KeyStream
generation algorithm
                COUNT          //128bit
                BEARER         //5bit,bearing layer identification,
                DIRECTION      //1bit
                M[]            //message
                LENGTH         //the bit length of M
Output:
Return:         MAC           //message authentication code
Others:
****************************************************************/
uint32_t zuc_integrity(unsigned char IK[], uint32_t COUNT, unsigned char BEARER, unsigned
                       char DIRECTION, uint32_t M[], int LENGTH)
{
    uint32_t *k, ki, MAC;
    int L, i;
    unsigned char iv[16];
    uint32_t T = 0;

    //generate vector iv1,iv2,...iv15
    iv[0] = (unsigned char)(COUNT >> 24);
    iv[1] = (unsigned char)((COUNT >> 16) & 0xff);
    iv[2] = (unsigned char)((COUNT >> 8) & 0xff);
    iv[3] = (unsigned char)(COUNT & 0xff);
    iv[4] = BEARER << 3;
    iv[5] = 0x00;
    iv[6] = 0x00;
    iv[7] = 0x00;
    iv[8] = iv[0] ^ (DIRECTION << 7);
    iv[9] = iv[1];
    iv[10] = iv[2];
    iv[11] = iv[3];
    iv[12] = iv[4];
    iv[13] = iv[5];
    iv[14] = iv[6] ^ (DIRECTION << 7);
    iv[15] = iv[7];

    //L,the length of key stream,taking 32bit as a unit
    L = (LENGTH + 31) / 32 + 2;
    k = malloc(sizeof(uint32_t) * L);

    //generate key stream k
    zuc_genkeystream(IK, iv, k, L);

    //T=T^ki
    for (i = 0; i < LENGTH; i++)
    {
        if (bit_value(M, i))
        {
            ki = get_word(k, i);
            T = T ^ ki;
        }
    }

    //T=T^kLENGTH
    ki = get_word(k, LENGTH);
    T = T ^ ki;

    //MAC=T^k(32*(L-1))
    ki = get_word(k, 32 * (L - 1));
    MAC = T ^ ki;

    free(k);
    return MAC;
}




