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

 
#include "sm9_standard.h"
#include "sm4_standard.h"
#include "miracl.h"
#include "mirdef.h"


void SM4_standard_block_encrypt(unsigned char key[], unsigned char * message, int mlen, unsigned char *cipher, int * cipher_len)
{
    unsigned char mess[16];
    int i, rem = mlen % 16;

    for(i = 0; i < mlen / 16; i++)
        SM4_encrypt(key, &message[i * 16], &cipher[i * 16]);
    //encrypt the last block
    memset(mess, 16 - rem, 16);
    if(rem)
        memcpy(mess, &message[i * 16], rem);
    SM4_encrypt(key, mess, &cipher[i*16]);
}


void SM4_standard_block_decrypt(unsigned char key[], unsigned char *cipher, int len, unsigned char *plain, int *plain_len)
{
    int i;
    for(i = 0; i < len / 16; i++)
        SM4_decrypt(key, cipher + i * 16, plain + i * 16);
    *plain_len = len - plain[len - 1];
}


int SM9_standard_enc_mac(unsigned char *K, int Klen, unsigned char *M, int Mlen, unsigned char C[])
{
    unsigned char *Z = NULL;
    int len = Klen + Mlen;
    Z = (char *)malloc(sizeof(char)*(len + 1));
    if(Z == NULL) 
        return SM9_ASK_MEMORY_ERR;
    memcpy(Z, M, Mlen);
    memcpy(Z + Mlen, K, Klen);
    SM3_256(Z, len, C);
    
    free(Z);
    return 0;
}


int SM9_standard_encrypt(unsigned char hid[], unsigned char *IDB, unsigned char *message, int mlen, unsigned char rand[],
                         int EncID, int k1_len, int k2_len, unsigned char Ppub[], unsigned char C[], int *C_len)
{
    big h, x, y, r;
    zzn12 g, w;
    epoint *Ppube, *QB, *C1;
    unsigned char *Z = NULL, *K = NULL, *C2 = NULL, C3[SM3_len / 8];
    int i = 0, j = 0, Zlen, buf, klen, C2_len;

    //initiate
    h = mirvar(0);
    r = mirvar(0);
    x = mirvar(0);
    y = mirvar(0);
    QB = epoint_init();
    Ppube = epoint_init();
    C1 = epoint_init();
    zzn12_init(&g);
    zzn12_init(&w);

    bytes_to_big(BNLEN, Ppub, x);
    bytes_to_big(BNLEN, Ppub + BNLEN, y);
    epoint_set(x, y, 0, Ppube);

    //Step1:calculate QB=[H1(IDB||hid,N)]P1+Ppube
    Zlen = strlen(IDB) + 1;
    Z = (char *)malloc(sizeof(char)*(Zlen + 1));
    if(Z == NULL) 
        return SM9_ASK_MEMORY_ERR;
    memcpy(Z, IDB, strlen(IDB));
    memcpy(Z + strlen(IDB), hid, 1);
    buf = SM9_standard_h1(Z, Zlen, N, h);
    if(buf) 
        return buf;
    ecurve_mult(h, P1, QB);
    ecurve_add(Ppube, QB);

    printf("\n*******************QB:=[H1(IDB||hid,N)]P1+Ppube*****************\n");
    epoint_get(QB, x, y);
    cotnum(x, stdout);
    cotnum(y, stdout);

    //Step2:randnom
    bytes_to_big(BNLEN, rand, r);
    printf("\n***********************randnum r:********************************\n");
    cotnum(r, stdout);

    //Step3:C1=[r]QB
    ecurve_mult(r, QB, C1);
    printf("\n*************************:C1=[r]QB*******************************\n");
    epoint_get(C1, x, y);
    cotnum(x, stdout);
    cotnum(y, stdout);
    big_to_bytes(BNLEN, x, C, 1);
    big_to_bytes(BNLEN, y, C + BNLEN, 1);

    //Step4:g = e(P2, Ppub-e)
    if(!ecap(P2, Ppube, para_t, X, &g)) 
        return SM9_MY_ECAP_12A_ERR;
    //test if a ZZn12 element is of order q
    if(!member(g, para_t, X)) 
        return SM9_MEMBER_ERR;
    printf("\n***********************g=e(P2,Ppube):****************************\n");
    zzn12_ElementPrint(g);

    //Step5:calculate w=g^r
    w = zzn12_pow(g, r);
    printf("\n***************************w=g^r:**********************************\n");
    zzn12_ElementPrint(w);

    free(Z);
    //Step6:calculate C2
    if(EncID == 0)
    {
        C2_len = mlen;
        *C_len = BNLEN * 2 + SM3_len / 8 + C2_len;

        //Step:6-1: calculate K=KDF(C1||w||IDB,klen)
        klen = mlen + k2_len;
        Zlen = strlen(IDB) + BNLEN * 14;
        Z = (char *)malloc(sizeof(char)*(Zlen + 1));
        K = (char *)malloc(sizeof(char)*(klen + 1));
        C2 = (char *)malloc(sizeof(char)*(mlen + 1));
        if(Z == NULL || K == NULL || C2 == NULL) 
            return SM9_ASK_MEMORY_ERR;

        LinkCharZzn12( C, BNLEN * 2, w, Z, (Zlen - strlen(IDB)));
        memcpy(Z + BNLEN * 14, IDB, strlen(IDB));
        SM3_kdf(Z, Zlen, klen, K);
        printf("\n*****************K=KDF(C1||w||IDB,klen):***********************\n");
        for(i = 0; i < klen; i++) 
            printf("%02x", K[i]);

        //Step:6-2: calculate C2=M^K1,and test if K1==0?
        for(i = 0; i < mlen; i++)
        {
            if(K[i] == 0) 
                j = j + 1;
            C2[i] = message[i] ^ K[i];
        }
        if(j == mlen) 
            return SM9_ERR_K1_ZERO;
        printf("\n************************* C2=M^K1 :***************************\n");
        for(i = 0; i < C2_len; i++) 
            printf("%02x", C2[i]);

        //Step7:calculate C3=MAC(K2,C2)
        SM9_standard_enc_mac(K + mlen, k2_len, C2, mlen, C3);
        printf("\n********************** C3=MAC(K2,C2):*************************\n");
        for(i = 0; i < 32; i++) 
            printf("%02x", C3[i]);

        memcpy(C + BNLEN * 2, C3, SM3_len / 8);
        memcpy(C + BNLEN * 2 + SM3_len / 8, C2, C2_len);
        free(Z);
        free(K);
        free(C2);
    }
    else
    {
        C2_len = (mlen / 16 + 1) * 16;
        *C_len = BNLEN * 2 + SM3_len / 8 + C2_len;

        //Step:6-1: calculate K=KDF(C1||w||IDB,klen)
        klen = k1_len + k2_len;
        Zlen = strlen(IDB) + BNLEN * 14;
        Z = (char *)malloc(sizeof(char)*(Zlen + 1));
        K = (char *)malloc(sizeof(char)*(klen + 1));
        C2 = (char *)malloc(sizeof(char)*(C2_len + 1));
        if(Z == NULL || K == NULL || C2 == NULL) 
            return SM9_ASK_MEMORY_ERR;

        LinkCharZzn12(C, BNLEN * 2, w, Z, Zlen - strlen(IDB));
        memcpy(Z + BNLEN * 14, IDB, strlen(IDB));
        SM3_kdf(Z, Zlen, klen, K);
        printf("\n*****************K=KDF(C1||w||IDB,klen):***********************\n");
        for(i = 0; i < klen; i++) 
            printf("%02x", K[i]);
    
        //Step:6-2: calculate C2=Enc(K1,M),and also test if K1==0?
        for(i = 0; i < k1_len; i++)
        {
            if(K[i] == 0) 
                j = j + 1;
        }
        if(j == k1_len) 
            return SM9_ERR_K1_ZERO;
    
        SM4_standard_block_encrypt(K, message, mlen, C2, &C2_len);
        printf("\n*********************** C2=Enc(K1,M) :*************************\n");
        for(i = 0; i < C2_len; i++) 
            printf("%02x", C2[i]);
    
        //Step7:calculate C3=MAC(K2,C2)
        SM9_standard_enc_mac(K + k1_len, k2_len, C2, C2_len, C3);
        printf("\n********************** C3=MAC(K2,C2):*************************\n");
        for(i = 0; i < 32; i++) 
            printf("%02x", C3[i]);
    
        memcpy(C + BNLEN * 2, C3, SM3_len / 8);
        memcpy(C + BNLEN * 2 + SM3_len / 8, C2, C2_len);
        free(Z);
        free(K);
        free(C2);
    }
    return 0;
}


int SM9_standard_decrypt (unsigned char C[], int C_len, unsigned char deB[], unsigned char *IDB, int EncID,
                          int k1_len, int k2_len, unsigned char M[], int * Mlen)
{
    big x, y;
    epoint *C1;
    zzn12 w;
    ecn2 dEB;
    int mlen, klen, Zlen, i, number = 0;
    unsigned char *Z = NULL, *K = NULL, *K1 = NULL, u[SM3_len / 8];

    x = mirvar(0);
    y = mirvar(0);
    dEB.x.a = mirvar(0); 
    dEB.x.b = mirvar(0);
    dEB.y.a = mirvar(0);
    dEB.y.b = mirvar(0);
    dEB.z.a = mirvar(0); 
    dEB.z.b = mirvar(0);
    dEB.marker = MR_EPOINT_INFINITY;
    C1 = epoint_init();
    zzn12_init(&w);

    bytes_to_big(BNLEN, C, x);
    bytes_to_big(BNLEN, C + BNLEN, y);
    bytes128_to_ecn2(deB, &dEB);
    
    //Step1:get C1,and test if C1 is on G1
    epoint_set(x, y, 1, C1);
    if(Test_Point(C1)) 
        return SM9_C1_NOT_VALID_G1;

    //Step2:w = e(C1, deB)
    if(!ecap(dEB, C1, para_t, X, &w)) 
        return SM9_MY_ECAP_12A_ERR;
    //test if a ZZn12 element is of order q
    if(!member(w, para_t, X)) return 
        SM9_MEMBER_ERR;
    printf("\n*********************** w = e(C1, deB):****************************\n");
    zzn12_ElementPrint(w);

    //Step3:Calculate plaintext
    mlen = C_len - BNLEN * 2 - SM3_len / 8;
    if(EncID == 0)
    {
        //Step3-1:calculate K=KDF(C1||w||IDB,klen)
        klen = mlen + k2_len;
        Zlen = strlen(IDB) + BNLEN * 14;
        Z = (char *)malloc(sizeof(char)*(Zlen + 1));
        K = (char *)malloc(sizeof(char)*(klen + 1));
        if(Z == NULL || K == NULL) 
            return SM9_ASK_MEMORY_ERR;

        LinkCharZzn12(C, BNLEN * 2, w, Z, Zlen - strlen(IDB));
        memcpy(Z + BNLEN * 14, IDB, strlen(IDB));
        SM3_kdf(Z, Zlen, klen, K);
        printf("\n*****************K=KDF(C1||w||IDB,klen):***********************\n");
        for(i = 0; i < klen; i++) 
            printf("%02x", K[i]);
    
        //Step:3-2: calculate M=C2^K1,and test if K1==0?
        for(i = 0; i < mlen; i++)
        {
            if(K[i] == 0) 
                number += 1;
            M[i] = C[i + C_len - mlen] ^ K[i];
        }
        if(number == mlen) 
            return SM9_ERR_K1_ZERO;
        *Mlen = mlen;
    
        //Step4:calculate u=MAC(K2,C2)
        SM9_standard_enc_mac(K + mlen, k2_len, &C[C_len - mlen], mlen, u);
        if(memcmp(u, &C[BNLEN * 2], SM3_len / 8)) 
            return SM9_C3_MEMCMP_ERR;

        printf("\n****************************** M:******************************\n");
        for(i = 0; i < mlen; i++) 
            printf("%02x", M[i]);
        free(Z);
        free(K);
    }
    else
    {
        //Step:3-1: calculate K=KDF(C1||w||IDB,klen)
        klen = k1_len + k2_len;
        Zlen = strlen(IDB) + BNLEN * 14;
        Z = (char *)malloc(sizeof(char)*(Zlen + 1));
        K = (char *)malloc(sizeof(char)*(klen + 1));
        K1 = (char *)malloc(sizeof(char)*(k1_len + 1));
        if(Z == NULL || K == NULL || K1 == NULL) 
            return SM9_ASK_MEMORY_ERR;

        LinkCharZzn12(C, BNLEN * 2, w, Z, Zlen - strlen(IDB));
        memcpy(Z + BNLEN * 14, IDB, strlen(IDB));
        SM3_kdf(Z, Zlen, klen, K);
        printf("\n*****************K=KDF(C1||w||IDB,klen):***********************\n");
        for(i = 0; i < klen; i++) 
            printf("%02x", K[i]);
        
        //Step:3-2: calculate M=dec(K1,C2),and test if K1==0?
        for(i = 0; i < k1_len; i++)
        {
            if(K[i] == 0) 
                number += 1;
            K1[i] = K[i];
        }
        if(number == k1_len) 
            return SM9_ERR_K1_ZERO;
        SM4_standard_block_decrypt(K1, &C[C_len - mlen], mlen, M, Mlen);
    
        //Step4:calculate u=MAC(K2,C2)
        SM9_standard_enc_mac(K + k1_len, k2_len, &C[C_len - mlen], mlen, u);
        if(memcmp(u, &C[BNLEN * 2], SM3_len / 8)) 
            return SM9_C3_MEMCMP_ERR;
        free(Z);
        free(K);
        free(K1);
    }
    return 0;
}


int SM9_standard_enc_selfcheck()
{
    //the master private key
    unsigned char KE[32] = {0x00, 0x01, 0xED, 0xEE, 0x37, 0x78, 0xF4, 0x41, 0xF8, 0xDE, 0xA3, 0xD9, 0xFA, 0x0A, 0xCC, 0x4E, 
                            0x07, 0xEE, 0x36, 0xC9, 0x3F, 0x9A, 0x08, 0x61, 0x8A, 0xF4, 0xAD, 0x85, 0xCE, 0xDE, 0x1C, 0x22};
    unsigned char rand[32] = {0x00, 0x00, 0xAA, 0xC0, 0x54, 0x17, 0x79, 0xC8, 0xFC, 0x45, 0xE3, 0xE2, 0xCB, 0x25, 0xC1, 0x2B,
                              0x5D, 0x25, 0x76, 0xB2, 0x12, 0x9A, 0xE8, 0xBB, 0x5E, 0xE2, 0xCB, 0xE5, 0xEC, 0x9E, 0x78, 0x5C};
    //standard datas
    unsigned char std_Ppub[64] = {0x78, 0x7E, 0xD7, 0xB8, 0xA5, 0x1F, 0x3A, 0xB8, 0x4E, 0x0A, 0x66, 0x00, 0x3F, 0x32, 0xDA, 0x5C,
                                  0x72, 0x0B, 0x17, 0xEC, 0xA7, 0x13, 0x7D, 0x39, 0xAB, 0xC6, 0x6E, 0x3C, 0x80, 0xA8, 0x92, 0xFF,
                                  0x76, 0x9D, 0xE6, 0x17, 0x91, 0xE5, 0xAD, 0xC4, 0xB9, 0xFF, 0x85, 0xA3, 0x13, 0x54, 0x90, 0x0B,
                                  0x20, 0x28, 0x71, 0x27, 0x9A, 0x8C, 0x49, 0xDC, 0x3F, 0x22, 0x0F, 0x64, 0x4C, 0x57, 0xA7, 0xB1};
    unsigned char std_deB[128] = {0x94, 0x73, 0x6A, 0xCD, 0x2C, 0x8C, 0x87, 0x96, 0xCC, 0x47, 0x85, 0xE9, 0x38, 0x30, 0x1A, 0x13,
                                  0x9A, 0x05, 0x9D, 0x35, 0x37, 0xB6, 0x41, 0x41, 0x40, 0xB2, 0xD3, 0x1E, 0xEC, 0xF4, 0x16, 0x83,
                                  0x11, 0x5B, 0xAE, 0x85, 0xF5, 0xD8, 0xBC, 0x6C, 0x3D, 0xBD, 0x9E, 0x53, 0x42, 0x97, 0x9A, 0xCC,
                                  0xCF, 0x3C, 0x2F, 0x4F, 0x28, 0x42, 0x0B, 0x1C, 0xB4, 0xF8, 0xC0, 0xB5, 0x9A, 0x19, 0xB1, 0x58,
                                  0x7A, 0xA5, 0xE4, 0x75, 0x70, 0xDA, 0x76, 0x00, 0xCD, 0x76, 0x0A, 0x0C, 0xF7, 0xBE, 0xAF, 0x71,
                                  0xC4, 0x47, 0xF3, 0x84, 0x47, 0x53, 0xFE, 0x74, 0xFA, 0x7B, 0xA9, 0x2C, 0xA7, 0xD3, 0xB5, 0x5F,
                                  0x27, 0x53, 0x8A, 0x62, 0xE7, 0xF7, 0xBF, 0xB5, 0x1D, 0xCE, 0x08, 0x70, 0x47, 0x96, 0xD9, 0x4C,
                                  0x9D, 0x56, 0x73, 0x4F, 0x11, 0x9E, 0xA4, 0x47, 0x32, 0xB5, 0x0E, 0x31, 0xCD, 0xEB, 0x75, 0xC1};
    unsigned char std_C_stream[116] = {0x24, 0x45, 0x47, 0x11, 0x64, 0x49, 0x06, 0x18, 0xE1, 0xEE, 0x20, 0x52, 0x8F, 0xF1, 0xD5, 0x45,
                                       0xB0, 0xF1, 0x4C, 0x8B, 0xCA, 0xA4, 0x45, 0x44, 0xF0, 0x3D, 0xAB, 0x5D, 0xAC, 0x07, 0xD8, 0xFF,
                                       0x42, 0xFF, 0xCA, 0x97, 0xD5, 0x7C, 0xDD, 0xC0, 0x5E, 0xA4, 0x05, 0xF2, 0xE5, 0x86, 0xFE, 0xB3,
                                       0xA6, 0x93, 0x07, 0x15, 0x53, 0x2B, 0x80, 0x00, 0x75, 0x9F, 0x13, 0x05, 0x9E, 0xD5, 0x9A, 0xC0,
                                       0xBA, 0x67, 0x23, 0x87, 0xBC, 0xD6, 0xDE, 0x50, 0x16, 0xA1, 0x58, 0xA5, 0x2B, 0xB2, 0xE7, 0xFC,
                                       0x42, 0x91, 0x97, 0xBC, 0xAB, 0x70, 0xB2, 0x5A, 0xFE, 0xE3, 0x7A, 0x2B, 0x9D, 0xB9, 0xF3, 0x67,
                                       0x1B, 0x5F, 0x5B, 0x0E, 0x95, 0x14, 0x89, 0x68, 0x2F, 0x3E, 0x64, 0xE1, 0x37, 0x8C, 0xDD, 0x5D,
                                       0xA9, 0x51, 0x3B, 0x1C};
    unsigned char std_C_cipher[128] = {0x24, 0x45, 0x47, 0x11, 0x64, 0x49, 0x06, 0x18, 0xE1, 0xEE, 0x20, 0x52, 0x8F, 0xF1, 0xD5, 0x45,
                                       0xB0, 0xF1, 0x4C, 0x8B, 0xCA, 0xA4, 0x45, 0x44, 0xF0, 0x3D, 0xAB, 0x5D, 0xAC, 0x07, 0xD8, 0xFF,
                                       0x42, 0xFF, 0xCA, 0x97, 0xD5, 0x7C, 0xDD, 0xC0, 0x5E, 0xA4, 0x05, 0xF2, 0xE5, 0x86, 0xFE, 0xB3,
                                       0xA6, 0x93, 0x07, 0x15, 0x53, 0x2B, 0x80, 0x00, 0x75, 0x9F, 0x13, 0x05, 0x9E, 0xD5, 0x9A, 0xC0,
                                       0xFD, 0x3C, 0x98, 0xDD, 0x92, 0xC4, 0x4C, 0x68, 0x33, 0x26, 0x75, 0xA3, 0x70, 0xCC, 0xEE, 0xDE,
                                       0x31, 0xE0, 0xC5, 0xCD, 0x20, 0x9C, 0x25, 0x76, 0x01, 0x14, 0x9D, 0x12, 0xB3, 0x94, 0xA2, 0xBE,
                                       0xE0, 0x5B, 0x6F, 0xAC, 0x6F, 0x11, 0xB9, 0x65, 0x26, 0x8C, 0x99, 0x4F, 0x00, 0xDB, 0xA7, 0xA8,
                                       0xBB, 0x00, 0xFD, 0x60, 0x58, 0x35, 0x46, 0xCB, 0xDF, 0x46, 0x49, 0x25, 0x08, 0x63, 0xF1, 0x0A};
    unsigned char *std_message = "Chinese IBE standard";
    unsigned char hid[] = {0x03};
    unsigned char *IDB = "Bob";
    
    unsigned char Ppub[64], deB[128];
    unsigned char message[1000], C[1000];
    int M_len, C_len;//M_len the length of message //C_len the length of C
    int k1_len = 16, k2_len = 32;
    int EncID = 0;//0,stream //1 block
    int tmp, i;
    big ke;

    tmp = SM9_standard_init();
    if(tmp != 0)
        return tmp;

    ke = mirvar(0);
    bytes_to_big(32, KE, ke);
    
    printf("\n*********************** SM9 key Generation ***************************\n");
    tmp = SM9_standard_generateencryptkey(hid, IDB, strlen(IDB), ke, Ppub, deB);
    if(tmp != 0) 
        return tmp;
    if(memcmp(Ppub, std_Ppub, 64) != 0)
        return SM9_GEPUB_ERR;
    if(memcmp(deB, std_deB, 128) !=0)
        return SM9_GEPRI_ERR;

    printf("\n*********************** SM9 encrypt algorithm **************************\n");
    tmp = SM9_standard_encrypt(hid, IDB, std_message, strlen(std_message), rand, EncID, k1_len, k2_len, Ppub, C, &C_len);
    if(tmp != 0) 
        return tmp;
    printf("\n******************************Cipher:************************************\n");
    for(i = 0; i < C_len; i++) 
        printf("%02x", C[i]);
    if(EncID == 0) 
        tmp = memcmp(C, std_C_stream, C_len);
    else 
        tmp = memcmp(C, std_C_cipher, C_len);
    if(tmp) 
        return SM9_ENCRYPT_ERR;
    
    printf("\n********************** SM9 Decrypt algorithm **************************\n");
    tmp = SM9_standard_decrypt(std_C_cipher, 128, deB, IDB, 2, k1_len, k2_len, message, &M_len);
    printf("\n**************************** Message:***********************************\n");
    for(i = 0; i < M_len; i++) 
        printf("%02x", message[i]);
    if(tmp != 0) 
        return tmp;
    if(memcmp(message, std_message, M_len) != 0)
        return SM9_DECRYPT_ERR;
    
    return 0;
}
