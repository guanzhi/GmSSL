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
#include "miracl.h"
#include "mirdef.h"


int SM9_standard_keyex_kdf(unsigned char *IDA, unsigned char *IDB, epoint *RA, epoint *RB, zzn12 g1, zzn12 g2, zzn12 g3, int klen, unsigned char K[])
{
    unsigned char *Z = NULL;
    int Zlen;
    int IDALen = strlen(IDA), IDBLen = strlen(IDB);
    big x1, y1, x2, y2;

    x1 = mirvar(0);
    y1 = mirvar(0);
    x2 = mirvar(0);
    y2 = mirvar(0);
    epoint_get(RA, x1, y1);
    epoint_get(RB, x2, y2);
    
    Zlen = IDALen + IDBLen + BNLEN * 40;
    Z = (char *)malloc(sizeof(char)*(Zlen + 1));
    if(Z == NULL) 
        return SM9_ASK_MEMORY_ERR;

    memcpy(Z, IDA, IDALen);
    memcpy(Z + IDALen, IDB, IDBLen);
    big_to_bytes(BNLEN, x1, Z + IDALen + IDBLen, 1);
    big_to_bytes(BNLEN, y1, Z + IDALen + IDBLen + BNLEN, 1);
    big_to_bytes(BNLEN, x2, Z + IDALen + IDBLen + BNLEN * 2, 1);
    big_to_bytes(BNLEN, y2, Z + IDALen + IDBLen + BNLEN * 3, 1);
    LinkCharZzn12(Z, 0, g1, Z + IDALen + IDBLen + BNLEN * 4, BNLEN * 12);
    LinkCharZzn12(Z, 0, g2, Z + IDALen + IDBLen + BNLEN * 16, BNLEN * 12);
    LinkCharZzn12(Z, 0, g3, Z + IDALen + IDBLen + BNLEN * 28, BNLEN * 12);
    
    SM3_kdf(Z, Zlen, klen, K);
    free(Z);
    return 0;
}


int SM9_standard_keyex_hash(unsigned char hashid[], unsigned char *IDA, unsigned char *IDB, epoint *RA, epoint *RB, zzn12 g1, zzn12 g2, zzn12 g3, unsigned char hash[])
{
    int Zlen;
    int IDALen = strlen(IDA), IDBLen = strlen(IDB);
    unsigned char *Z = NULL;
    big x1, y1, x2, y2;

    x1 = mirvar(0);
    y1 = mirvar(0);
    x2 = mirvar(0);
    y2 = mirvar(0);
    epoint_get(RA, x1, y1); 
    epoint_get(RB, x2, y2);

    Zlen = IDALen + IDBLen + BNLEN * 28;
    Z = (char *)malloc(sizeof(char)*(Zlen + 1));
    if(Z == NULL) 
        return SM9_ASK_MEMORY_ERR;

    LinkCharZzn12(Z, 0, g2, Z, BNLEN * 12);
    LinkCharZzn12(Z, 0, g3, Z + BNLEN * 12, BNLEN * 12);
    memcpy(Z + BNLEN * 24, IDA, IDALen);
    memcpy(Z + BNLEN * 24 + IDALen, IDB, IDBLen);
    big_to_bytes(BNLEN, x1, Z + BNLEN * 24 + IDALen + IDBLen, 1);
    big_to_bytes(BNLEN, y1, Z + BNLEN * 25 + IDALen + IDBLen, 1);
    big_to_bytes(BNLEN, x2, Z + BNLEN * 26 + IDALen + IDBLen, 1);
    big_to_bytes(BNLEN, y2, Z + BNLEN * 27 + IDALen + IDBLen, 1);

    SM3_256(Z, Zlen, hash);

    Zlen = 1 + BNLEN * 12 + SM3_len / 8;
    memcpy(Z, hashid, 1);
    LinkCharZzn12(Z, 1, g1, Z, 1 + BNLEN * 12);
    memcpy(Z + 1 + BNLEN * 12, hash, SM3_len / 8);

    SM3_256(Z, Zlen, hash);
    free(Z);
    return 0;
}


int SM9_standard_keyex_inita_i(unsigned char hid[], unsigned char *IDB, unsigned char randA[], 
                               unsigned char Ppub[], unsigned char deA[], epoint *RA)
{
    big h, x, y, rA;
    epoint *Ppube, *QB;
    unsigned char *Z = NULL;
    int Zlen, buf;

    //initiate
    h = mirvar(0);
    rA = mirvar(0);
    x = mirvar(0);
    y = mirvar(0);
    QB = epoint_init();
    Ppube = epoint_init();

    bytes_to_big(BNLEN, Ppub, x);
    bytes_to_big(BNLEN, Ppub + BNLEN, y);
    epoint_set(x, y, 0, Ppube);

    //----------A1:calculate QB=[H1(IDB||hid,N)]P1+Ppube----------
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

    //--------------- Step A2:randnom -------------------
    bytes_to_big(BNLEN, randA, rA);
    printf("\n***********************randnum rA:******************************\n");
    cotnum(rA, stdout);

    //----------------Step A3:RA=[r]QB
    ecurve_mult(rA, QB, RA);
    
    free(Z);
    return 0;
}



int SM9_standard_keyex_reb_i(unsigned char hid[], unsigned char *IDA, unsigned char *IDB, unsigned char randB[], unsigned char Ppub[],
                             unsigned char deB[], epoint *RA, epoint *RB, unsigned char SB[], zzn12 *g1, zzn12 *g2, zzn12 *g3)
{
    big h, x, y, rB;
    epoint *Ppube, *QA;
    unsigned char *Z = NULL, hashid[] = {0x82};
    unsigned char SKB[16];
    ecn2 dEB;
    int Zlen, buf, i;

    //initiate
    h = mirvar(0);
    rB = mirvar(0);
    x = mirvar(0);
    y = mirvar(0);
    QA = epoint_init();
    Ppube = epoint_init();
    dEB.x.a = mirvar(0); 
    dEB.x.b = mirvar(0);
    dEB.y.a = mirvar(0);
    dEB.y.b = mirvar(0);
    dEB.z.a = mirvar(0); 
    dEB.z.b = mirvar(0);
    dEB.marker = MR_EPOINT_INFINITY;
    
    bytes_to_big(BNLEN, Ppub, x);
    bytes_to_big(BNLEN, Ppub + BNLEN, y);
    bytes128_to_ecn2(deB, &dEB);
    epoint_set(x, y, 0, Ppube);

    //----------B1:calculate QA=[H1(IDA||hid,N)]P1+Ppube----------
    Zlen = strlen(IDA) + 1;
    Z = (char *)malloc(sizeof(char)*(Zlen + 1));
    if(Z == NULL) 
        return SM9_ASK_MEMORY_ERR;
    memcpy(Z, IDA, strlen(IDA));
    memcpy(Z + strlen(IDA), hid, 1);

    buf = SM9_standard_h1(Z, Zlen, N, h);
    if(buf) 
        return buf;
    ecurve_mult(h, P1, QA);
    ecurve_add(Ppube, QA);
    printf("\n*******************QA:=[H1(IDA||hid,N)]P1+Ppube*****************\n");
    epoint_get(QA, x, y);
    cotnum(x, stdout);
    cotnum(y, stdout);

    //--------------- Step B2:randnom -------------------
    bytes_to_big(BNLEN, randB, rB);
    printf("\n***********************randnum rB:********************************\n");
    cotnum(rB, stdout);

    //----------------Step B3:RB=[rB]QA------------------
    ecurve_mult(rB, QA, RB);
    printf("\n*************************:RB=[rB]QA*******************************\n");
    epoint_get(RB, x, y);
    cotnum(x, stdout);
    cotnum(y, stdout);

    //test if RA is on G1
    if(Test_Point(RA)) 
        return SM9_NOT_VALID_G1;

    //----------------Step B4:g1=e(deB,RA),g2=(e(P2,Ppube))^rB,g3=g1^rB
    if(!ecap(dEB, RA, para_t, X, g1)) 
        return SM9_MY_ECAP_12A_ERR;
    if(!ecap(P2, Ppube, para_t, X, g2)) 
        return SM9_MY_ECAP_12A_ERR;
    //test if a ZZn12 element is of order q
    if((!member(*g1, para_t, X)) || (!member(*g2, para_t, X))) 
        return SM9_MEMBER_ERR;

    *g2 = zzn12_pow(*g2, rB);
    *g3 = zzn12_pow(*g1, rB);

    printf("\n***********************g1=e(RA,deB):****************************\n");
    zzn12_ElementPrint(*g1);
    printf("\n*******************g2=(e(P2,Ppub3))^rB:*************************\n");
    zzn12_ElementPrint(*g2);
    printf("\n***********************g3=g1^rB:********************************\n");
    zzn12_ElementPrint(*g3);

    //---------------- B5:SKB=KDF(IDA||IDB||RA||RB||g1||g2||g3,klen)----------
    buf = SM9_standard_keyex_kdf(IDA, IDB, RA, RB, *g1, *g2, *g3, 16, SKB);
    if(buf) 
        return buf;
    printf("\n***********SKB=KDF(IDA||IDB||RA||RB||g1||g2||g3,klen):***********\n");
    for(i = 0; i < 16; i++) 
        printf("%02x", SKB[i]);

    //---------------- B6(optional):SB=Hash(0x82||g1||Hash(g2||g3||IDA||IDB||RA||RB))----------
    buf = SM9_standard_keyex_hash(hashid, IDA, IDB, RA, RB, *g1, *g2, *g3, SB);
    if(buf) 
        return buf;
    printf("\n********SB=Hash(0x82||g1||Hash(g2||g3||IDA||IDB||RA||RB))********\n");
    for(i = 0; i < SM3_len / 8; i++) 
        printf("%02x", SB[i]);
    
    free(Z);
    return 0;
}


int SM9_standard_keyex_inita_ii(unsigned char *IDA, unsigned char *IDB, unsigned char randA[], unsigned char Ppub[],
                                unsigned char deA[], epoint *RA, epoint *RB, unsigned char SB[], unsigned char SA[])
{
    big h, x, y, rA;
    epoint *Ppube;
    unsigned char hashid[] = {0x82};
    unsigned char S1[SM3_len / 8], SKA[16];
    zzn12 g1, g2, g3;
    ecn2 dEA;
    int buf, i;

    //initiate
    h = mirvar(0);
    rA = mirvar(0);
    x = mirvar(0);
    y = mirvar(0);
    Ppube = epoint_init();
    dEA.x.a = mirvar(0); 
    dEA.x.b = mirvar(0);
    dEA.y.a = mirvar(0);
    dEA.y.b = mirvar(0);
    dEA.z.a = mirvar(0); 
    dEA.z.b = mirvar(0);
    dEA.marker = MR_EPOINT_INFINITY;
    zzn12_init(&g1);
    zzn12_init(&g2);
    zzn12_init(&g3);

    bytes_to_big(BNLEN, Ppub, x);
    bytes_to_big(BNLEN, Ppub + BNLEN, y);
    bytes_to_big(BNLEN, randA, rA);
    bytes128_to_ecn2(deA, &dEA);
    epoint_set(x, y, 0, Ppube);

    //test if RB is on G1
    if(Test_Point(RB)) 
        return SM9_NOT_VALID_G1;

    //----------------Step A5:g1=(e(P2,Ppube))^rA,g2=e(deA,RB),g3=g2^rA---------
    if(!ecap(P2, Ppube, para_t, X, &g1)) 
        return SM9_MY_ECAP_12A_ERR;
    if(!ecap(dEA, RB, para_t, X, &g2)) 
        return SM9_MY_ECAP_12A_ERR;
    //test if a ZZn12 element is of order q
    if((!member(g1, para_t, X)) || (!member(g2, para_t, X))) 
        return SM9_MEMBER_ERR;

    g1 = zzn12_pow(g1, rA);
    g3 = zzn12_pow(g2, rA);
    printf("\n***********************g1=e(Ppub,P2):****************************\n");
    zzn12_ElementPrint(g1);
    printf("\n*******************g2=(e(RB,deA))^rB:*************************\n");
    zzn12_ElementPrint(g2);
    printf("\n***********************g3=g2^rB:********************************\n");
    zzn12_ElementPrint(g3);

    //------------------ A6:S1=Hash(0x82||g1||Hash(g2||g3||IDA||IDB||RA||RB))----------
    buf = SM9_standard_keyex_hash(hashid, IDA, IDB, RA, RB, g1, g2, g3, S1);
    if(buf) 
        return buf;
    printf("\n*********S1=Hash(0x82||g1||Hash(g2||g3||IDA||IDB||RA||RB))********\n");
    for(i = 0; i < SM3_len / 8; i++) 
        printf("%02x", S1[i]);
    
    if(memcmp(S1, SB, SM3_len / 8)) 
        return SM9_ERR_CMP_S1SB;
    
    //---------- A7: SKA=KDF(IDA||IDB||RA||RB||g1||g2||g3,klen)----------
    buf = SM9_standard_keyex_kdf(IDA, IDB, RA, RB, g1, g2, g3, 16, SKA);
    if(buf) 
        return buf;
    printf("\n************SKA=KDF(IDA||IDB||RA||RB||g1||g2||g3,klen)************\n");
    for(i = 0; i < 16; i++) 
        printf("%02x", SKA[i]);

    //--------- A8(optional):SA=Hash(0x83||g1||Hash(g2||g3||IDA||IDB||RA||RB))----------
    hashid[0] = (unsigned char)0x83;
    buf = SM9_standard_keyex_hash(hashid, IDA, IDB, RA, RB, g1, g2, g3, SA);
    if(buf) 
        return buf;
    printf("\n*********SA=Hash(0x83||g1||Hash(g2||g3||IDA||IDB||RA||RB))********\n");
    for(i = 0; i < SM3_len / 8; i++) 
        printf("%02x", SA[i]);
    
    return 0;
}


int SM9_standard_keyex_reb_ii(unsigned char *IDA, unsigned char *IDB, zzn12 g1, zzn12 g2, zzn12 g3, epoint *RA, epoint *RB, unsigned char SA[])
{
    unsigned char hashid[] = {0x83};
    unsigned char S2[SM3_len / 8];
    int buf, i;

    //---------------- B8(optional):S2=Hash(0x83||g1||Hash(g2||g3||IDA||IDB||RA||RB))----------
    buf = SM9_standard_keyex_hash(hashid, IDA, IDB, RA, RB, g1, g2, g3, S2);
    if(buf) 
        return buf;
    printf("\n*************** S2=Hash(0x83||g1||Hash(g2||g3||IDA||IDB||RA||RB))****************\n");
    for(i = 0; i < SM3_len / 8; i++) 
        printf("%02x", S2[i]);

    if(memcmp(S2, SA, SM3_len / 8)) 
        return SM9_ERR_CMP_S2SA;
    return 0;
}


int SM9_standard_exch_selfcheck()
{
    //the master private key
    unsigned char KE[32] = {0x00, 0x02, 0xE6, 0x5B, 0x07, 0x62, 0xD0, 0x42, 0xF5, 0x1F, 0x0D, 0x23, 0x54, 0x2B, 0x13, 0xED,
                            0x8C, 0xFA, 0x2E, 0x9A, 0x0E, 0x72, 0x06, 0x36, 0x1E, 0x01, 0x3A, 0x28, 0x39, 0x05, 0xE3, 0x1F};
    unsigned char randA[32] = {0x00, 0x00, 0x58, 0x79, 0xDD, 0x1D, 0x51, 0xE1, 0x75, 0x94, 0x6F, 0x23, 0xB1, 0xB4, 0x1E, 0x93,
                               0xBA, 0x31, 0xC5, 0x84, 0xAE, 0x59, 0xA4, 0x26, 0xEC, 0x10, 0x46, 0xA4, 0xD0, 0x3B, 0x06, 0xC8};
    unsigned char randB[32] = {0x00, 0x01, 0x8B, 0x98, 0xC4, 0x4B, 0xEF, 0x9F, 0x85, 0x37, 0xFB, 0x7D, 0x07, 0x1B, 0x2C, 0x92,
                               0x8B, 0x3B, 0xC6, 0x5B, 0xD3, 0xD6, 0x9E, 0x1E, 0xEE, 0x21, 0x35, 0x64, 0x90, 0x56, 0x34, 0xFE};
    //standard datas
    unsigned char std_Ppub[64] = {0x91, 0x74, 0x54, 0x26, 0x68, 0xE8, 0xF1, 0x4A, 0xB2, 0x73, 0xC0, 0x94, 0x5C, 0x36, 0x90, 0xC6,
                                  0x6E, 0x5D, 0xD0, 0x96, 0x78, 0xB8, 0x6F, 0x73, 0x4C, 0x43, 0x50, 0x56, 0x7E, 0xD0, 0x62, 0x83,
                                  0x54, 0xE5, 0x98, 0xC6, 0xBF, 0x74, 0x9A, 0x3D, 0xAC, 0xC9, 0xFF, 0xFE, 0xDD, 0x9D, 0xB6, 0x86,
                                  0x6C, 0x50, 0x45, 0x7C, 0xFC, 0x7A, 0xA2, 0xA4, 0xAD, 0x65, 0xC3, 0x16, 0x8F, 0xF7, 0x42, 0x10};
    unsigned char std_deA[128] = {0x0F, 0xE8, 0xEA, 0xB3, 0x95, 0x19, 0x9B, 0x56, 0xBF, 0x1D, 0x75, 0xBD, 0x2C, 0xD6, 0x10, 0xB6,
                                  0x42, 0x4F, 0x08, 0xD1, 0x09, 0x29, 0x22, 0xC5, 0x88, 0x2B, 0x52, 0xDC, 0xD6, 0xCA, 0x83, 0x2A,
                                  0x7D, 0xA5, 0x7B, 0xC5, 0x02, 0x41, 0xF9, 0xE5, 0xBF, 0xDD, 0xC0, 0x75, 0xDD, 0x9D, 0x32, 0xC7,
                                  0x77, 0x71, 0x00, 0xD7, 0x36, 0x91, 0x6C, 0xFC, 0x16, 0x5D, 0x8D, 0x36, 0xE0, 0x63, 0x4C, 0xD7,
                                  0x83, 0xA4, 0x57, 0xDA, 0xF5, 0x2C, 0xAD, 0x46, 0x4C, 0x90, 0x3B, 0x26, 0x06, 0x2C, 0xAF, 0x93,
                                  0x7B, 0xB4, 0x0E, 0x37, 0xDA, 0xDE, 0xD9, 0xED, 0xA4, 0x01, 0x05, 0x0E, 0x49, 0xC8, 0xAD, 0x0C,
                                  0x69, 0x70, 0x87, 0x6B, 0x9A, 0xAD, 0x1B, 0x7A, 0x50, 0xBB, 0x48, 0x63, 0xA1, 0x1E, 0x57, 0x4A,
                                  0xF1, 0xFE, 0x3C, 0x59, 0x75, 0x16, 0x1D, 0x73, 0xDE, 0x4C, 0x3A, 0xF6, 0x21, 0xFB, 0x1E, 0xFB};
    unsigned char std_deB[128] = {0x74, 0xCC, 0xC3, 0xAC, 0x9C, 0x38, 0x3C, 0x60, 0xAF, 0x08, 0x39, 0x72, 0xB9, 0x6D, 0x05, 0xC7,
                                  0x5F, 0x12, 0xC8, 0x90, 0x7D, 0x12, 0x8A, 0x17, 0xAD, 0xAF, 0xBA, 0xB8, 0xC5, 0xA4, 0xAC, 0xF7,
                                  0x01, 0x09, 0x2F, 0xF4, 0xDE, 0x89, 0x36, 0x26, 0x70, 0xC2, 0x17, 0x11, 0xB6, 0xDB, 0xE5, 0x2D,
                                  0xCD, 0x5F, 0x8E, 0x40, 0xC6, 0x65, 0x4B, 0x3D, 0xEC, 0xE5, 0x73, 0xC2, 0xAB, 0x3D, 0x29, 0xB2,
                                  0x44, 0xB0, 0x29, 0x4A, 0xA0, 0x42, 0x90, 0xE1, 0x52, 0x4F, 0xF3, 0xE3, 0xDA, 0x8C, 0xFD, 0x43,
                                  0x2B, 0xB6, 0x4D, 0xE3, 0xA8, 0x04, 0x0B, 0x5B, 0x88, 0xD1, 0xB5, 0xFC, 0x86, 0xA4, 0xEB, 0xC1,
                                  0x8C, 0xFC, 0x48, 0xFB, 0x4F, 0xF3, 0x7F, 0x1E, 0x27, 0x72, 0x74, 0x64, 0xF3, 0xC3, 0x4E, 0x21,
                                  0x53, 0x86, 0x1A, 0xD0, 0x8E, 0x97, 0x2D, 0x16, 0x25, 0xFC, 0x1A, 0x7B, 0xD1, 0x8D, 0x55, 0x39};
    unsigned char std_RA[64] = {0x7C, 0xBA, 0x5B, 0x19, 0x06, 0x9E, 0xE6, 0x6A, 0xA7, 0x9D, 0x49, 0x04, 0x13, 0xD1, 0x18, 0x46,
                                0xB9, 0xBA, 0x76, 0xDD, 0x22, 0x56, 0x7F, 0x80, 0x9C, 0xF2, 0x3B, 0x6D, 0x96, 0x4B, 0xB2, 0x65,
                                0xA9, 0x76, 0x0C, 0x99, 0xCB, 0x6F, 0x70, 0x63, 0x43, 0xFE, 0xD0, 0x56, 0x37, 0x08, 0x58, 0x64,
                                0x95, 0x8D, 0x6C, 0x90, 0x90, 0x2A, 0xBA, 0x7D, 0x40, 0x5F, 0xBE, 0xDF, 0x7B, 0x78, 0x15, 0x99};
    unsigned char std_RB[64] = {0x86, 0x1E, 0x91, 0x48, 0x5F, 0xB7, 0x62, 0x3D, 0x27, 0x94, 0xF4, 0x95, 0x03, 0x1A, 0x35, 0x59,
                                0x8B, 0x49, 0x3B, 0xD4, 0x5B, 0xE3, 0x78, 0x13, 0xAB, 0xC7, 0x10, 0xFC, 0xC1, 0xF3, 0x44, 0x82,
                                0x32, 0xD9, 0x06, 0xA4, 0x69, 0xEB, 0xC1, 0x21, 0x6A, 0x80, 0x2A, 0x70, 0x52, 0xD5, 0x61, 0x7C,
                                0xD4, 0x30, 0xFB, 0x56, 0xFB, 0xA7, 0x29, 0xD4, 0x1D, 0x9B, 0xD6, 0x68, 0xE9, 0xEB, 0x96, 0x00};
    unsigned char std_SA[32] = {0x19, 0x5D, 0x1B, 0x72, 0x56, 0xBA, 0x7E, 0x0E, 0x67, 0xC7, 0x12, 0x02, 0xA2, 0x5F, 0x8C, 0x94,
                                0xFF, 0x82, 0x41, 0x70, 0x2C, 0x2F, 0x55, 0xD6, 0x13, 0xAE, 0x1C, 0x6B, 0x98, 0x21, 0x51, 0x72};
    unsigned char std_SB[32] = {0x3B, 0xB4, 0xBC, 0xEE, 0x81, 0x39, 0xC9, 0x60, 0xB4, 0xD6, 0x56, 0x6D, 0xB1, 0xE0, 0xD5, 0xF0,
                                0xB2, 0x76, 0x76, 0x80, 0xE5, 0xE1, 0xBF, 0x93, 0x41, 0x03, 0xE6, 0xC6, 0x6E, 0x40, 0xFF, 0xEE};
    
    unsigned char hid[] = {0x02}, *IDA = "Alice", *IDB = "Bob";
    unsigned char Ppub[64], deA[128], deB[128];
    unsigned char xy[64], SA[SM3_len / 8], SB[SM3_len / 8];
    epoint *RA, *RB;
    big ke, x, y;
    zzn12 g1, g2, g3;
    int tmp, i;

    mip = mirsys(1000, 16);
    mip->IOBASE = 16;
    x = mirvar(0);
    y = mirvar(0);
    ke = mirvar(0);
    bytes_to_big(32, KE, ke);
    RA = epoint_init();
    RB = epoint_init();
    zzn12_init(&g1);
    zzn12_init(&g2);
    zzn12_init(&g3);

    tmp = SM9_standard_init();
    if(tmp != 0) 
        return tmp;

    printf("\n*********************** SM9 key Generation ***************************\n");
    tmp = SM9_standard_generateencryptkey(hid, IDA, strlen(IDA), ke, Ppub, deA);
    if(tmp != 0) 
        return tmp;
    tmp = SM9_standard_generateencryptkey(hid, IDB, strlen(IDB), ke, Ppub, deB);
    if(tmp != 0) 
        return tmp;
    if(memcmp(Ppub, std_Ppub, 64) != 0)
        return SM9_GEPUB_ERR;
    if(memcmp(deA, std_deA, 128) != 0)
        return SM9_GEPRI_ERR;
    if(memcmp(deB, std_deB, 128) != 0)
        return SM9_GEPRI_ERR;

    printf("\n**********************PublicKey Ppubs=[ke]P1：*************************\n");
    for(i = 0; i < 64; i++) 
        printf("%02x", Ppub[i]);
    printf("\n**************The private key deA = (xdeA, ydeA)：*********************\n");
    for(i = 0; i < 128; i++) 
        printf("%02x", deA[i]);
    printf("\n**************The private key deB = (xdeB, ydeB)：*********************\n");
    for(i = 0; i < 128; i++) 
        printf("%02x", deB[i]);

    printf("\n//////////////////// SM9 Key exchange A1-A4://////////////////////////\n");
    tmp = SM9_standard_keyex_inita_i(hid, IDB, randA, Ppub, deA, RA);
    if(tmp != 0) 
        return tmp;
    printf("\n ////////////////////////////:RA=[r]QB //////////////////////////////\n");
    epoint_get(RA, x, y);
    cotnum(x, stdout);
    cotnum(y, stdout);
    big_to_bytes(BNLEN, x, xy, 1);
    big_to_bytes(BNLEN, y, xy + BNLEN, 1);
    if(memcmp(xy, std_RA, BNLEN * 2) != 0)
        return SM9_ERR_RA;

    printf("\n//////////////////////// SM9 Key exchange B1-B7:///////////////////////\n");
    tmp = SM9_standard_keyex_reb_i(hid, IDA, IDB, randB, Ppub, deB, RA, RB, SB, &g1, &g2, &g3);
    if(tmp != 0) 
        return tmp;
    epoint_get(RB, x, y);
    big_to_bytes(BNLEN, x, xy, 1);
    big_to_bytes(BNLEN, y, xy + BNLEN, 1);
    
    if(memcmp(xy, std_RB, BNLEN * 2) != 0)
        return SM9_ERR_RB;
    if(memcmp(SB, std_SB, SM3_len / 8) != 0)
        return SM9_ERR_SB;

    printf("\n//////////////////////// SM9 Key exchange A5-A8:///////////////////////\n");
    tmp = SM9_standard_keyex_inita_ii(IDA, IDB, randA, Ppub, deA, RA, RB, SB, SA);
    if(tmp!=0) 
        return tmp;
    if(memcmp(SA, std_SA, SM3_len / 8) != 0)
        return SM9_ERR_SA;

    printf("\n//////////////////////// SM9 Key exchange B8:///////////////////////\n");
    tmp = SM9_standard_keyex_reb_ii(IDA, IDB, g1, g2, g3, RA, RB, SA);
    if(tmp != 0) 
        return tmp;
    
    return 0;
}
