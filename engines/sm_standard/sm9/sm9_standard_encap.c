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


int SM9_standard_key_encap(unsigned char hid[], unsigned char *IDB, unsigned char rand[],
                           unsigned char Ppub[], unsigned char C[], unsigned char K[], int Klen)
{
    big h, x, y, r;
    epoint *Ppube, *QB, *Cipher;
    unsigned char *Z = NULL;
    int Zlen, buf, i, num = 0;
    zzn12 g, w;

    //initiate
    h = mirvar(0);
    r = mirvar(0);
    x = mirvar(0);
    y = mirvar(0);
    QB = epoint_init();
    Ppube = epoint_init();
    Cipher = epoint_init();
    zzn12_init(&g);
    zzn12_init(&w);

    bytes_to_big(BNLEN, Ppub, x);
    bytes_to_big(BNLEN, Ppub + BNLEN, y);
    epoint_set(x, y, 0, Ppube);

    //----------Step1:calculate QB=[H1(IDB||hid,N)]P1+Ppube----------
    Zlen = strlen(IDB) + 1;
    Z = (char *)malloc(sizeof(char)*(Zlen + 1));
    if(Z == NULL) 
        return SM9_ASK_MEMORY_ERR;
    memcpy(Z, IDB, strlen(IDB));
    memcpy(Z + strlen(IDB), hid, 1);
    buf = SM9_standard_h1(Z, Zlen, N, h);
    free(Z);
    if(buf) 
        return buf;
    printf("\n************************ H1(IDB||hid,N) ************************\n");
    cotnum(h, stdout);

    ecurve_mult(h, P1, QB);
    ecurve_add(Ppube, QB);
    printf("\n*******************QB:=[H1(IDB||hid,N)]P1+Ppube*****************\n");
    epoint_get(QB, x, y);
    cotnum(x, stdout);
    cotnum(y, stdout);

    //-------------------- Step2:randnom -------------------
    bytes_to_big(BNLEN, rand, r);
    printf("\n***********************randnum r: ******************************\n");
    cotnum(r, stdout);

    //----------------Step3:C=[r]QB------------------------
    ecurve_mult(r, QB, Cipher);
    epoint_get(Cipher, x, y);
    printf("\n*********************** C=[r]QB: ******************************\n");
    cotnum(x, stdout);
    cotnum(y, stdout);
    big_to_bytes(BNLEN, x, C, 1);
    big_to_bytes(BNLEN, y, C + BNLEN, 1);

    //----------------Step4:g=e(Ppube,P2)------------------------
    if(!ecap(P2, Ppube, para_t, X, &g)) 
        return SM9_MY_ECAP_12A_ERR;
    //test if a ZZn12 element is of order q
    if(!member(g, para_t, X)) 
        return SM9_MEMBER_ERR;

    printf("\n***********************g=e(Ppube,P2):****************************\n");
    zzn12_ElementPrint(g);

    //----------------Step5:w=g^r------------------------
    w = zzn12_pow(g, r);
    printf("\n************************* w=g^r:*********************************\n");
    zzn12_ElementPrint(w);

    //----------------Step6:K=KDF(C||w||IDB,klen)------------------------
    Zlen = strlen(IDB) + BNLEN * 14;
    Z = (char *)malloc(sizeof(char)*(Zlen + 1));
    if(Z == NULL) 
        return SM9_ASK_MEMORY_ERR;
    LinkCharZzn12(C, BNLEN * 2, w, Z, BNLEN * 14);
    memcpy(Z + BNLEN * 14, IDB, strlen(IDB));

    SM3_kdf(Z, Zlen, Klen, K);
    free(Z);
    //----------------test if K equals 0------------------------
    printf("\n******************* K=KDF(C||w||IDB,klen):***********************\n");
    for(i = 0; i < Klen; i++)
    {
        if(K[i] == 0) 
            num += 1;
        printf("%02x", K[i]);
    }
    if(num == Klen) 
        return SM9_ERR_K1_ZERO;
    
    return 0;
}


int SM9_standard_key_decap(unsigned char *IDB, unsigned char deB[], unsigned char C[], int Klen, unsigned char K[])
{
    big h, x, y;
    epoint *Cipher;
    unsigned char *Z = NULL;
    int Zlen, i, num = 0;
    zzn12 w;
    ecn2 dEB;

    //initiate
    h = mirvar(0);
    x = mirvar(0);
    y = mirvar(0);
    Cipher = epoint_init();
    zzn12_init(&w);
    dEB.x.a = mirvar(0); 
    dEB.x.b = mirvar(0);
    dEB.y.a = mirvar(0);
    dEB.y.b = mirvar(0);
    dEB.z.a = mirvar(0); 
    dEB.z.b = mirvar(0);
    dEB.marker = MR_EPOINT_INFINITY;

    bytes_to_big(BNLEN, C, x);
    bytes_to_big(BNLEN, C + BNLEN, y);
    epoint_set(x, y, 0, Cipher);
    bytes128_to_ecn2(deB, &dEB);

    //----------Step1:test if C is on G1-----------------
    if(Test_Point(Cipher)) 
        return SM9_NOT_VALID_G1;

    //----------Step2:calculate w=e(C,deB)-----------------
    if(!ecap(dEB, Cipher, para_t, X, &w)) 
        return SM9_MY_ECAP_12A_ERR;
    //test if a ZZn12 element is of order q
    if(!member(w, para_t, X)) 
        return SM9_MEMBER_ERR;

    printf("\n***********************w=e(C,deB):****************************\n");
    zzn12_ElementPrint(w);

    //----------Step3:K=KDF(C||w'||IDB,klen)------------------------
    Zlen = strlen(IDB) + BNLEN * 14;
    Z = (char *)malloc(sizeof(char)*(Zlen + 1));
    if(Z == NULL) 
        return SM9_ASK_MEMORY_ERR;
    LinkCharZzn12(C, BNLEN * 2, w, Z, BNLEN * 14);
    memcpy(Z + BNLEN * 14, IDB, strlen(IDB));
    SM3_kdf(Z, Zlen, Klen, K);

    //----------------test if K equals 0------------------------
    printf("\n******************* K=KDF(C||w||IDB,klen):***********************\n");
    for(i = 0; i < Klen; i++)
    {
        if(K[i] == 0) 
            num += 1;
        printf("%02x", K[i]);
    }
    if(num == Klen) 
        return SM9_ERR_K1_ZERO;

    free(Z);
    return 0;
}


int SM9_standard_encap_selfcheck()
{
    //the master private key
    unsigned char KE[32] = {0x00, 0x01, 0xED, 0xEE, 0x37, 0x78, 0xF4, 0x41, 0xF8, 0xDE, 0xA3, 0xD9, 0xFA, 0x0A, 0xCC, 0x4E, 
                            0x07, 0xEE, 0x36, 0xC9, 0x3F, 0x9A, 0x08, 0x61, 0x8A, 0xF4, 0xAD, 0x85, 0xCE, 0xDE, 0x1C, 0x22};
    unsigned char rand[32] = {0x00, 0x00, 0x74, 0x01, 0x5F, 0x84, 0x89, 0xC0, 0x1E, 0xF4, 0x27, 0x04, 0x56, 0xF9, 0xE6, 0x47,
                              0x5B, 0xFB, 0x60, 0x2B, 0xDE, 0x7F, 0x33, 0xFD, 0x48, 0x2A, 0xB4, 0xE3, 0x68, 0x4A, 0x67, 0x22};
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
    unsigned char std_K[64] = {0x4F, 0xF5, 0xCF, 0x86, 0xD2, 0xAD, 0x40, 0xC8, 0xF4, 0xBA, 0xC9, 0x8D, 0x76, 0xAB, 0xDB, 0xDE,
                               0x0C, 0x0E, 0x2F, 0x0A, 0x82, 0x9D, 0x3F, 0x91, 0x1E, 0xF5, 0xB2, 0xBC, 0xE0, 0x69, 0x54, 0x80};
    unsigned char std_C[64] = {0x1E, 0xDE, 0xE2, 0xC3, 0xF4, 0x65, 0x91, 0x44, 0x91, 0xDE, 0x44, 0xCE, 0xFB, 0x2C, 0xB4, 0x34,
                               0xAB, 0x02, 0xC3, 0x08, 0xD9, 0xDC, 0x5E, 0x20, 0x67, 0xB4, 0xFE, 0xD5, 0xAA, 0xAC, 0x8A, 0x0F,
                               0x1C, 0x9B, 0x4C, 0x43, 0x5E, 0xCA, 0x35, 0xAB, 0x83, 0xBB, 0x73, 0x41, 0x74, 0xC0, 0xF7, 0x8F,
                               0xDE, 0x81, 0xA5, 0x33, 0x74, 0xAF, 0xF3, 0xB3, 0x60, 0x2B, 0xBC, 0x5E, 0x37, 0xBE, 0x9A, 0x4C};

    unsigned char hid[] = {0x03}, *IDB = "Bob";
    unsigned char Ppub[64], deB[128], C[64], K[32], K_decap[32];
    big ke;
    int tmp, i;
    int Klen = 32;

    mip = mirsys(1000, 16);
    mip->IOBASE = 16;
    ke = mirvar(0);
    bytes_to_big(32, KE, ke);

    tmp = SM9_standard_init();
    if(tmp != 0) 
        return tmp;

    printf("\n*********************** SM9 key Generation ***************************\n");
    tmp = SM9_standard_generateencryptkey(hid, IDB, strlen(IDB), ke, Ppub, deB);
    if(tmp != 0) 
        return tmp;
    if(memcmp(Ppub, std_Ppub, 64) != 0)
        return SM9_GEPUB_ERR;
    if(memcmp(deB, std_deB, 128) != 0)
        return SM9_GEPRI_ERR;

    printf("\n**********************PublicKey Ppubs=[ke]P1：*************************\n");
    for(i = 0; i < 64; i++)
    {
        if(i == 32) 
            printf("\n");
        printf("%02x", Ppub[i]);
    }
    printf("\n**************The private key deB = (xdeB, ydeB)：*********************\n");
    for(i = 0; i < 128; i++)
    { 
        if(i == 64) 
            printf("\n");
        printf("%02x", deB[i]);
    }
    
    printf("\n///////////////////SM9 Key encapsulation mechanism//////////////////////\n");
    tmp = SM9_standard_key_encap(hid, IDB, rand, Ppub, C, K, Klen);
    if(tmp != 0) 
        return tmp;

    if(memcmp(C, std_C, 64) != 0)
        return SM9_ERR_Encap_C;
    if(memcmp(K, std_K, Klen) != 0)
        return SM9_ERR_Encap_K;

    printf("\n///////////////////SM9 Key decapsulation mechanism//////////////////////\n");
    tmp = SM9_standard_key_decap(IDB, deB, C, Klen, K_decap);
    if(tmp != 0) 
        return tmp;

    if(memcmp(K_decap, std_K, 32) != 0)
        return SM9_ERR_Decap_K;
    
    return 0;
}
