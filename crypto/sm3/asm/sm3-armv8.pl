#! /usr/bin/env perl
# Copyright (c) 2014 - 2021 The GmSSL Project.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. All advertising materials mentioning features or use of this
#    software must display the following acknowledgment:
#    "This product includes software developed by the GmSSL Project.
#    (http://gmssl.org/)"
#
# 4. The name "GmSSL Project" must not be used to endorse or promote
#    products derived from this software without prior written
#    permission. For written permission, please contact
#    guanzhi1980@gmail.com.
#
# 5. Products derived from this software may not be called "GmSSL"
#    nor may "GmSSL" appear in their names without prior written
#    permission of the GmSSL Project.
#
# 6. Redistributions of any form whatsoever must retain the following
#    acknowledgment:
#    "This product includes software developed by the GmSSL Project
#    (http://gmssl.org/)"
#
# THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
# EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
# ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.

# ====================================================================
# Written by Jiang Mengshan <jiangmengshan@hotmail.com> for the GmSSL 
# project.
# ====================================================================

$flavour = shift;
$output  = shift;

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}arm-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/arm-xlate.pl" and -f $xlate) or
die "can't locate arm-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour $output";
*STDOUT=*OUT;

my ($digest,$block,$nb)=("x0","x1","x2");
my $TBL="x3";
@V1=($a,$b,$c,$d)=map("w$_",(4..7));
@V2=($e,$f,$g,$h)=map("w$_",(8..11));
my ($t0,$t1,$t2,$t3,$t4,$t5)=map("w$_",(12..17));
my $W="w19";
my ($V0,$V1,$V2,$V3,$V4,$V5,$V6,$V7)=map("w$_",(20..27));
my ($T0,$T1,$T2,$T3,$T4)=("w0","w1","w2","w28","w30");
@M=($M0,$M1,$M2,$M3)=map("v$_",(0..3));
my ($XTMP0,$XTMP1,$XTMP2,$XTMP3,$XTMP4,$XTMP5)=map("v$_",(4..7,16,17));
my ($XFER)=("v18");

$code.=<<___;
.text

.align 5
.LK256:
.word 0x79CC4519,0xF3988A32,0xE7311465,0xCE6228CB
.word 0x9CC45197,0x3988A32F,0x7311465E,0xE6228CBC
.word 0xCC451979,0x988A32F3,0x311465E7,0x6228CBCE
.word 0xC451979C,0x88A32F39,0x11465E73,0x228CBCE6
.word 0x9D8A7A87,0x3B14F50F,0x7629EA1E,0xEC53D43C
.word 0xD8A7A879,0xB14F50F3,0x629EA1E7,0xC53D43CE
.word 0x8A7A879D,0x14F50F3B,0x29EA1E76,0x53D43CEC
.word 0xA7A879D8,0x4F50F3B1,0x9EA1E762,0x3D43CEC5
.word 0x7A879D8A,0xF50F3B14,0xEA1E7629,0xD43CEC53
.word 0xA879D8A7,0x50F3B14F,0xA1E7629E,0x43CEC53D
.word 0x879D8A7A,0x0F3B14F5,0x1E7629EA,0x3CEC53D4
.word 0x79D8A7A8,0xF3B14F50,0xE7629EA1,0xCEC53D43
.word 0x9D8A7A87,0x3B14F50F,0x7629EA1E,0xEC53D43C
.word 0xD8A7A879,0xB14F50F3,0x629EA1E7,0xC53D43CE
.word 0x8A7A879D,0x14F50F3B,0x29EA1E76,0x53D43CEC
.word 0xA7A879D8,0x4F50F3B1,0x9EA1E762,0x3D43CEC5
___

sub ROUND_00_15_1()
{
    my ($X0,$X1,$X2,$X3,$A,$B,$C,$D,$E,$F,$G,$H) = @_;
$code.=<<___;
     eor $XFER.16b,$X0.16b,$X1.16b         // WW
    ror $t0,$A,#20                         // A <<< 12
     ext $XTMP0.16b,$X0.16b,$X1.16b,#12    // (W[-13],W[-12],W[-11],XXX)
    eor $t1,$A,$B                          // A ^ B
    ldr $t3,[$TBL],#4                      // Tj <<< j
    add $t2,$t0,$E                         // (A <<< 12) + E
     shl $XTMP1.4s,$XTMP0.4s,#7            // ((W[-13],W[-12],W[-11],XXX) << 7)
     mov $W,$X0.s[0]                       // W[-16]
    eor $t5,$E,$F                          // E ^ F
    eor $t1,$t1,$C                         // FF(A, B, C)
    add $t4,$t2,$t3                        // (A <<< 12) + E + (Tj <<< j)
     ushr $XTMP2.4s,$XTMP0.4s,#25          // (W[-13],W[-12],W[-11],XXX) >> 25
    eor $t5,$t5,$G                         // GG(E, F, G)
    add $H,$H,$W                           // H + Wj
    ror $t4,$t4,#25                        // SS1
     eor $XTMP0.16b,$XTMP1.16b,$XTMP2.16b  // (W[-13],W[-12],W[-11],XXX] <<< 17
    add $D,$t1,$D                          // FF(A, B, C) + D
    ror $B,$B,#23                          // B <<< 9
    add $t1,$t4,$t5                        // GG(E, F, G) + SS1
     ext $XTMP2.16b,$X2.16b,$X3.16b,#8     // (W[-6],W[-5],W[-4],XXX)
     mov $W,$XFER.s[0]                     // WW[-16]
    eor $t2,$t0,$t4                        // SS2
    add $H,$H,$t1                          // TT2 = GG(E, F, G) + H + SS1 + Wj
    ror $F,$F,#13                          // F <<< 19
     eor $XTMP0.16b,$XTMP0.16b,$XTMP2.16b  // (W[-6],W[-5],W[-4],XXX)^((W[-13],W[-12],W[-11],XXX) <<< 17)
    ror $t3,$H,#23
    add $D,$D,$t2                          // FF(A, B, C) + D + SS2
    eor $H,$H,$H,ror#15
     ext $XTMP1.16b,$X3.16b,$X2.16b,#4     // (W[-3],W[-2],W[-1],XXX)
    add $D,$D,$W                           // TT1 = FF(A, B, C) + D + SS2 + W'j
    eor $H,$H,$t3                          // P0(TT2)
___
}

sub ROUND_00_15_2()
{
    my ($X0,$X1,$X2,$X3,$A,$B,$C,$D,$E,$F,$G,$H) = @_;
$code.=<<___;
    ror $t0,$A,#20                         // A <<< 12
     shl $XTMP2.4s,$XTMP1.4s,#15           // (W[-3],W[-2],W[-1],XXX) << 15
    eor $t1,$A,$B                          // A ^ B
    ldr $t3,[$TBL],#4                      // Tj <<< j
    add $t2,$t0,$E                         // (A <<< 12) + E
     ushr $XTMP1.4s,$XTMP1.4s,#17          // (W[-3],W[-2],W[-1],XXX) >> 17
     mov $W,$X0.s[1]                       // W[-15]
    eor $t5,$E,$F                          // E ^ F
    eor $t1,$t1,$C                         // FF(A, B, C)
    add $t4,$t2,$t3                        // (A <<< 12) + E + (Tj <<< j)
     eor $XTMP1.16b,$XTMP1.16b,$XTMP2.16b  // (W[-3],W[-2],W[-1],XXX) <<< 15
    eor $t5,$t5,$G                         // GG(E, F, G)
    add $H,$H,$W                           // H + Wj
    ror $t4,$t4,#25                        // SS1
     ext $XTMP2.16b,$X1.16b,$X2.16b,#12    // W[-9],W[-8],W[-7],W[-6]
    add $D,$t1,$D                          // FF(A, B, C) + D
    ror $B,$B,#23                          // B <<< 9
    add $t1,$t4,$t5                        // GG(E, F, G) + SS1
     eor $XTMP2.16b,$XTMP2.16b,$X0.16b     // (W[-9],W[-8],W[-7],W[-6]) ^ (W[-16],W[-15],W[-14],W[-13])
     mov $W,$XFER.s[1]                     // WW[-15]
    eor $t2,$t0,$t4                        // SS2
    add $H,$H,$t1                          // TT2 = GG(E, F, G) + H + SS1 + Wj
    ror $F,$F,#13                          // F <<< 19
     eor $XTMP1.16b,$XTMP1.16b,$XTMP2.16b  // (W[-9],W[-8],W[-7],W[-6]) ^ (W[-16],W[-15],W[-14],W[-13])^((W[-3],W[-2],W[-1],W[0]) <<< 15)
    ror $t3,$H,#23
    add $D,$D,$t2                          // FF(A, B, C) + D + SS2
    eor $H,$H,$H,ror#15
     shl $XTMP3.4s,$XTMP1.4s,#15           // P1(X), X << 15
    add $D,$D,$W                           // TT1 = FF(A, B, C) + D + SS2 + W'j
    eor $H,$H,$t3                          // P0(TT2)
___
}

sub ROUND_00_15_3()
{
    my ($X0,$X1,$X2,$X3,$A,$B,$C,$D,$E,$F,$G,$H) = @_;
$code.=<<___;
    ror $t0,$A,#20                         // A <<< 12
     ushr $XTMP4.4s,$XTMP1.4s,#17          // P1(X), X >> 17
    eor $t1,$A,$B                          // A ^ B
    ldr $t3,[$TBL],#4                      // Tj <<< j
    add $t2,$t0,$E                         // (A <<< 12) + E
     eor $XTMP3.16b,$XTMP3.16b,$XTMP4.16b  // P1(X), X <<< 15
     mov $W,$X0.s[2]                       // W[-14]
    eor $t5,$E,$F                          // E ^ F
    eor $t1,$t1,$C                         // FF(A, B, C)
    add $t4,$t2,$t3                        // (A <<< 12) + E + (Tj <<< j)
     shl $XTMP4.4s,$XTMP1.4s,#23           // P1(X), X << 23
    eor $t5,$t5,$G                         // GG(E, F, G)
    add $H,$H,$W                           // H + Wj
    ror $t4,$t4,#25                        // SS1
     ushr $XTMP5.4s,$XTMP1.4s,#9           // P1(X), X >> 9
    add $D,$t1,$D                          // FF(A, B, C) + D
    ror $B,$B,#23                          // B <<< 9
    add $t1,$t4,$t5                        // GG(E, F, G) + SS1
     eor $XTMP5.16b,$XTMP4.16b,$XTMP5.16b  // P1(X), X << 23
     mov $W,$XFER.s[2]                     // WW[-14]
    eor $t2,$t0,$t4                        // SS2
    add $H,$H,$t1                          // TT2 = GG(E, F, G) + H + SS1 + Wj
    ror $F,$F,#13                          // F <<< 19
     eor $XTMP1.16b,$XTMP1.16b,$XTMP3.16b  // P1(X), X ^ (X <<< 15)
    ror $t3,$H,#23
    add $D,$D,$t2                          // FF(A, B, C) + D + SS2
    eor $H,$H,$H,ror#15
     eor $XTMP1.16b,$XTMP1.16b,$XTMP5.16b  // P1(X), X ^ (X <<< 15) ^ (X <<< 23)
    add $D,$D,$W                           // TT1 = FF(A, B, C) + D + SS2 + W'j
    eor $H,$H,$t3                          // P0(TT2)
___
}

sub ROUND_00_15_4()
{
    my ($X0,$X1,$X2,$X3,$A,$B,$C,$D,$E,$F,$G,$H) = @_;
$code.=<<___;
     mov $W,$X0.s[3]                       // W[-13]
    ror $t0,$A,#20                         // A <<< 12
     eor $X0.16b,$XTMP1.16b,$XTMP0.16b     // W[0],W[1],W[2],XXX
    eor $t1,$A,$B                          // A ^ B
    ldr $t3,[$TBL],#4                      // Tj <<< j
    add $t2,$t0,$E                         // (A <<< 12) + E
     mov $T0,$X0.s[0]                      // W[0]
    eor $t5,$E,$F                          // E ^ F
    eor $t1,$t1,$C                         // FF(A, B, C)
     mov $T1,$XTMP2.s[3]                   // W[-13] ^ W[-6]
    add $t4,$t2,$t3                        // (A <<< 12) + E + (Tj <<< j)
    eor $t5,$t5,$G                         // GG(E, F, G)
     mov $T2,$XTMP0.s[3]                   // (W[-10] <<< 7) ^ W[-3]
     eor $T1,$T1,$T0,ror#17                // Z = W[-13] ^ W[-6] ^ (W[0] <<< 15)
    add $H,$H,$W                           // H + Wj
    ror $t4,$t4,#25                        // SS1
    add $D,$t1,$D                          // FF(A, B, C) + D
     ror $T3,$T1,#17                       // Z <<< 15
    ror $B,$B,#23                          // B <<< 9
    add $t1,$t4,$t5                        // GG(E, F, G) + SS1
     eor $T1,$T1,$T1,ror#9                 // Z ^ (Z <<< 23)
     mov $W,$XFER.s[3]                     // WW[-13]
    eor $t2,$t0,$t4                        // SS2
    add $H,$H,$t1                          // TT2 = GG(E, F, G) + H + SS1 + Wj
    ror $F,$F,#13                          // F <<< 19
     eor $T1,$T1,$T3                       // Z ^ (Z <<< 15) ^ (Z <<< 23)
    ror $t3,$H,#23
    add $D,$D,$t2                          // FF(A, B, C) + D + SS2
    eor $H,$H,$H,ror#15
     eor $T2,$T1,$T2                       // W[3]
    add $D,$D,$W                           // TT1 = FF(A, B, C) + D + SS2 + W'j
    eor $H,$H,$t3                          // P0(TT2)
     mov $X0.s[3],$T2                      // W[0],W[1],W[2],W[3]
___
}


sub ROUND_16_51_1()
{
    my ($X0,$X1,$X2,$X3,$A,$B,$C,$D,$E,$F,$G,$H) = @_;
$code.=<<___;
     eor $XFER.16b,$X0.16b,$X1.16b         // WW
    ror $t0,$A,#20                         // A <<< 12
     ext $XTMP0.16b,$X0.16b,$X1.16b,#12    // (W[-13],W[-12],W[-11],XXX)
    orr $t1,$B,$C                          // B | C
    ldr $t3,[$TBL],#4                      // Tj <<< j
    add $t2,$t0,$E                         // (A <<< 12) + E
    and $T0,$B,$C                          // B & C
     shl $XTMP1.4s,$XTMP0.4s,#7            // ((W[-13],W[-12],W[-11],XXX) << 7)
    and $T1,$A,$t1                         // A & (B | C)
     mov $W,$X0.s[0]                       // W[-16]
    eor $t5,$F,$G                          // F ^ G
    orr $t1,$T0,$T1                        // FF(A, B, C)
    add $t4,$t2,$t3                        // (A <<< 12) + E + (Tj <<< j)
     ushr $XTMP2.4s,$XTMP0.4s,#25          // (W[-13],W[-12],W[-11],XXX) >> 25
    and $t5,$t5,$E                         // (F ^ G) & E
    add $H,$H,$W                           // H + Wj
    ror $t4,$t4,#25                        // SS1
     eor $XTMP0.16b,$XTMP1.16b,$XTMP2.16b  // (W[-13],W[-12],W[-11],XXX] <<< 17
    eor $t5,$t5,$G                         // GG(E, F, G)
    add $D,$t1,$D                          // FF(A, B, C) + D
    ror $B,$B,#23                          // B <<< 9
     ext $XTMP2.16b,$X2.16b,$X3.16b,#8     // (W[-6],W[-5],W[-4],XXX)
    add $t1,$t4,$t5                        // GG(E, F, G) + SS1
     mov $W,$XFER.s[0]                     // WW[-16]
    eor $t2,$t0,$t4                        // SS2
    add $H,$H,$t1                          // TT2 = GG(E, F, G) + H + SS1 + Wj
    ror $F,$F,#13                          // F <<< 19
     eor $XTMP0.16b,$XTMP0.16b,$XTMP2.16b  // (W[-6],W[-5],W[-4],XXX)^((W[-13],W[-12],W[-11],XXX) <<< 17)
    ror $t3,$H,#23
    add $D,$D,$t2                          // FF(A, B, C) + D + SS2
    eor $H,$H,$H,ror#15
     ext $XTMP1.16b,$X3.16b,$X2.16b,#4     // (W[-3],W[-2],W[-1],XXX)
    add $D,$D,$W                           // TT1 = FF(A, B, C) + D + SS2 + W'j
    eor $H,$H,$t3                          // P0(TT2)
___
}

sub ROUND_16_51_2()
{
    my ($X0,$X1,$X2,$X3,$A,$B,$C,$D,$E,$F,$G,$H) = @_;
$code.=<<___;
    ror $t0,$A,#20                         // A <<< 12
     shl $XTMP2.4s,$XTMP1.4s,#15           // (W[-3],W[-2],W[-1],XXX) << 15
    orr $t1,$B,$C                          // B | C
    ldr $t3,[$TBL],#4                      // Tj <<< j
    add $t2,$t0,$E                         // (A <<< 12) + E
    and $T0,$B,$C                          // B & C
     ushr $XTMP1.4s,$XTMP1.4s,#17          // (W[-3],W[-2],W[-1],XXX) >> 17
    and $T1,$A,$t1                         // A & (B | C)
     mov $W,$X0.s[1]                       // W[-15]
    eor $t5,$F,$G                          // F ^ G
    orr $t1,$T0,$T1                        // FF(A, B, C)
    add $t4,$t2,$t3                        // (A <<< 12) + E + (Tj <<< j)
     eor $XTMP1.16b,$XTMP1.16b,$XTMP2.16b  // (W[-3],W[-2],W[-1],XXX) <<< 15
    and $t5,$t5,$E                         // (F ^ G) & E
    add $H,$H,$W                           // H + Wj
    ror $t4,$t4,#25                        // SS1
     ext $XTMP2.16b,$X1.16b,$X2.16b,#12    // W[-9],W[-8],W[-7],W[-6]
    eor $t5,$t5,$G                         // GG(E, F, G)
    add $D,$t1,$D                          // FF(A, B, C) + D
    ror $B,$B,#23                          // B <<< 9
     eor $XTMP2.16b,$XTMP2.16b,$X0.16b     // (W[-9],W[-8],W[-7],W[-6]) ^ (W[-16],W[-15],W[-14],W[-13])
    add $t1,$t4,$t5                        // GG(E, F, G) + SS1
     mov $W,$XFER.s[1]                     // WW[-15]
    eor $t2,$t0,$t4                        // SS2
    add $H,$H,$t1                          // TT2 = GG(E, F, G) + H + SS1 + Wj
    ror $F,$F,#13                          // F <<< 19
     eor $XTMP1.16b,$XTMP1.16b,$XTMP2.16b  // (W[-9],W[-8],W[-7],W[-6]) ^ (W[-16],W[-15],W[-14],W[-13])^((W[-3],W[-2],W[-1],W[0]) <<< 15)
    ror $t3,$H,#23
    add $D,$D,$t2                          // FF(A, B, C) + D + SS2
    eor $H,$H,$H,ror#15
     shl $XTMP3.4s,$XTMP1.4s,#15           // P1(X), X << 15
    add $D,$D,$W                           // TT1 = FF(A, B, C) + D + SS2 + W'j
    eor $H,$H,$t3                          // P0(TT2)
___
}

sub ROUND_16_51_3()
{
    my ($X0,$X1,$X2,$X3,$A,$B,$C,$D,$E,$F,$G,$H) = @_;
$code.=<<___;
    ror $t0,$A,#20                         // A <<< 12
     ushr $XTMP4.4s,$XTMP1.4s,#17          // P1(X), X >> 17
    orr $t1,$B,$C                          // B | C
    ldr $t3,[$TBL],#4                      // Tj <<< j
    add $t2,$t0,$E                         // (A <<< 12) + E
    and $T0,$B,$C                          // B & C
     eor $XTMP3.16b,$XTMP3.16b,$XTMP4.16b  // P1(X), X <<< 15
    and $T1,$A,$t1                         // A & (B | C)
     mov $W,$X0.s[2]                       // W[-14]
    eor $t5,$F,$G                          // F ^ G
    orr $t1,$T0,$T1                        // FF(A, B, C)
    add $t4,$t2,$t3                        // (A <<< 12) + E + (Tj <<< j)
     shl $XTMP4.4s,$XTMP1.4s,#23           // P1(X), X << 23
    and $t5,$t5,$E                         // (F ^ G) & E
    add $H,$H,$W                           // H + Wj
    ror $t4,$t4,#25                        // SS1
     ushr $XTMP5.4s,$XTMP1.4s,#9           // P1(X), X >> 9
    eor $t5,$t5,$G                         // GG(E, F, G)
    add $D,$t1,$D                          // FF(A, B, C) + D
    ror $B,$B,#23                          // B <<< 9
     eor $XTMP5.16b,$XTMP4.16b,$XTMP5.16b  // P1(X), X << 23
    add $t1,$t4,$t5                        // GG(E, F, G) + SS1
     mov $W,$XFER.s[2]                     // WW[-14]
    eor $t2,$t0,$t4                        // SS2
    add $H,$H,$t1                          // TT2 = GG(E, F, G) + H + SS1 + Wj
    ror $F,$F,#13                          // F <<< 19
     eor $XTMP1.16b,$XTMP1.16b,$XTMP3.16b  // P1(X), X ^ (X <<< 15)
    ror $t3,$H,#23
    add $D,$D,$t2                          // FF(A, B, C) + D + SS2
    eor $H,$H,$H,ror#15
     eor $XTMP1.16b,$XTMP1.16b,$XTMP5.16b  // P1(X), X ^ (X <<< 15) ^ (X <<< 23)
    add $D,$D,$W                           // TT1 = FF(A, B, C) + D + SS2 + W'j
    eor $H,$H,$t3                          // P0(TT2)
___
}

sub ROUND_16_51_4()
{
    my ($X0,$X1,$X2,$X3,$A,$B,$C,$D,$E,$F,$G,$H) = @_;
$code.=<<___;
     mov $W,$X0.s[3]                       // W[-13]
    ror $t0,$A,#20                         // A <<< 12
     eor $X0.16b,$XTMP1.16b,$XTMP0.16b     // W[0],W[1],W[2],XXX
    orr $t1,$B,$C                          // B | C
    ldr $t3,[$TBL],#4                      // Tj <<< j
    add $t2,$t0,$E                         // (A <<< 12) + E
     mov $T0,$X0.s[0]                      // W[0]
    and $T3,$B,$C                          // B & C
    and $T4,$A,$t1                         // A & (B | C)
     mov $T1,$XTMP2.s[3]                   // W[-13] ^ W[-6]
    eor $t5,$F,$G                          // F ^ G
    orr $t1,$T3,$T4                        // FF(A, B, C)
     mov $T2,$XTMP0.s[3]                   // (W[-10] <<< 7) ^ W[-3]
     eor $T1,$T1,$T0,ror#17                // Z = W[-13] ^ W[-6] ^ (W[0] <<< 15)
    add $t4,$t2,$t3                        // (A <<< 12) + E + (Tj <<< j)
     ror $T3,$T1,#17                       // Z <<< 15
    and $t5,$t5,$E                         // (F ^ G) & E
    add $H,$H,$W                           // H + Wj
    ror $t4,$t4,#25                        // SS1
     eor $T1,$T1,$T1,ror#9                 // Z ^ (Z <<< 23)
    eor $t5,$t5,$G                         // GG(E, F, G)
    add $D,$t1,$D                          // FF(A, B, C) + D
    ror $B,$B,#23                          // B <<< 9
     mov $W,$XFER.s[3]                     // WW[-13]
    add $t1,$t4,$t5                        // GG(E, F, G) + SS1
    eor $t2,$t0,$t4                        // SS2
    add $H,$H,$t1                          // TT2 = GG(E, F, G) + H + SS1 + Wj
     eor $T1,$T1,$T3                       // Z ^ (Z <<< 15) ^ (Z <<< 23)
    ror $F,$F,#13                          // F <<< 19
    ror $t3,$H,#23
    add $D,$D,$t2                          // FF(A, B, C) + D + SS2
    eor $H,$H,$H,ror#15
     eor $T2,$T1,$T2                       // W[3]
    add $D,$D,$W                           // TT1 = FF(A, B, C) + D + SS2 + W'j
    eor $H,$H,$t3                          // P0(TT2)
     mov $X0.s[3],$T2                      // W[0],W[1],W[2],W[3]
___
}


sub ROUND_52_63_1()
{
    my ($X0,$X1,$X2,$X3,$A,$B,$C,$D,$E,$F,$G,$H) = @_;
$code.=<<___;
     eor $XFER.16b,$X0.16b,$X1.16b         // WW
    ror $t0,$A,#20                         // A <<< 12
    orr $t1,$B,$C                          // B | C
    ldr $t3,[$TBL],#4                      // Tj <<< j
    add $t2,$t0,$E                         // (A <<< 12) + E
    and $T0,$B,$C                          // B & C
    and $T1,$A,$t1                         // A & (B | C)
     mov $W,$X0.s[0]                       // W[-16]
    eor $t5,$F,$G                          // F ^ G
    orr $t1,$T0,$T1                        // FF(A, B, C)
    add $t4,$t2,$t3                        // (A <<< 12) + E + (Tj <<< j)
    and $t5,$t5,$E                         // (F ^ G) & E
    add $H,$H,$W                           // H + Wj
    ror $t4,$t4,#25                        // SS1
    eor $t5,$t5,$G                         // GG(E, F, G)
    add $D,$t1,$D                          // FF(A, B, C) + D
    ror $B,$B,#23                          // B <<< 9
    add $t1,$t4,$t5                        // GG(E, F, G) + SS1
     mov $W,$XFER.s[0]                     // WW[-16]
    eor $t2,$t0,$t4                        // SS2
    add $H,$H,$t1                          // TT2 = GG(E, F, G) + H + SS1 + Wj
    ror $F,$F,#13                          // F <<< 19
    ror $t3,$H,#23
    add $D,$D,$t2                          // FF(A, B, C) + D + SS2
    eor $H,$H,$H,ror#15
    add $D,$D,$W                           // TT1 = FF(A, B, C) + D + SS2 + W'j
    eor $H,$H,$t3                          // P0(TT2)
___
}

sub ROUND_52_63_2()
{
    my ($X0,$X1,$X2,$X3,$A,$B,$C,$D,$E,$F,$G,$H) = @_;
$code.=<<___;
    ror $t0,$A,#20                         // A <<< 12
    orr $t1,$B,$C                          // B | C
    ldr $t3,[$TBL],#4                      // Tj <<< j
    add $t2,$t0,$E                         // (A <<< 12) + E
    and $T0,$B,$C                          // B & C
    and $T1,$A,$t1                         // A & (B | C)
     mov $W,$X0.s[1]                       // W[-16]
    eor $t5,$F,$G                          // F ^ G
    orr $t1,$T0,$T1                        // FF(A, B, C)
    add $t4,$t2,$t3                        // (A <<< 12) + E + (Tj <<< j)
    and $t5,$t5,$E                         // (F ^ G) & E
    add $H,$H,$W                           // H + Wj
    ror $t4,$t4,#25                        // SS1
    eor $t5,$t5,$G                         // GG(E, F, G)
    add $D,$t1,$D                          // FF(A, B, C) + D
    ror $B,$B,#23                          // B <<< 9
    add $t1,$t4,$t5                        // GG(E, F, G) + SS1
     mov $W,$XFER.s[1]                     // WW[-16]
    eor $t2,$t0,$t4                        // SS2
    add $H,$H,$t1                          // TT2 = GG(E, F, G) + H + SS1 + Wj
    ror $F,$F,#13                          // F <<< 19
    ror $t3,$H,#23
    add $D,$D,$t2                          // FF(A, B, C) + D + SS2
    eor $H,$H,$H,ror#15
    add $D,$D,$W                           // TT1 = FF(A, B, C) + D + SS2 + W'j
    eor $H,$H,$t3                          // P0(TT2)
___
}

sub ROUND_52_63_3()
{
    my ($X0,$X1,$X2,$X3,$A,$B,$C,$D,$E,$F,$G,$H) = @_;
$code.=<<___;
    ror $t0,$A,#20                         // A <<< 12
    orr $t1,$B,$C                          // B | C
    ldr $t3,[$TBL],#4                      // Tj <<< j
    add $t2,$t0,$E                         // (A <<< 12) + E
    and $T0,$B,$C                          // B & C
    and $T1,$A,$t1                         // A & (B | C)
     mov $W,$X0.s[2]                       // W[-16]
    eor $t5,$F,$G                          // F ^ G
    orr $t1,$T0,$T1                        // FF(A, B, C)
    add $t4,$t2,$t3                        // (A <<< 12) + E + (Tj <<< j)
    and $t5,$t5,$E                         // (F ^ G) & E
    add $H,$H,$W                           // H + Wj
    ror $t4,$t4,#25                        // SS1
    eor $t5,$t5,$G                         // GG(E, F, G)
    add $D,$t1,$D                          // FF(A, B, C) + D
    ror $B,$B,#23                          // B <<< 9
    add $t1,$t4,$t5                        // GG(E, F, G) + SS1
     mov $W,$XFER.s[2]                     // WW[-16]
    eor $t2,$t0,$t4                        // SS2
    add $H,$H,$t1                          // TT2 = GG(E, F, G) + H + SS1 + Wj
    ror $F,$F,#13                          // F <<< 19
    ror $t3,$H,#23
    add $D,$D,$t2                          // FF(A, B, C) + D + SS2
    eor $H,$H,$H,ror#15
    add $D,$D,$W                           // TT1 = FF(A, B, C) + D + SS2 + W'j
    eor $H,$H,$t3                          // P0(TT2)
___
}

sub ROUND_52_63_4()
{
    my ($X0,$X1,$X2,$X3,$A,$B,$C,$D,$E,$F,$G,$H) = @_;
$code.=<<___;
    ror $t0,$A,#20                         // A <<< 12
    orr $t1,$B,$C                          // B | C
    ldr $t3,[$TBL],#4                      // Tj <<< j
    add $t2,$t0,$E                         // (A <<< 12) + E
    and $T0,$B,$C                          // B & C
    and $T1,$A,$t1                         // A & (B | C)
     mov $W,$X0.s[3]                       // W[-16]
    eor $t5,$F,$G                          // F ^ G
    orr $t1,$T0,$T1                        // FF(A, B, C)
    add $t4,$t2,$t3                        // (A <<< 12) + E + (Tj <<< j)
    and $t5,$t5,$E                         // (F ^ G) & E
    add $H,$H,$W                           // H + Wj
    ror $t4,$t4,#25                        // SS1
    eor $t5,$t5,$G                         // GG(E, F, G)
    add $D,$t1,$D                          // FF(A, B, C) + D
    ror $B,$B,#23                          // B <<< 9
    add $t1,$t4,$t5                        // GG(E, F, G) + SS1
     mov $W,$XFER.s[3]                     // WW[-16]
    eor $t2,$t0,$t4                        // SS2
    add $H,$H,$t1                          // TT2 = GG(E, F, G) + H + SS1 + Wj
    ror $F,$F,#13                          // F <<< 19
    ror $t3,$H,#23
    add $D,$D,$t2                          // FF(A, B, C) + D + SS2
    eor $H,$H,$H,ror#15
    add $D,$D,$W                           // TT1 = FF(A, B, C) + D + SS2 + W'j
    eor $H,$H,$t3                          // P0(TT2)
___
}

$code.=<<___;
#include "arm_arch.h"

.globl	sm3_compress_blocks
.type	sm3_compress_blocks,%function
.align	5
sm3_compress_blocks:
    .inst 0xd503233f                       // paciasp
    stp x29,x30,[sp,#-96]!
    add x29,sp,#0
    stp x19,x20,[sp,#16]
    stp x21,x22,[sp,#32]
    stp x23,x24,[sp,#48]
    stp x25,x26,[sp,#64]
    stp x27,x28,[sp,#80]
    sub	sp,sp,#32

    ldp $a,$b,[$digest]
    ldp $c,$d,[$digest,#8]
    mov $V0,$a
    mov $V1,$b
    mov $V2,$c
    mov $V3,$d
    ldp $e,$f,[$digest,#16]
    ldp $g,$h,[$digest,#24]
    mov $V4,$e
    mov $V5,$f
    mov $V6,$g
    mov $V7,$h
    str $digest,[sp]

.Lneon_loop:
    subs $nb,$nb,#1
    blo .Ldone_hash
    ld1 {$M0.16b,$M1.16b,$M2.16b,$M3.16b},[$block],#64
#ifndef __ARMEB__
    # le -> be
    rev32 $M0.16b,$M0.16b
    rev32 $M1.16b,$M1.16b
    rev32 $M2.16b,$M2.16b
    rev32 $M3.16b,$M3.16b
#endif
    adr $TBL,.LK256
    stp $block,$nb,[sp,#8]
___

# first 16 rounds
for($i=0;$i<4;$i++) {
    &ROUND_00_15_1(@M,@V1,@V2);
    unshift(@V1,pop(@V1));
    unshift(@V2,pop(@V2));
    &ROUND_00_15_2(@M,@V1,@V2);
    unshift(@V1,pop(@V1));
    unshift(@V2,pop(@V2));
    &ROUND_00_15_3(@M,@V1,@V2);
    unshift(@V1,pop(@V1));
    unshift(@V2,pop(@V2));
    &ROUND_00_15_4(@M,@V1,@V2);
    unshift(@V1,pop(@V1));
    unshift(@V2,pop(@V2));

    push(@M,shift(@M));
}

# second 36 rounds
for($i=0;$i<9;$i++) {
    &ROUND_16_51_1(@M,@V1,@V2);
    unshift(@V1,pop(@V1));
    unshift(@V2,pop(@V2));
    &ROUND_16_51_2(@M,@V1,@V2);
    unshift(@V1,pop(@V1));
    unshift(@V2,pop(@V2));
    &ROUND_16_51_3(@M,@V1,@V2);
    unshift(@V1,pop(@V1));
    unshift(@V2,pop(@V2));
    &ROUND_16_51_4(@M,@V1,@V2);
    unshift(@V1,pop(@V1));
    unshift(@V2,pop(@V2));

    push(@M,shift(@M));
}

# third 12 rounds
for($i=0;$i<3;$i++) {
    &ROUND_52_63_1(@M,@V1,@V2);
    unshift(@V1,pop(@V1));
    unshift(@V2,pop(@V2));
    &ROUND_52_63_2(@M,@V1,@V2);
    unshift(@V1,pop(@V1));
    unshift(@V2,pop(@V2));
    &ROUND_52_63_3(@M,@V1,@V2);
    unshift(@V1,pop(@V1));
    unshift(@V2,pop(@V2));
    &ROUND_52_63_4(@M,@V1,@V2);
    unshift(@V1,pop(@V1));
    unshift(@V2,pop(@V2));

    push(@M,shift(@M));
}

$code.=<<___;
    ldp $block,$nb,[sp,#8]
    eor $a,$a,$V0
    eor $b,$b,$V1
    eor $c,$c,$V2
    eor $d,$d,$V3
    mov $V0,$a
    mov $V1,$b
    mov $V2,$c
    mov $V3,$d
    eor $e,$e,$V4
    eor $f,$f,$V5
    eor $g,$g,$V6
    eor $h,$h,$V7
    mov $V4,$e
    mov $V5,$f
    mov $V6,$g
    mov $V7,$h
    b .Lneon_loop

.Ldone_hash:
    ldr $digest,[sp]
    stp $V0,$V1,[$digest]
    stp $V2,$V3,[$digest,#8]
    stp $V4,$V5,[$digest,#16]
    stp $V6,$V7,[$digest,#24]

    ldp x19,x20,[x29,#16]
     add sp,x29,#0
    ldp x21,x22,[x29,#32]
    ldp x23,x24,[x29,#48]
    ldp x25,x26,[x29,#64]
    ldp x27,x28,[x29,#80]
    ldp x29,x30,[sp],#96
    .inst 0xd50323bf             // autiasp
    ret
.size	sm3_compress_blocks,.-sm3_compress_blocks
___

print $code;
close STDOUT;
