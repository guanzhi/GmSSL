/* This is an implementation of the encryption algorithm:               */   
/*         Serpent by Ross Anderson, Eli Biham and Lars Knudsen         */   
/* which is a candidate algorithm in the Advanced Encryption Standard   */   
/* programme of the US National Institute of Standards and Technology.  */   
/* Copyright in this implementation is held by Dou Qinglin.   but I     */   
/* hereby give permission for its free direct or derivative use subject */   
/* to acknowledgment of its origin and compliance with any conditions   */   
/* that the originators of the algorithm place on its exploitation.     */   
   
#include <stdio.h>
#include <stdlib.h>
#include "myserpent.h"

#define IN
#define OUT
void linear(IN unsigned long int *li_0,IN unsigned long int *li_1,IN unsigned long int *li_2,IN unsigned long int *li_3,OUT unsigned long int *lo_0,OUT unsigned long int *lo_1,OUT unsigned long int *lo_2,OUT unsigned long int *lo_3);
void IP(IN unsigned long int *ip_i0,IN unsigned long int *ip_i1,IN unsigned long int *ip_i2,IN unsigned long int *ip_i3,OUT unsigned long int *ip_o0,OUT unsigned long int *ip_o1,OUT unsigned long int *ip_o2,OUT unsigned long int *ip_o3);
void FP(IN unsigned long int *fp_i0,IN unsigned long int *fp_i1,IN unsigned long int *fp_i2,IN unsigned long int *fp_i3,OUT unsigned long int *fp_o0,OUT unsigned long int *fp_o1,OUT unsigned long int *fp_o2,OUT unsigned long int *fp_o3);

volatile unsigned long int  takbit_in0,takbit_in1,takbit_in2,takbit_in3;

unsigned char takebit(unsigned char bit_num){
	unsigned char bit_out;
	if      (bit_num< 32)  bit_out = ((takbit_in0<< bit_num    )&0x80000000)>>31;
	else if (bit_num< 64)  bit_out = ((takbit_in1<<(bit_num-32))&0x80000000)>>31;
	else if (bit_num< 96)  bit_out = ((takbit_in2<<(bit_num-64))&0x80000000)>>31;
	else if (bit_num< 128) bit_out = ((takbit_in3<<(bit_num-96))&0x80000000)>>31;
	else ;
	return	(bit_out & 0x00000001);
}

//sbox involking func, each block use 1 sbox 32 times by involking this func for 4 times
unsigned long int sb(char sb_num,unsigned long int sb_in_long){
	char sb_i[8];
	char sb_o[8];
	unsigned long int sb_out_long;
	char cnt;
//data div, 32bit input divide into 8 parts, each 4bit 
	sb_i[0] = (sb_in_long>>28) & 0x0f; //  0~3f
	sb_i[1] = (sb_in_long>>24) & 0x0f; //  4~7
	sb_i[2] = (sb_in_long>>20) & 0x0f; //  8~11
	sb_i[3] = (sb_in_long>>16) & 0x0f; // 12~15
	sb_i[4] = (sb_in_long>>12) & 0x0f; // 16~19
	sb_i[5] = (sb_in_long>> 8) & 0x0f; // 20~23
	sb_i[6] = (sb_in_long>> 4) & 0x0f; // 24~27
	sb_i[7] = (sb_in_long    ) & 0x0f; // 28~31
	//judge which sbox to use,and get 8 outputs of 8 independent 
	switch (sb_num)
	{
		case  0:	for (cnt = 0; cnt < 8; cnt++) sb_o[cnt] = sb0(sb_i[cnt] );break;
		case  1:	for (cnt = 0; cnt < 8; cnt++) sb_o[cnt] = sb1(sb_i[cnt] );break;
		case  2:	for (cnt = 0; cnt < 8; cnt++) sb_o[cnt] = sb2(sb_i[cnt] );break;
		case  3:	for (cnt = 0; cnt < 8; cnt++) sb_o[cnt] = sb3(sb_i[cnt] );break;
		case  4:	for (cnt = 0; cnt < 8; cnt++) sb_o[cnt] = sb4(sb_i[cnt] );break;
		case  5:	for (cnt = 0; cnt < 8; cnt++) sb_o[cnt] = sb5(sb_i[cnt] );break;
		case  6:	for (cnt = 0; cnt < 8; cnt++) sb_o[cnt] = sb6(sb_i[cnt] );break;
		case  7:	for (cnt = 0; cnt < 8; cnt++) sb_o[cnt] = sb7(sb_i[cnt] );break;
		default: for (cnt = 0; cnt < 8; cnt++) sb_o[cnt] = 0x0;            break;
	}
	//combine the sbox output together
	sb_out_long = (sb_o[0]<<28) + (sb_o[1]<<24) + (sb_o[2]<<20) + (sb_o[3]<<16) + (sb_o[4]<<12) + (sb_o[5]<<8) + (sb_o[6]<<4) + sb_o[7];
	
	return sb_out_long;
}

//define the sbox0~7 un-linear logic
char sb0(char sb0_in){
	char sb0_o;
	switch (sb0_in){
		case 0x0: sb0_o= 3 ;break;
		case 0x1: sb0_o= 8 ;break;
		case 0x2: sb0_o= 15;break;
		case 0x3: sb0_o= 1 ;break;
		case 0x4: sb0_o= 10;break;
		case 0x5: sb0_o= 6 ;break;
		case 0x6: sb0_o= 5 ;break;
		case 0x7: sb0_o= 11;break;
		case 0x8: sb0_o= 14;break;
		case 0x9: sb0_o= 13;break;
		case 0xA: sb0_o= 4 ;break;
		case 0xB: sb0_o= 2 ;break;
		case 0xC: sb0_o= 7 ;break;
		case 0xD: sb0_o= 0 ;break;
		case 0xE: sb0_o= 9 ;break;
		case 0xF: sb0_o= 12;break;
	default:  sb0_o= 0 ;break;		
	}
	return sb0_o;
}

char sb1(char sb1_in){
	char sb1_o;
	switch (sb1_in){
		case 0x0: sb1_o= 15;break;
		case 0x1: sb1_o= 12;break;
		case 0x2: sb1_o= 2 ;break;
		case 0x3: sb1_o= 7 ;break;
		case 0x4: sb1_o= 9 ;break;
		case 0x5: sb1_o= 0 ;break;
		case 0x6: sb1_o= 5 ;break;
		case 0x7: sb1_o= 10;break;
		case 0x8: sb1_o= 1 ;break;
		case 0x9: sb1_o= 11;break;
		case 0xA: sb1_o= 14;break;
		case 0xB: sb1_o= 8 ;break;
		case 0xC: sb1_o= 6 ;break;
		case 0xD: sb1_o= 13;break;
		case 0xE: sb1_o= 3 ;break;
		case 0xF: sb1_o= 4 ;break;
	default:  sb1_o= 0 ;break;		
	}
	return sb1_o;
}

char sb2(char sb2_in){
	char sb2_o;
	switch (sb2_in){
		case 0x0: sb2_o= 8 ;break;
		case 0x1: sb2_o= 6 ;break;
		case 0x2: sb2_o= 7 ;break;
		case 0x3: sb2_o= 9 ;break;
		case 0x4: sb2_o= 3 ;break;
		case 0x5: sb2_o= 12;break;
		case 0x6: sb2_o= 10;break;
		case 0x7: sb2_o= 15;break;
		case 0x8: sb2_o= 13;break;
		case 0x9: sb2_o= 1 ;break;
		case 0xA: sb2_o= 14;break;
		case 0xB: sb2_o= 4 ;break;
		case 0xC: sb2_o= 0 ;break;
		case 0xD: sb2_o= 11;break;
		case 0xE: sb2_o= 5 ;break;
		case 0xF: sb2_o= 2 ;break;
	default:  sb2_o= 0 ;break;	
	}
	return sb2_o;
}
	
char sb3(char sb3_in){
	char sb3_o;
	switch (sb3_in){
		case 0x0: sb3_o= 0 ;break;
		case 0x1: sb3_o= 15;break;
		case 0x2: sb3_o= 11;break;
		case 0x3: sb3_o= 8 ;break;
		case 0x4: sb3_o= 12;break;
		case 0x5: sb3_o= 9 ;break;
		case 0x6: sb3_o= 6 ;break;
		case 0x7: sb3_o= 3 ;break;
		case 0x8: sb3_o= 13;break;
		case 0x9: sb3_o= 1 ;break;
		case 0xA: sb3_o= 2 ;break;
		case 0xB: sb3_o= 4 ;break;
		case 0xC: sb3_o= 10;break;
		case 0xD: sb3_o= 7 ;break;
		case 0xE: sb3_o= 5 ;break;
		case 0xF: sb3_o= 14;break;
	default:  sb3_o= 0 ;break;
	}
	return sb3_o;
}
	
char sb4(char sb4_in){
	char sb4_o;
	switch (sb4_in){
		case 0x0: sb4_o= 1 ;break;
		case 0x1: sb4_o= 15;break;
		case 0x2: sb4_o= 8 ;break;
		case 0x3: sb4_o= 3 ;break;
		case 0x4: sb4_o= 12;break;
		case 0x5: sb4_o= 0 ;break;
		case 0x6: sb4_o= 11;break;
		case 0x7: sb4_o= 6 ;break;
		case 0x8: sb4_o= 2 ;break;
		case 0x9: sb4_o= 5 ;break;
		case 0xA: sb4_o= 4 ;break;
		case 0xB: sb4_o= 10;break;
		case 0xC: sb4_o= 9 ;break;
		case 0xD: sb4_o= 14;break;
		case 0xE: sb4_o= 7 ;break;
		case 0xF: sb4_o= 13;break;
	default:  sb4_o= 0;	break;	
	}
	return sb4_o;
}	
	
char sb5(char sb5_in){
	char sb5_o;
	switch (sb5_in){
		case 0x0: sb5_o= 15;break;
		case 0x1: sb5_o= 5 ;break;
		case 0x2: sb5_o= 2 ;break;
		case 0x3: sb5_o= 11;break;
		case 0x4: sb5_o= 4 ;break;
		case 0x5: sb5_o= 10;break;
		case 0x6: sb5_o= 9 ;break;
		case 0x7: sb5_o= 12;break;
		case 0x8: sb5_o= 0 ;break;
		case 0x9: sb5_o= 3 ;break;
		case 0xA: sb5_o= 14;break;
		case 0xB: sb5_o= 8 ;break;
		case 0xC: sb5_o= 13;break;
		case 0xD: sb5_o= 6 ;break;
		case 0xE: sb5_o= 7 ;break;
		case 0xF: sb5_o= 1 ;break;
	default:  sb5_o= 0;	break;
	}
	return sb5_o;
}		
	
char sb6(char sb6_in){
	char sb6_o;
	switch (sb6_in){
		case 0x0: sb6_o= 7 ;break;
		case 0x1: sb6_o= 2 ;break;
		case 0x2: sb6_o= 12;break;
		case 0x3: sb6_o= 5 ;break;
		case 0x4: sb6_o= 8 ;break;
		case 0x5: sb6_o= 4 ;break;
		case 0x6: sb6_o= 6 ;break;
		case 0x7: sb6_o= 11;break;
		case 0x8: sb6_o= 14;break;
		case 0x9: sb6_o= 9 ;break;
		case 0xA: sb6_o= 1 ;break;
		case 0xB: sb6_o= 15;break;
		case 0xC: sb6_o= 13;break;
		case 0xD: sb6_o= 3 ;break;
		case 0xE: sb6_o= 10;break;
		case 0xF: sb6_o= 0 ;break;
	default:  sb6_o= 0 ;break;		
	}
    return sb6_o;
}			
	
char sb7(char sb7_in){
	char sb7_o;
	switch (sb7_in){
		case 0x0: sb7_o= 1 ;break;
		case 0x1: sb7_o= 13;break;
		case 0x2: sb7_o= 15;break;
		case 0x3: sb7_o= 0 ;break;
		case 0x4: sb7_o= 14;break;
		case 0x5: sb7_o= 8 ;break;
		case 0x6: sb7_o= 2 ;break;
		case 0x7: sb7_o= 11;break;
		case 0x8: sb7_o= 7 ;break;
		case 0x9: sb7_o= 4 ;break;
		case 0xA: sb7_o= 12;break;
		case 0xB: sb7_o= 10;break;
		case 0xC: sb7_o= 9 ;break;
		case 0xD: sb7_o= 3 ;break;
		case 0xE: sb7_o= 5 ;break;
		case 0xF: sb7_o= 6 ;break;
	default:  sb7_o= 0 ;break;		
	}
	return sb7_o;
}			

//initial permutation
void IP(IN unsigned long int *ip_i0,IN unsigned long int *ip_i1,IN unsigned long int *ip_i2,IN unsigned long int *ip_i3,OUT unsigned long int *ip_o0,OUT unsigned long int *ip_o1,OUT unsigned long int *ip_o2,OUT unsigned long int *ip_o3){
	unsigned long int tmp_0,tmp_1,tmp_2,tmp_3;
	takbit_in0 = *ip_i0;
	takbit_in1 = *ip_i1;
	takbit_in2 = *ip_i2;
	takbit_in3 = *ip_i3;
	//execute takbit function 
	tmp_0 = (takebit(120)<<31) + (takebit( 88)<<30) + (takebit( 56)<<29) + (takebit( 24)<<28) + (takebit(121)<<27) + (takebit( 89)<<26) + (takebit( 57)<<25) + (takebit( 25)<<24) + (takebit(122)<<23) + (takebit( 90)<<22) + (takebit( 58)<<21) + (takebit( 26)<<20) + (takebit(123)<<19) + (takebit( 91)<<18) + (takebit( 59)<<17) + (takebit( 27)<<16) + (takebit(124)<<15) + (takebit( 92)<<14) + (takebit( 60)<<13) + (takebit( 28)<<12) + (takebit(125)<<11) + (takebit( 93)<<10) + (takebit( 61)<<9 ) + (takebit( 29)<<8 ) + (takebit(126)<<7 ) + (takebit( 94)<<6 ) + (takebit( 62)<<5 ) + (takebit( 30)<<4 ) + (takebit(127)<<3 ) + (takebit( 95)<<2 ) + (takebit( 63)<<1 ) + (takebit( 31)    ); 
	tmp_1 = (takebit(112)<<31) + (takebit( 80)<<30) + (takebit( 48)<<29) + (takebit( 16)<<28) + (takebit(113)<<27) + (takebit( 81)<<26) + (takebit( 49)<<25) + (takebit( 17)<<24) + (takebit(114)<<23) + (takebit( 82)<<22) + (takebit( 50)<<21) + (takebit( 18)<<20) + (takebit(115)<<19) + (takebit( 83)<<18) + (takebit( 51)<<17) + (takebit( 19)<<16) + (takebit(116)<<15) + (takebit( 84)<<14) + (takebit( 52)<<13) + (takebit( 20)<<12) + (takebit(117)<<11) + (takebit( 85)<<10) + (takebit( 53)<<9 ) + (takebit( 21)<<8 ) + (takebit(118)<<7 ) + (takebit( 86)<<6 ) + (takebit( 54)<<5 ) + (takebit( 22)<<4 ) + (takebit(119)<<3 ) + (takebit( 87)<<2 ) + (takebit( 55)<<1 ) + (takebit( 23)    ); 
	tmp_2 = (takebit(104)<<31) + (takebit( 72)<<30) + (takebit( 40)<<29) + (takebit(  8)<<28) + (takebit(105)<<27) + (takebit( 73)<<26) + (takebit( 41)<<25) + (takebit(  9)<<24) + (takebit(106)<<23) + (takebit( 74)<<22) + (takebit( 42)<<21) + (takebit( 10)<<20) + (takebit(107)<<19) + (takebit( 75)<<18) + (takebit( 43)<<17) + (takebit( 11)<<16) + (takebit(108)<<15) + (takebit( 76)<<14) + (takebit( 44)<<13) + (takebit( 12)<<12) + (takebit(109)<<11) + (takebit( 77)<<10) + (takebit( 45)<<9 ) + (takebit( 13)<<8 ) + (takebit(110)<<7 ) + (takebit( 78)<<6 ) + (takebit( 46)<<5 ) + (takebit( 14)<<4 ) + (takebit(111)<<3 ) + (takebit( 79)<<2 ) + (takebit( 47)<<1 ) + (takebit( 15)    ); 
	tmp_3 = (takebit( 96)<<31) + (takebit( 64)<<30) + (takebit( 32)<<29) + (takebit(  0)<<28) + (takebit( 97)<<27) + (takebit( 65)<<26) + (takebit( 33)<<25) + (takebit(  1)<<24) + (takebit( 98)<<23) + (takebit( 66)<<22) + (takebit( 34)<<21) + (takebit(  2)<<20) + (takebit( 99)<<19) + (takebit( 67)<<18) + (takebit( 35)<<17) + (takebit(  3)<<16) + (takebit(100)<<15) + (takebit( 68)<<14) + (takebit( 36)<<13) + (takebit(  4)<<12) + (takebit(101)<<11) + (takebit( 69)<<10) + (takebit( 37)<<9 ) + (takebit(  5)<<8 ) + (takebit(102)<<7 ) + (takebit( 70)<<6 ) + (takebit( 38)<<5 ) + (takebit(  6)<<4 ) + (takebit(103)<<3 ) + (takebit( 71)<<2 ) + (takebit( 39)<<1 ) + (takebit(  7)    ); 
	//write data to sb_in[]
	*ip_o0  = tmp_0;                              
	*ip_o1  = tmp_1;                              
	*ip_o2  = tmp_2;                              
	*ip_o3  = tmp_3;
}

//initial permutation
void FP(IN unsigned long int *fp_i0,IN unsigned long int *fp_i1,IN unsigned long int *fp_i2,IN unsigned long int *fp_i3,OUT unsigned long int *fp_o0,OUT unsigned long int *fp_o1,OUT unsigned long int *fp_o2,OUT unsigned long int *fp_o3){
	unsigned long int tmp_0,tmp_1,tmp_2,tmp_3;
	takbit_in0 = *fp_i0;
	takbit_in1 = *fp_i1;
	takbit_in2 = *fp_i2;
	takbit_in3 = *fp_i3;
	//execute takbit function
	tmp_3 = (takebit(96)<<31) + (takebit(100 )<<30) + (takebit(104 )<<29) + (takebit(108 )<<28) + (takebit(112 )<<27) + (takebit(116 )<<26) + (takebit(120 )<<25) + (takebit(124 )<<24) + (takebit(64)<<23) + (takebit(68  )<<22) + (takebit(72  )<<21) + (takebit(76  )<<20) + (takebit(80  )<<19) + (takebit(84  )<<18) + (takebit(88  )<<17) + (takebit(92  )<<16) + (takebit(32)<<15) + (takebit(36  )<<14) + (takebit(40  )<<13) + (takebit(44  )<<12) + (takebit(48  )<<11) + (takebit(52  )<<10) + (takebit(56  )<<9) + (takebit(60  )<<8) + (takebit(0 )<<7) + (takebit( 4  )<<6) + (takebit( 8  )<<5) + (takebit(12  )<<4) + (takebit(16  )<<3) + (takebit(20  )<<2) + (takebit(24  )<<1) + takebit(28  );   
	tmp_2 = (takebit(97)<<31) + (takebit(101 )<<30) + (takebit(105 )<<29) + (takebit(109 )<<28) + (takebit(113 )<<27) + (takebit(117 )<<26) + (takebit(121 )<<25) + (takebit(125 )<<24) + (takebit(65)<<23) + (takebit(69  )<<22) + (takebit(73  )<<21) + (takebit(77  )<<20) + (takebit(81  )<<19) + (takebit(85  )<<18) + (takebit(89  )<<17) + (takebit(93  )<<16) + (takebit(33)<<15) + (takebit(37  )<<14) + (takebit(41  )<<13) + (takebit(45  )<<12) + (takebit(49  )<<11) + (takebit(53  )<<10) + (takebit(57  )<<9) + (takebit(61  )<<8) + (takebit(1 )<<7) + (takebit( 5  )<<6) + (takebit( 9  )<<5) + (takebit(13  )<<4) + (takebit(17  )<<3) + (takebit(21  )<<2) + (takebit(25  )<<1) + takebit(29  );   
	tmp_1 = (takebit(98)<<31) + (takebit(102 )<<30) + (takebit(106 )<<29) + (takebit(110 )<<28) + (takebit(114 )<<27) + (takebit(118 )<<26) + (takebit(122 )<<25) + (takebit(126 )<<24) + (takebit(66)<<23) + (takebit(70  )<<22) + (takebit(74  )<<21) + (takebit(78  )<<20) + (takebit(82  )<<19) + (takebit(86  )<<18) + (takebit(90  )<<17) + (takebit(94  )<<16) + (takebit(34)<<15) + (takebit(38  )<<14) + (takebit(42  )<<13) + (takebit(46  )<<12) + (takebit(50  )<<11) + (takebit(54  )<<10) + (takebit(58  )<<9) + (takebit(62  )<<8) + (takebit(2 )<<7) + (takebit( 6  )<<6) + (takebit(10  )<<5) + (takebit(14  )<<4) + (takebit(18  )<<3) + (takebit(22  )<<2) + (takebit(26  )<<1) + takebit(30  );   
	tmp_0 = (takebit(99)<<31) + (takebit(103 )<<30) + (takebit(107 )<<29) + (takebit(111 )<<28) + (takebit(115 )<<27) + (takebit(119 )<<26) + (takebit(123 )<<25) + (takebit(127 )<<24) + (takebit(67)<<23) + (takebit(71  )<<22) + (takebit(75  )<<21) + (takebit(79  )<<20) + (takebit(83  )<<19) + (takebit(87  )<<18) + (takebit(91  )<<17) + (takebit(95  )<<16) + (takebit(35)<<15) + (takebit(39  )<<14) + (takebit(43	 )<<13) + (takebit(47  )<<12) + (takebit(51	 )<<11) + (takebit(55	 )<<10) + (takebit(59	 )<<9) + (takebit(63	)<<8) + (takebit(3 )<<7) + (takebit( 7  )<<6) + (takebit(11  )<<5) + (takebit(15  )<<4) + (takebit(19  )<<3) + (takebit(23  )<<2) + (takebit(27  )<<1) + takebit(31  ); 	
	//data out
	*fp_o0 = tmp_0;                              
	*fp_o1 = tmp_1;                              
	*fp_o2 = tmp_2;                              
	*fp_o3 = tmp_3;
}

void linear(IN unsigned long int *li_0,IN unsigned long int *li_1,IN unsigned long int *li_2,IN unsigned long int *li_3,OUT unsigned long int *lo_0,OUT unsigned long int *lo_1,OUT unsigned long int *lo_2,OUT unsigned long int *lo_3){
	unsigned long int tmp_0,tmp_1,tmp_2,tmp_3;
	tmp_0 = *li_0;
	tmp_1 = *li_1;
	tmp_2 = *li_2;
	tmp_3 = *li_3;
	
	tmp_0  = rotl(tmp_0, 13);
	tmp_2  = rotl(tmp_2, 3);
	tmp_1  = tmp_1 ^ tmp_0 ^ tmp_2;
	tmp_3  = tmp_3 ^ tmp_2 ^ (tmp_0 << 3); 
	tmp_1  = rotl(tmp_1, 1);
	tmp_3  = rotl(tmp_3, 7);
	tmp_0  = tmp_0 ^ tmp_1 ^ tmp_3;
	tmp_2  = tmp_2 ^ tmp_3 ^ (tmp_1 << 7);
	tmp_0  = rotl(tmp_0, 5);
	tmp_2  = rotl(tmp_2, 22);
	
	*lo_0  = tmp_0;                              
	*lo_1  = tmp_1;                              
	*lo_2  = tmp_2;                              
	*lo_3  = tmp_3;
}


}
