#ifndef MYSERPENT_H 
#define MYSERPENT_H
unsigned char takebit(unsigned char bit_num);
unsigned long int sb(char sb_num,unsigned long int sb_in_long);
void linear(IN unsigned long int *li_0,IN unsigned long int *li_1,IN unsigned long int *li_2,IN unsigned long int *li_3,OUT unsigned long int *lo_0,OUT unsigned long int *lo_1,OUT unsigned long int *lo_2,OUT unsigned long int *lo_3);
void IP(IN unsigned long int *ip_i0,IN unsigned long int *ip_i1,IN unsigned long int *ip_i2,IN unsigned long int *ip_i3,OUT unsigned long int *ip_o0,OUT unsigned long int *ip_o1,OUT unsigned long int *ip_o2,OUT unsigned long int *ip_o3);
void FP(IN unsigned long int *fp_i0,IN unsigned long int *fp_i1,IN unsigned long int *fp_i2,IN unsigned long int *fp_i3,OUT unsigned long int *fp_o0,OUT unsigned long int *fp_o1,OUT unsigned long int *fp_o2,OUT unsigned long int *fp_o3);
extern char sb0(char sb0_in);
extern char sb1(char sb1_in);
extern char sb2(char sb2_in);
extern char sb3(char sb3_in);
extern char sb4(char sb4_in);
extern char sb5(char sb5_in);
extern char sb6(char sb6_in);
extern char sb7(char sb7_in);
#define rotl(x,n)    (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))
#define rotr(x,n)    (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))

#endif
