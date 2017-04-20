#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../e_os.h"

#ifdef OPENSSL_NO_SERPENT
int main(int argc, char **argv)
{
	printf("No Serpent support\n");
	return 0;
}
#else

#include <openssl/serpent.h>

int main(int argc, char* argv[]){
    
	unsigned long int key_0,key_1,key_2,key_3; //128bit key input
	int i;
	unsigned long int p_0,p_1,p_2,p_3; //plain data in 
	unsigned long int c_0,c_1,c_2,c_3; //cipher data out
	unsigned long int wi[8] = {0}; //pre_key -8~-1
	unsigned long int w[132] = {0};//pre_key 0~131
	unsigned long int sb_in[132] = {0}; //sbox input after data_twist1
	unsigned long int sb_out[132] = {0};//sbox output 
	unsigned long int k[132] = {0}; //sub_key 
	
	unsigned long int b[132]      = {0}; //round input and result
	unsigned long int xor[132]    = {0}; //round data after xor
	unsigned long int sbox[132]   = {0}; //round data after sbox
	unsigned long int li[132]     = {0}; //round data for linear transformation input,sbox output after FP 
	unsigned long int lo[132]     = {0}; //round data for linear transformation output,will goto IP 
	
	unsigned long int tmp_0,tmp_4,tmp_5;
	//here we start to record detail data
	FILE *fp;
	fp = fopen("serpent_data.sti","w");
	
	tmp_4 = 0x1;
	
	//detail data initial 
	while(1){
	for( i = 0; i < 132; i++){
  	    w[i]      = 0x0;
  	    sb_in[i]  = 0x0;
  	    sb_out[i] = 0x0;
  	    k[i]      = 0x0;
  	    b[i]      = 0x0;
  	    xor[i]    = 0x0;
  	    sbox[i]   = 0x0;
  	    li[i]     = 0x0;
  	    lo[i]     = 0x0;
    }

//step 0, key & plain data assignment

	printf("============================================ \n");
	printf("=======SERPENT-1 START, RUN_CNT = %d ======= \n",tmp_4);
	printf("============================================ \n");
	printf("=======INPUT KEYS======= \n");
	printf("=======128bit key======= \n");
	
	printf("PLEASE INPUT KEY_0 IN HEX \n");  scanf_s("%x",&key_0);
	printf("PLEASE INPUT KEY_1 IN HEX \n");  scanf_s("%x",&key_1);
	printf("PLEASE INPUT KEY_2 IN HEX \n");  scanf_s("%x",&key_2);
	printf("PLEASE INPUT KEY_3 IN HEX \n");  scanf_s("%x",&key_3);
	
	printf("PLEASE INPUT P_0 IN HEX \n");	scanf_s("%x",&p_0);
	printf("PLEASE INPUT P_1 IN HEX \n");	scanf_s("%x",&p_1);
	printf("PLEASE INPUT P_2 IN HEX \n");	scanf_s("%x",&p_2);
	printf("PLEASE INPUT P_3 IN HEX \n");	scanf_s("%x",&p_3);
	
//step 1, sub-key generation
//setp 1-1, generate 256bit full-length key and start to generate wi[0]~wi[7]

	wi[0] = key_0;
	wi[1] = key_1;
	wi[2] = key_2;
	wi[3] = key_3;
	//padding the key to 256 bit
	wi[4] = 0x00000000;		
	wi[5] = 0x00000000;
	wi[6] = 0x00000000;
	wi[7] = 0x80000000;
	
//setp 1-2, generate w[0]~w[7] with wi[0]~wi[7]
//w[i]=(w[i-8]^w[i-5]^w[i-3]^w[i-1]^phai^i)<<<11
//w[-8]-->wi[0]
//w[-7]-->wi[1]
//w[-6]-->wi[2]
//w[-5]-->wi[3]
//w[-4]-->wi[4]
//w[-3]-->wi[5]
//w[-2]-->wi[6]
//w[-1]-->wi[7]

//w[0]
	tmp_0 = wi[0] ^ wi[3] ^ wi[5] ^ wi[7] ^ 0x9e3779b9 ^ 0x0;  
	w[0] = (tmp_0 << 11) | (tmp_0 >> 21);    
//w[1]
	tmp_0 = wi[1] ^ wi[4] ^ wi[6] ^  w[0] ^ 0x9e3779b9 ^ 0x1;  
	w[1] = (tmp_0 << 11) | (tmp_0 >> 21);    
//w[2]
	tmp_0 = wi[2] ^ wi[5] ^ wi[7] ^  w[1] ^ 0x9e3779b9 ^ 0x2;  
	w[2] = (tmp_0 << 11) | (tmp_0 >> 21);    
//w[3]
	tmp_0 = wi[3] ^ wi[6] ^  w[0] ^  w[2] ^ 0x9e3779b9 ^ 0x3;  
	w[3] = (tmp_0 << 11) | (tmp_0 >> 21);    
//w[4]
	tmp_0 = wi[4] ^ wi[7] ^  w[1] ^  w[3] ^ 0x9e3779b9 ^ 0x4;  
	w[4] = (tmp_0 << 11) | (tmp_0 >> 21);    
//w[5]
	tmp_0 = wi[5] ^  w[0] ^  w[2] ^  w[4] ^ 0x9e3779b9 ^ 0x5;  
	w[5] = (tmp_0 << 11) | (tmp_0 >> 21);    
//w[6]
	tmp_0 = wi[6] ^  w[1] ^  w[3] ^  w[5] ^ 0x9e3779b9 ^ 0x6;  
	w[6] = (tmp_0 << 11) | (tmp_0 >> 21);
//w[7]
	tmp_0 = wi[7] ^  w[2] ^  w[4] ^  w[6] ^ 0x9e3779b9 ^ 0x7;
	w[7] = (tmp_0 << 11) | (tmp_0 >> 21);

//setp 1-3, generate w[8]~w[131] with w[0]~w[7]
	for( i = 8; i < 132; i++){
 		tmp_0 = w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ 0x9e3779b9 ^ i;   
		w[i] = (tmp_0 << 11) | (tmp_0 >> 21);    
	}   
	
	fprintf(fp,"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ \n");
	fprintf(fp,"DETAIL DATA FOR RUN_CNT = %d \n",tmp_4);
	for( i = 0; i < 8; i++){
 		fprintf(fp,"w[%d] = %08x \n",i-8,wi[i]);
	}   
	for( i = 0; i < 132; i++){
 		fprintf(fp,"w[%d] = %08x \n",i,w[i]);
	}   
	
	//setp 1-4,input w[0]~w[131] to sbox,generate k_0[0]~k_0[131]
	//data will be permutated before input into SBOX
		for( i = 0; i < 132; i = i + 4){
  	    IP(&w[i+0],&w[i+1],&w[i+2],&w[i+3],&sb_in[i+0],&sb_in[i+1],&sb_in[i+2],&sb_in[i+3]);
		sb_out[i+0] = sb(((35-i/4)%8),sb_in[i+0]);
		sb_out[i+1] = sb(((35-i/4)%8),sb_in[i+1]);	
		sb_out[i+2] = sb(((35-i/4)%8),sb_in[i+2]);
		sb_out[i+3] = sb(((35-i/4)%8),sb_in[i+3]);
		k[i+0] = sb_out[i+0] ;
		k[i+1] = sb_out[i+1] ;
		k[i+2] = sb_out[i+2] ;
		k[i+3] = sb_out[i+3] ;
	}   
	
	fprintf(fp,"sub_key data~~~~~~~~~~~~~~~~~~~~ \n");
	for(i = 0; i < 132; i++){ 
		if((i%4) == 0) {fprintf(fp,"=======sub_key[%d]: =======\n",i/4);}
		fprintf(fp,"sub_key[%d]_%d = %08x \n",i/4,i%4, k[i]);
	}
	fprintf(fp," \n");
	fprintf(fp," \n");
	fprintf(fp,"encryption data~~~~~~~~~~~~~~~~~~~~ \n");

	//========================================================================
	//By now,we've got the sub_key0~32,then we can start to encrypt plain data
	//step 2, data encryption
	//initial permutation
	IP(&p_0,&p_1,&p_2,&p_3,&b[0],&b[1],&b[2],&b[3]);
	
	fprintf(fp,"p_0 = %08x \n",p_0);
	fprintf(fp,"p_1 = %08x \n",p_1);
	fprintf(fp,"p_2 = %08x \n",p_2);
	fprintf(fp,"p_3 = %08x \n",p_3);

	fprintf(fp,"b_0 = %08x \n",b[0]);
	fprintf(fp,"b_1 = %08x \n",b[1]);
	fprintf(fp,"b_2 = %08x \n",b[2]);
	fprintf(fp,"b_3 = %08x \n",b[3]);
	
	//step 2-1,32 rounds of data encryption 
	//round0~30, 31 normal rounds
	for(i = 0; i < 31; i++)
	{ 
		//xor operation
		xor[i*4+0] = b[i*4+0] ^ k[i*4+0];
		xor[i*4+1] = b[i*4+1] ^ k[i*4+1];
		xor[i*4+2] = b[i*4+2] ^ k[i*4+2];
		xor[i*4+3] = b[i*4+3] ^ k[i*4+3];
		//SBOX
		sbox[i*4+0] = sb((i%8),xor[i*4+0]);    
		sbox[i*4+1] = sb((i%8),xor[i*4+1]);    
		sbox[i*4+2] = sb((i%8),xor[i*4+2]);    
		sbox[i*4+3] = sb((i%8),xor[i*4+3]);
		//linear
		FP(&sbox[i*4+0],&sbox[i*4+1],&sbox[i*4+2],&sbox[i*4+3],&li[i*4+0],&li[i*4+1],&li[i*4+2],&li[i*4+3]);	
		linear(&li[i*4+0],&li[i*4+1],&li[i*4+2],&li[i*4+3],&lo[i*4+0],&lo[i*4+1],&lo[i*4+2],&lo[i*4+3]);
		IP(&lo[i*4+0],&lo[i*4+1],&lo[i*4+2],&lo[i*4+3],&b[i*4+4],&b[i*4+5],&b[i*4+6],&b[i*4+7]);

		fprintf(fp,"////////////////////\n");
		fprintf(fp,"i = %d \n",i);
		fprintf(fp,"xored[%d] = %08x \n", i*4+0, xor[i*4+0]);
		fprintf(fp,"xored[%d] = %08x \n", i*4+1, xor[i*4+1]);
		fprintf(fp,"xored[%d] = %08x \n", i*4+2, xor[i*4+2]);
		fprintf(fp,"xored[%d] = %08x \n", i*4+3, xor[i*4+3]);
			
		fprintf(fp,"sbox[%d] = %08x \n", i*4+0, sbox[i*4+0]);
		fprintf(fp,"sbox[%d] = %08x \n", i*4+1, sbox[i*4+1]);
		fprintf(fp,"sbox[%d] = %08x \n", i*4+2, sbox[i*4+2]);
		fprintf(fp,"sbox[%d] = %08x \n", i*4+3, sbox[i*4+3]);
		  
		fprintf(fp,"linear_in[%d] = %08x \n", i*4+0, li[i*4+0]);
		fprintf(fp,"linear_in[%d] = %08x \n", i*4+1, li[i*4+1]);
		fprintf(fp,"linear_in[%d] = %08x \n", i*4+2, li[i*4+2]);
		fprintf(fp,"linear_in[%d] = %08x \n", i*4+3, li[i*4+3]);					
		  
		fprintf(fp,"linear_out[%d] = %08x \n", i*4+0, lo[i*4+0]);
		fprintf(fp,"linear_out[%d] = %08x \n", i*4+1, lo[i*4+1]);
		fprintf(fp,"linear_out[%d] = %08x \n", i*4+2, lo[i*4+2]);
		fprintf(fp,"linear_out[%d] = %08x \n", i*4+3, lo[i*4+3]);					
		  
		fprintf(fp,"b[%d] = %08x \n", i*4+4, b[i*4+4]);
		fprintf(fp,"b[%d] = %08x \n", i*4+5, b[i*4+5]);
		fprintf(fp,"b[%d] = %08x \n", i*4+6, b[i*4+6]);
		fprintf(fp,"b[%d] = %08x \n", i*4+7, b[i*4+7]);			
	}
	//round31
	//xor operation
	xor[124] = b[124] ^ k[124];
	xor[125] = b[125] ^ k[125];
	xor[126] = b[126] ^ k[126];
	xor[127] = b[127] ^ k[127];
	fprintf(fp,"////////////////////\n");
	fprintf(fp,"i = %d \n", i);
	fprintf(fp,"xored = %08x \n", xor[i*4+0]);
	fprintf(fp,"xored = %08x \n", xor[i*4+1]);
	fprintf(fp,"xored = %08x \n", xor[i*4+2]);
	fprintf(fp,"xored = %08x \n", xor[i*4+3]);
	//SBOX
	sbox[124] = sb(0x7,xor[124]);    
	sbox[125] = sb(0x7,xor[125]);    
	sbox[126] = sb(0x7,xor[126]);    
	sbox[127] = sb(0x7,xor[127]);
	fprintf(fp,"sbox = %08x \n", sbox[i*4+0]);
	fprintf(fp,"sbox = %08x \n", sbox[i*4+1]);
	fprintf(fp,"sbox = %08x \n", sbox[i*4+2]);
	fprintf(fp,"sbox = %08x \n", sbox[i*4+3]);
	//xor operation-2
	b[128] = sbox[124] ^ k[128];
	b[129] = sbox[125] ^ k[129];
	b[130] = sbox[126] ^ k[130];
	b[131] = sbox[127] ^ k[131];
	fprintf(fp,"k[128]= %08x \n", k[128]);
	fprintf(fp,"k[129]= %08x \n", k[129]);
	fprintf(fp,"k[130]= %08x \n", k[130]);
	fprintf(fp,"k[131]= %08x \n", k[131]);

	fprintf(fp,"b[128]= %08x \n", b[128]);
	fprintf(fp,"b[129]= %08x \n", b[129]);
	fprintf(fp,"b[130]= %08x \n", b[130]);
	fprintf(fp,"b[131]= %08x \n", b[131]);
	
//step 2-2, final permutation

	FP(&b[128],&b[129],&b[130],&b[131],&c_0,&c_1,&c_2,&c_3);

	fprintf(fp,"P0 = %08x \n", p_0);	    fprintf(fp,"P1 = %08x \n", p_1);	    fprintf(fp,"P2 = %08x \n", p_2);	    fprintf(fp,"P3 = %08x \n", p_3);	
	fprintf(fp,"KEY0 = %08x \n", key_0);	fprintf(fp,"KEY1 = %08x \n", key_1);	fprintf(fp,"KEY2 = %08x \n", key_2);	fprintf(fp,"KEY3 = %08x \n", key_3);	
	fprintf(fp,"C0 = %08x \n", c_0);	    fprintf(fp,"C1 = %08x \n", c_1);	    fprintf(fp,"C2 = %08x \n", c_2);	    fprintf(fp,"C3 = %08x \n", c_3);	
	//fclose(fp);	

	printf("================================== \n");
	printf("==============RESULT============== \n");
	printf("================================== \n");
	printf("P0   = %08x ", p_0);      printf("P1   = %08x ", p_1);      printf("P2   = %08x ", p_2);      printf("P3   = %08x \n", p_3);
	printf("KEY0 = %08x ", key_0);    printf("KEY1 = %08x ", key_1);    printf("KEY2 = %08x ", key_2);    printf("KEY3 = %08x \n", key_3);
	printf("C0   = %08x ", c_0);      printf("C1   = %08x ", c_1);      printf("C2   = %08x ", c_2);      printf("C3   = %08x \n", c_3);	  
	tmp_4++;
	printf("WILL YOU CALCULATE SERPENT-1 AGAIN ? 1:YES  0:NO \n");  
	scanf_s("%x",&tmp_5);	
	if(tmp_5 == 0x0)
		break;
	fclose(fp);	
    return 0;
}
#endif
