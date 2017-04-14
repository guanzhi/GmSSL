#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ec.h"
#include "test.h"

int main(int argc, char** argv){
	/*
	int i;

	for(i = 0; i < argc; i++){
		printf("arg %d: %s\n", i, argv[i]);
	}
	*/

	char* cmd = argv[1];
	if(!initDomainParameters(argc, argv)){
		return 1;
	}
	if(strcmp(cmd, "testFieldArithmetic") == 0){
		return testFieldArithmetic();
	} else if(strcmp(cmd, "testPointArithmetic") == 0){
		return testPointArithmetic();
	} else if(strcmp(cmd, "testAES") == 0){
		return testAES();
	} else if(strcmp(cmd, "benchmark_ec2") == 0){
		return benchmark_EC2();
	} else if(strcmp(cmd, "testKernelEc2m") == 0){
		return testKernelEc2m();
	} else if(strcmp(cmd, "testMisc") == 0){
		return testMisc();
	} else if(strcmp(cmd, "testCycles") == 0){
		return benchmark_cycles();
	}

	return 1;
}
