#ifndef _TEST_H_
#define _TEST_H_


extern int initDomainParameters(int argc, char** argv);
extern int testFieldArithmetic();
extern int testPointArithmetic();
extern int testAES();
extern int testKernelEc2m();
extern int testMisc();
extern int testEC2M();
extern int benchmark_cycles();

extern int benchmark_EC2();


#endif
