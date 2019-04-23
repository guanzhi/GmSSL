#include <sys/time.h>//get timeof day;
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#include "sm2.h"



#define _PPROF_
#ifdef _PPROF_

#include <gperftools/profiler.h>
#define StartPProf() ProfilerStart("sm2.out")
#define StopPProf() ProfilerStop()

#else

#define StartPProf() 
#define StopPProf() 

#endif

char buf[] = {"test data for test!!!!!!!!!!"};
char pvd[] = {"6F99C28B50D059C26399B07837D95F99919CA25417FB2AF262D51034E78745F1"};
int testSM2_hex()
{
    char *prv = NULL;
    char *pub = NULL;
    char *sig = NULL;
    int ret = 0;

    prv = GeneratePrivateKey_hex();
    if (!prv)
    {
        goto err;
    }
    pub = GetPublicKeyByPriv_hex(prv);
    if (!pub)
    {
        goto err;
    }
    sig = Sign_hex(prv,buf,strlen(buf));
    if (!sig)
    {
        goto err;
    }
    ret = Verify_hex(pub,sig,buf,strlen(buf)); 
err :
    if (prv && prv != pvd)SM2Free(prv);
    if (pub)SM2Free(pub);
    if (sig)SM2Free(sig);
    return ret;
}

int testSM2_bin()
{
    char *prv = NULL;
    char *pub = NULL;
    char *sig = NULL;
    int ret = 0;
    prv = GeneratePrivateKey_bin();
    if (!prv)
    {
        goto err;
    }
    pub = GetPublicKeyByPriv_bin(prv,Size_PriKey);
    if (!pub)
    {
        goto err;
    }
    sig = Sign_bin(prv,Size_PriKey,buf,strlen(buf));
    if (!sig)
    {
        goto err;
    }
    ret = Verify_bin(pub,sig,buf,strlen(buf));
err :
    if (prv && prv != pvd)SM2Free(prv);
    if (pub)SM2Free(pub);
    if (sig)SM2Free(sig);
    return ret;
}

int dohex = 0;
char dotype[2][8] = {{"BIN"},{"HEX"}};

int testSM2()
{
    if (dohex)
    {
        return testSM2_hex();
    }
    else
    {
        return testSM2_bin();
    }
    
}

const int64_t one_m = 1000*1000;

int benchmark(int total ,char *buf)
{
    struct timeval start,end;
    gettimeofday(&start,NULL);
    //const int total = 1024;
    int ntime = 0;
    for (;ntime<total;++ntime)
    {
        if (!testSM2())
        {
            _exit(1);
            break;
        }
    } 
    gettimeofday(&end,NULL);
    int64_t sec = end.tv_sec - start.tv_sec;
    int64_t usec = sec*one_m+(end.tv_usec - start.tv_usec);//milli sec;
    int64_t perusec = usec / ntime;
    sec = usec / one_m;
    usec = usec % one_m;
    if (sec > 0 ){
        return sprintf(buf,"run %4d(%d)'time cost %2d.%06d's ; % 6d'us one times\n",total,ntime,sec,usec,perusec);
    }else{
        return sprintf(buf,"run %4d(%d)'time cost %6d'us; % 6d'us one times\n",total,ntime,usec,perusec);
    }
}

const char *sep = "\n------------------------------------thread_%d_(%s)-------------------------------------------\n\n%s";

void runtest(int times,int thid)
{
    int count = 0;
    if (dohex != 0)
    {
        dohex = 1;
    }
    while (count++<times)
    {
        char buf[1024*2] = {0};
        int n = 0;
        n += benchmark(100,buf+n);
        n += benchmark(1000,buf+n);
        n += benchmark(3000,buf+n);
        n += benchmark(5000,buf+n);
        //n += benchmark(10000,buf+n);
        printf(sep,thid,dotype[dohex],buf);
        sleep(2);
    }
}

void *thread_run(void *arg)
{
    int *idx = (int*)arg;
    int count = 2;
    runtest(count,*idx);
    return NULL;
}

const int NUM_THREADS = 2;

int mutilthread()
{
    pthread_t thread[NUM_THREADS];
    int idxs[NUM_THREADS];
    int t = 0;
    for(t = 0; t < NUM_THREADS; t++)
    {
        idxs[t] = t+1;
        int rc = pthread_create(&thread[t], NULL, thread_run, idxs+t);
        if (rc != 0)
        {
            printf("ERROR; return code is %d\n", rc);
            return 1;
        }
    }
    for(t = 0; t < NUM_THREADS; t++)
        pthread_join(thread[t], NULL);
    return 0;
}

int main()
{
    StartPProf();
    if (initPrivKey())
    {
        dohex = 1;
        //mutilthread();
        runtest(1,0);
        dohex = 0;
        //mutilthread();
        runtest(1,0);
    }
    StopPProf();
    return 0;
}