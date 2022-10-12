#ifndef GMSSL_U_TIME_H
#define GMSSL_U_TIME_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SECS_PER_DAY (24 * 60 * 60)

int GMSSL_gmtime(const time_t *timep, struct tm *tm_time);
time_t GMSSL_timegm(struct tm *tm);
int GMSSL_gmtime_adj(struct tm *tm, long offset_sec);
int asn1_generalizedtime_to_tm(char *gtime,struct tm *tm);
int asn1_utctime_to_tm(struct tm *tm, char *utime);
int asn1_tm_to_generalizedtime(struct tm *tm, char *gtime);
int asn1_tm_to_utctime(struct tm *tm, char *utime);

#if __cplusplus
}
#endif
#endif