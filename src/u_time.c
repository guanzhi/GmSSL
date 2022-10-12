#include "u_time.h"

//convert timestamp to struct tm
int GMSSL_gmtime(const time_t *timep, struct tm *tm_time)
{
    time_t timestamp = *timep;
    unsigned int four_year_num;   
    unsigned int one_year_hours;  

    const static unsigned char Days[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    const static unsigned int ONE_YEAR_HOURS = 8760;
    const static unsigned int FOUR_YEAR_HOURS = 35064;

    if (timestamp > 0x7FFFFFFF)
    {
        return -1;
    }
        
    tm_time->tm_isdst = 0;

    tm_time->tm_sec = (int)(timestamp % 60);
    timestamp /= 60;
   
    tm_time->tm_min = (int)(timestamp % 60);
    timestamp /= 60;
   
    tm_time->tm_wday = (int)(timestamp/24 + 4) % 7;
   
    four_year_num = timestamp / FOUR_YEAR_HOURS;    
   
    tm_time->tm_year=(four_year_num << 2) + 70;
   
    timestamp %= FOUR_YEAR_HOURS;
   
    while (1)
    {
        one_year_hours = ONE_YEAR_HOURS;
       
        if ((tm_time->tm_year & 3) == 0)
        {
            one_year_hours += 24;
        }

        if (timestamp < one_year_hours)
        {
            break;
        }

        tm_time->tm_year++;
        timestamp -= one_year_hours;
    }

    tm_time->tm_hour=(int)(timestamp % 24);

    timestamp /= 24;
    timestamp++;
  
    tm_time->tm_yday = timestamp-1; 

    if ((tm_time->tm_year & 3) == 0) 
    {
        if (timestamp > 60)
        {
            timestamp--;
        }
        else if (timestamp == 60)
        {
            tm_time->tm_mon = 1;
            tm_time->tm_mday = 29;
            return 0;
        }
    }

    for (tm_time->tm_mon = 0; Days[tm_time->tm_mon] < timestamp; tm_time->tm_mon++)
    {
        timestamp -= Days[tm_time->tm_mon];
    }

    tm_time->tm_mday = (int)(timestamp);

    return 0;
}

//convert struct tm to timestamp
time_t GMSSL_timegm(struct tm *tm)
{
    static const int msum [2][12] = {
        { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334},        /* normal years */
        { 0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335}        /* leap years */
    };
    static const int mlen [2][12] = {
        { 31, 28, 31, 30,  31,  30,  31,  31,  30,  31,  30, 31},
        { 31, 29, 31, 30,  31,  30,  31,  31,  30,  31,  30, 31}
    };
    static const int tmstr_year= 1900; /* base of 'tm_year' in 'struct tm' */
    static const int epoch_year= 1970; /* unix timestamp epoch */
    static const int base_year=  1601;  /* start of a 400-year period: used to be 1601,
                                            but this allows larger range (in 64 bit)
                                            mind you, this is proleptic Gregorian */
    int year, ytmp, dtmp, ytmpe, dtmpe;
    int isleapyear;
    long long t;

    if (!tm) return -1;

    year = tm->tm_year + tmstr_year;
    isleapyear= (year%4==0) - (year%100==0) + (year%400==0);

/* days between 'current year' and 'epoch_year' has to be calculated
   in three steps: */

/* 1. days between current year and 'base_year' */
    ytmp = year - base_year;
    dtmp = ytmp*365 + ytmp/4 - ytmp/100 + ytmp/400;

/* 2. days between 'epoch year' and 'base_year' */
    ytmpe = epoch_year - base_year;
    dtmpe = ytmpe*365 + ytmpe/4 - ytmpe/100 + ytmpe/400;

/* 3. days between 'current year' and 'epoch_year' */
    t  = dtmp - dtmpe;

    t += msum[isleapyear][tm->tm_mon];
    t += tm->tm_mday-1;

    t  = t*24 + tm->tm_hour;
    t  = t*60 + tm->tm_min;
    t  = t*60 + tm->tm_sec;

    return t;
}

//offset to struct tm
int GMSSL_gmtime_adj(struct tm *tm, long offset_sec)
{
    time_t t = GMSSL_timegm(tm);
    if(t == -1)
        return -1;

    t += offset_sec;

    return GMSSL_gmtime(&t,tm) == 0;
}

//convert generalizedtime to tm
int asn1_generalizedtime_to_tm(char *gtime,struct tm *tm)
{
    static const int min[9] = { 0, 0, 1, 1, 0, 0, 0, 0, 0 };
    static const int max[9] = { 99, 99, 12, 31, 23, 59, 59, 12, 59 };
    char *a;
    int n, i, l, o;

    l = strlen(gtime);
    a = gtime;
    o = 0;
    /*
     * GENERALIZEDTIME is similar to UTCTIME except the year is represented
     * as YYYY. This stuff treats everything as a two digit field so make
     * first two fields 00 to 99
     */
    if (l < 13)
        goto err;
    for (i = 0; i < 7; i++) {
        if ((i == 6) && ((a[o] == 'Z') || (a[o] == '+') || (a[o] == '-'))) {
            i++;
            if (tm)
                tm->tm_sec = 0;
            break;
        }
        if ((a[o] < '0') || (a[o] > '9'))
            goto err;
        n = a[o] - '0';
        if (++o > l)
            goto err;

        if ((a[o] < '0') || (a[o] > '9'))
            goto err;
        n = (n * 10) + a[o] - '0';
        if (++o > l)
            goto err;

        if ((n < min[i]) || (n > max[i]))
            goto err;
        if (tm) {
            switch (i) {
            case 0:
                tm->tm_year = n * 100 - 1900;
                break;
            case 1:
                tm->tm_year += n;
                break;
            case 2:
                tm->tm_mon = n - 1;
                break;
            case 3:
                tm->tm_mday = n;
                break;
            case 4:
                tm->tm_hour = n;
                break;
            case 5:
                tm->tm_min = n;
                break;
            case 6:
                tm->tm_sec = n;
                break;
            }
        }
    }
    /*
     * Optional fractional seconds: decimal point followed by one or more
     * digits.
     */
    if (a[o] == '.') {
        if (++o > l)
            goto err;
        i = o;
        while ((a[o] >= '0') && (a[o] <= '9') && (o <= l))
            o++;
        /* Must have at least one digit after decimal point */
        if (i == o)
            goto err;
    }

    if (a[o] == 'Z')
        o++;
    else if ((a[o] == '+') || (a[o] == '-')) {
        int offsign = a[o] == '+' ? -1 : 1, offset = 0;
        o++;
        if (o + 4 > l)
            goto err;
        for (i = 7; i < 9; i++) {
            if ((a[o] < '0') || (a[o] > '9'))
                goto err;
            n = a[o] - '0';
            o++;
            if ((a[o] < '0') || (a[o] > '9'))
                goto err;
            n = (n * 10) + a[o] - '0';
            if ((n < min[i]) || (n > max[i]))
                goto err;
            if (tm) {
                if (i == 7)
                    offset = n * 3600;
                else if (i == 8)
                    offset += n * 60;
            }
            o++;
        }
        if (offset && !GMSSL_gmtime_adj(tm, offset * offsign))
            return 0;
    } else if (a[o]) {
        /* Missing time zone information. */
        goto err;
    }
    return (o == l);
 err:
    return (0);
}

//convert utctime to tm
int asn1_utctime_to_tm(struct tm *tm, char *utime)
{
    static const int min[8] = { 0, 1, 1, 0, 0, 0, 0, 0 };
    static const int max[8] = { 99, 12, 31, 23, 59, 59, 12, 59 };
    char *a;
    int n, i, l, o;

    l = strlen(utime);
    a = utime;
    o = 0;

    if (l < 11)
        goto err;
    for (i = 0; i < 6; i++) {
        if ((i == 5) && ((a[o] == 'Z') || (a[o] == '+') || (a[o] == '-'))) {
            i++;
            if (tm)
                tm->tm_sec = 0;
            break;
        }
        if ((a[o] < '0') || (a[o] > '9'))
            goto err;
        n = a[o] - '0';
        if (++o > l)
            goto err;

        if ((a[o] < '0') || (a[o] > '9'))
            goto err;
        n = (n * 10) + a[o] - '0';
        if (++o > l)
            goto err;

        if ((n < min[i]) || (n > max[i]))
            goto err;
        if (tm) {
            switch (i) {
            case 0:
                tm->tm_year = n < 50 ? n + 100 : n;
                break;
            case 1:
                tm->tm_mon = n - 1;
                break;
            case 2:
                tm->tm_mday = n;
                break;
            case 3:
                tm->tm_hour = n;
                break;
            case 4:
                tm->tm_min = n;
                break;
            case 5:
                tm->tm_sec = n;
                break;
            }
        }
    }
    if (a[o] == 'Z')
        o++;
    else if ((a[o] == '+') || (a[o] == '-')) {
        int offsign = a[o] == '+' ? -1 : 1, offset = 0;
        o++;
        if (o + 4 > l)
            goto err;
        for (i = 6; i < 8; i++) {
            if ((a[o] < '0') || (a[o] > '9'))
                goto err;
            n = a[o] - '0';
            o++;
            if ((a[o] < '0') || (a[o] > '9'))
                goto err;
            n = (n * 10) + a[o] - '0';
            if ((n < min[i]) || (n > max[i]))
                goto err;
            if (tm) {
                if (i == 6)
                    offset = n * 3600;
                else if (i == 7)
                    offset += n * 60;
            }
            o++;
        }
        if (offset && !GMSSL_gmtime_adj(tm, offset * offsign))
            return 0;
    }
    return o == l;
 err:
    return 0;
}

//convert tm to generalizedtime
int asn1_tm_to_generalizedtime(struct tm *tm, char *gtime)
{
    char p[20] = {0};
    int i = 0, j = 0;
    static const int min[6] = { 0, 1, 1, 0, 0, 0 };
    static const int max[6] = { 9999, 12, 31, 23, 59, 59};

    //year
    int year0 = tm->tm_year + 1900;
    if(year0 < min[i] || year0 > max[i])
        goto err;
    p[j++] = year0 / 1000 + '0';
    year0 = year0 % 1000;
    p[j++] = year0 / 100 + '0';
    year0 = year0 % 100;
    p[j++] = year0 / 10 + '0';
    year0 = year0 % 10;
    p[j++] = year0 + '0';
    i++;

    //month
    int mon0 = tm->tm_mon + 1;
    if(mon0 < min[i] || mon0>max[i])
        goto err;
    p[j++] = mon0 /10 + '0';
    mon0 = mon0%10;
    p[j++] = mon0 + '0';
    i++;

    //day
    int day0 = tm->tm_mday;
    if(day0 < min[i] || day0>max[i])
        goto err;
    p[j++] = day0 /10 + '0';
    day0 = day0%10;
    p[j++] = day0 + '0';
    i++;

    //hour
    int hour0 = tm->tm_hour;
    if(hour0 < min[i] || hour0>max[i])
        goto err;
    p[j++] = hour0 /10 + '0';
    hour0 = hour0%10;
    p[j++] = hour0 + '0';
    i++;

    //min
    int min0 = tm->tm_min;
    if(min0 < min[i] || min0>max[i])
        goto err;
    p[j++] = min0 /10 + '0';
    min0 = min0%10;
    p[j++] = min0 + '0';
    i++;

    //sec
    int sec0 = tm->tm_sec;
    if(sec0 < min[i] || sec0>max[i])
        goto err;
    p[j++] = sec0 /10 + '0';
    sec0 = sec0%10;
    p[j++] = sec0 + '0';

    p[j++] = 'Z';

    memcpy(gtime,p,j);
    
    return 0;

err:
    return -1;
}


//convert asn1 tm to utctime
int asn1_tm_to_utctime(struct tm *tm, char *utime)
{
    char p[20] = {0};
    int i = 0, j = 0;
    static const int min[6] = { 0, 1, 1, 0, 0, 0 };
    static const int max[6] = { 99, 12, 31, 23, 59, 59};

    //year
    int year0 = tm->tm_year % 100;
    if(year0 < min[i] || year0 > max[i])
        goto err;
    p[j++] = year0 / 10 + '0';
    year0 = year0 % 10;
    p[j++] = year0 + '0';
    i++;

    //month
    int mon0 = tm->tm_mon + 1;
    if(mon0 < min[i] || mon0>max[i])
        goto err;
    p[j++] = mon0 /10 + '0';
    mon0 = mon0%10;
    p[j++] = mon0 + '0';
    i++;

    //day
    int day0 = tm->tm_mday;
    if(day0 < min[i] || day0>max[i])
        goto err;
    p[j++] = day0 /10 + '0';
    day0 = day0%10;
    p[j++] = day0 + '0';
    i++;

    //hour
    int hour0 = tm->tm_hour;
    if(hour0 < min[i] || hour0>max[i])
        goto err;
    p[j++] = hour0 /10 + '0';
    hour0 = hour0%10;
    p[j++] = hour0 + '0';
    i++;

    //min
    int min0 = tm->tm_min;
    if(min0 < min[i] || min0>max[i])
        goto err;
    p[j++] = min0 /10 + '0';
    min0 = min0%10;
    p[j++] = min0 + '0';
    i++;

    //sec
    int sec0 = tm->tm_sec;
    if(sec0 < min[i] || sec0>max[i])
        goto err;
    p[j++] = sec0 /10 + '0';
    sec0 = sec0%10;
    p[j++] = sec0 + '0';

    p[j++] = 'Z';
    memcpy(utime,p,j);
    
    return 0;

err:
    return -1;
}