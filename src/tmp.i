# 1 "tls12.c"
# 1 "<built-in>" 1
# 1 "<built-in>" 3
# 466 "<built-in>" 3
# 1 "<command line>" 1
# 1 "<built-in>" 2
# 1 "tls12.c" 2
# 11 "tls12.c"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/time.h" 1 3 4
# 63 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/time.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_time.h" 1 3 4
# 66 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_time.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_types.h" 1 3 4
# 27 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_types.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types.h" 1 3 4
# 32 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/cdefs.h" 1 3 4
# 808 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/cdefs.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_symbol_aliasing.h" 1 3 4
# 809 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/cdefs.h" 2 3 4
# 874 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/cdefs.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_posix_availability.h" 1 3 4
# 875 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/cdefs.h" 2 3 4
# 992 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/cdefs.h" 3 4
# 1 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/ptrcheck.h" 1 3 4
# 993 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/cdefs.h" 2 3 4
# 33 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/machine/_types.h" 1 3 4
# 34 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/machine/_types.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/_types.h" 1 3 4
# 28 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/_types.h" 3 4
typedef signed char __int8_t;



typedef unsigned char __uint8_t;
typedef short __int16_t;
typedef unsigned short __uint16_t;
typedef int __int32_t;
typedef unsigned int __uint32_t;
typedef long long __int64_t;
typedef unsigned long long __uint64_t;

typedef long __darwin_intptr_t;
typedef unsigned int __darwin_natural_t;
# 61 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/_types.h" 3 4
typedef int __darwin_ct_rune_t;





typedef union {
 char __mbstate8[128];
 long long _mbstateL;
} __mbstate_t;

typedef __mbstate_t __darwin_mbstate_t;




typedef long int __darwin_ptrdiff_t;
# 87 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/_types.h" 3 4
typedef long unsigned int __darwin_size_t;







typedef __builtin_va_list __darwin_va_list;







typedef int __darwin_wchar_t;




typedef __darwin_wchar_t __darwin_rune_t;


typedef int __darwin_wint_t;




typedef unsigned long __darwin_clock_t;
typedef __uint32_t __darwin_socklen_t;
typedef long __darwin_ssize_t;
typedef long __darwin_time_t;
# 35 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/machine/_types.h" 2 3 4
# 34 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types.h" 2 3 4
# 67 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types.h" 3 4
typedef __int64_t __darwin_blkcnt_t;
typedef __int32_t __darwin_blksize_t;
typedef __int32_t __darwin_dev_t;
typedef unsigned int __darwin_fsblkcnt_t;
typedef unsigned int __darwin_fsfilcnt_t;
typedef __uint32_t __darwin_gid_t;
typedef __uint32_t __darwin_id_t;
typedef __uint64_t __darwin_ino64_t;

typedef __darwin_ino64_t __darwin_ino_t;



typedef __darwin_natural_t __darwin_mach_port_name_t;
typedef __darwin_mach_port_name_t __darwin_mach_port_t;
typedef __uint16_t __darwin_mode_t;
typedef __int64_t __darwin_off_t;
typedef __int32_t __darwin_pid_t;
typedef __uint32_t __darwin_sigset_t;
typedef __int32_t __darwin_suseconds_t;
typedef __uint32_t __darwin_uid_t;
typedef __uint32_t __darwin_useconds_t;
typedef unsigned char __darwin_uuid_t[16];
typedef char __darwin_uuid_string_t[37];



# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_pthread/_pthread_types.h" 1 3 4
# 57 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_pthread/_pthread_types.h" 3 4
struct __darwin_pthread_handler_rec {
 void (*__routine)(void *);
 void *__arg;
 struct __darwin_pthread_handler_rec *__next;
};

struct _opaque_pthread_attr_t {
 long __sig;
 char __opaque[56];
};

struct _opaque_pthread_cond_t {
 long __sig;
 char __opaque[40];
};

struct _opaque_pthread_condattr_t {
 long __sig;
 char __opaque[8];
};

struct _opaque_pthread_mutex_t {
 long __sig;
 char __opaque[56];
};

struct _opaque_pthread_mutexattr_t {
 long __sig;
 char __opaque[8];
};

struct _opaque_pthread_once_t {
 long __sig;
 char __opaque[8];
};

struct _opaque_pthread_rwlock_t {
 long __sig;
 char __opaque[192];
};

struct _opaque_pthread_rwlockattr_t {
 long __sig;
 char __opaque[16];
};

struct _opaque_pthread_t {
 long __sig;
 struct __darwin_pthread_handler_rec *__cleanup_stack;
 char __opaque[8176];
};

typedef struct _opaque_pthread_attr_t __darwin_pthread_attr_t;
typedef struct _opaque_pthread_cond_t __darwin_pthread_cond_t;
typedef struct _opaque_pthread_condattr_t __darwin_pthread_condattr_t;
typedef unsigned long __darwin_pthread_key_t;
typedef struct _opaque_pthread_mutex_t __darwin_pthread_mutex_t;
typedef struct _opaque_pthread_mutexattr_t __darwin_pthread_mutexattr_t;
typedef struct _opaque_pthread_once_t __darwin_pthread_once_t;
typedef struct _opaque_pthread_rwlock_t __darwin_pthread_rwlock_t;
typedef struct _opaque_pthread_rwlockattr_t __darwin_pthread_rwlockattr_t;
typedef struct _opaque_pthread_t *__darwin_pthread_t;
# 95 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types.h" 2 3 4
# 28 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_bounds.h" 1 3 4
# 29 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_types.h" 2 3 4
# 43 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_types.h" 3 4
typedef int __darwin_nl_item;
typedef int __darwin_wctrans_t;

typedef __uint32_t __darwin_wctype_t;
# 67 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_time.h" 2 3 4


# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 1 3 4
# 196 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/AvailabilityVersions.h" 1 3 4
# 197 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/AvailabilityInternal.h" 1 3 4
# 33 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/AvailabilityInternal.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/AvailabilityVersions.h" 1 3 4
# 34 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/AvailabilityInternal.h" 2 3 4
# 198 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/AvailabilityInternalLegacy.h" 1 3 4
# 34 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/AvailabilityInternalLegacy.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/AvailabilityInternal.h" 1 3 4
# 35 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/AvailabilityInternalLegacy.h" 2 3 4
# 199 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 2 3 4
# 70 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_time.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_clock_t.h" 1 3 4
# 30 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_clock_t.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/machine/types.h" 1 3 4
# 37 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/machine/types.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/types.h" 1 3 4
# 55 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/types.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_int8_t.h" 1 3 4
# 30 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_int8_t.h" 3 4
typedef signed char int8_t;
# 56 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_int16_t.h" 1 3 4
# 30 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_int16_t.h" 3 4
typedef short int16_t;
# 57 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_int32_t.h" 1 3 4
# 30 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_int32_t.h" 3 4
typedef int int32_t;
# 58 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_int64_t.h" 1 3 4
# 30 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_int64_t.h" 3 4
typedef long long int64_t;
# 59 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/types.h" 2 3 4

# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_u_int8_t.h" 1 3 4
# 30 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_u_int8_t.h" 3 4
typedef unsigned char u_int8_t;
# 61 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_u_int16_t.h" 1 3 4
# 30 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_u_int16_t.h" 3 4
typedef unsigned short u_int16_t;
# 62 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_u_int32_t.h" 1 3 4
# 30 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_u_int32_t.h" 3 4
typedef unsigned int u_int32_t;
# 63 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_u_int64_t.h" 1 3 4
# 30 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_u_int64_t.h" 3 4
typedef unsigned long long u_int64_t;
# 64 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/types.h" 2 3 4


typedef int64_t register_t;




# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_intptr_t.h" 1 3 4
# 32 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_intptr_t.h" 3 4
typedef __darwin_intptr_t intptr_t;
# 72 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_uintptr_t.h" 1 3 4
# 34 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_uintptr_t.h" 3 4
typedef unsigned long uintptr_t;
# 73 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/types.h" 2 3 4




typedef u_int64_t user_addr_t;
typedef u_int64_t user_size_t;
typedef int64_t user_ssize_t;
typedef int64_t user_long_t;
typedef u_int64_t user_ulong_t;
typedef int64_t user_time_t;
typedef int64_t user_off_t;
# 105 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/types.h" 3 4
typedef u_int64_t syscall_arg_t;
# 38 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/machine/types.h" 2 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_clock_t.h" 2 3 4
typedef __darwin_clock_t clock_t;
# 71 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_time.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_null.h" 1 3 4
# 72 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_time.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_size_t.h" 1 3 4
# 50 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_size_t.h" 3 4
typedef __darwin_size_t size_t;
# 73 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_time.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_time_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_time_t.h" 3 4
typedef __darwin_time_t time_t;
# 74 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_time.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_timespec.h" 1 3 4
# 33 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_timespec.h" 3 4
struct timespec
{
 __darwin_time_t tv_sec;
 long tv_nsec;
};
# 75 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_time.h" 2 3 4



struct tm {
 int tm_sec;
 int tm_min;
 int tm_hour;
 int tm_mday;
 int tm_mon;
 int tm_year;
 int tm_wday;
 int tm_yday;
 int tm_isdst;
 long tm_gmtoff;
 char * tm_zone;
};
# 101 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_time.h" 3 4
extern char * tzname[];


extern int getdate_err;

extern long timezone __asm("_" "timezone" );

extern int daylight;


char * asctime(const struct tm *);
clock_t clock(void) __asm("_" "clock" );
char * ctime(const time_t *);
double difftime(time_t, time_t);
struct tm *getdate(const char *);
struct tm *gmtime(const time_t *);
struct tm *localtime(const time_t *);
time_t mktime(struct tm *) __asm("_" "mktime" );
size_t strftime(char * restrict, size_t __maxsize, const char * restrict, const struct tm * restrict) __asm("_" "strftime" );
char * strptime(const char * restrict, const char * restrict, struct tm * restrict) __asm("_" "strptime" );
time_t time(time_t *);


void tzset(void);



char * asctime_r(const struct tm * restrict, char * restrict );
char * ctime_r(const time_t *, char *);
struct tm *gmtime_r(const time_t * restrict, struct tm * restrict);
struct tm *localtime_r(const time_t * restrict, struct tm * restrict);


time_t posix2time(time_t);



void tzsetwall(void);
time_t time2posix(time_t);
time_t timelocal(struct tm * const);
time_t timegm(struct tm * const);



int nanosleep(const struct timespec *__rqtp, struct timespec *__rmtp) __asm("_" "nanosleep" );
# 156 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_time.h" 3 4
typedef enum {
_CLOCK_REALTIME __attribute__((availability(macosx,introduced=10.12))) __attribute__((availability(ios,introduced=10.0))) __attribute__((availability(tvos,introduced=10.0))) __attribute__((availability(watchos,introduced=3.0))) = 0,

_CLOCK_MONOTONIC __attribute__((availability(macosx,introduced=10.12))) __attribute__((availability(ios,introduced=10.0))) __attribute__((availability(tvos,introduced=10.0))) __attribute__((availability(watchos,introduced=3.0))) = 6,


_CLOCK_MONOTONIC_RAW __attribute__((availability(macosx,introduced=10.12))) __attribute__((availability(ios,introduced=10.0))) __attribute__((availability(tvos,introduced=10.0))) __attribute__((availability(watchos,introduced=3.0))) = 4,

_CLOCK_MONOTONIC_RAW_APPROX __attribute__((availability(macosx,introduced=10.12))) __attribute__((availability(ios,introduced=10.0))) __attribute__((availability(tvos,introduced=10.0))) __attribute__((availability(watchos,introduced=3.0))) = 5,

_CLOCK_UPTIME_RAW __attribute__((availability(macosx,introduced=10.12))) __attribute__((availability(ios,introduced=10.0))) __attribute__((availability(tvos,introduced=10.0))) __attribute__((availability(watchos,introduced=3.0))) = 8,

_CLOCK_UPTIME_RAW_APPROX __attribute__((availability(macosx,introduced=10.12))) __attribute__((availability(ios,introduced=10.0))) __attribute__((availability(tvos,introduced=10.0))) __attribute__((availability(watchos,introduced=3.0))) = 9,


_CLOCK_PROCESS_CPUTIME_ID __attribute__((availability(macosx,introduced=10.12))) __attribute__((availability(ios,introduced=10.0))) __attribute__((availability(tvos,introduced=10.0))) __attribute__((availability(watchos,introduced=3.0))) = 12,

_CLOCK_THREAD_CPUTIME_ID __attribute__((availability(macosx,introduced=10.12))) __attribute__((availability(ios,introduced=10.0))) __attribute__((availability(tvos,introduced=10.0))) __attribute__((availability(watchos,introduced=3.0))) = 16

} clockid_t;

__attribute__((availability(macosx,introduced=10.12))) __attribute__((availability(ios,introduced=10.0))) __attribute__((availability(tvos,introduced=10.0))) __attribute__((availability(watchos,introduced=3.0)))
int clock_getres(clockid_t __clock_id, struct timespec *__res);

__attribute__((availability(macosx,introduced=10.12))) __attribute__((availability(ios,introduced=10.0))) __attribute__((availability(tvos,introduced=10.0))) __attribute__((availability(watchos,introduced=3.0)))
int clock_gettime(clockid_t __clock_id, struct timespec *__tp);


__attribute__((availability(macosx,introduced=10.12))) __attribute__((availability(ios,introduced=10.0))) __attribute__((availability(tvos,introduced=10.0))) __attribute__((availability(watchos,introduced=3.0)))
__uint64_t clock_gettime_nsec_np(clockid_t __clock_id);


__attribute__((availability(macosx,introduced=10.12))) __attribute__((availability(ios,unavailable)))
__attribute__((availability(tvos,unavailable))) __attribute__((availability(watchos,unavailable)))
int clock_settime(clockid_t __clock_id, const struct timespec *__tp);
# 201 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_time.h" 3 4
__attribute__((availability(macos,introduced=10.15))) __attribute__((availability(ios,introduced=13.0))) __attribute__((availability(tvos,introduced=13.0))) __attribute__((availability(watchos,introduced=6.0)))
int timespec_get(struct timespec *ts, int base);
# 64 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/time.h" 2 3 4
# 12 "tls12.c" 2
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdio.h" 1 3 4
# 61 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdio.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 1 3 4
# 71 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 1 3 4
# 72 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 2 3 4





# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_va_list.h" 1 3 4
# 44 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_va_list.h" 3 4
typedef __darwin_va_list va_list;
# 78 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_size_t.h" 1 3 4
# 79 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_null.h" 1 3 4
# 80 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 2 3 4

# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/stdio.h" 1 3 4
# 44 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/stdio.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 1 3 4
# 45 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/stdio.h" 2 3 4



int renameat(int, const char *, int, const char *) __attribute__((availability(macosx,introduced=10.10)));



int renamex_np(const char *, const char *, unsigned int) __attribute__((availability(macosx,introduced=10.12))) __attribute__((availability(ios,introduced=10.0))) __attribute__((availability(tvos,introduced=10.0))) __attribute__((availability(watchos,introduced=3.0)));
int renameatx_np(int, const char *, int, const char *, unsigned int) __attribute__((availability(macosx,introduced=10.12))) __attribute__((availability(ios,introduced=10.0))) __attribute__((availability(tvos,introduced=10.0))) __attribute__((availability(watchos,introduced=3.0)));
# 82 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_printf.h" 1 3 4
# 34 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_printf.h" 3 4
int printf(const char * restrict, ...) __attribute__((__format__ (__printf__, 1, 2)));
# 83 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 2 3 4



typedef __darwin_off_t fpos_t;
# 97 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 3 4
struct __sbuf {
 unsigned char * _base;
 int _size;
};


struct __sFILEX;
# 131 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 3 4
typedef struct __sFILE {
 unsigned char * _p;
 int _r;
 int _w;
 short _flags;
 short _file;
 struct __sbuf _bf;
 int _lbfsize;


 void *_cookie;
 int (* _Nullable _close)(void *);
 int (* _Nullable _read) (void *, char *, int __n);
 fpos_t (* _Nullable _seek) (void *, fpos_t, int);
 int (* _Nullable _write)(void *, const char *, int __n);


 struct __sbuf _ub;
 struct __sFILEX *_extra;
 int _ur;


 unsigned char _ubuf[3];
 unsigned char _nbuf[1];


 struct __sbuf _lb;


 int _blksize;
 fpos_t _offset;
} FILE;

# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_seek_set.h" 1 3 4
# 165 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 2 3 4


extern FILE *__stdinp __attribute__((__swift_attr__("nonisolated(unsafe)")));
extern FILE *__stdoutp __attribute__((__swift_attr__("nonisolated(unsafe)")));
extern FILE *__stderrp __attribute__((__swift_attr__("nonisolated(unsafe)")));
# 232 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 3 4
void clearerr(FILE *);
int fclose(FILE *);
int feof(FILE *);
int ferror(FILE *);
int fflush(FILE *);
int fgetc(FILE *);
int fgetpos(FILE * restrict, fpos_t *);
char * fgets(char * restrict , int __size, FILE *);



FILE *fopen(const char * restrict __filename, const char * restrict __mode) __asm("_" "fopen" );

int fprintf(FILE * restrict, const char * restrict, ...) __attribute__((__format__ (__printf__, 2, 3)));
int fputc(int, FILE *);
int fputs(const char * restrict, FILE * restrict) __asm("_" "fputs" );
size_t fread(void * restrict __ptr, size_t __size, size_t __nitems, FILE * restrict __stream);
FILE *freopen(const char * restrict, const char * restrict,
     FILE * restrict) __asm("_" "freopen" );
int fscanf(FILE * restrict, const char * restrict, ...) __attribute__((__format__ (__scanf__, 2, 3)));
int fseek(FILE *, long, int);
int fsetpos(FILE *, const fpos_t *);
long ftell(FILE *);
size_t fwrite(const void * restrict __ptr, size_t __size, size_t __nitems, FILE * restrict __stream) __asm("_" "fwrite" );
int getc(FILE *);
int getchar(void);


__attribute__((__deprecated__("This function is provided for compatibility reasons only.  Due to security concerns inherent in the design of gets(3), it is highly recommended that you use fgets(3) instead.")))

char * gets(char *) ;

void perror(const char *) __attribute__((__cold__));
int putc(int, FILE *);
int putchar(int);
int puts(const char *);
int remove(const char *);
int rename (const char *__old, const char *__new);
void rewind(FILE *);
int scanf(const char * restrict, ...) __attribute__((__format__ (__scanf__, 1, 2)));
void setbuf(FILE * restrict, char * restrict );
int setvbuf(FILE * restrict, char * restrict , int, size_t __size);

__attribute__((__availability__(swift, unavailable, message="Use snprintf instead.")))


__attribute__((__deprecated__("This function is provided for compatibility reasons only.  Due to security concerns inherent in the design of sprintf(3), it is highly recommended that you use snprintf(3) instead.")))

int sprintf(char * restrict , const char * restrict, ...) __attribute__((__format__ (__printf__, 2, 3))) ;

int sscanf(const char * restrict, const char * restrict, ...) __attribute__((__format__ (__scanf__, 2, 3)));
FILE *tmpfile(void);

__attribute__((__availability__(swift, unavailable, message="Use mkstemp(3) instead.")))

__attribute__((__deprecated__("This function is provided for compatibility reasons only.  Due to security concerns inherent in the design of tmpnam(3), it is highly recommended that you use mkstemp(3) instead.")))

char * tmpnam(char *);

int ungetc(int, FILE *);
int vfprintf(FILE * restrict, const char * restrict, va_list) __attribute__((__format__ (__printf__, 2, 0)));
int vprintf(const char * restrict, va_list) __attribute__((__format__ (__printf__, 1, 0)));

__attribute__((__availability__(swift, unavailable, message="Use vsnprintf instead.")))


__attribute__((__deprecated__("This function is provided for compatibility reasons only.  Due to security concerns inherent in the design of sprintf(3), it is highly recommended that you use vsnprintf(3) instead.")))

int vsprintf(char * restrict , const char * restrict, va_list) __attribute__((__format__ (__printf__, 2, 0))) ;
# 315 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_ctermid.h" 1 3 4
# 38 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_ctermid.h" 3 4
char * ctermid(char *);
# 316 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 2 3 4






FILE *fdopen(int, const char *) __asm("_" "fdopen" );

int fileno(FILE *);
# 335 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 3 4
int pclose(FILE *) __attribute__((__availability__(swift, unavailable, message="Use posix_spawn APIs or NSTask instead. (On iOS, process spawning is unavailable.)")));



FILE *popen(const char *, const char *) __asm("_" "popen" ) __attribute__((__availability__(swift, unavailable, message="Use posix_spawn APIs or NSTask instead. (On iOS, process spawning is unavailable.)")));
# 354 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 3 4
int __srget(FILE *);
int __svfscanf(FILE *, const char *, va_list) __attribute__((__format__ (__scanf__, 2, 0)));
int __swbuf(int, FILE *);
# 365 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 3 4
inline __attribute__ ((__always_inline__)) int __sputc(int _c, FILE *_p) {
 if (--_p->_w >= 0 || (_p->_w >= _p->_lbfsize && (char)_c != '\n'))
  return (*_p->_p++ = _c);
 else
  return (__swbuf(_c, _p));
}
# 391 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 3 4
void flockfile(FILE *);
int ftrylockfile(FILE *);
void funlockfile(FILE *);
int getc_unlocked(FILE *);
int getchar_unlocked(void);
int putc_unlocked(int, FILE *);
int putchar_unlocked(int);



int getw(FILE *);
int putw(int, FILE *);


__attribute__((__availability__(swift, unavailable, message="Use mkstemp(3) instead.")))

__attribute__((__deprecated__("This function is provided for compatibility reasons only.  Due to security concerns inherent in the design of tempnam(3), it is highly recommended that you use mkstemp(3) instead.")))

char * tempnam(const char *__dir, const char *__prefix) __asm("_" "tempnam" );
# 429 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_off_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_off_t.h" 3 4
typedef __darwin_off_t off_t;
# 430 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 2 3 4


int fseeko(FILE * __stream, off_t __offset, int __whence);
off_t ftello(FILE * __stream);





int snprintf(char * restrict __str, size_t __size, const char * restrict __format, ...) __attribute__((__format__ (__printf__, 3, 4)));
int vfscanf(FILE * restrict __stream, const char * restrict __format, va_list) __attribute__((__format__ (__scanf__, 2, 0)));
int vscanf(const char * restrict __format, va_list) __attribute__((__format__ (__scanf__, 1, 0)));
int vsnprintf(char * restrict __str, size_t __size, const char * restrict __format, va_list) __attribute__((__format__ (__printf__, 3, 0)));
int vsscanf(const char * restrict __str, const char * restrict __format, va_list) __attribute__((__format__ (__scanf__, 2, 0)));
# 454 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_ssize_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_ssize_t.h" 3 4
typedef __darwin_ssize_t ssize_t;
# 455 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 2 3 4


int dprintf(int, const char * restrict, ...) __attribute__((__format__ (__printf__, 2, 3))) __attribute__((availability(macosx,introduced=10.7)));
int vdprintf(int, const char * restrict, va_list) __attribute__((__format__ (__printf__, 2, 0))) __attribute__((availability(macosx,introduced=10.7)));
ssize_t getdelim(char * *restrict __linep, size_t * restrict __linecapp, int __delimiter, FILE * restrict __stream) __attribute__((availability(macosx,introduced=10.7)));
ssize_t getline(char * *restrict __linep, size_t * restrict __linecapp, FILE * restrict __stream) __attribute__((availability(macosx,introduced=10.7)));
FILE *fmemopen(void * restrict __buf , size_t __size, const char * restrict __mode) __attribute__((availability(macos,introduced=10.13))) __attribute__((availability(ios,introduced=11.0))) __attribute__((availability(tvos,introduced=11.0))) __attribute__((availability(watchos,introduced=4.0)));
FILE *open_memstream(char * *__bufp, size_t *__sizep) __attribute__((availability(macos,introduced=10.13))) __attribute__((availability(ios,introduced=11.0))) __attribute__((availability(tvos,introduced=11.0))) __attribute__((availability(watchos,introduced=4.0)));
# 472 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 3 4
extern const int sys_nerr;
extern const char *const sys_errlist[];

int asprintf(char * *restrict, const char * restrict, ...) __attribute__((__format__ (__printf__, 2, 3)));
char * ctermid_r(char *);
char * fgetln(FILE *, size_t *__len);
const char *fmtcheck(const char *, const char *) __attribute__((format_arg(2)));
int fpurge(FILE *);
void setbuffer(FILE *, char *, int __size);
int setlinebuf(FILE *);
int vasprintf(char * *restrict, const char * restrict, va_list) __attribute__((__format__ (__printf__, 2, 0)));





FILE *funopen(const void *,
     int (* _Nullable)(void *, char *, int __n),
     int (* _Nullable)(void *, const char *, int __n),
     fpos_t (* _Nullable)(void *, fpos_t, int),
     int (* _Nullable)(void *));
# 507 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/secure/_stdio.h" 1 3 4
# 32 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/secure/_stdio.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/secure/_common.h" 1 3 4
# 33 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/secure/_stdio.h" 2 3 4





extern int __snprintf_chk (char * restrict , size_t __maxlen, int, size_t,
     const char * restrict, ...);
extern int __vsnprintf_chk (char * restrict , size_t __maxlen, int, size_t,
     const char * restrict, va_list);

extern int __sprintf_chk (char * restrict , int, size_t,
     const char * restrict, ...);
extern int __vsprintf_chk (char * restrict , int, size_t,
     const char * restrict, va_list);
# 508 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdio.h" 2 3 4
# 62 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdio.h" 2 3 4
# 13 "tls12.c" 2
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdlib.h" 1 3 4
# 58 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdlib.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdlib.h" 1 3 4
# 64 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdlib.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 1 3 4
# 65 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdlib.h" 2 3 4





# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/wait.h" 1 3 4
# 79 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/wait.h" 3 4
typedef enum {
 P_ALL,
 P_PID,
 P_PGID
} idtype_t;





# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_pid_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_pid_t.h" 3 4
typedef __darwin_pid_t pid_t;
# 90 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/wait.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_id_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_id_t.h" 3 4
typedef __darwin_id_t id_t;
# 91 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/wait.h" 2 3 4
# 109 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/wait.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/signal.h" 1 3 4
# 73 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/signal.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/appleapiopts.h" 1 3 4
# 74 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/signal.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 1 3 4
# 75 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/signal.h" 2 3 4







# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/machine/signal.h" 1 3 4
# 34 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/machine/signal.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/signal.h" 1 3 4
# 17 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/signal.h" 3 4
typedef int sig_atomic_t;
# 35 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/machine/signal.h" 2 3 4
# 83 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/signal.h" 2 3 4
# 146 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/signal.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/machine/_mcontext.h" 1 3 4
# 34 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/machine/_mcontext.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/_mcontext.h" 1 3 4
# 36 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/_mcontext.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/mach/machine/_structs.h" 1 3 4
# 35 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/mach/machine/_structs.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/mach/arm/_structs.h" 1 3 4
# 41 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/mach/arm/_structs.h" 3 4
struct __darwin_arm_exception_state
{
 __uint32_t __exception;
 __uint32_t __fsr;
 __uint32_t __far;
};
# 59 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/mach/arm/_structs.h" 3 4
struct __darwin_arm_exception_state64
{
 __uint64_t __far;
 __uint32_t __esr;
 __uint32_t __exception;
};

struct __darwin_arm_exception_state64_v2
{
 __uint64_t __far;
 __uint64_t __esr;
};
# 89 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/mach/arm/_structs.h" 3 4
struct __darwin_arm_thread_state
{
 __uint32_t __r[13];
 __uint32_t __sp;
 __uint32_t __lr;
 __uint32_t __pc;
 __uint32_t __cpsr;
};
# 148 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/mach/arm/_structs.h" 3 4
struct __darwin_arm_thread_state64
{
 __uint64_t __x[29];
 __uint64_t __fp;
 __uint64_t __lr;
 __uint64_t __sp;
 __uint64_t __pc;
 __uint32_t __cpsr;
 __uint32_t __pad;
};
# 519 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/mach/arm/_structs.h" 3 4
struct __darwin_arm_vfp_state
{
 __uint32_t __r[64];
 __uint32_t __fpscr;
};
# 538 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/mach/arm/_structs.h" 3 4
struct __darwin_arm_neon_state64
{
 __uint128_t __v[32];
 __uint32_t __fpsr;
 __uint32_t __fpcr;
};

struct __darwin_arm_neon_state
{
 __uint128_t __v[16];
 __uint32_t __fpsr;
 __uint32_t __fpcr;
};
# 609 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/mach/arm/_structs.h" 3 4
struct __arm_pagein_state
{
 int __pagein_error;
};



struct __darwin_arm_sme_state
{
 __uint64_t __svcr;
 __uint64_t __tpidr2_el0;
 __uint16_t __svl_b;
};


struct __darwin_arm_sve_z_state
{
 char __z[16][256];
} __attribute__((aligned(4)));


struct __darwin_arm_sve_p_state
{
 char __p[16][256 / 8];
} __attribute__((aligned(4)));


struct __darwin_arm_sme_za_state
{
 char __za[4096];
} __attribute__((aligned(4)));


struct __darwin_arm_sme2_state
{
 char __zt0[64];
} __attribute__((aligned(4)));
# 712 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/mach/arm/_structs.h" 3 4
struct __arm_legacy_debug_state
{
 __uint32_t __bvr[16];
 __uint32_t __bcr[16];
 __uint32_t __wvr[16];
 __uint32_t __wcr[16];
};
# 735 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/mach/arm/_structs.h" 3 4
struct __darwin_arm_debug_state32
{
 __uint32_t __bvr[16];
 __uint32_t __bcr[16];
 __uint32_t __wvr[16];
 __uint32_t __wcr[16];
 __uint64_t __mdscr_el1;
};


struct __darwin_arm_debug_state64
{
 __uint64_t __bvr[16];
 __uint64_t __bcr[16];
 __uint64_t __wvr[16];
 __uint64_t __wcr[16];
 __uint64_t __mdscr_el1;
};
# 777 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/mach/arm/_structs.h" 3 4
struct __darwin_arm_cpmu_state64
{
 __uint64_t __ctrs[16];
};
# 36 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/mach/machine/_structs.h" 2 3 4
# 37 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/_mcontext.h" 2 3 4




struct __darwin_mcontext32
{
 struct __darwin_arm_exception_state __es;
 struct __darwin_arm_thread_state __ss;
 struct __darwin_arm_vfp_state __fs;
};
# 64 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/_mcontext.h" 3 4
struct __darwin_mcontext64
{
 struct __darwin_arm_exception_state64 __es;
 struct __darwin_arm_thread_state64 __ss;
 struct __darwin_arm_neon_state64 __ns;
};
# 85 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/_mcontext.h" 3 4
typedef struct __darwin_mcontext64 *mcontext_t;
# 35 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/machine/_mcontext.h" 2 3 4
# 147 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/signal.h" 2 3 4

# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_pthread/_pthread_attr_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_pthread/_pthread_attr_t.h" 3 4
typedef __darwin_pthread_attr_t pthread_attr_t;
# 149 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/signal.h" 2 3 4

# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_sigaltstack.h" 1 3 4
# 42 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_sigaltstack.h" 3 4
struct __darwin_sigaltstack
{
 void *ss_sp;
 __darwin_size_t ss_size;
 int ss_flags;
};
typedef struct __darwin_sigaltstack stack_t;
# 151 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/signal.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_ucontext.h" 1 3 4
# 43 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_ucontext.h" 3 4
struct __darwin_ucontext
{
 int uc_onstack;
 __darwin_sigset_t uc_sigmask;
 struct __darwin_sigaltstack uc_stack;
 struct __darwin_ucontext *uc_link;
 __darwin_size_t uc_mcsize;
 struct __darwin_mcontext64 *uc_mcontext;



};


typedef struct __darwin_ucontext ucontext_t;
# 152 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/signal.h" 2 3 4


# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_sigset_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_sigset_t.h" 3 4
typedef __darwin_sigset_t sigset_t;
# 155 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/signal.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_size_t.h" 1 3 4
# 156 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/signal.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_uid_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_uid_t.h" 3 4
typedef __darwin_uid_t uid_t;
# 157 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/signal.h" 2 3 4

union sigval {

 int sival_int;
 void *sival_ptr;
};






struct sigevent {
 int sigev_notify;
 int sigev_signo;
 union sigval sigev_value;
 void (*sigev_notify_function)(union sigval);
 pthread_attr_t *sigev_notify_attributes;
};


typedef struct __siginfo {
 int si_signo;
 int si_errno;
 int si_code;
 pid_t si_pid;
 uid_t si_uid;
 int si_status;
 void *si_addr;
 union sigval si_value;
 long si_band;
 unsigned long __pad[7];
} siginfo_t;
# 270 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/signal.h" 3 4
union __sigaction_u {
 void (*__sa_handler)(int);
 void (*__sa_sigaction)(int, struct __siginfo *,
     void *);
};


struct __sigaction {
 union __sigaction_u __sigaction_u;
 void (*sa_tramp)(void *, int, int, siginfo_t *, void *);
 sigset_t sa_mask;
 int sa_flags;
};




struct sigaction {
 union __sigaction_u __sigaction_u;
 sigset_t sa_mask;
 int sa_flags;
};
# 332 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/signal.h" 3 4
typedef void (*sig_t)(int);
# 349 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/signal.h" 3 4
struct sigvec {
 void (*sv_handler)(int);
 int sv_mask;
 int sv_flags;
};
# 368 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/signal.h" 3 4
struct sigstack {
 char *ss_sp;
 int ss_onstack;
};
# 391 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/signal.h" 3 4
void(*signal(int, void (*)(int)))(int);
# 110 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/wait.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/resource.h" 1 3 4
# 72 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/resource.h" 3 4
# 1 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/stdint.h" 1 3 4
# 56 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/stdint.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdint.h" 1 3 4
# 23 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdint.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_types/_uint8_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_types/_uint8_t.h" 3 4
typedef unsigned char uint8_t;
# 24 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdint.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_types/_uint16_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_types/_uint16_t.h" 3 4
typedef unsigned short uint16_t;
# 25 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdint.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_types/_uint32_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_types/_uint32_t.h" 3 4
typedef unsigned int uint32_t;
# 26 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdint.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_types/_uint64_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_types/_uint64_t.h" 3 4
typedef unsigned long long uint64_t;
# 27 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdint.h" 2 3 4


typedef int8_t int_least8_t;
typedef int16_t int_least16_t;
typedef int32_t int_least32_t;
typedef int64_t int_least64_t;
typedef uint8_t uint_least8_t;
typedef uint16_t uint_least16_t;
typedef uint32_t uint_least32_t;
typedef uint64_t uint_least64_t;



typedef int8_t int_fast8_t;
typedef int16_t int_fast16_t;
typedef int32_t int_fast32_t;
typedef int64_t int_fast64_t;
typedef uint8_t uint_fast8_t;
typedef uint16_t uint_fast16_t;
typedef uint32_t uint_fast32_t;
typedef uint64_t uint_fast64_t;
# 58 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdint.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_types/_intmax_t.h" 1 3 4
# 32 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_types/_intmax_t.h" 3 4
typedef long int intmax_t;
# 59 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdint.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_types/_uintmax_t.h" 1 3 4
# 32 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_types/_uintmax_t.h" 3 4
typedef long unsigned int uintmax_t;
# 60 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdint.h" 2 3 4
# 57 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/stdint.h" 2 3 4
# 73 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/resource.h" 2 3 4


# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 1 3 4
# 76 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/resource.h" 2 3 4




# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_timeval.h" 1 3 4
# 34 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_timeval.h" 3 4
struct timeval
{
 __darwin_time_t tv_sec;
 __darwin_suseconds_t tv_usec;
};
# 81 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/resource.h" 2 3 4








typedef __uint64_t rlim_t;
# 152 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/resource.h" 3 4
struct rusage {
 struct timeval ru_utime;
 struct timeval ru_stime;
# 163 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/resource.h" 3 4
 long ru_maxrss;

 long ru_ixrss;
 long ru_idrss;
 long ru_isrss;
 long ru_minflt;
 long ru_majflt;
 long ru_nswap;
 long ru_inblock;
 long ru_oublock;
 long ru_msgsnd;
 long ru_msgrcv;
 long ru_nsignals;
 long ru_nvcsw;
 long ru_nivcsw;


};
# 200 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/resource.h" 3 4
typedef void *rusage_info_t;

struct rusage_info_v0 {
 uint8_t ri_uuid[16];
 uint64_t ri_user_time;
 uint64_t ri_system_time;
 uint64_t ri_pkg_idle_wkups;
 uint64_t ri_interrupt_wkups;
 uint64_t ri_pageins;
 uint64_t ri_wired_size;
 uint64_t ri_resident_size;
 uint64_t ri_phys_footprint;
 uint64_t ri_proc_start_abstime;
 uint64_t ri_proc_exit_abstime;
};

struct rusage_info_v1 {
 uint8_t ri_uuid[16];
 uint64_t ri_user_time;
 uint64_t ri_system_time;
 uint64_t ri_pkg_idle_wkups;
 uint64_t ri_interrupt_wkups;
 uint64_t ri_pageins;
 uint64_t ri_wired_size;
 uint64_t ri_resident_size;
 uint64_t ri_phys_footprint;
 uint64_t ri_proc_start_abstime;
 uint64_t ri_proc_exit_abstime;
 uint64_t ri_child_user_time;
 uint64_t ri_child_system_time;
 uint64_t ri_child_pkg_idle_wkups;
 uint64_t ri_child_interrupt_wkups;
 uint64_t ri_child_pageins;
 uint64_t ri_child_elapsed_abstime;
};

struct rusage_info_v2 {
 uint8_t ri_uuid[16];
 uint64_t ri_user_time;
 uint64_t ri_system_time;
 uint64_t ri_pkg_idle_wkups;
 uint64_t ri_interrupt_wkups;
 uint64_t ri_pageins;
 uint64_t ri_wired_size;
 uint64_t ri_resident_size;
 uint64_t ri_phys_footprint;
 uint64_t ri_proc_start_abstime;
 uint64_t ri_proc_exit_abstime;
 uint64_t ri_child_user_time;
 uint64_t ri_child_system_time;
 uint64_t ri_child_pkg_idle_wkups;
 uint64_t ri_child_interrupt_wkups;
 uint64_t ri_child_pageins;
 uint64_t ri_child_elapsed_abstime;
 uint64_t ri_diskio_bytesread;
 uint64_t ri_diskio_byteswritten;
};

struct rusage_info_v3 {
 uint8_t ri_uuid[16];
 uint64_t ri_user_time;
 uint64_t ri_system_time;
 uint64_t ri_pkg_idle_wkups;
 uint64_t ri_interrupt_wkups;
 uint64_t ri_pageins;
 uint64_t ri_wired_size;
 uint64_t ri_resident_size;
 uint64_t ri_phys_footprint;
 uint64_t ri_proc_start_abstime;
 uint64_t ri_proc_exit_abstime;
 uint64_t ri_child_user_time;
 uint64_t ri_child_system_time;
 uint64_t ri_child_pkg_idle_wkups;
 uint64_t ri_child_interrupt_wkups;
 uint64_t ri_child_pageins;
 uint64_t ri_child_elapsed_abstime;
 uint64_t ri_diskio_bytesread;
 uint64_t ri_diskio_byteswritten;
 uint64_t ri_cpu_time_qos_default;
 uint64_t ri_cpu_time_qos_maintenance;
 uint64_t ri_cpu_time_qos_background;
 uint64_t ri_cpu_time_qos_utility;
 uint64_t ri_cpu_time_qos_legacy;
 uint64_t ri_cpu_time_qos_user_initiated;
 uint64_t ri_cpu_time_qos_user_interactive;
 uint64_t ri_billed_system_time;
 uint64_t ri_serviced_system_time;
};

struct rusage_info_v4 {
 uint8_t ri_uuid[16];
 uint64_t ri_user_time;
 uint64_t ri_system_time;
 uint64_t ri_pkg_idle_wkups;
 uint64_t ri_interrupt_wkups;
 uint64_t ri_pageins;
 uint64_t ri_wired_size;
 uint64_t ri_resident_size;
 uint64_t ri_phys_footprint;
 uint64_t ri_proc_start_abstime;
 uint64_t ri_proc_exit_abstime;
 uint64_t ri_child_user_time;
 uint64_t ri_child_system_time;
 uint64_t ri_child_pkg_idle_wkups;
 uint64_t ri_child_interrupt_wkups;
 uint64_t ri_child_pageins;
 uint64_t ri_child_elapsed_abstime;
 uint64_t ri_diskio_bytesread;
 uint64_t ri_diskio_byteswritten;
 uint64_t ri_cpu_time_qos_default;
 uint64_t ri_cpu_time_qos_maintenance;
 uint64_t ri_cpu_time_qos_background;
 uint64_t ri_cpu_time_qos_utility;
 uint64_t ri_cpu_time_qos_legacy;
 uint64_t ri_cpu_time_qos_user_initiated;
 uint64_t ri_cpu_time_qos_user_interactive;
 uint64_t ri_billed_system_time;
 uint64_t ri_serviced_system_time;
 uint64_t ri_logical_writes;
 uint64_t ri_lifetime_max_phys_footprint;
 uint64_t ri_instructions;
 uint64_t ri_cycles;
 uint64_t ri_billed_energy;
 uint64_t ri_serviced_energy;
 uint64_t ri_interval_max_phys_footprint;
 uint64_t ri_runnable_time;
};

struct rusage_info_v5 {
 uint8_t ri_uuid[16];
 uint64_t ri_user_time;
 uint64_t ri_system_time;
 uint64_t ri_pkg_idle_wkups;
 uint64_t ri_interrupt_wkups;
 uint64_t ri_pageins;
 uint64_t ri_wired_size;
 uint64_t ri_resident_size;
 uint64_t ri_phys_footprint;
 uint64_t ri_proc_start_abstime;
 uint64_t ri_proc_exit_abstime;
 uint64_t ri_child_user_time;
 uint64_t ri_child_system_time;
 uint64_t ri_child_pkg_idle_wkups;
 uint64_t ri_child_interrupt_wkups;
 uint64_t ri_child_pageins;
 uint64_t ri_child_elapsed_abstime;
 uint64_t ri_diskio_bytesread;
 uint64_t ri_diskio_byteswritten;
 uint64_t ri_cpu_time_qos_default;
 uint64_t ri_cpu_time_qos_maintenance;
 uint64_t ri_cpu_time_qos_background;
 uint64_t ri_cpu_time_qos_utility;
 uint64_t ri_cpu_time_qos_legacy;
 uint64_t ri_cpu_time_qos_user_initiated;
 uint64_t ri_cpu_time_qos_user_interactive;
 uint64_t ri_billed_system_time;
 uint64_t ri_serviced_system_time;
 uint64_t ri_logical_writes;
 uint64_t ri_lifetime_max_phys_footprint;
 uint64_t ri_instructions;
 uint64_t ri_cycles;
 uint64_t ri_billed_energy;
 uint64_t ri_serviced_energy;
 uint64_t ri_interval_max_phys_footprint;
 uint64_t ri_runnable_time;
 uint64_t ri_flags;
};

struct rusage_info_v6 {
 uint8_t ri_uuid[16];
 uint64_t ri_user_time;
 uint64_t ri_system_time;
 uint64_t ri_pkg_idle_wkups;
 uint64_t ri_interrupt_wkups;
 uint64_t ri_pageins;
 uint64_t ri_wired_size;
 uint64_t ri_resident_size;
 uint64_t ri_phys_footprint;
 uint64_t ri_proc_start_abstime;
 uint64_t ri_proc_exit_abstime;
 uint64_t ri_child_user_time;
 uint64_t ri_child_system_time;
 uint64_t ri_child_pkg_idle_wkups;
 uint64_t ri_child_interrupt_wkups;
 uint64_t ri_child_pageins;
 uint64_t ri_child_elapsed_abstime;
 uint64_t ri_diskio_bytesread;
 uint64_t ri_diskio_byteswritten;
 uint64_t ri_cpu_time_qos_default;
 uint64_t ri_cpu_time_qos_maintenance;
 uint64_t ri_cpu_time_qos_background;
 uint64_t ri_cpu_time_qos_utility;
 uint64_t ri_cpu_time_qos_legacy;
 uint64_t ri_cpu_time_qos_user_initiated;
 uint64_t ri_cpu_time_qos_user_interactive;
 uint64_t ri_billed_system_time;
 uint64_t ri_serviced_system_time;
 uint64_t ri_logical_writes;
 uint64_t ri_lifetime_max_phys_footprint;
 uint64_t ri_instructions;
 uint64_t ri_cycles;
 uint64_t ri_billed_energy;
 uint64_t ri_serviced_energy;
 uint64_t ri_interval_max_phys_footprint;
 uint64_t ri_runnable_time;
 uint64_t ri_flags;
 uint64_t ri_user_ptime;
 uint64_t ri_system_ptime;
 uint64_t ri_pinstructions;
 uint64_t ri_pcycles;
 uint64_t ri_energy_nj;
 uint64_t ri_penergy_nj;
 uint64_t ri_secure_time_in_system;
 uint64_t ri_secure_ptime_in_system;
 uint64_t ri_neural_footprint;
 uint64_t ri_lifetime_max_neural_footprint;
 uint64_t ri_interval_max_neural_footprint;
 uint64_t ri_reserved[9];
};

typedef struct rusage_info_v6 rusage_info_current;
# 464 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/resource.h" 3 4
struct rlimit {
 rlim_t rlim_cur;
 rlim_t rlim_max;
};
# 499 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/resource.h" 3 4
struct proc_rlimit_control_wakeupmon {
 uint32_t wm_flags;
 int32_t wm_rate;
};
# 578 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/resource.h" 3 4
int getpriority(int, id_t);

int getiopolicy_np(int, int) __attribute__((availability(macosx,introduced=10.5)));

int getrlimit(int, struct rlimit *) __asm("_" "getrlimit" );
int getrusage(int, struct rusage *);
int setpriority(int, id_t, int);

int setiopolicy_np(int, int, int) __attribute__((availability(macosx,introduced=10.5)));

int setrlimit(int, const struct rlimit *) __asm("_" "setrlimit" );
# 111 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/wait.h" 2 3 4
# 186 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/wait.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/machine/endian.h" 1 3 4
# 37 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/machine/endian.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/endian.h" 1 3 4
# 61 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/endian.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_endian.h" 1 3 4
# 94 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_endian.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/machine/_endian.h" 1 3 4
# 37 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/machine/_endian.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/_endian.h" 1 3 4
# 95 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/_endian.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/__endian.h" 1 3 4
# 96 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/_endian.h" 2 3 4
# 38 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/machine/_endian.h" 2 3 4
# 95 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_endian.h" 2 3 4
# 131 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_endian.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/libkern/_OSByteOrder.h" 1 3 4
# 62 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/libkern/_OSByteOrder.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/libkern/arm/_OSByteOrder.h" 1 3 4
# 48 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/libkern/arm/_OSByteOrder.h" 3 4
static inline
__uint16_t
_OSSwapInt16(
 __uint16_t _data
 )
{

 return (__uint16_t)(_data << 8 | _data >> 8);
}

static inline
__uint32_t
_OSSwapInt32(
 __uint32_t _data
 )
{

 _data = __builtin_bswap32(_data);





 return _data;
}

static inline
__uint64_t
_OSSwapInt64(
 __uint64_t _data
 )
{

 return __builtin_bswap64(_data);
# 95 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/libkern/arm/_OSByteOrder.h" 3 4
}
# 63 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/libkern/_OSByteOrder.h" 2 3 4
# 132 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_endian.h" 2 3 4
# 62 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/endian.h" 2 3 4
# 38 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/machine/endian.h" 2 3 4
# 187 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/wait.h" 2 3 4







union wait {
 int w_status;



 struct {

  unsigned int w_Termsig:7,
      w_Coredump:1,
      w_Retcode:8,
      w_Filler:16;






 } w_T;





 struct {

  unsigned int w_Stopval:8,
      w_Stopsig:8,
      w_Filler:16;





 } w_S;
};
# 246 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/wait.h" 3 4
pid_t wait(int *) __asm("_" "wait" );
pid_t waitpid(pid_t, int *, int) __asm("_" "waitpid" );

int waitid(idtype_t, id_t, siginfo_t *, int) __asm("_" "waitid" );


pid_t wait3(int *, int, struct rusage *);
pid_t wait4(pid_t, int *, int, struct rusage *);
# 71 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdlib.h" 2 3 4

# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/alloca.h" 1 3 4
# 30 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/alloca.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_size_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/alloca.h" 2 3 4




void * alloca(size_t __size);
# 73 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdlib.h" 2 3 4
# 91 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdlib.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_size_t.h" 1 3 4
# 92 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdlib.h" 2 3 4


# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_ct_rune_t.h" 1 3 4
# 32 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_ct_rune_t.h" 3 4
typedef __darwin_ct_rune_t ct_rune_t;
# 95 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdlib.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_rune_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_rune_t.h" 3 4
typedef __darwin_rune_t rune_t;
# 96 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdlib.h" 2 3 4


# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_wchar_t.h" 1 3 4
# 53 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_wchar_t.h" 3 4
typedef __darwin_wchar_t wchar_t;
# 99 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdlib.h" 2 3 4



typedef struct {
 int quot;
 int rem;
} div_t;

typedef struct {
 long quot;
 long rem;
} ldiv_t;


typedef struct {
 long long quot;
 long long rem;
} lldiv_t;


# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_null.h" 1 3 4
# 120 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdlib.h" 2 3 4
# 138 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdlib.h" 3 4
extern int __mb_cur_max;





# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/malloc/_malloc.h" 1 3 4
# 33 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/malloc/_malloc.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 1 3 4
# 34 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/malloc/_malloc.h" 2 3 4


# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_size_t.h" 1 3 4
# 37 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/malloc/_malloc.h" 2 3 4







# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/malloc/_malloc_type.h" 1 3 4
# 27 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/malloc/_malloc_type.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/malloc/_ptrcheck.h" 1 3 4
# 28 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/malloc/_malloc_type.h" 2 3 4


typedef unsigned long long malloc_type_id_t;




# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 1 3 4
# 36 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/malloc/_malloc_type.h" 2 3 4

# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_size_t.h" 1 3 4
# 38 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/malloc/_malloc_type.h" 2 3 4
# 92 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/malloc/_malloc_type.h" 3 4
__attribute__((availability(macos,introduced=14.0))) __attribute__((availability(ios,introduced=17.0))) __attribute__((availability(tvos,introduced=17.0))) __attribute__((availability(watchos,introduced=10.0))) __attribute__((availability(visionos,introduced=1.0))) __attribute__((availability(driverkit,introduced=23.0)))
void * malloc_type_malloc(size_t size, malloc_type_id_t type_id) __attribute__((__warn_unused_result__)) __attribute__((alloc_size(1)));
__attribute__((availability(macos,introduced=14.0))) __attribute__((availability(ios,introduced=17.0))) __attribute__((availability(tvos,introduced=17.0))) __attribute__((availability(watchos,introduced=10.0))) __attribute__((availability(visionos,introduced=1.0))) __attribute__((availability(driverkit,introduced=23.0)))
void * malloc_type_calloc(size_t count, size_t size, malloc_type_id_t type_id) __attribute__((__warn_unused_result__)) __attribute__((alloc_size(1,2)));
__attribute__((availability(macos,introduced=14.0))) __attribute__((availability(ios,introduced=17.0))) __attribute__((availability(tvos,introduced=17.0))) __attribute__((availability(watchos,introduced=10.0))) __attribute__((availability(visionos,introduced=1.0))) __attribute__((availability(driverkit,introduced=23.0)))
void malloc_type_free(void * ptr, malloc_type_id_t type_id);
__attribute__((availability(macos,introduced=14.0))) __attribute__((availability(ios,introduced=17.0))) __attribute__((availability(tvos,introduced=17.0))) __attribute__((availability(watchos,introduced=10.0))) __attribute__((availability(visionos,introduced=1.0))) __attribute__((availability(driverkit,introduced=23.0)))
void * malloc_type_realloc(void * ptr, size_t size, malloc_type_id_t type_id) __attribute__((__warn_unused_result__)) __attribute__((alloc_size(2)));
__attribute__((availability(macos,introduced=14.0))) __attribute__((availability(ios,introduced=17.0))) __attribute__((availability(tvos,introduced=17.0))) __attribute__((availability(watchos,introduced=10.0))) __attribute__((availability(visionos,introduced=1.0))) __attribute__((availability(driverkit,introduced=23.0)))
void * malloc_type_valloc(size_t size, malloc_type_id_t type_id) __attribute__((__warn_unused_result__)) __attribute__((alloc_size(1)));
__attribute__((availability(macos,introduced=14.0))) __attribute__((availability(ios,introduced=17.0))) __attribute__((availability(tvos,introduced=17.0))) __attribute__((availability(watchos,introduced=10.0))) __attribute__((availability(visionos,introduced=1.0))) __attribute__((availability(driverkit,introduced=23.0)))
void * malloc_type_aligned_alloc(size_t alignment, size_t size, malloc_type_id_t type_id) __attribute__((__warn_unused_result__)) __attribute__((alloc_align(1))) __attribute__((alloc_size(2)));

__attribute__((availability(macos,introduced=14.0))) __attribute__((availability(ios,introduced=17.0))) __attribute__((availability(tvos,introduced=17.0))) __attribute__((availability(watchos,introduced=10.0))) __attribute__((availability(visionos,introduced=1.0))) __attribute__((availability(driverkit,introduced=23.0)))
int malloc_type_posix_memalign(void * *memptr, size_t alignment, size_t size, malloc_type_id_t type_id) ;



typedef struct _malloc_zone_t malloc_zone_t;

__attribute__((availability(macos,introduced=14.0))) __attribute__((availability(ios,introduced=17.0))) __attribute__((availability(tvos,introduced=17.0))) __attribute__((availability(watchos,introduced=10.0))) __attribute__((availability(visionos,introduced=1.0))) __attribute__((availability(driverkit,introduced=23.0)))
void * malloc_type_zone_malloc(malloc_zone_t *zone, size_t size, malloc_type_id_t type_id) __attribute__((__warn_unused_result__)) __attribute__((alloc_size(2)));
__attribute__((availability(macos,introduced=14.0))) __attribute__((availability(ios,introduced=17.0))) __attribute__((availability(tvos,introduced=17.0))) __attribute__((availability(watchos,introduced=10.0))) __attribute__((availability(visionos,introduced=1.0))) __attribute__((availability(driverkit,introduced=23.0)))
void * malloc_type_zone_calloc(malloc_zone_t *zone, size_t count, size_t size, malloc_type_id_t type_id) __attribute__((__warn_unused_result__)) __attribute__((alloc_size(2,3)));
__attribute__((availability(macos,introduced=14.0))) __attribute__((availability(ios,introduced=17.0))) __attribute__((availability(tvos,introduced=17.0))) __attribute__((availability(watchos,introduced=10.0))) __attribute__((availability(visionos,introduced=1.0))) __attribute__((availability(driverkit,introduced=23.0)))
void malloc_type_zone_free(malloc_zone_t *zone, void * ptr, malloc_type_id_t type_id);
__attribute__((availability(macos,introduced=14.0))) __attribute__((availability(ios,introduced=17.0))) __attribute__((availability(tvos,introduced=17.0))) __attribute__((availability(watchos,introduced=10.0))) __attribute__((availability(visionos,introduced=1.0))) __attribute__((availability(driverkit,introduced=23.0)))
void * malloc_type_zone_realloc(malloc_zone_t *zone, void * ptr, size_t size, malloc_type_id_t type_id) __attribute__((__warn_unused_result__)) __attribute__((alloc_size(3)));
__attribute__((availability(macos,introduced=14.0))) __attribute__((availability(ios,introduced=17.0))) __attribute__((availability(tvos,introduced=17.0))) __attribute__((availability(watchos,introduced=10.0))) __attribute__((availability(visionos,introduced=1.0))) __attribute__((availability(driverkit,introduced=23.0)))
void * malloc_type_zone_valloc(malloc_zone_t *zone, size_t size, malloc_type_id_t type_id) __attribute__((__warn_unused_result__)) __attribute__((alloc_size(2)));
__attribute__((availability(macos,introduced=14.0))) __attribute__((availability(ios,introduced=17.0))) __attribute__((availability(tvos,introduced=17.0))) __attribute__((availability(watchos,introduced=10.0))) __attribute__((availability(visionos,introduced=1.0))) __attribute__((availability(driverkit,introduced=23.0)))
void * malloc_type_zone_memalign(malloc_zone_t *zone, size_t alignment, size_t size, malloc_type_id_t type_id) __attribute__((__warn_unused_result__)) __attribute__((alloc_align(2))) __attribute__((alloc_size(3)));
# 45 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/malloc/_malloc.h" 2 3 4
# 54 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/malloc/_malloc.h" 3 4
void * malloc(size_t __size) __attribute__((__warn_unused_result__)) __attribute__((alloc_size(1))) ;
void * calloc(size_t __count, size_t __size) __attribute__((__warn_unused_result__)) __attribute__((alloc_size(1,2))) ;
void free(void * );
void * realloc(void * __ptr, size_t __size) __attribute__((__warn_unused_result__)) __attribute__((alloc_size(2))) ;

void * reallocf(void * __ptr, size_t __size) __attribute__((__warn_unused_result__)) __attribute__((alloc_size(2)));
void * valloc(size_t __size) __attribute__((__warn_unused_result__)) __attribute__((alloc_size(1))) ;




void * aligned_alloc(size_t __alignment, size_t __size) __attribute__((__warn_unused_result__)) __attribute__((alloc_align(1))) __attribute__((alloc_size(2))) __attribute__((availability(macosx,introduced=10.15))) __attribute__((availability(ios,introduced=13.0))) __attribute__((availability(tvos,introduced=13.0))) __attribute__((availability(watchos,introduced=6.0)));


int posix_memalign(void * *__memptr, size_t __alignment, size_t __size) __attribute__((availability(macosx,introduced=10.6)));
# 145 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdlib.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_abort.h" 1 3 4
# 33 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_abort.h" 3 4
void abort(void) __attribute__((__cold__)) __attribute__((__noreturn__));
# 146 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdlib.h" 2 3 4


int abs(int) __attribute__((__const__));
int atexit(void (* _Nonnull)(void));


int at_quick_exit(void (*)(void));

double atof(const char *);
int atoi(const char *);
long atol(const char *);

long long
  atoll(const char *);

void *bsearch(const void * __key, const void * __base, size_t __nel,
     size_t __width, int (* _Nonnull __compar)(const void *, const void *));

div_t div(int, int) __attribute__((__const__));
void exit(int) __attribute__((__noreturn__));

char * getenv(const char *);
long labs(long) __attribute__((__const__));
ldiv_t ldiv(long, long) __attribute__((__const__));

long long
  llabs(long long);
lldiv_t lldiv(long long, long long);


int mblen(const char * __s, size_t __n);
size_t mbstowcs(wchar_t * restrict , const char * restrict, size_t __n);
int mbtowc(wchar_t * restrict, const char * restrict , size_t __n);

void qsort(void * __base, size_t __nel, size_t __width,
     int (* _Nonnull __compar)(const void *, const void *));


void quick_exit(int) __attribute__((__noreturn__));

int rand(void) __attribute__((__availability__(swift, unavailable, message="Use arc4random instead.")));

void srand(unsigned) __attribute__((__availability__(swift, unavailable, message="Use arc4random instead.")));
double strtod(const char *, char * *) __asm("_" "strtod" );
float strtof(const char *, char * *) __asm("_" "strtof" );
long strtol(const char *__str, char * *__endptr, int __base);
long double
  strtold(const char *, char * *);

long long
  strtoll(const char *__str, char * *__endptr, int __base);

unsigned long
  strtoul(const char *__str, char * *__endptr, int __base);

unsigned long long
  strtoull(const char *__str, char * *__endptr, int __base);


__attribute__((__availability__(swift, unavailable, message="Use posix_spawn APIs or NSTask instead. (On iOS, process spawning is unavailable.)")))
__attribute__((availability(macos,introduced=10.0))) __attribute__((availability(ios,unavailable)))
__attribute__((availability(watchos,unavailable))) __attribute__((availability(tvos,unavailable)))
int system(const char *) __asm("_" "system" );


size_t wcstombs(char * restrict , const wchar_t * restrict, size_t __n);
int wctomb(char *, wchar_t);


void _Exit(int) __attribute__((__noreturn__));
long a64l(const char *);
double drand48(void);
char * ecvt(double, int, int *restrict, int *restrict);
double erand48(unsigned short[3]);
char * fcvt(double, int, int *restrict, int *restrict);
char * gcvt(double, int, char *) ;
int getsubopt(char * *, char * const *, char * *);
int grantpt(int);

char *
  initstate(unsigned, char *, size_t __size);




long jrand48(unsigned short[3]) __attribute__((__availability__(swift, unavailable, message="Use arc4random instead.")));
char *l64a(long);
void lcong48(unsigned short[7]);
long lrand48(void) __attribute__((__availability__(swift, unavailable, message="Use arc4random instead.")));

__attribute__((__deprecated__("This function is provided for compatibility reasons only.  Due to security concerns inherent in the design of mktemp(3), it is highly recommended that you use mkstemp(3) instead.")))

char * mktemp(char *);
int mkstemp(char *);
long mrand48(void) __attribute__((__availability__(swift, unavailable, message="Use arc4random instead.")));
long nrand48(unsigned short[3]) __attribute__((__availability__(swift, unavailable, message="Use arc4random instead.")));
int posix_openpt(int);
char * ptsname(int);


int ptsname_r(int fildes, char * buffer, size_t buflen) __attribute__((availability(macos,introduced=10.13.4))) __attribute__((availability(ios,introduced=11.3))) __attribute__((availability(tvos,introduced=11.3))) __attribute__((availability(watchos,introduced=4.3)));


int putenv(char *) __asm("_" "putenv" );
long random(void) __attribute__((__availability__(swift, unavailable, message="Use arc4random instead.")));
int rand_r(unsigned *) __attribute__((__availability__(swift, unavailable, message="Use arc4random instead.")));

char * realpath(const char * restrict, char * restrict ) __asm("_" "realpath" "$DARWIN_EXTSN");



unsigned short * seed48(unsigned short[3]);
int setenv(const char * __name, const char * __value, int __overwrite) __asm("_" "setenv" );

void setkey(const char *) __asm("_" "setkey" );



char * setstate(const char *);
void srand48(long);

void srandom(unsigned);



int unlockpt(int);

int unsetenv(const char *) __asm("_" "unsetenv" );
# 282 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdlib.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_dev_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_dev_t.h" 3 4
typedef __darwin_dev_t dev_t;
# 283 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdlib.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_mode_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_mode_t.h" 3 4
typedef __darwin_mode_t mode_t;
# 284 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdlib.h" 2 3 4



uint32_t arc4random(void);
void arc4random_addrandom(unsigned char * , int __datlen)
    __attribute__((availability(macosx,introduced=10.0))) __attribute__((availability(macosx,deprecated=10.12,message="use arc4random_stir")))
    __attribute__((availability(ios,introduced=2.0))) __attribute__((availability(ios,deprecated=10.0,message="use arc4random_stir")))
    __attribute__((availability(tvos,introduced=2.0))) __attribute__((availability(tvos,deprecated=10.0,message="use arc4random_stir")))
    __attribute__((availability(watchos,introduced=1.0))) __attribute__((availability(watchos,deprecated=3.0,message="use arc4random_stir")));
void arc4random_buf(void * __buf, size_t __nbytes) __attribute__((availability(macosx,introduced=10.7)));
void arc4random_stir(void);
uint32_t
  arc4random_uniform(uint32_t __upper_bound) __attribute__((availability(macosx,introduced=10.7)));

int atexit_b(void (^ _Nonnull)(void)) __attribute__((availability(macosx,introduced=10.6)));
# 307 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdlib.h" 3 4
void *bsearch_b(const void * __key, const void * __base, size_t __nel,
     size_t __width, int (^ _Nonnull __compar)(const void *, const void *) __attribute__((__noescape__)))
     __attribute__((availability(macosx,introduced=10.6)));



char * cgetcap(char *, const char *, int);
int cgetclose(void);
int cgetent(char * *, char * *, const char *);
int cgetfirst(char * *, char * *);
int cgetmatch(const char *, const char *);
int cgetnext(char * *, char * *);
int cgetnum(char *, const char *, long *);
int cgetset(const char *);
int cgetstr(char *, const char *, char * *);
int cgetustr(char *, const char *, char * *);

int daemon(int, int) __asm("_" "daemon" ) __attribute__((availability(macosx,introduced=10.0,deprecated=10.5,message="Use posix_spawn APIs instead."))) __attribute__((availability(watchos,unavailable))) __attribute__((availability(tvos,unavailable)));
char * devname(dev_t, mode_t);
char * devname_r(dev_t, mode_t, char * buf, int len);
char * getbsize(int *, long *);
int getloadavg(double [], int __nelem);
const char
 *getprogname(void);
void setprogname(const char *);
# 341 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_stdlib.h" 3 4
int heapsort(void * __base, size_t __nel, size_t __width,
     int (* _Nonnull __compar)(const void *, const void *));

int heapsort_b(void * __base, size_t __nel, size_t __width,
     int (^ _Nonnull __compar)(const void *, const void *) __attribute__((__noescape__)))
     __attribute__((availability(macosx,introduced=10.6)));

int mergesort(void * __base, size_t __nel, size_t __width,
     int (* _Nonnull __compar)(const void *, const void *));

int mergesort_b(void * __base, size_t __nel, size_t __width,
     int (^ _Nonnull __compar)(const void *, const void *) __attribute__((__noescape__)))
     __attribute__((availability(macosx,introduced=10.6)));

void psort(void * __base, size_t __nel, size_t __width,
     int (* _Nonnull __compar)(const void *, const void *))
     __attribute__((availability(macosx,introduced=10.6)));

void psort_b(void * __base, size_t __nel, size_t __width,
     int (^ _Nonnull __compar)(const void *, const void *) __attribute__((__noescape__)))
     __attribute__((availability(macosx,introduced=10.6)));

void psort_r(void * __base, size_t __nel, size_t __width, void *,
     int (* _Nonnull __compar)(void *, const void *, const void *))
     __attribute__((availability(macosx,introduced=10.6)));

void qsort_b(void * __base, size_t __nel, size_t __width,
     int (^ _Nonnull __compar)(const void *, const void *) __attribute__((__noescape__)))
     __attribute__((availability(macosx,introduced=10.6)));

void qsort_r(void * __base, size_t __nel, size_t __width, void *,
     int (* _Nonnull __compar)(void *, const void *, const void *));
int radixsort(const unsigned char * * __base, int __nel, const unsigned char * __table,
     unsigned __endbyte);
int rpmatch(const char *)
 __attribute__((availability(macos,introduced=10.15))) __attribute__((availability(ios,introduced=13.0))) __attribute__((availability(tvos,introduced=13.0))) __attribute__((availability(watchos,introduced=6.0)));
int sradixsort(const unsigned char * * __base, int __nel, const unsigned char * __table,
     unsigned __endbyte);
void sranddev(void);
void srandomdev(void);

long long
 strtonum(const char *__numstr, long long __minval, long long __maxval, const char * *__errstrp)
 __attribute__((availability(macos,introduced=11.0))) __attribute__((availability(ios,introduced=14.0))) __attribute__((availability(tvos,introduced=14.0))) __attribute__((availability(watchos,introduced=7.0)));

long long
  strtoq(const char *__str, char * *__endptr, int __base);
unsigned long long
  strtouq(const char *__str, char * *__endptr, int __base);

extern char * suboptarg;
# 59 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdlib.h" 2 3 4
# 14 "tls12.c" 2
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/string.h" 1 3 4
# 58 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/string.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_string.h" 1 3 4
# 64 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_string.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 1 3 4
# 65 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_string.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_size_t.h" 1 3 4
# 66 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_string.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_null.h" 1 3 4
# 67 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_string.h" 2 3 4






void *
  memchr(const void * __s, int __c, size_t __n);
int memcmp(const void * __s1, const void * __s2,
  size_t __n);
void *
  memcpy(void * __dst, const void * __src,
  size_t __n);
void *
  memmove(void * __dst,
  const void * __src, size_t __len);
void *
  memset(void * __b, int __c, size_t __len);
char *
  strcat(char * __s1, const char *__s2)
                                  ;
char * strchr(const char *__s, int __c);
int strcmp(const char *__s1, const char *__s2);
int strcoll(const char *__s1, const char *__s2);
char *
  strcpy(char * __dst, const char *__src)
                                  ;
size_t strcspn(const char *__s, const char *__charset);
char * strerror(int __errnum) __asm("_" "strerror" );
size_t strlen(const char *__s);
char *
  strncat(char * __s1,
  const char * __s2, size_t __n)
                                  ;
int strncmp(const char * __s1,
  const char * __s2, size_t __n);
char *
  strncpy(char * __dst,
        const char * __src, size_t __n)
                                        ;
char * strpbrk(const char *__s, const char *__charset);
char * strrchr(const char *__s, int __c);
size_t strspn(const char *__s, const char *__charset);
char * strstr(const char *__big, const char *__little);
char * strtok(char * __str, const char *__sep);
size_t strxfrm(char * __s1, const char *__s2, size_t __n);
# 125 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_string.h" 3 4
char *
        strtok_r(char * __str, const char *__sep,
        char * *__lasts);
# 139 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_string.h" 3 4
int strerror_r(int __errnum, char * __strerrbuf,
        size_t __buflen);
char * strdup(const char *__s1);
void *
        memccpy(void * __dst, const void * __src,
        int __c, size_t __n);
# 156 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_string.h" 3 4
char *
        stpcpy(char * __dst, const char *__src) ;
char *
        stpncpy(char * __dst,
        const char * __src, size_t __n)
        __attribute__((availability(macosx,introduced=10.7)))
                                        ;
char * strndup(const char * __s1, size_t __n) __attribute__((availability(macosx,introduced=10.7)));
size_t strnlen(const char * __s1, size_t __n) __attribute__((availability(macosx,introduced=10.7)));
char * strsignal(int __sig);






# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_rsize_t.h" 1 3 4
# 50 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_rsize_t.h" 3 4
typedef __darwin_size_t rsize_t;
# 173 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_string.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_errno_t.h" 1 3 4
# 30 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_errno_t.h" 3 4
typedef int errno_t;
# 174 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_string.h" 2 3 4


errno_t memset_s(void * __s, rsize_t __smax, int __c, rsize_t __n) __attribute__((availability(macosx,introduced=10.9)));
# 186 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_string.h" 3 4
void *
        memmem(const void * __big, size_t __big_len,
        const void * __little, size_t __little_len) __attribute__((availability(macosx,introduced=10.7)));
void memset_pattern4(void * __b, const void * __pattern4, size_t __len) __attribute__((availability(macosx,introduced=10.5)));
void memset_pattern8(void * __b, const void * __pattern8, size_t __len) __attribute__((availability(macosx,introduced=10.5)));
void memset_pattern16(void * __b, const void * __pattern16, size_t __len) __attribute__((availability(macosx,introduced=10.5)));

char *
        strcasestr(const char *__big, const char *__little);
__attribute__((availability(macosx,introduced=15.4))) __attribute__((availability(ios,introduced=18.4)))
__attribute__((availability(tvos,introduced=18.4))) __attribute__((availability(watchos,introduced=11.4)))
char *
        strchrnul(const char *__s, int __c);
char *
        strnstr(const char * __big, const char *__little, size_t __len);
size_t strlcat(char * __dst, const char *__source, size_t __size);
size_t strlcpy(char * __dst, const char *__source, size_t __size);
void strmode(int __mode, char * __bp);
char *
        strsep(char * *__stringp, const char *__delim);


void swab(const void * restrict, void * restrict, ssize_t __len);

__attribute__((availability(macosx,introduced=10.12.1))) __attribute__((availability(ios,introduced=10.1)))
__attribute__((availability(tvos,introduced=10.0.1))) __attribute__((availability(watchos,introduced=3.1)))
int timingsafe_bcmp(const void * __b1, const void * __b2, size_t __len);

__attribute__((availability(macosx,introduced=11.0))) __attribute__((availability(ios,introduced=14.0)))
__attribute__((availability(tvos,introduced=14.0))) __attribute__((availability(watchos,introduced=7.0)))
int strsignal_r(int __sig, char * __strsignalbuf, size_t __buflen);





# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_strings.h" 1 3 4
# 65 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_strings.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 1 3 4
# 66 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_strings.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_size_t.h" 1 3 4
# 67 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_strings.h" 2 3 4






int bcmp(const void *, const void *, size_t __n) ;
void bcopy(const void *, void *, size_t __n) ;
void bzero(void *, size_t __n) ;
char * index(const char *, int) ;
char * rindex(const char *, int) ;


int ffs(int);
int strcasecmp(const char *, const char *);
int strncasecmp(const char *, const char *, size_t);





int ffsl(long) __attribute__((availability(macosx,introduced=10.5)));
int ffsll(long long) __attribute__((availability(macosx,introduced=10.9)));
int fls(int) __attribute__((availability(macosx,introduced=10.5)));
int flsl(long) __attribute__((availability(macosx,introduced=10.5)));
int flsll(long long) __attribute__((availability(macosx,introduced=10.9)));





# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/secure/_strings.h" 1 3 4
# 32 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/secure/_strings.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 1 3 4
# 33 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/secure/_strings.h" 2 3 4
# 99 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_strings.h" 2 3 4
# 223 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_string.h" 2 3 4





# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/secure/_string.h" 1 3 4
# 32 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/secure/_string.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 1 3 4
# 33 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/secure/_string.h" 2 3 4
# 229 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_string.h" 2 3 4
# 59 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/string.h" 2 3 4
# 15 "tls12.c" 2
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/assert.h" 1 3 4
# 55 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/assert.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_assert.h" 1 3 4
# 63 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_assert.h" 3 4
void __assert_rtn(const char *, const char *, int, const char *) __attribute__((__noreturn__)) __attribute__((__cold__)) __attribute__((__disable_tail_calls__));
# 56 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/assert.h" 2 3 4
# 81 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/assert.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_static_assert.h" 1 3 4
# 82 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/assert.h" 2 3 4
# 16 "tls12.c" 2
# 1 "/usr/local/include/gmssl/rand.h" 1
# 15 "/usr/local/include/gmssl/rand.h"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdlib.h" 1 3 4
# 16 "/usr/local/include/gmssl/rand.h" 2








int rand_bytes(uint8_t *buf, size_t buflen);
# 17 "tls12.c" 2
# 1 "/usr/local/include/gmssl/x509.h" 1
# 14 "/usr/local/include/gmssl/x509.h"
# 1 "/usr/local/include/gmssl/x509_cer.h" 1
# 15 "/usr/local/include/gmssl/x509_cer.h"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/time.h" 1 3 4
# 16 "/usr/local/include/gmssl/x509_cer.h" 2
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/string.h" 1 3 4
# 17 "/usr/local/include/gmssl/x509_cer.h" 2

# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdlib.h" 1 3 4
# 19 "/usr/local/include/gmssl/x509_cer.h" 2
# 1 "/usr/local/include/gmssl/sm2.h" 1
# 15 "/usr/local/include/gmssl/sm2.h"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdio.h" 1 3 4
# 16 "/usr/local/include/gmssl/sm2.h" 2

# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdlib.h" 1 3 4
# 18 "/usr/local/include/gmssl/sm2.h" 2
# 1 "/usr/local/include/gmssl/sm3.h" 1
# 14 "/usr/local/include/gmssl/sm3.h"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/string.h" 1 3 4
# 15 "/usr/local/include/gmssl/sm3.h" 2
# 27 "/usr/local/include/gmssl/sm3.h"
typedef struct {
 uint32_t digest[8];
 uint64_t nblocks;
 uint8_t block[64];
 size_t num;
} SM3_CTX;

void sm3_compress_blocks(uint32_t digest[8], const uint8_t *data, size_t blocks);

void sm3_init(SM3_CTX *ctx);
void sm3_update(SM3_CTX *ctx, const uint8_t *data, size_t datalen);
void sm3_finish(SM3_CTX *ctx, uint8_t dgst[32]);




typedef struct {
 SM3_CTX sm3_ctx;
 uint8_t key[64];
} SM3_HMAC_CTX;

void sm3_hmac_init(SM3_HMAC_CTX *ctx, const uint8_t *key, size_t keylen);
void sm3_hmac_update(SM3_HMAC_CTX *ctx, const uint8_t *data, size_t datalen);
void sm3_hmac_finish(SM3_HMAC_CTX *ctx, uint8_t mac[(32)]);


typedef struct {
 SM3_CTX sm3_ctx;
 size_t outlen;
} SM3_KDF_CTX;

void sm3_kdf_init(SM3_KDF_CTX *ctx, size_t outlen);
void sm3_kdf_update(SM3_KDF_CTX *ctx, const uint8_t *in, size_t inlen);
void sm3_kdf_finish(SM3_KDF_CTX *ctx, uint8_t *out);







int sm3_pbkdf2(const char *pass, size_t passlen,
 const uint8_t *salt, size_t saltlen, size_t count,
 size_t outlen, uint8_t *out);


typedef struct {
 union {
  SM3_CTX sm3_ctx;
  SM3_HMAC_CTX hmac_ctx;
 };
 int state;
} SM3_DIGEST_CTX;

int sm3_digest_init(SM3_DIGEST_CTX *ctx, const uint8_t *key, size_t keylen);
int sm3_digest_update(SM3_DIGEST_CTX *ctx, const uint8_t *data, size_t datalen);
int sm3_digest_finish(SM3_DIGEST_CTX *ctx, uint8_t dgst[32]);
# 19 "/usr/local/include/gmssl/sm2.h" 2
# 1 "/usr/local/include/gmssl/sm2_z256.h" 1
# 14 "/usr/local/include/gmssl/sm2_z256.h"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdio.h" 1 3 4
# 15 "/usr/local/include/gmssl/sm2_z256.h" 2

# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdlib.h" 1 3 4
# 17 "/usr/local/include/gmssl/sm2_z256.h" 2







typedef uint64_t sm2_z256_t[4];
typedef uint64_t sm2_z512_t[8];


void sm2_z256_set_one(sm2_z256_t r);
void sm2_z256_set_zero(sm2_z256_t r);

int sm2_z256_rand_range(sm2_z256_t r, const sm2_z256_t range);
void sm2_z256_copy(sm2_z256_t r, const sm2_z256_t a);
void sm2_z256_copy_conditional(sm2_z256_t dst, const sm2_z256_t src, uint64_t move);
void sm2_z256_from_bytes(sm2_z256_t r, const uint8_t in[32]);
void sm2_z256_to_bytes(const sm2_z256_t a, uint8_t out[32]);
int sm2_z256_cmp(const sm2_z256_t a, const sm2_z256_t b);
uint64_t sm2_z256_is_zero(const sm2_z256_t a);
uint64_t sm2_z256_equ(const sm2_z256_t a, const sm2_z256_t b);
void sm2_z256_rshift(sm2_z256_t r, const sm2_z256_t a, unsigned int nbits);
uint64_t sm2_z256_add(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b);
uint64_t sm2_z256_sub(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b);
void sm2_z256_mul(sm2_z512_t r, const sm2_z256_t a, const sm2_z256_t b);
int sm2_z256_get_booth(const sm2_z256_t a, unsigned int window_size, int i);
void sm2_z256_from_hex(sm2_z256_t r, const char *hex);
int sm2_z256_equ_hex(const sm2_z256_t a, const char *hex);
int sm2_z256_print(FILE *fp, int ind, int fmt, const char *label, const sm2_z256_t a);

void sm2_z256_modp_add(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b);
void sm2_z256_modp_dbl(sm2_z256_t r, const sm2_z256_t a);
void sm2_z256_modp_tri(sm2_z256_t r, const sm2_z256_t a);
void sm2_z256_modp_sub(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b);
void sm2_z256_modp_neg(sm2_z256_t r, const sm2_z256_t a);
void sm2_z256_modp_haf(sm2_z256_t r, const sm2_z256_t a);

void sm2_z256_modp_to_mont(const sm2_z256_t a, sm2_z256_t r);
void sm2_z256_modp_from_mont(sm2_z256_t r, const sm2_z256_t a);
void sm2_z256_modp_mont_mul(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b);
void sm2_z256_modp_mont_sqr(sm2_z256_t r, const sm2_z256_t a);
void sm2_z256_modp_mont_exp(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t e);
void sm2_z256_modp_mont_inv(sm2_z256_t r, const sm2_z256_t a);
int sm2_z256_modp_mont_sqrt(sm2_z256_t r, const sm2_z256_t a);

void sm2_z256_modn_add(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b);
void sm2_z256_modn_sub(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b);
void sm2_z256_modn_neg(sm2_z256_t r, const sm2_z256_t a);
void sm2_z256_modn_mul(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b);
void sm2_z256_modn_sqr(sm2_z256_t r, const sm2_z256_t a);
void sm2_z256_modn_exp(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t e);
void sm2_z256_modn_inv(sm2_z256_t r, const sm2_z256_t a);

void sm2_z256_modn_to_mont(const sm2_z256_t a, sm2_z256_t r);
void sm2_z256_modn_from_mont(sm2_z256_t r, const sm2_z256_t a);
void sm2_z256_modn_mont_mul(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b);
void sm2_z256_modn_mont_sqr(sm2_z256_t r, const sm2_z256_t a);
void sm2_z256_modn_mont_exp(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t e);
void sm2_z256_modn_mont_inv(sm2_z256_t r, const sm2_z256_t a);


typedef struct {
 sm2_z256_t X;
 sm2_z256_t Y;
 sm2_z256_t Z;
} SM2_Z256_POINT;

void sm2_z256_point_set_infinity(SM2_Z256_POINT *P);
int sm2_z256_point_is_at_infinity(const SM2_Z256_POINT *P);
int sm2_z256_point_to_bytes(const SM2_Z256_POINT *P, uint8_t out[64]);
int sm2_z256_point_from_bytes(SM2_Z256_POINT *P, const uint8_t in[64]);
int sm2_z256_point_from_hex(SM2_Z256_POINT *P, const char *hex);
int sm2_z256_point_equ_hex(const SM2_Z256_POINT *P, const char *hex);
int sm2_z256_point_is_on_curve(const SM2_Z256_POINT *P);
int sm2_z256_point_equ(const SM2_Z256_POINT *P, const SM2_Z256_POINT *Q);
int sm2_z256_point_get_xy(const SM2_Z256_POINT *P, uint64_t x[4], uint64_t y[4]);

void sm2_z256_point_dbl(SM2_Z256_POINT *R, const SM2_Z256_POINT *A);
void sm2_z256_point_add(SM2_Z256_POINT *r, const SM2_Z256_POINT *a, const SM2_Z256_POINT *b);
void sm2_z256_point_neg(SM2_Z256_POINT *R, const SM2_Z256_POINT *P);
void sm2_z256_point_sub(SM2_Z256_POINT *R, const SM2_Z256_POINT *A, const SM2_Z256_POINT *B);
void sm2_z256_point_get_affine(const SM2_Z256_POINT *P, uint64_t x[4], uint64_t y[4]);
int sm2_z256_point_print(FILE *fp, int fmt, int ind, const char *label, const SM2_Z256_POINT *P);


typedef struct {
 sm2_z256_t x;
 sm2_z256_t y;
} SM2_Z256_AFFINE_POINT;

void sm2_z256_point_copy_affine(SM2_Z256_POINT *R, const SM2_Z256_AFFINE_POINT *P);
void sm2_z256_point_add_affine(SM2_Z256_POINT *r, const SM2_Z256_POINT *a, const SM2_Z256_AFFINE_POINT *b);
void sm2_z256_point_sub_affine(SM2_Z256_POINT *R, const SM2_Z256_POINT *A, const SM2_Z256_AFFINE_POINT *B);
int sm2_z256_point_affine_print(FILE *fp, int fmt, int ind, const char *label, const SM2_Z256_AFFINE_POINT *P);

void sm2_z256_point_mul_generator(SM2_Z256_POINT *R, const sm2_z256_t k);
void sm2_z256_point_mul_pre_compute(const SM2_Z256_POINT *P, SM2_Z256_POINT T[16]);
void sm2_z256_point_mul_ex(SM2_Z256_POINT *R, const sm2_z256_t k, const SM2_Z256_POINT P_table[16]);
void sm2_z256_point_mul(SM2_Z256_POINT *R, const sm2_z256_t k, const SM2_Z256_POINT *P);
void sm2_z256_point_mul_sum(SM2_Z256_POINT *R, const sm2_z256_t t, const SM2_Z256_POINT *P, const sm2_z256_t s);


const uint64_t *sm2_z256_prime(void);
const uint64_t *sm2_z256_order(void);
const uint64_t *sm2_z256_order_minus_one(void);
const uint64_t *sm2_z256_one(void);


enum {
 SM2_point_at_infinity = 0x00,
 SM2_point_compressed_y_even = 0x02,
 SM2_point_compressed_y_odd = 0x03,
 SM2_point_uncompressed = 0x04,
 SM2_point_uncompressed_y_even = 0x06,
 SM2_point_uncompressed_y_odd = 0x07,
};

int sm2_z256_point_from_x_bytes(SM2_Z256_POINT *P, const uint8_t x_bytes[32], int y_is_odd);
int sm2_z256_point_from_hash(SM2_Z256_POINT *R, const uint8_t *data, size_t datalen, int y_is_odd);
int sm2_z256_point_from_octets(SM2_Z256_POINT *P, const uint8_t *in, size_t inlen);

int sm2_z256_point_to_uncompressed_octets(const SM2_Z256_POINT *P, uint8_t out[65]);
int sm2_z256_point_to_compressed_octets(const SM2_Z256_POINT *P, uint8_t out[33]);






int sm2_z256_point_to_der(const SM2_Z256_POINT *P, uint8_t **out, size_t *outlen);
int sm2_z256_point_from_der(SM2_Z256_POINT *P, const uint8_t **in, size_t *inlen);
int sm2_z256_point_print(FILE *fp, int fmt, int ind, const char *label, const SM2_Z256_POINT *P);
# 20 "/usr/local/include/gmssl/sm2.h" 2






typedef struct {
 SM2_Z256_POINT public_key;
 sm2_z256_t private_key;
} SM2_KEY;




int sm2_key_generate(SM2_KEY *key);
int sm2_key_print(FILE *fp, int fmt, int ind, const char *label, const SM2_KEY *key);
int sm2_key_set_private_key(SM2_KEY *key, const sm2_z256_t private_key);
int sm2_key_set_public_key(SM2_KEY *key, const SM2_Z256_POINT *public_key);

int sm2_public_key_equ(const SM2_KEY *sm2_key, const SM2_KEY *pub_key);
int sm2_public_key_digest(const SM2_KEY *key, uint8_t dgst[32]);
int sm2_public_key_to_der(const SM2_KEY *key, uint8_t **out, size_t *outlen);
int sm2_public_key_from_der(SM2_KEY *key, const uint8_t **in, size_t *inlen);
int sm2_public_key_print(FILE *fp, int fmt, int ind, const char *label, const SM2_KEY *pub_key);
# 64 "/usr/local/include/gmssl/sm2.h"
int sm2_private_key_to_der(const SM2_KEY *key, uint8_t **out, size_t *outlen);
int sm2_private_key_from_der(SM2_KEY *key, const uint8_t **in, size_t *inlen);
int sm2_private_key_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);
int sm2_private_key_to_pem(const SM2_KEY *key, FILE *fp);
int sm2_private_key_from_pem(SM2_KEY *key, FILE *fp);






int sm2_public_key_algor_to_der(uint8_t **out, size_t *outlen);
int sm2_public_key_algor_from_der(const uint8_t **in, size_t *inlen);
# 85 "/usr/local/include/gmssl/sm2.h"
int sm2_public_key_info_to_der(const SM2_KEY *a, uint8_t **out, size_t *outlen);
int sm2_public_key_info_from_der(SM2_KEY *a, const uint8_t **in, size_t *inlen);
int sm2_public_key_info_to_pem(const SM2_KEY *a, FILE *fp);
int sm2_public_key_info_from_pem(SM2_KEY *a, FILE *fp);
# 99 "/usr/local/include/gmssl/sm2.h"
enum {
 PKCS8_private_key_info_version = 0,
};


int sm2_private_key_info_to_der(const SM2_KEY *key, uint8_t **out, size_t *outlen);
int sm2_private_key_info_from_der(SM2_KEY *key, const uint8_t **attrs, size_t *attrslen, const uint8_t **in, size_t *inlen);
int sm2_private_key_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);
int sm2_private_key_info_to_pem(const SM2_KEY *key, FILE *fp);

int sm2_private_key_info_from_pem(SM2_KEY *key, FILE *fp);






int sm2_private_key_info_encrypt_to_der(const SM2_KEY *key,
 const char *pass, uint8_t **out, size_t *outlen);
int sm2_private_key_info_decrypt_from_der(SM2_KEY *key, const uint8_t **attrs, size_t *attrs_len,
 const char *pass, const uint8_t **in, size_t *inlen);
int sm2_private_key_info_encrypt_to_pem(const SM2_KEY *key, const char *pass, FILE *fp);

int sm2_private_key_info_decrypt_from_pem(SM2_KEY *key, const char *pass, FILE *fp);



typedef struct {
 uint8_t r[32];
 uint8_t s[32];
} SM2_SIGNATURE;

int sm2_do_sign(const SM2_KEY *key, const uint8_t dgst[32], SM2_SIGNATURE *sig);
int sm2_do_verify(const SM2_KEY *key, const uint8_t dgst[32], const SM2_SIGNATURE *sig);

int sm2_fast_sign_compute_key(const SM2_KEY *key, sm2_z256_t fast_private);

typedef struct {
 sm2_z256_t k;
 sm2_z256_t x1_modn;
} SM2_SIGN_PRE_COMP;



int sm2_fast_sign_pre_compute(SM2_SIGN_PRE_COMP pre_comp[32]);
int sm2_fast_sign(const sm2_z256_t fast_private, SM2_SIGN_PRE_COMP *pre_comp,
 const uint8_t dgst[32], SM2_SIGNATURE *sig);
int sm2_fast_verify(const SM2_Z256_POINT point_table[16],
 const uint8_t dgst[32], const SM2_SIGNATURE *sig);




int sm2_signature_to_der(const SM2_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int sm2_signature_from_der(SM2_SIGNATURE *sig, const uint8_t **in, size_t *inlen);
int sm2_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);
int sm2_sign(const SM2_KEY *key, const uint8_t dgst[32], uint8_t *sig, size_t *siglen);
int sm2_verify(const SM2_KEY *key, const uint8_t dgst[32], const uint8_t *sig, size_t siglen);

enum {
 SM2_signature_compact_size = 70,
 SM2_signature_typical_size = 71,
 SM2_signature_max_size = 72,
};
int sm2_sign_fixlen(const SM2_KEY *key, const uint8_t dgst[32], size_t siglen, uint8_t *sig);
# 173 "/usr/local/include/gmssl/sm2.h"
int sm2_compute_z(uint8_t z[32], const SM2_Z256_POINT *pub, const char *id, size_t idlen);



typedef struct {
 SM3_CTX sm3_ctx;
 SM3_CTX saved_sm3_ctx;
 SM2_KEY key;
 sm2_z256_t fast_sign_private;
 SM2_SIGN_PRE_COMP pre_comp[32];
 unsigned int num_pre_comp;


 SM2_Z256_POINT public_point_table[16];
} SM2_SIGN_CTX;

int sm2_sign_init(SM2_SIGN_CTX *ctx, const SM2_KEY *key, const char *id, size_t idlen);
int sm2_sign_update(SM2_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sm2_sign_finish(SM2_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int sm2_sign_reset(SM2_SIGN_CTX *ctx);
int sm2_sign_finish_fixlen(SM2_SIGN_CTX *ctx, size_t siglen, uint8_t *sig);

typedef struct {
 SM3_CTX sm3_ctx;
 SM3_CTX saved_sm3_ctx;
 SM2_KEY key;
 SM2_Z256_POINT public_point_table[16];
} SM2_VERIFY_CTX;

int sm2_verify_init(SM2_VERIFY_CTX *ctx, const SM2_KEY *key, const char *id, size_t idlen);
int sm2_verify_update(SM2_VERIFY_CTX *ctx, const uint8_t *data, size_t datalen);
int sm2_verify_finish(SM2_VERIFY_CTX *ctx, const uint8_t *sig, size_t siglen);
int sm2_verify_reset(SM2_VERIFY_CTX *ctx);
# 218 "/usr/local/include/gmssl/sm2.h"
typedef struct {
 uint8_t x[32];
 uint8_t y[32];
} SM2_POINT;

typedef struct {
 SM2_POINT point;
 uint8_t hash[32];
 uint8_t ciphertext_size;
 uint8_t ciphertext[255];
} SM2_CIPHERTEXT;


int sm2_kdf(const uint8_t *in, size_t inlen, size_t outlen, uint8_t *out);

int sm2_do_encrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, SM2_CIPHERTEXT *out);
int sm2_do_decrypt(const SM2_KEY *key, const SM2_CIPHERTEXT *in, uint8_t *out, size_t *outlen);



int sm2_ciphertext_to_der(const SM2_CIPHERTEXT *c, uint8_t **out, size_t *outlen);
int sm2_ciphertext_from_der(SM2_CIPHERTEXT *c, const uint8_t **in, size_t *inlen);
int sm2_ciphertext_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen);
int sm2_encrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm2_decrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);

enum {
 SM2_ciphertext_compact_point_size = 68,
 SM2_ciphertext_typical_point_size = 69,
 SM2_ciphertext_max_point_size = 70,
};
int sm2_do_encrypt_fixlen(const SM2_KEY *key, const uint8_t *in, size_t inlen, int point_size, SM2_CIPHERTEXT *out);
int sm2_encrypt_fixlen(const SM2_KEY *key, const uint8_t *in, size_t inlen, int point_size, uint8_t *out, size_t *outlen);


int sm2_do_ecdh(const SM2_KEY *key, const SM2_KEY *peer_key, uint8_t out[32]);
int sm2_ecdh(const SM2_KEY *key, const uint8_t uncompressed_point[65], uint8_t out[32]);


typedef struct {
 sm2_z256_t k;
 SM2_POINT C1;
} SM2_ENC_PRE_COMP;


int sm2_encrypt_pre_compute(SM2_ENC_PRE_COMP pre_comp[8]);
int sm2_do_encrypt_ex(const SM2_KEY *key, const SM2_ENC_PRE_COMP *pre_comp,
 const uint8_t *in, size_t inlen, SM2_CIPHERTEXT *out);

typedef struct {
 SM2_ENC_PRE_COMP pre_comp[8];
 size_t pre_comp_num;
 uint8_t buf[255];
 size_t buf_size;
} SM2_ENC_CTX;

int sm2_encrypt_init(SM2_ENC_CTX *ctx);
int sm2_encrypt_update(SM2_ENC_CTX *ctx, const uint8_t *in, size_t inlen);
int sm2_encrypt_finish(SM2_ENC_CTX *ctx, const SM2_KEY *public_key, uint8_t *out, size_t *outlen);
int sm2_encrypt_reset(SM2_ENC_CTX *ctx);

typedef struct {
 uint8_t buf[366];
 size_t buf_size;
} SM2_DEC_CTX;

int sm2_decrypt_init(SM2_DEC_CTX *ctx);
int sm2_decrypt_update(SM2_DEC_CTX *ctx, const uint8_t *in, size_t inlen);
int sm2_decrypt_finish(SM2_DEC_CTX *ctx, const SM2_KEY *key, uint8_t *out, size_t *outlen);
int sm2_decrypt_reset(SM2_DEC_CTX *ctx);
# 20 "/usr/local/include/gmssl/x509_cer.h" 2
# 1 "/usr/local/include/gmssl/oid.h" 1
# 21 "/usr/local/include/gmssl/oid.h"
enum {
 OID_undef = 0,


 OID_sm1,
 OID_ssf33,
 OID_sm4,
 OID_zuc,
 OID_sm2,
 OID_sm2sign,
 OID_sm2keyagreement,
 OID_sm2encrypt,
 OID_sm9,
 OID_sm9sign,
 OID_sm9keyagreement,
 OID_sm9encrypt,
 OID_sm3,
 OID_sm3_keyless,
 OID_hmac_sm3,
 OID_sm2sign_with_sm3,
 OID_rsasign_with_sm3,
 OID_ec_public_key,
 OID_prime192v1,
 OID_prime256v1,
 OID_secp256k1,
 OID_secp192k1,
 OID_secp224k1,
 OID_secp224r1,
 OID_secp384r1,
 OID_secp521r1,

 OID_at_name,
 OID_at_surname,
 OID_at_given_name,
 OID_at_initials,
 OID_at_generation_qualifier,
 OID_at_common_name,
 OID_at_locality_name,
 OID_at_state_or_province_name,
 OID_at_organization_name,
 OID_at_organizational_unit_name,
 OID_at_title,
 OID_at_dn_qualifier,
 OID_at_country_name,
 OID_at_serial_number,
 OID_at_pseudonym,
 OID_domain_component,
 OID_email_address,


 OID_ce_authority_key_identifier,
 OID_ce_subject_key_identifier,
 OID_ce_key_usage,
 OID_ce_certificate_policies,
 OID_ce_policy_mappings,
 OID_ce_subject_alt_name,
 OID_ce_issuer_alt_name,
 OID_ce_subject_directory_attributes,
 OID_ce_basic_constraints,
 OID_ce_name_constraints,
 OID_ce_policy_constraints,
 OID_ce_ext_key_usage,
 OID_ce_crl_distribution_points,
 OID_ce_inhibit_any_policy,
 OID_ce_freshest_crl,
 OID_netscape_cert_type,
 OID_netscape_cert_comment,
 OID_ct_precertificate_scts,

 OID_ad_ca_issuers,
 OID_ad_ocsp,




 OID_ce_crl_number,
 OID_ce_delta_crl_indicator,
 OID_ce_issuing_distribution_point,

 OID_pe_authority_info_access,


 OID_ce_crl_reasons,
 OID_ce_invalidity_date,
 OID_ce_certificate_issuer,


 OID_any_extended_key_usage,
 OID_kp_server_auth,
 OID_kp_client_auth,
 OID_kp_code_signing,
 OID_kp_email_protection,
 OID_kp_time_stamping,
 OID_kp_ocsp_signing,

 OID_qt_cps,
 OID_qt_unotice,

 OID_md5,
 OID_sha1,
 OID_sha224,
 OID_sha256,
 OID_sha384,
 OID_sha512,
 OID_sha512_224,
 OID_sha512_256,


 OID_hmac_sha1,
 OID_hmac_sha224,
 OID_hmac_sha256,
 OID_hmac_sha384,
 OID_hmac_sha512,
 OID_hmac_sha512_224,
 OID_hmac_sha512_256,

 OID_pbkdf2,
 OID_pbes2,



 OID_sm4_ecb,
 OID_sm4_cbc,

 OID_aes,
 OID_aes128_cbc,
 OID_aes192_cbc,
 OID_aes256_cbc,

 OID_aes128,

 OID_ecdsa_with_sha1,
 OID_ecdsa_with_sha224,
 OID_ecdsa_with_sha256,
 OID_ecdsa_with_sha384,
 OID_ecdsa_with_sha512,

 OID_rsasign_with_md5,
 OID_rsasign_with_sha1,
 OID_rsasign_with_sha224,
 OID_rsasign_with_sha256,
 OID_rsasign_with_sha384,
 OID_rsasign_with_sha512,

 OID_rsa_encryption,
 OID_rsaes_oaep,

 OID_any_policy,

 OID_cms_data,
 OID_cms_signed_data,
 OID_cms_enveloped_data,
 OID_cms_signed_and_enveloped_data,
 OID_cms_encrypted_data,
 OID_cms_key_agreement_info,

 OID_lms_hashsig,
 OID_hss_lms_hashsig,
 OID_xmss_hashsig,
 OID_xmssmt_hashsig,
 OID_sphincs_hashsig,
};
# 21 "/usr/local/include/gmssl/x509_cer.h" 2
# 1 "/usr/local/include/gmssl/asn1.h" 1
# 15 "/usr/local/include/gmssl/asn1.h"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/time.h" 1 3 4
# 16 "/usr/local/include/gmssl/asn1.h" 2
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdlib.h" 1 3 4
# 17 "/usr/local/include/gmssl/asn1.h" 2
# 39 "/usr/local/include/gmssl/asn1.h"
enum ASN1_TAG {
 ASN1_TAG_END_OF_CONTENTS = 0,
 ASN1_TAG_BOOLEAN = 1,
 ASN1_TAG_INTEGER = 2,
 ASN1_TAG_BIT_STRING = 3,
 ASN1_TAG_OCTET_STRING = 4,
 ASN1_TAG_NULL = 5,
 ASN1_TAG_OBJECT_IDENTIFIER = 6,
 ASN1_TAG_ObjectDescriptor = 7,
 ASN1_TAG_EXTERNAL = 8,
 ASN1_TAG_REAL = 9,
 ASN1_TAG_ENUMERATED = 10,
 ASN1_TAG_EMBEDDED = 11,
 ASN1_TAG_UTF8String = 12,
 ASN1_TAG_RELATIVE_OID = 13,




 ASN1_TAG_NumericString = 18,
 ASN1_TAG_PrintableString = 19,
 ASN1_TAG_TeletexString = 20,
 ASN1_TAG_VideotexString = 21,
 ASN1_TAG_IA5String = 22,
 ASN1_TAG_UTCTime = 23,
 ASN1_TAG_GeneralizedTime = 24,
 ASN1_TAG_GraphicString = 25,
 ASN1_TAG_VisibleString = 26,
 ASN1_TAG_GeneralString = 27,
 ASN1_TAG_UniversalString = 28,
 ASN1_TAG_CHARACTER_STRING = 29,
 ASN1_TAG_BMPString = 30,


 ASN1_TAG_SEQUENCE = 0x30,
 ASN1_TAG_SET = 0x31,


 ASN1_TAG_EXPLICIT = 0xa0,




};






const char *asn1_tag_name(int tag);
int asn1_tag_is_cstring(int tag);
int asn1_tag_to_der(int tag, uint8_t **out, size_t *outlen);
int asn1_tag_from_der(int *tag, const uint8_t **in, size_t *inlen);
int asn1_tag_from_der_readonly(int *tag, const uint8_t **in, size_t *inlen);
int asn1_length_to_der(size_t dlen, uint8_t **out, size_t *outlen);
int asn1_length_from_der(size_t *dlen, const uint8_t **in, size_t *inlen);
int asn1_length_is_zero(size_t len);
int asn1_length_le(size_t len1, size_t len2);
int asn1_data_to_der(const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen);
int asn1_data_from_der(const uint8_t **d, size_t dlen, const uint8_t **in, size_t *inlen);

int asn1_type_to_der(int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen);
int asn1_type_from_der(int tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen);
int asn1_nonempty_type_to_der(int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen);
int asn1_nonempty_type_from_der(int tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen);
int asn1_any_type_from_der(int *tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen);
int asn1_any_to_der(const uint8_t *a, size_t alen, uint8_t **out, size_t *outlen);
int asn1_any_from_der(const uint8_t **a, size_t *alen, const uint8_t **in, size_t *inlen);




const char *asn1_boolean_name(int val);
int asn1_boolean_from_name(int *val, const char *name);
int asn1_boolean_to_der_ex(int tag, int val, uint8_t **out, size_t *outlen);
int asn1_boolean_from_der_ex(int tag, int *val, const uint8_t **in, size_t *inlen);






int asn1_integer_to_der_ex(int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen);
int asn1_integer_from_der_ex(int tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen);






int asn1_int_to_der_ex(int tag, int val, uint8_t **out, size_t *outlen);
int asn1_int_from_der_ex(int tag, int *val, const uint8_t **in, size_t *inlen);






int asn1_bit_string_to_der_ex(int tag, const uint8_t *d, size_t nbits, uint8_t **out, size_t *outlen);
int asn1_bit_string_from_der_ex(int tag, const uint8_t **d, size_t *nbits, const uint8_t **in, size_t *inlen);






int asn1_bit_octets_to_der_ex(int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen);
int asn1_bit_octets_from_der_ex(int tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen);






int asn1_bits_to_der_ex(int tag, int bits, uint8_t **out, size_t *outlen);
int asn1_bits_from_der_ex(int tag, int *bits, const uint8_t **in, size_t *inlen);





int asn1_bits_print(FILE *fp, int fmt, int ind, const char *label, const char **names, size_t names_cnt, int bits);
# 170 "/usr/local/include/gmssl/asn1.h"
const char *asn1_null_name(void);
int asn1_null_to_der(uint8_t **out, size_t *outlen);
int asn1_null_from_der(const uint8_t **in, size_t *inlen);





int asn1_object_identifier_to_octets(const uint32_t *nodes, size_t nodes_cnt, uint8_t *out, size_t *outlen);
int asn1_object_identifier_from_octets(uint32_t *nodes, size_t *nodes_cnt, const uint8_t *in, size_t inlen);

int asn1_object_identifier_to_der_ex(int tag, const uint32_t *nodes, size_t nodes_cnt, uint8_t **out, size_t *outlen);
int asn1_object_identifier_from_der_ex(int tag, uint32_t *nodes, size_t *nodes_cnt, const uint8_t **in, size_t *inlen);




int asn1_object_identifier_equ(const uint32_t *a, size_t a_cnt, const uint32_t *b, size_t b_cnt);
int asn1_object_identifier_print(FILE *fp, int fmt, int ind, const char *label, const char *name,
 const uint32_t *nodes, size_t nodes_cnt);

typedef struct {
 int oid;
 char *name;
 uint32_t *nodes;
 size_t nodes_cnt;
 int flags;
 char *description;
} ASN1_OID_INFO;

const ASN1_OID_INFO *asn1_oid_info_from_name(const ASN1_OID_INFO *infos, size_t count, const char *name);
const ASN1_OID_INFO *asn1_oid_info_from_oid(const ASN1_OID_INFO *infos, size_t count, int oid);


int asn1_oid_info_from_der_ex(const ASN1_OID_INFO **info, uint32_t *nodes, size_t *nodes_cnt,
 const ASN1_OID_INFO *infos, size_t count, const uint8_t **in, size_t *inlen);
int asn1_oid_info_from_der(const ASN1_OID_INFO **info,
 const ASN1_OID_INFO *infos, size_t count, const uint8_t **in, size_t *inlen);
# 216 "/usr/local/include/gmssl/asn1.h"
int asn1_string_is_utf8_string(const char *d, size_t dlen);
int asn1_utf8_string_to_der_ex(int tag, const char *d, size_t dlen, uint8_t **out, size_t *outlen);
int asn1_utf8_string_from_der_ex(int tag, const char **d, size_t *dlen, const uint8_t **in, size_t *inlen);





int asn1_string_is_printable_string(const char *d, size_t dlen);
int asn1_printable_string_case_ignore_match(const char *a, size_t alen, const char *b, size_t blen);
int asn1_printable_string_to_der_ex(int tag, const char *d, size_t dlen, uint8_t **out, size_t *outlen);
int asn1_printable_string_from_der_ex(int tag, const char **d, size_t *dlen, const uint8_t **in, size_t *inlen);





int asn1_string_is_ia5_string(const char *d, size_t dlen);
int asn1_ia5_string_to_der_ex(int tag, const char *d, size_t dlen, uint8_t **out, size_t *outlen);
int asn1_ia5_string_from_der_ex(int tag, const char **d, size_t *dlen, const uint8_t **in, size_t *inlen);





int asn1_string_print(FILE *fp, int fmt, int ind, const char *label, int tag, const uint8_t *d, size_t dlen);





int asn1_time_to_str(int utc_time, time_t timestamp, char *str);
int asn1_time_from_str(int utc_time, time_t *timestamp, const char *str);

int asn1_utc_time_to_der_ex(int tag, time_t tv, uint8_t **out, size_t *outlen);
int asn1_utc_time_from_der_ex(int tag, time_t *tv, const uint8_t **in, size_t *inlen);





int asn1_generalized_time_to_der_ex(int tag, time_t tv, uint8_t **out, size_t *outlen);
int asn1_generalized_time_from_der_ex(int tag, time_t *tv, const uint8_t **in, size_t *inlen);
# 272 "/usr/local/include/gmssl/asn1.h"
int asn1_sequence_of_int_to_der(const int *nums, size_t nums_cnt, uint8_t **out, size_t *outlen);
int asn1_sequence_of_int_from_der(int *nums, size_t *nums_cnt, size_t max_nums, const uint8_t **in, size_t *inlen);
int asn1_sequence_of_int_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);
# 287 "/usr/local/include/gmssl/asn1.h"
int asn1_header_to_der(int tag, size_t dlen, uint8_t **out, size_t *outlen);
# 305 "/usr/local/include/gmssl/asn1.h"
int asn1_types_get_count(const uint8_t *d, size_t dlen, int tag, size_t *cnt);
int asn1_types_get_item_by_index(const uint8_t *d, size_t dlen, int tag,
 int index, const uint8_t **item_d, size_t *item_dlen);





int asn1_check(int expr);
# 22 "/usr/local/include/gmssl/x509_cer.h" 2
# 1 "/usr/local/include/gmssl/x509_key.h" 1
# 15 "/usr/local/include/gmssl/x509_key.h"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/time.h" 1 3 4
# 16 "/usr/local/include/gmssl/x509_key.h" 2
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/string.h" 1 3 4
# 17 "/usr/local/include/gmssl/x509_key.h" 2

# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdlib.h" 1 3 4
# 19 "/usr/local/include/gmssl/x509_key.h" 2



# 1 "/usr/local/include/gmssl/ecdsa.h" 1
# 15 "/usr/local/include/gmssl/ecdsa.h"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/string.h" 1 3 4
# 16 "/usr/local/include/gmssl/ecdsa.h" 2

# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdlib.h" 1 3 4
# 18 "/usr/local/include/gmssl/ecdsa.h" 2
# 1 "/usr/local/include/gmssl/sha2.h" 1
# 15 "/usr/local/include/gmssl/sha2.h"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/string.h" 1 3 4
# 16 "/usr/local/include/gmssl/sha2.h" 2

# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 1 3 4
# 84 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_u_char.h" 1 3 4
# 30 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_u_char.h" 3 4
typedef unsigned char u_char;
# 85 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_u_short.h" 1 3 4
# 30 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_u_short.h" 3 4
typedef unsigned short u_short;
# 86 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_u_int.h" 1 3 4
# 30 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_u_int.h" 3 4
typedef unsigned int u_int;
# 87 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4

typedef unsigned long u_long;


typedef unsigned short ushort;

typedef unsigned int uint;




typedef u_int64_t u_quad_t;
typedef int64_t quad_t;
typedef quad_t * qaddr_t;

# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_caddr_t.h" 1 3 4
# 30 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_caddr_t.h" 3 4
typedef char * caddr_t;
# 103 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4

typedef int32_t daddr_t;



typedef u_int32_t fixpt_t;

# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_blkcnt_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_blkcnt_t.h" 3 4
typedef __darwin_blkcnt_t blkcnt_t;
# 111 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_blksize_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_blksize_t.h" 3 4
typedef __darwin_blksize_t blksize_t;
# 112 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_gid_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_gid_t.h" 3 4
typedef __darwin_gid_t gid_t;
# 113 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_in_addr_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_in_addr_t.h" 3 4
typedef __uint32_t in_addr_t;
# 114 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_in_port_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_in_port_t.h" 3 4
typedef __uint16_t in_port_t;
# 115 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_ino_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_ino_t.h" 3 4
typedef __darwin_ino_t ino_t;
# 116 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4


# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_ino64_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_ino64_t.h" 3 4
typedef __darwin_ino64_t ino64_t;
# 119 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4


# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_key_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_key_t.h" 3 4
typedef __int32_t key_t;
# 122 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4

# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_nlink_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_nlink_t.h" 3 4
typedef __uint16_t nlink_t;
# 124 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4




typedef int32_t segsz_t;
typedef int32_t swblk_t;
# 169 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_size_t.h" 1 3 4
# 170 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4



# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_useconds_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_useconds_t.h" 3 4
typedef __darwin_useconds_t useconds_t;
# 174 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_suseconds_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_suseconds_t.h" 3 4
typedef __darwin_suseconds_t suseconds_t;
# 175 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4


# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_rsize_t.h" 1 3 4
# 178 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4
# 187 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_fd_def.h" 1 3 4
# 32 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_fd_def.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 1 3 4
# 33 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_fd_def.h" 2 3 4
# 50 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_fd_def.h" 3 4
typedef struct fd_set {
 __int32_t fds_bits[((((1024) % ((sizeof(__int32_t) * 8))) == 0) ? ((1024) / ((sizeof(__int32_t) * 8))) : (((1024) / ((sizeof(__int32_t) * 8))) + 1))];
} fd_set;

int __darwin_check_fd_set_overflow(int, const void *, int) __attribute__((availability(macos,introduced=11.0))) __attribute__((availability(ios,introduced=14.0))) __attribute__((availability(tvos,introduced=14.0))) __attribute__((availability(watchos,introduced=7.0)));


inline __attribute__ ((__always_inline__)) int
__darwin_check_fd_set(int _a, const void *_b)
{

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunguarded-availability-new"

 if ((uintptr_t)&__darwin_check_fd_set_overflow != (uintptr_t) 0) {



  return __darwin_check_fd_set_overflow(_a, _b, 0);

 } else {
  return 1;
 }

#pragma clang diagnostic pop

}


inline __attribute__ ((__always_inline__)) int
__darwin_fd_isset(int _fd, const struct fd_set *_p)
{
 if (__darwin_check_fd_set(_fd, (const void *) _p)) {
  return _p->fds_bits[(unsigned long)_fd / (sizeof(__int32_t) * 8)] & ((__int32_t)(((unsigned long)1) << ((unsigned long)_fd % (sizeof(__int32_t) * 8))));
 }

 return 0;
}

inline __attribute__ ((__always_inline__)) void
__darwin_fd_set(int _fd, struct fd_set *const _p)
{
 if (__darwin_check_fd_set(_fd, (const void *) _p)) {
  (_p->fds_bits[(unsigned long)_fd / (sizeof(__int32_t) * 8)] |= ((__int32_t)(((unsigned long)1) << ((unsigned long)_fd % (sizeof(__int32_t) * 8)))));
 }
}

inline __attribute__ ((__always_inline__)) void
__darwin_fd_clr(int _fd, struct fd_set *const _p)
{
 if (__darwin_check_fd_set(_fd, (const void *) _p)) {
  (_p->fds_bits[(unsigned long)_fd / (sizeof(__int32_t) * 8)] &= ~((__int32_t)(((unsigned long)1) << ((unsigned long)_fd % (sizeof(__int32_t) * 8)))));
 }
}
# 188 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4




typedef __int32_t fd_mask;







# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_fd_setsize.h" 1 3 4
# 201 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_fd_set.h" 1 3 4
# 202 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_fd_clr.h" 1 3 4
# 203 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_fd_zero.h" 1 3 4
# 204 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_fd_isset.h" 1 3 4
# 205 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4


# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_fd_copy.h" 1 3 4
# 208 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4
# 219 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_pthread/_pthread_cond_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_pthread/_pthread_cond_t.h" 3 4
typedef __darwin_pthread_cond_t pthread_cond_t;
# 220 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_pthread/_pthread_condattr_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_pthread/_pthread_condattr_t.h" 3 4
typedef __darwin_pthread_condattr_t pthread_condattr_t;
# 221 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_pthread/_pthread_mutex_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_pthread/_pthread_mutex_t.h" 3 4
typedef __darwin_pthread_mutex_t pthread_mutex_t;
# 222 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_pthread/_pthread_mutexattr_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_pthread/_pthread_mutexattr_t.h" 3 4
typedef __darwin_pthread_mutexattr_t pthread_mutexattr_t;
# 223 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_pthread/_pthread_once_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_pthread/_pthread_once_t.h" 3 4
typedef __darwin_pthread_once_t pthread_once_t;
# 224 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_pthread/_pthread_rwlock_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_pthread/_pthread_rwlock_t.h" 3 4
typedef __darwin_pthread_rwlock_t pthread_rwlock_t;
# 225 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_pthread/_pthread_rwlockattr_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_pthread/_pthread_rwlockattr_t.h" 3 4
typedef __darwin_pthread_rwlockattr_t pthread_rwlockattr_t;
# 226 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_pthread/_pthread_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_pthread/_pthread_t.h" 3 4
typedef __darwin_pthread_t pthread_t;
# 227 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4



# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_pthread/_pthread_key_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_pthread/_pthread_key_t.h" 3 4
typedef __darwin_pthread_key_t pthread_key_t;
# 231 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4




# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_fsblkcnt_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_fsblkcnt_t.h" 3 4
typedef __darwin_fsblkcnt_t fsblkcnt_t;
# 236 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_fsfilcnt_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_fsfilcnt_t.h" 3 4
typedef __darwin_fsfilcnt_t fsfilcnt_t;
# 237 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/types.h" 2 3 4
# 18 "/usr/local/include/gmssl/sha2.h" 2
# 31 "/usr/local/include/gmssl/sha2.h"
typedef struct {
 uint32_t state[8];
 uint64_t nblocks;
 uint8_t block[64];
 size_t num;
} SHA224_CTX;

void sha224_init(SHA224_CTX *ctx);
void sha224_update(SHA224_CTX *ctx, const uint8_t* data, size_t datalen);
void sha224_finish(SHA224_CTX *ctx, uint8_t dgst[28]);






typedef struct {
 uint32_t state[8];
 uint64_t nblocks;
 uint8_t block[64];
 size_t num;
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t* data, size_t datalen);
void sha256_finish(SHA256_CTX *ctx, uint8_t dgst[32]);






typedef struct {
 uint64_t state[8];
 uint64_t nblocks;
 uint8_t block[128];
 size_t num;
} SHA384_CTX;

void sha384_init(SHA384_CTX *ctx);
void sha384_update(SHA384_CTX *ctx, const uint8_t* data, size_t datalen);
void sha384_finish(SHA384_CTX *ctx, uint8_t dgst[48]);






typedef struct {
 uint64_t state[8];
 uint64_t nblocks;
 uint8_t block[128];
 size_t num;
} SHA512_CTX;

void sha512_init(SHA512_CTX *ctx);
void sha512_update(SHA512_CTX *ctx, const uint8_t* data, size_t datalen);
void sha512_finish(SHA512_CTX *ctx, uint8_t dgst[64]);




typedef struct {
 SHA256_CTX sha256_ctx;
 uint8_t key[64];
} SHA256_HMAC_CTX;

void sha256_hmac_init(SHA256_HMAC_CTX *ctx, const uint8_t *key, size_t keylen);
void sha256_hmac_update(SHA256_HMAC_CTX *ctx, const uint8_t *data, size_t datalen);
void sha256_hmac_finish(SHA256_HMAC_CTX *ctx, uint8_t mac[(32)]);
# 19 "/usr/local/include/gmssl/ecdsa.h" 2
# 1 "/usr/local/include/gmssl/secp256r1_key.h" 1
# 14 "/usr/local/include/gmssl/secp256r1_key.h"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdio.h" 1 3 4
# 15 "/usr/local/include/gmssl/secp256r1_key.h" 2

# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdlib.h" 1 3 4
# 17 "/usr/local/include/gmssl/secp256r1_key.h" 2
# 1 "/usr/local/include/gmssl/secp256r1.h" 1
# 16 "/usr/local/include/gmssl/secp256r1.h"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdio.h" 1 3 4
# 17 "/usr/local/include/gmssl/secp256r1.h" 2

# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdlib.h" 1 3 4
# 19 "/usr/local/include/gmssl/secp256r1.h" 2
# 36 "/usr/local/include/gmssl/secp256r1.h"
typedef uint32_t secp256r1_t[8];



extern const secp256r1_t SECP256R1_P;
extern const secp256r1_t SECP256R1_B;
extern const secp256r1_t SECP256R1_N;
extern const uint32_t SECP256R1_U_P[9];
extern const uint32_t SECP256R1_U_N[9];

int secp256r1_is_zero(const secp256r1_t a);
int secp256r1_is_one(const secp256r1_t a);
int secp256r1_cmp(const secp256r1_t a, const secp256r1_t b);
void secp256r1_set_zero(secp256r1_t r);
void secp256r1_set_one(secp256r1_t r);
void secp256r1_copy(secp256r1_t r, const secp256r1_t a);
void secp256r1_to_32bytes(const secp256r1_t a, uint8_t out[32]);
void secp256r1_from_32bytes(secp256r1_t r, const uint8_t in[32]);
int secp256r1_print(FILE *fp, int fmt, int ind, const char *label, const secp256r1_t a);

void secp256r1_modp_add(secp256r1_t r, const secp256r1_t a, const secp256r1_t b);
void secp256r1_modp_dbl(secp256r1_t r, const secp256r1_t a);
void secp256r1_modp_tri(secp256r1_t r, const secp256r1_t a);
void secp256r1_modp_sub(secp256r1_t r, const secp256r1_t a, const secp256r1_t b);
void secp256r1_modp_neg(secp256r1_t r, const secp256r1_t a);
void secp256r1_modp_haf(secp256r1_t r, const secp256r1_t a);
void secp256r1_modp_mul(secp256r1_t r, const secp256r1_t a, const secp256r1_t b);
void secp256r1_modp_sqr(secp256r1_t r, const secp256r1_t a);
void secp256r1_modp_exp(secp256r1_t r, const secp256r1_t a, const secp256r1_t e);
void secp256r1_modp_inv(secp256r1_t r, const secp256r1_t a);

void secp256r1_modn(secp256r1_t r, const secp256r1_t a);
void secp256r1_modn_add(secp256r1_t r, const secp256r1_t a, const secp256r1_t b);
void secp256r1_modn_dbl(secp256r1_t r, const secp256r1_t a);
void secp256r1_modn_tri(secp256r1_t r, const secp256r1_t a);
void secp256r1_modn_sub(secp256r1_t r, const secp256r1_t a, const secp256r1_t b);
void secp256r1_modn_neg(secp256r1_t r, const secp256r1_t a);
void secp256r1_modn_mul(secp256r1_t r, const secp256r1_t a, const secp256r1_t b);
void secp256r1_modn_sqr(secp256r1_t r, const secp256r1_t a);
void secp256r1_modn_exp(secp256r1_t r, const secp256r1_t a, const secp256r1_t e);
void secp256r1_modn_inv(secp256r1_t r, const secp256r1_t a);


typedef struct {
 secp256r1_t X;
 secp256r1_t Y;
 secp256r1_t Z;
} SECP256R1_POINT;

extern const SECP256R1_POINT SECP256R1_POINT_G;

void secp256r1_point_set_infinity(SECP256R1_POINT *R);
int secp256r1_point_is_at_infinity(const SECP256R1_POINT *P);
int secp256r1_point_is_on_curve(const SECP256R1_POINT *P);
int secp256r1_point_equ(const SECP256R1_POINT *P, const SECP256R1_POINT *Q);
int secp256r1_point_set_xy(SECP256R1_POINT *R, const secp256r1_t x, const secp256r1_t y);
int secp256r1_point_get_xy(const SECP256R1_POINT *P, secp256r1_t x, secp256r1_t y);
void secp256r1_point_copy(SECP256R1_POINT *R, const SECP256R1_POINT *P);
void secp256r1_point_dbl(SECP256R1_POINT *R, const SECP256R1_POINT *P);
void secp256r1_point_add(SECP256R1_POINT *R, const SECP256R1_POINT *P, const SECP256R1_POINT *Q);
void secp256r1_point_neg(SECP256R1_POINT *R, const SECP256R1_POINT *P);
void secp256r1_point_sub(SECP256R1_POINT *R, const SECP256R1_POINT *P, const SECP256R1_POINT *Q);
void secp256r1_point_mul(SECP256R1_POINT *R, const secp256r1_t k, const SECP256R1_POINT *P);
void secp256r1_point_mul_generator(SECP256R1_POINT *R, const secp256r1_t k);
int secp256r1_point_print(FILE *fp, int fmt, int ind, const char *label, const SECP256R1_POINT *P);
int secp256r1_point_to_uncompressed_octets(const SECP256R1_POINT *P, uint8_t octets[65]);
int secp256r1_point_from_uncompressed_octets(SECP256R1_POINT *P, const uint8_t octets[65]);
# 18 "/usr/local/include/gmssl/secp256r1_key.h" 2






typedef struct {
 SECP256R1_POINT public_key;
 secp256r1_t private_key;
} SECP256R1_KEY;

int secp256r1_key_generate(SECP256R1_KEY *key);
int secp256r1_key_set_private_key(SECP256R1_KEY *key, const secp256r1_t private_key);
int secp256r1_public_key_equ(const SECP256R1_KEY *key, const SECP256R1_KEY *pub);
void secp256r1_key_cleanup(SECP256R1_KEY *key);

int secp256r1_public_key_print(FILE *fp, int fmt, int ind, const char *label, const SECP256R1_KEY *key);
int secp256r1_private_key_print(FILE *fp, int fmt, int ind, const char *label, const SECP256R1_KEY *key);

int secp256r1_public_key_to_bytes(const SECP256R1_KEY *key, uint8_t **out, size_t *outlen);
int secp256r1_public_key_from_bytes(SECP256R1_KEY *key, const uint8_t **in, size_t *inlen);
int secp256r1_public_key_to_der(const SECP256R1_KEY *key, uint8_t **out, size_t *outlen);
int secp256r1_public_key_from_der(SECP256R1_KEY *key, const uint8_t **in, size_t *inlen);
int secp256r1_private_key_to_der(const SECP256R1_KEY *key, uint8_t **out, size_t *outlen);
int secp256r1_private_key_from_der(SECP256R1_KEY *key, const uint8_t **in, size_t *inlen);
int secp256r1_private_key_info_to_der(const SECP256R1_KEY *key, uint8_t **out, size_t *outlen);
int secp256r1_private_key_info_from_der(SECP256R1_KEY *key, const uint8_t **attrs, size_t *attrslen,
 const uint8_t **in, size_t *inlen);
int secp256r1_private_key_info_encrypt_to_der(const SECP256R1_KEY *ec_key, const char *pass,
 uint8_t **out, size_t *outlen);
int secp256r1_private_key_info_decrypt_from_der(SECP256R1_KEY *ec_key,
 const uint8_t **attrs, size_t *attrs_len,
 const char *pass, const uint8_t **in, size_t *inlen);

int secp256r1_private_key_info_encrypt_to_pem(const SECP256R1_KEY *key, const char *pass, FILE *fp);
int secp256r1_private_key_info_decrypt_from_pem(SECP256R1_KEY *key, const char *pass, FILE *fp);

int secp256r1_do_ecdh(const SECP256R1_KEY *key, const SECP256R1_KEY *pub, uint8_t out[32]);
int secp256r1_ecdh(const SECP256R1_KEY *key, const uint8_t uncompressed_point[65], uint8_t out[32]);
# 20 "/usr/local/include/gmssl/ecdsa.h" 2







typedef struct {
 secp256r1_t r;
 secp256r1_t s;
} ECDSA_SIGNATURE;





int ecdsa_signature_to_der(const ECDSA_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int ecdsa_signature_from_der(ECDSA_SIGNATURE *sig, const uint8_t **in, size_t *inlen);
int ecdsa_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const ECDSA_SIGNATURE *sig);
int ecdsa_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);

int ecdsa_do_sign_ex(const SECP256R1_KEY *key, const secp256r1_t k, const uint8_t dgst[32], ECDSA_SIGNATURE *sig);
int ecdsa_do_sign(const SECP256R1_KEY *key, const uint8_t dgst[32], ECDSA_SIGNATURE *sig);
int ecdsa_do_verify(const SECP256R1_KEY *key, const uint8_t dgst[32], const ECDSA_SIGNATURE *sig);
int ecdsa_sign(const SECP256R1_KEY *key, const uint8_t dgst[32], uint8_t *sig, size_t *siglen);
int ecdsa_sign_fixlen(const SECP256R1_KEY *key, const uint8_t dgst[32], size_t siglen, uint8_t *sig);
int ecdsa_verify(const SECP256R1_KEY *key, const uint8_t dgst[32], const uint8_t *sig, size_t siglen);


typedef struct {
 SHA256_CTX sha256_ctx;
 SECP256R1_KEY key;
 ECDSA_SIGNATURE sig;
} ECDSA_SIGN_CTX;

int ecdsa_sign_init(ECDSA_SIGN_CTX *ctx, const SECP256R1_KEY *key);
int ecdsa_sign_update(ECDSA_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int ecdsa_sign_finish(ECDSA_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int ecdsa_sign_finish_fixlen(ECDSA_SIGN_CTX *ctx, size_t siglen, uint8_t *sig);
int ecdsa_verify_init(ECDSA_SIGN_CTX *ctx, const SECP256R1_KEY *key, const uint8_t *sig, size_t siglen);
int ecdsa_verify_update(ECDSA_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int ecdsa_verify_finish(ECDSA_SIGN_CTX *ctx);
# 23 "/usr/local/include/gmssl/x509_key.h" 2
# 1 "/usr/local/include/gmssl/lms.h" 1
# 14 "/usr/local/include/gmssl/lms.h"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdio.h" 1 3 4
# 15 "/usr/local/include/gmssl/lms.h" 2
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/string.h" 1 3 4
# 16 "/usr/local/include/gmssl/lms.h" 2
# 32 "/usr/local/include/gmssl/lms.h"
typedef uint8_t lms_hash256_t[32];
# 58 "/usr/local/include/gmssl/lms.h"
enum {



 LMOTS_SM3_N32_W8 = 14,
};
# 74 "/usr/local/include/gmssl/lms.h"
typedef lms_hash256_t lmots_key_t[34];
typedef lms_hash256_t lmots_sig_t[34];

char *lmots_type_name(int lmots_type);
void lmots_derive_secrets(const lms_hash256_t seed, const uint8_t I[16], int q, lms_hash256_t x[34]);
void lmots_secrets_to_public_hash(const uint8_t I[16], int q, const lms_hash256_t x[34], lms_hash256_t pub);
void lmots_compute_signature(const uint8_t I[16], int q, const lms_hash256_t dgst, const lms_hash256_t x[34], lms_hash256_t y[34]);
void lmots_signature_to_public_hash(const uint8_t I[16], int q, const lms_hash256_t y[34], const lms_hash256_t dgst, lms_hash256_t pub);
# 94 "/usr/local/include/gmssl/lms.h"
enum {
 LMS_SM3_M32_H5 = 5,
 LMS_SM3_M32_H10 = 6,
 LMS_SM3_M32_H15 = 7,
 LMS_SM3_M32_H20 = 8,
 LMS_SM3_M32_H25 = 9,
};
# 127 "/usr/local/include/gmssl/lms.h"
char *lms_type_name(int lms_type);
int lms_type_from_name(const char *name);
int lms_type_to_height(int type, size_t *height);
void lms_derive_merkle_tree(const lms_hash256_t seed, const uint8_t I[16], int height, lms_hash256_t *tree);
void lms_derive_merkle_root(const lms_hash256_t seed, const uint8_t I[16], int height, lms_hash256_t root);

typedef struct {
 int lms_type;
 int lmots_type;
 uint8_t I[16];
 lms_hash256_t root;
} LMS_PUBLIC_KEY;



typedef struct LMS_KEY_st LMS_KEY;

typedef int (*lms_key_update_callback)(LMS_KEY *key);

typedef struct LMS_KEY_st {
 LMS_PUBLIC_KEY public_key;
 lms_hash256_t seed;
 uint32_t q;

 lms_hash256_t *tree;
 lms_key_update_callback update_callback;
 void *update_param;
} LMS_KEY;



int lms_key_generate_ex(LMS_KEY *key, int lms_type, const lms_hash256_t seed, const uint8_t I[16], int cache_tree);
int lms_key_generate(LMS_KEY *key, int lms_type);
int lms_key_set_update_callback(LMS_KEY *key, lms_key_update_callback update_cb, void *param);
int lms_key_update(LMS_KEY *key);
int lms_key_remaining_signs(const LMS_KEY *key, size_t *count);
int lms_key_get_signature_size(const LMS_KEY *key, size_t *siglen);
void lms_key_cleanup(LMS_KEY *key);

int lms_public_key_to_bytes_ex(const LMS_PUBLIC_KEY *public_key, uint8_t **out, size_t *outlen);
int lms_public_key_from_bytes_ex(LMS_PUBLIC_KEY *public_key, const uint8_t **in, size_t *inlen);
int lms_public_key_to_bytes(const LMS_KEY *key, uint8_t **out, size_t *outlen);
int lms_public_key_from_bytes(LMS_KEY *key, const uint8_t **in, size_t *inlen);
int lms_public_key_print(FILE *fp, int fmt, int ind, const char *label, const LMS_KEY *pub);
int lms_private_key_to_bytes(const LMS_KEY *key, uint8_t **out, size_t *outlen);
int lms_private_key_from_bytes(LMS_KEY *key, const uint8_t **in, size_t *inlen);
int lms_private_key_print(FILE *fp, int fmt, int ind, const char *label, const LMS_KEY *key);


typedef struct {
 uint32_t q;
 struct {
  int lmots_type;
  lms_hash256_t C;
  lms_hash256_t y[34];
 } lmots_sig;
 int lms_type;
 lms_hash256_t path[25];
} LMS_SIGNATURE;

int lms_signature_to_merkle_root(const uint8_t I[16], size_t h, int q,
 const lms_hash256_t y[34], const lms_hash256_t *path,
 const lms_hash256_t dgst, lms_hash256_t root);
# 199 "/usr/local/include/gmssl/lms.h"
int lms_signature_size(int lms_type, size_t *siglen);
int lms_signature_to_bytes(const LMS_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int lms_signature_from_bytes(LMS_SIGNATURE *sig, const uint8_t **in, size_t *inlen);
int lms_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const LMS_SIGNATURE *sig);
int lms_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);

typedef struct {
 SM3_CTX lms_hash256_ctx;
 LMS_PUBLIC_KEY lms_public_key;
 LMS_SIGNATURE lms_sig;
} LMS_SIGN_CTX;

int lms_sign_init(LMS_SIGN_CTX *ctx, LMS_KEY *key);
int lms_sign_update(LMS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int lms_sign_finish_ex(LMS_SIGN_CTX *ctx, LMS_SIGNATURE *sig);
int lms_sign_finish(LMS_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int lms_verify_init_ex(LMS_SIGN_CTX *ctx, const LMS_KEY *key, const LMS_SIGNATURE *sig);
int lms_verify_init(LMS_SIGN_CTX *ctx, const LMS_KEY *key, const uint8_t *sig, size_t siglen);
int lms_verify_update(LMS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int lms_verify_finish(LMS_SIGN_CTX *ctx);
void lms_sign_ctx_cleanup(LMS_SIGN_CTX *ctx);




typedef struct {
 uint32_t levels;
 LMS_PUBLIC_KEY lms_public_key;
} HSS_PUBLIC_KEY;



typedef struct HSS_KEY_st HSS_KEY;

typedef int (*hss_key_update_callback)(HSS_KEY *key);

typedef struct HSS_KEY_st {
 uint32_t levels;
 LMS_KEY lms_key[5];
 LMS_SIGNATURE lms_sig[4];
 hss_key_update_callback update_callback;
 void *update_param;
} HSS_KEY;


int hss_private_key_size(const int *lms_types, size_t levels, size_t *len);

int hss_key_generate(HSS_KEY *key, const int *lms_types, size_t levels);
int hss_key_set_update_callback(HSS_KEY *key, hss_key_update_callback update_cb, void *param);
int hss_key_update(HSS_KEY *key);
int hss_key_get_signature_size(const HSS_KEY *key, size_t *siglen);
void hss_key_cleanup(HSS_KEY *key);

int hss_public_key_equ(const HSS_KEY *key, const HSS_KEY *pub);
int hss_public_key_to_bytes(const HSS_KEY *key, uint8_t **out, size_t *outlen);
int hss_private_key_to_bytes(const HSS_KEY *key, uint8_t **out, size_t *outlen);
int hss_public_key_from_bytes(HSS_KEY *key, const uint8_t **in, size_t *inlen);
int hss_private_key_from_bytes(HSS_KEY *key, const uint8_t **in, size_t *inlen);
int hss_public_key_print(FILE *fp, int fmt, int ind, const char *label, const HSS_KEY *key);
int hss_private_key_print(FILE *fp, int fmt, int ind, const char *label, const HSS_KEY *key);

typedef struct {
 uint32_t num_signed_public_keys;
 struct {
  LMS_SIGNATURE lms_sig;
  LMS_PUBLIC_KEY lms_public_key;
 } signed_public_keys[5 - 1];
 LMS_SIGNATURE msg_lms_sig;
} HSS_SIGNATURE;


int hss_signature_size(const int *lms_types, size_t levels, size_t *len);
int hss_signature_to_bytes(const HSS_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int hss_signature_from_bytes(HSS_SIGNATURE *sig, const uint8_t **in, size_t *inlen);
int hss_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const HSS_SIGNATURE *sig);
int hss_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);

typedef struct {
 LMS_SIGN_CTX lms_sign_ctx;
 uint32_t levels;
 LMS_SIGNATURE lms_sigs[5 - 1];
 LMS_PUBLIC_KEY lms_public_keys[5 - 1];
} HSS_SIGN_CTX;

int hss_sign_init(HSS_SIGN_CTX *ctx, HSS_KEY *key);
int hss_sign_update(HSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int hss_sign_finish_ex(HSS_SIGN_CTX *ctx, HSS_SIGNATURE *sig);
int hss_sign_finish(HSS_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int hss_verify_init_ex(HSS_SIGN_CTX *ctx, const HSS_KEY *key, const HSS_SIGNATURE *sig);
int hss_verify_init(HSS_SIGN_CTX *ctx, const HSS_KEY *key, const uint8_t *sigbuf, size_t siglen);
int hss_verify_update(HSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int hss_verify_finish(HSS_SIGN_CTX *ctx);
void hss_sign_ctx_cleanup(HSS_SIGN_CTX *ctx);
# 24 "/usr/local/include/gmssl/x509_key.h" 2
# 1 "/usr/local/include/gmssl/xmss.h" 1
# 14 "/usr/local/include/gmssl/xmss.h"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdio.h" 1 3 4
# 15 "/usr/local/include/gmssl/xmss.h" 2
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/string.h" 1 3 4
# 16 "/usr/local/include/gmssl/xmss.h" 2
# 27 "/usr/local/include/gmssl/xmss.h"
typedef uint8_t xmss_hash256_t[32];
# 48 "/usr/local/include/gmssl/xmss.h"
enum {
 XMSS_ADRS_TYPE_OTS = 0,
 XMSS_ADRS_TYPE_LTREE = 1,
 XMSS_ADRS_TYPE_HASHTREE = 2,
};

enum {
 XMSS_ADRS_GENERATE_KEY = 0,
 XMSS_ADRS_GENERATE_BITMASK = 1,
};

typedef struct {
 uint32_t layer_address;
 uint64_t tree_address;
 uint32_t type;
 uint32_t ots_address;
 uint32_t chain_address;
 uint32_t hash_address;
 uint32_t key_and_mask;
} XMSS_ADRS_OTS;

typedef struct {
 uint32_t layer_address;
 uint64_t tree_address;
 uint32_t type;
 uint32_t ltree_address;
 uint32_t tree_height;
 uint32_t tree_index;
 uint32_t key_and_mask;
} XMSS_ADRS_LTREE;

typedef struct {
 uint32_t layer_address;
 uint64_t tree_address;
 uint32_t type;
 uint32_t padding;
 uint32_t tree_height;
 uint32_t tree_index;
 uint32_t key_and_mask;
} XMSS_ADRS_HASHTREE;

typedef uint8_t xmss_adrs_t[32];

void xmss_adrs_copy_layer_address(xmss_adrs_t dst, const xmss_adrs_t src);
void xmss_adrs_copy_tree_address(xmss_adrs_t dst, const xmss_adrs_t src);
void xmss_adrs_copy_type(xmss_adrs_t dst, const xmss_adrs_t src);
void xmss_adrs_copy_ots_address(xmss_adrs_t dst, const xmss_adrs_t src);
void xmss_adrs_copy_ltree_address(xmss_adrs_t dst, const xmss_adrs_t src);
void xmss_adrs_copy_padding(xmss_adrs_t dst, const xmss_adrs_t src);
void xmss_adrs_copy_chain_address(xmss_adrs_t dst, const xmss_adrs_t src);
void xmss_adrs_copy_tree_height(xmss_adrs_t dst, const xmss_adrs_t src);
void xmss_adrs_copy_hash_address(xmss_adrs_t dst, const xmss_adrs_t src);
void xmss_adrs_copy_tree_index(xmss_adrs_t dst, const xmss_adrs_t src);
void xmss_adrs_copy_key_and_mask(xmss_adrs_t dst, const xmss_adrs_t src);

void xmss_adrs_set_layer_address(xmss_adrs_t adrs, uint32_t layer);
void xmss_adrs_set_tree_address(xmss_adrs_t adrs, uint64_t tree_addr);
void xmss_adrs_set_type(xmss_adrs_t adrs, uint32_t type);
void xmss_adrs_set_ots_address(xmss_adrs_t adrs, uint32_t address);
void xmss_adrs_set_ltree_address(xmss_adrs_t adrs, uint32_t address);
void xmss_adrs_set_padding(xmss_adrs_t adrs, uint32_t padding);
void xmss_adrs_set_chain_address(xmss_adrs_t adrs, uint32_t address);
void xmss_adrs_set_tree_height(xmss_adrs_t adrs, uint32_t height);
void xmss_adrs_set_hash_address(xmss_adrs_t adrs, uint32_t address);
void xmss_adrs_set_tree_index(xmss_adrs_t adrs, uint32_t index);
void xmss_adrs_set_key_and_mask(xmss_adrs_t adrs, uint32_t key_and_mask);

int xmss_adrs_print(FILE *fp, int fmt, int ind, const char *label, const xmss_hash256_t adrs);






typedef xmss_hash256_t xmss_wots_key_t[67];
typedef xmss_hash256_t xmss_wots_sig_t[67];


void xmss_wots_derive_sk(const xmss_hash256_t secret,
 const xmss_hash256_t seed, const xmss_adrs_t adrs,
 xmss_wots_key_t sk);
void xmss_wots_chain(const xmss_hash256_t x,
 const xmss_hash256_t seed, const xmss_adrs_t adrs,
 int start, int steps, xmss_hash256_t y);
void xmss_wots_sk_to_pk(const xmss_wots_key_t sk,
 const xmss_hash256_t seed, const xmss_adrs_t adrs,
 xmss_wots_key_t pk);
void xmss_wots_sign(const xmss_wots_key_t sk,
 const xmss_hash256_t seed, const xmss_adrs_t adrs,
 const xmss_hash256_t dgst, xmss_wots_sig_t sig);
void xmss_wots_sig_to_pk(const xmss_wots_sig_t sig,
 const xmss_hash256_t seed, const xmss_adrs_t adrs,
 const xmss_hash256_t dgst, xmss_wots_key_t pk);
void xmss_wots_pk_to_root(const xmss_wots_key_t pk,
 const xmss_hash256_t seed, const xmss_adrs_t adrs,
 xmss_hash256_t wots_root);
void xmss_wots_derive_root(const xmss_hash256_t secret,
 const xmss_hash256_t seed, const xmss_adrs_t adrs,
 xmss_hash256_t wots_root);
int xmss_wots_verify(const xmss_hash256_t wots_root,
 const xmss_hash256_t seed, const xmss_adrs_t adrs,
 const xmss_hash256_t dgst, const xmss_wots_sig_t sig);




enum {
 XMSS_SHA2_10_256 = 0x00000001,
 XMSS_SHA2_16_256 = 0x00000002,
 XMSS_SHA2_20_256 = 0x00000003,
};

enum {
 XMSS_SM3_10_256 = 0x10000001,
 XMSS_SM3_16_256 = 0x10000002,
 XMSS_SM3_20_256 = 0x10000003,
};
# 185 "/usr/local/include/gmssl/xmss.h"
char *xmss_type_name(uint32_t xmss_type);
uint32_t xmss_type_from_name(const char *name);

int xmss_type_to_height(uint32_t xmss_type, size_t *height);

size_t xmss_num_tree_nodes(size_t height);
void xmss_build_tree(const xmss_hash256_t secret,
 const xmss_hash256_t seed, const xmss_adrs_t adrs,
 size_t height, xmss_hash256_t *tree);
void xmss_build_auth_path(const xmss_hash256_t *tree, size_t height,
 uint32_t index, xmss_hash256_t *auth_path);
void xmss_build_root(const xmss_hash256_t wots_root, uint32_t index,
 const xmss_hash256_t seed, const xmss_adrs_t adrs,
 const xmss_hash256_t *auth_path, size_t height,
 xmss_hash256_t xmss_root);


typedef struct {
 uint32_t xmss_type;
 xmss_hash256_t seed;
 xmss_hash256_t root;
} XMSS_PUBLIC_KEY;



typedef struct XMSS_KEY_st XMSS_KEY;

typedef int (*xmss_key_update_callback)(XMSS_KEY *key);

typedef struct XMSS_KEY_st {
 XMSS_PUBLIC_KEY public_key;
 uint32_t index;
 xmss_hash256_t secret;
 xmss_hash256_t sk_prf;
 xmss_hash256_t *tree;
 xmss_key_update_callback update_callback;
 void *update_param;
} XMSS_KEY;




int xmss_private_key_size(uint32_t xmss_type, size_t *keysize);



int xmss_key_generate(XMSS_KEY *key, uint32_t xmss_type);
int xmss_key_remaining_signs(const XMSS_KEY *key, size_t *count);
int xmss_key_set_update_callback(XMSS_KEY *key, xmss_key_update_callback update_cb, void *param);
int xmss_key_update(XMSS_KEY *key);
void xmss_key_cleanup(XMSS_KEY *key);

int xmss_public_key_to_bytes(const XMSS_KEY *key, uint8_t **out, size_t *outlen);
int xmss_public_key_from_bytes(XMSS_KEY *key, const uint8_t **in, size_t *inlen);
int xmss_public_key_print(FILE *fp, int fmt, int ind, const char *label, const XMSS_KEY *key);
int xmss_private_key_to_bytes(const XMSS_KEY *key, uint8_t **out, size_t *outlen);
int xmss_private_key_from_bytes(XMSS_KEY *key, const uint8_t **in, size_t *inlen);
int xmss_private_key_from_file(XMSS_KEY *key, FILE *fp);
int xmss_private_key_print(FILE *fp, int fmt, int ind, const char *label, const XMSS_KEY *key);


typedef struct {
 uint32_t index;
 xmss_hash256_t random;
 xmss_wots_sig_t wots_sig;
 xmss_hash256_t auth_path[20];
} XMSS_SIGNATURE;






int xmss_signature_size(uint32_t xmss_type, size_t *siglen);
int xmss_key_get_signature_size(const XMSS_KEY *key, size_t *siglen);
int xmss_signature_to_bytes(const XMSS_SIGNATURE *sig, uint32_t xmss_type, uint8_t **out, size_t *outlen);
int xmss_signature_from_bytes(XMSS_SIGNATURE *sig, uint32_t xmss_type, const uint8_t **in, size_t *inlen);
int xmss_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *in, size_t inlen);
int xmss_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const XMSS_SIGNATURE *sig);

typedef struct {
 XMSS_PUBLIC_KEY xmss_public_key;
 XMSS_SIGNATURE xmss_sig;
 SM3_CTX hash256_ctx;
} XMSS_SIGN_CTX;

int xmss_sign_init(XMSS_SIGN_CTX *ctx, XMSS_KEY *key);
int xmss_sign_update(XMSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int xmss_sign_finish(XMSS_SIGN_CTX *ctx, uint8_t *sigbuf, size_t *siglen);
int xmss_verify_init(XMSS_SIGN_CTX *ctx, const XMSS_KEY *key, const uint8_t *sigbuf, size_t siglen);
int xmss_verify_update(XMSS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int xmss_verify_finish(XMSS_SIGN_CTX *ctx);
void xmss_sign_ctx_cleanup(XMSS_SIGN_CTX *ctx);


enum {
 XMSSMT_SM3_20_2_256 = 0x00000001,
 XMSSMT_SM3_20_4_256 = 0x00000002,
 XMSSMT_SM3_40_2_256 = 0x00000003,
 XMSSMT_SM3_40_4_256 = 0x00000004,
 XMSSMT_SM3_40_8_256 = 0x00000005,
 XMSSMT_SM3_60_3_256 = 0x00000006,
 XMSSMT_SM3_60_6_256 = 0x00000007,
 XMSSMT_SM3_60_12_256 = 0x00000008,
};


enum {
 XMSSMT_RESERVED = 0x00000000,
 XMSSMT_SHA2_20_2_256 = 0x00000001,
 XMSSMT_SHA2_20_4_256 = 0x00000002,
 XMSSMT_SHA2_40_2_256 = 0x00000003,
 XMSSMT_SHA2_40_4_256 = 0x00000004,
 XMSSMT_SHA2_40_8_256 = 0x00000005,
 XMSSMT_SHA2_60_3_256 = 0x00000006,
 XMSSMT_SHA2_60_6_256 = 0x00000007,
 XMSSMT_SHA2_60_12_256 = 0x00000008,
};
# 341 "/usr/local/include/gmssl/xmss.h"
char *xmssmt_type_name(uint32_t xmssmt_type);
uint32_t xmssmt_type_from_name(const char *name);



int xmssmt_type_to_height_and_layers(uint32_t xmssmt_type, size_t *height, size_t *layers);

size_t xmssmt_num_trees_nodes(size_t height, size_t layers);

typedef struct {
 uint32_t xmssmt_type;
 xmss_hash256_t seed;
 xmss_hash256_t root;
} XMSSMT_PUBLIC_KEY;



typedef struct XMSSMT_KEY_st XMSSMT_KEY;

typedef int (*xmssmt_key_update_callback)(XMSSMT_KEY *key);

typedef struct XMSSMT_KEY_st {
 XMSSMT_PUBLIC_KEY public_key;
 uint64_t index;
 xmss_hash256_t secret;
 xmss_hash256_t sk_prf;
 xmss_hash256_t *trees;
 xmss_wots_sig_t wots_sigs[12 - 1];
 xmssmt_key_update_callback update_callback;
 void *update_param;
} XMSSMT_KEY;
# 383 "/usr/local/include/gmssl/xmss.h"
int xmssmt_private_key_size(uint32_t xmssmt_type, size_t *len);
int xmssmt_build_auth_path(const xmss_hash256_t *tree, size_t height, size_t layers, uint64_t index, xmss_hash256_t *auth_path);

int xmssmt_key_generate(XMSSMT_KEY *key, uint32_t xmssmt_type);
int xmssmt_key_set_update_callback(XMSSMT_KEY *key, xmssmt_key_update_callback update_cb, void *param);
int xmssmt_key_update(XMSSMT_KEY *key);
int xmssmt_public_key_to_bytes(const XMSSMT_KEY *key, uint8_t **out, size_t *outlen);
int xmssmt_public_key_from_bytes(XMSSMT_KEY *key, const uint8_t **in, size_t *inlen);
int xmssmt_public_key_print(FILE *fp, int fmt, int ind, const char *label, const XMSSMT_KEY *key);
int xmssmt_private_key_to_bytes(const XMSSMT_KEY *key, uint8_t **out, size_t *outlen);
int xmssmt_private_key_from_bytes(XMSSMT_KEY *key, const uint8_t **in, size_t *inlen);
int xmssmt_private_key_from_file(XMSSMT_KEY *key, FILE *fp);
int xmssmt_private_key_print(FILE *fp, int fmt, int ind, const char *label, const XMSSMT_KEY *key);
void xmssmt_key_cleanup(XMSSMT_KEY *key);


typedef struct {
 uint64_t index;
 xmss_hash256_t random;
 xmss_wots_sig_t wots_sigs[12];
 xmss_hash256_t auth_path[60];
} XMSSMT_SIGNATURE;

int xmssmt_index_to_bytes(uint64_t index, uint32_t xmssmt_type, uint8_t **out, size_t *outlen);
int xmssmt_index_from_bytes(uint64_t *index, uint32_t xmssmt_type, const uint8_t **in, size_t *inlen);



int xmssmt_key_get_signature_size(const XMSSMT_KEY *key, size_t *siglen);
int xmssmt_signature_size(uint32_t xmssmt_type, size_t *siglen);
int xmssmt_signature_to_bytes(const XMSSMT_SIGNATURE *sig, uint32_t xmssmt_type, uint8_t **out, size_t *outlen);
int xmssmt_signature_from_bytes(XMSSMT_SIGNATURE *sig, uint32_t xmssmt_type, const uint8_t **in, size_t *inlen);
int xmssmt_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const XMSSMT_SIGNATURE *sig, uint32_t xmssmt_type);
int xmssmt_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen, uint32_t xmssmt_type);


typedef struct {
 XMSSMT_PUBLIC_KEY xmssmt_public_key;
 XMSSMT_SIGNATURE xmssmt_sig;
 SM3_CTX hash256_ctx;
} XMSSMT_SIGN_CTX;

int xmssmt_sign_init(XMSSMT_SIGN_CTX *ctx, XMSSMT_KEY *key);
int xmssmt_sign_update(XMSSMT_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int xmssmt_sign_finish(XMSSMT_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int xmssmt_sign_finish_ex(XMSSMT_SIGN_CTX *ctx, XMSSMT_SIGNATURE *sig);
int xmssmt_verify_init_ex(XMSSMT_SIGN_CTX *ctx, const XMSSMT_KEY *key, const XMSSMT_SIGNATURE *sig);
int xmssmt_verify_init(XMSSMT_SIGN_CTX *ctx, const XMSSMT_KEY *key, const uint8_t *sig, size_t siglen);
int xmssmt_verify_update(XMSSMT_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int xmssmt_verify_finish(XMSSMT_SIGN_CTX *ctx);
void xmssmt_sign_ctx_cleanup(XMSSMT_SIGN_CTX *ctx);
# 25 "/usr/local/include/gmssl/x509_key.h" 2
# 1 "/usr/local/include/gmssl/sphincs.h" 1
# 14 "/usr/local/include/gmssl/sphincs.h"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdio.h" 1 3 4
# 15 "/usr/local/include/gmssl/sphincs.h" 2
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/string.h" 1 3 4
# 16 "/usr/local/include/gmssl/sphincs.h" 2
# 61 "/usr/local/include/gmssl/sphincs.h"
typedef uint8_t sphincs_hash128_t[16];

typedef uint8_t sphincs_hash256_t[32];
# 90 "/usr/local/include/gmssl/sphincs.h"
enum {
 SPHINCS_ADRS_TYPE_WOTS_HASH = 0,
 SPHINCS_ADRS_TYPE_WOTS_PK = 1,
 SPHINCS_ADRS_TYPE_TREE = 2,
 SPHINCS_ADRS_TYPE_FORS_TREE = 3,
 SPHINCS_ADRS_TYPE_FORS_ROOTS = 4,
 SPHINCS_ADRS_TYPE_WOTS_PRF = 5,
 SPHINCS_ADRS_TYPE_FORS_PRF = 6,
};

typedef struct {
 uint32_t layer_address;
 uint32_t tree_address[3];
 uint32_t type;
 uint32_t keypair_address;
 uint32_t chain_address;
 uint32_t hash_address;
} SPHINCS_ADRS_WOTS_HASH;

typedef struct {
 uint32_t layer_address;
 uint32_t tree_address[3];
 uint32_t type;
 uint32_t keypair_address;
 uint32_t padding2;
 uint32_t padding3;
} SPHINCS_ADRS_WOTS_PK;

typedef struct {
 uint32_t layer_address;
 uint32_t tree_address[3];
 uint32_t type;
 uint32_t padding1;
 uint32_t tree_height;
 uint32_t tree_index;
} SPHINCS_ADRS_TREE;

typedef struct {
 uint32_t layer_address;
 uint32_t tree_address[3];
 uint32_t type;
 uint32_t keypair_address;
 uint32_t tree_height;
 uint32_t tree_index;
} SPHINCS_ADRS_FORS_TREE;

typedef struct {
 uint32_t layer_address;
 uint32_t tree_address[3];
 uint32_t type;
 uint32_t keypair_address;
 uint32_t padding2;
 uint32_t padding3;
} SPHINCS_ADRS_FORS_ROOTS;

typedef struct {
 uint32_t layer_address;
 uint32_t tree_address[3];
 uint32_t type;
 uint32_t keypair_address;
 uint32_t chain_address;
 uint32_t hash_address;
} SPHINCS_ADRS_WOTS_PRF;

typedef struct {
 uint32_t layer_address;
 uint32_t tree_address[3];
 uint32_t type;
 uint32_t keypair_address;
 uint32_t tree_height;
 uint32_t tree_index;
} SPHINCS_ADRS_FORS_PRF;

typedef uint8_t sphincs_adrs_t[32];

void sphincs_adrs_copy_layer_address(sphincs_adrs_t dst, const sphincs_adrs_t src);
void sphincs_adrs_copy_tree_address(sphincs_adrs_t dst, const sphincs_adrs_t src);
void sphincs_adrs_copy_type(sphincs_adrs_t dst, const sphincs_adrs_t src);
void sphincs_adrs_copy_keypair_address(sphincs_adrs_t dst, const sphincs_adrs_t src);
void sphincs_adrs_copy_chain_address(sphincs_adrs_t dst, const sphincs_adrs_t src);
void sphincs_adrs_copy_hash_address(sphincs_adrs_t dst, const sphincs_adrs_t src);
void sphincs_adrs_copy_tree_height(sphincs_adrs_t dst, const sphincs_adrs_t src);
void sphincs_adrs_copy_tree_index(sphincs_adrs_t dst, const sphincs_adrs_t src);
void sphincs_adrs_init_padding1(sphincs_adrs_t adrs);
void sphincs_adrs_init_padding2(sphincs_adrs_t adrs);
void sphincs_adrs_init_padding3(sphincs_adrs_t adrs);
void sphincs_adrs_set_layer_address(sphincs_adrs_t adrs, const uint32_t address);
void sphincs_adrs_set_tree_address(sphincs_adrs_t adrs, const uint64_t address);
void sphincs_adrs_set_type(sphincs_adrs_t adrs, const uint32_t type);
void sphincs_adrs_set_keypair_address(sphincs_adrs_t adrs, const uint32_t address);
void sphincs_adrs_set_chain_address(sphincs_adrs_t adrs, const uint32_t address);
void sphincs_adrs_set_hash_address(sphincs_adrs_t adrs, const uint32_t address);
void sphincs_adrs_set_tree_height(sphincs_adrs_t adrs, uint32_t height);
void sphincs_adrs_set_tree_index(sphincs_adrs_t adrs, uint32_t index);
int sphincs_adrs_print(FILE *fp, int fmt, int ind, const char *label, const sphincs_adrs_t adrs);

typedef struct {
 uint8_t layer_address;
 uint64_t tree_address;
 uint8_t type;
 uint32_t others[3];
} SPHINCS_ADRSC;



typedef uint8_t sphincs_adrsc_t[22];

void sphincs_adrs_compress(const sphincs_adrs_t adrs, sphincs_adrsc_t adrsc);




typedef sphincs_hash128_t sphincs_wots_key_t[35];
typedef sphincs_hash128_t sphincs_wots_sig_t[35];

int sphincs_wots_key_print(FILE *fp, int fmt, int ind, const char *label, const sphincs_wots_key_t key);
int sphincs_wots_sig_print(FILE *fp, int fmt, int ind, const char *label, const sphincs_wots_sig_t sig);

void sphincs_wots_derive_sk(const sphincs_hash128_t secret,
 const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
 sphincs_wots_key_t sk);
void sphincs_wots_chain(const sphincs_hash128_t x,
 const sphincs_hash128_t seed, const sphincs_adrs_t ots_adrs,
 int start, int steps, sphincs_hash128_t y);
void sphincs_wots_sk_to_pk(const sphincs_wots_key_t sk,
 const sphincs_hash128_t seed, const sphincs_adrs_t ots_adrs,
 sphincs_wots_key_t pk);
void sphincs_wots_sign(const sphincs_wots_key_t sk,
 const sphincs_hash128_t seed, const sphincs_adrs_t ots_adrs,
 const sphincs_hash128_t dgst, sphincs_wots_sig_t sig);
void sphincs_wots_sig_to_pk(const sphincs_wots_sig_t sig,
 const sphincs_hash128_t seed, const sphincs_adrs_t ots_adrs,
 const sphincs_hash128_t dgst, sphincs_wots_key_t pk);
void sphincs_wots_pk_to_root(const sphincs_wots_key_t pk,
 const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
 sphincs_hash128_t root);




void sphincs_xmss_tree_hash(
 const sphincs_hash128_t left_child, const sphincs_hash128_t right_child,
 const sphincs_hash128_t seed, const sphincs_adrs_t adrs,
 sphincs_hash256_t parent);
void sphincs_xmss_build_tree(const sphincs_hash128_t secret,
 const sphincs_hash128_t seed, const sphincs_adrs_t adrs,
 sphincs_hash128_t tree[((1 << ((63/7) + 1)) - 1)]);
void sphincs_xmss_build_auth_path(const sphincs_hash128_t tree[((1 << ((63/7) + 1)) - 1)],
 uint32_t tree_index, sphincs_hash128_t auth_path[(63/7)]);
void sphincs_xmss_build_root(const sphincs_hash128_t wots_root, uint32_t tree_index,
 const sphincs_hash128_t seed, const sphincs_adrs_t adrs,
 const sphincs_hash128_t auth_path[(63/7)],
 sphincs_hash256_t root);

typedef struct {
 sphincs_wots_sig_t wots_sig;
 sphincs_hash128_t auth_path[(63/7)];
} SPHINCS_XMSS_SIGNATURE;

int sphincs_xmss_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const SPHINCS_XMSS_SIGNATURE *sig);
int sphincs_xmss_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);
int sphincs_xmss_signature_to_bytes(const SPHINCS_XMSS_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int sphincs_xmss_signature_from_bytes(SPHINCS_XMSS_SIGNATURE *sig, const uint8_t **in, size_t *inlen);

void sphincs_xmss_sign(const sphincs_hash128_t secret,
 const sphincs_hash128_t seed, const sphincs_adrs_t adrs, uint32_t keypair_address,
 const sphincs_hash128_t tbs_root,
 SPHINCS_XMSS_SIGNATURE *sig);
void sphincs_xmss_sig_to_root(const SPHINCS_XMSS_SIGNATURE *sig,
 const sphincs_hash128_t seed, const sphincs_adrs_t adrs, uint32_t keypair_address,
 const sphincs_hash128_t tbs_root,
 sphincs_hash128_t xmss_root);



void sphincs_hypertree_derive_root(const sphincs_hash128_t secret, const sphincs_hash128_t seed,
 sphincs_hash128_t root);
void sphincs_hypertree_sign(const sphincs_hash128_t secret,
 const sphincs_hash128_t seed, uint64_t tree_address, uint32_t keypair_address,
 const sphincs_hash128_t tbs_fors_root,
 SPHINCS_XMSS_SIGNATURE sig[7]);
int sphincs_hypertree_verify(const sphincs_hash128_t top_xmss_root,
 const sphincs_hash128_t seed, uint64_t tree_address, uint32_t keypair_address,
 const sphincs_hash128_t tbs_fors_root,
 const SPHINCS_XMSS_SIGNATURE sig[7]);




void sphincs_fors_derive_sk(const sphincs_hash128_t secret,
 const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
 uint32_t fors_index, sphincs_hash128_t sk);
void sphincs_fors_build_tree(const sphincs_hash128_t secret,
 const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs, int tree_addr,
 sphincs_hash128_t tree[((1 << (12 + 1)) - 1)]);;
void sphincs_fors_derive_root(const sphincs_hash128_t secret,
 const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
 sphincs_hash128_t fors_root);

typedef struct {
 sphincs_hash128_t fors_sk[14];
 sphincs_hash128_t auth_path[14][12];
} SPHINCS_FORS_SIGNATURE;



int sphincs_fors_signature_to_bytes(const SPHINCS_FORS_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int sphincs_fors_signature_from_bytes(SPHINCS_FORS_SIGNATURE *sig, const uint8_t **in, size_t *inlen);
int sphincs_fors_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const SPHINCS_FORS_SIGNATURE *sig);
int sphincs_fors_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);

void sphincs_fors_sign(const sphincs_hash128_t secret,
 const sphincs_hash128_t seed, const sphincs_adrs_t in_adrs,
 const uint8_t dgst[((12 * 14 + 7)/8)],
 SPHINCS_FORS_SIGNATURE *sig);
void sphincs_fors_sig_to_root(const SPHINCS_FORS_SIGNATURE *sig,
 const sphincs_hash128_t seed, const sphincs_adrs_t adrs,
 const uint8_t dgst[((12 * 14 + 7)/8)], sphincs_hash128_t fors_root);




typedef struct {
 sphincs_hash128_t seed;
 sphincs_hash128_t root;
} SPHINCS_PUBLIC_KEY;



typedef struct {
 SPHINCS_PUBLIC_KEY public_key;
 sphincs_hash128_t secret;
 sphincs_hash128_t sk_prf;
} SPHINCS_KEY;



int sphincs_key_generate(SPHINCS_KEY *key);
int sphincs_public_key_to_bytes(const SPHINCS_KEY *key, uint8_t **out, size_t *outlen);
int sphincs_public_key_from_bytes(SPHINCS_KEY *key, const uint8_t **in, size_t *inlen);
int sphincs_public_key_print(FILE *fp, int fmt, int ind, const char *label, const SPHINCS_KEY *key);
int sphincs_private_key_to_bytes(const SPHINCS_KEY *key, uint8_t **out, size_t *outlen);
int sphincs_private_key_from_bytes(SPHINCS_KEY *key, const uint8_t **in, size_t *inlen);
int sphincs_private_key_print(FILE *fp, int fmt, int ind, const char *label, const SPHINCS_KEY *key);
void sphincs_key_cleanup(SPHINCS_KEY *key);

typedef struct {
 sphincs_hash128_t random;
 SPHINCS_FORS_SIGNATURE fors_sig;
 SPHINCS_XMSS_SIGNATURE xmss_sigs[7];
} SPHINCS_SIGNATURE;



int sphincs_signature_to_bytes(const SPHINCS_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int sphincs_signature_from_bytes(SPHINCS_SIGNATURE *sig, const uint8_t **in, size_t *inlen);
int sphincs_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const SPHINCS_SIGNATURE *sig);
int sphincs_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);

typedef struct {
 SM3_HMAC_CTX hmac_ctx;
 SM3_CTX hash_ctx;
 SPHINCS_SIGNATURE sig;
 int state;
 size_t round1_msglen;
 size_t round2_msglen;
 SPHINCS_KEY key;
} SPHINCS_SIGN_CTX;


int sphincs_sign_init_ex(SPHINCS_SIGN_CTX *ctx, const SPHINCS_KEY *key, const sphincs_hash128_t optional_random);
int sphincs_sign_init(SPHINCS_SIGN_CTX *ctx, const SPHINCS_KEY *key);
int sphincs_sign_prepare(SPHINCS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sphincs_sign_update(SPHINCS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sphincs_sign_finish_ex(SPHINCS_SIGN_CTX *ctx, SPHINCS_SIGNATURE *sig);
int sphincs_sign_finish(SPHINCS_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int sphincs_verify_init_ex(SPHINCS_SIGN_CTX *ctx, const SPHINCS_KEY *key, const SPHINCS_SIGNATURE *sig);
int sphincs_verify_init(SPHINCS_SIGN_CTX *ctx, const SPHINCS_KEY *key, const uint8_t *sig, size_t siglen);
int sphincs_verify_update(SPHINCS_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sphincs_verify_finish(SPHINCS_SIGN_CTX *ctx);
void sphincs_sign_ctx_cleanup(SPHINCS_SIGN_CTX *ctx);
# 26 "/usr/local/include/gmssl/x509_key.h" 2








typedef struct {
 int algor;
 int algor_param;
 union {
  SM2_KEY sm2_key;
  LMS_KEY lms_key;
  HSS_KEY hss_key;
  XMSS_KEY xmss_key;
  XMSSMT_KEY xmssmt_key;
  SPHINCS_KEY sphincs_key;
  SECP256R1_KEY secp256r1_key;
 } u;
 const char *signer_id;
 size_t signer_idlen;
} X509_KEY;

int x509_key_set_sm2_key(X509_KEY *x509_key, const SM2_KEY *sm2_key);
int x509_key_set_lms_key(X509_KEY *x509_key, const LMS_KEY *lms_key);
int x509_key_set_hss_key(X509_KEY *x509_key, const HSS_KEY *hss_key);
int x509_key_set_xmss_key(X509_KEY *x509_key, const XMSS_KEY *xmss_key);
int x509_key_set_xmssmt_key(X509_KEY *x509_key, const XMSSMT_KEY *xmssmt_key);
int x509_key_set_sphincs_key(X509_KEY *x509_key, const SPHINCS_KEY *sphincs_key);
int x509_key_set_secp256r1_key(X509_KEY *x509_key, const SECP256R1_KEY *secp256r1_key);


int x509_algor_param_from_lms_types(int *algor_param, const int *lms_types, size_t num);
int x509_algor_param_to_lms_types(int algor_param, int lms_types[5], size_t *num);
# 72 "/usr/local/include/gmssl/x509_key.h"
int x509_key_generate(X509_KEY *key, int algor, int algor_param);
int x509_private_key_from_file(X509_KEY *key, int algor, const char *pass, FILE *fp);
void x509_key_cleanup(X509_KEY *key);
# 85 "/usr/local/include/gmssl/x509_key.h"
int x509_public_key_to_bytes(const X509_KEY *key, uint8_t **out, size_t *outlen);
int x509_public_key_digest(const X509_KEY *key, uint8_t dgst[32]);
int x509_public_key_equ(const X509_KEY *key, const X509_KEY *pub);
int x509_public_key_print(FILE *fp, int fmt, int ind, const char *label, const X509_KEY *key);
int x509_private_key_print(FILE *fp, int fmt, int ind, const char *label, const X509_KEY *key);


int x509_public_key_info_to_der(const X509_KEY *key, uint8_t **out, size_t *outlen);
int x509_public_key_info_from_der(X509_KEY *key, const uint8_t **in, size_t *inlen);
int x509_public_key_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);


int ec_private_key_to_der(const X509_KEY *key, int encode_params, int encode_pubkey, uint8_t **out, size_t *outlen);
int ec_private_key_from_der(X509_KEY *key, int opt_curve, const uint8_t **in, size_t *inlen);
# 107 "/usr/local/include/gmssl/x509_key.h"
int x509_private_key_info_to_der(const X509_KEY *key, uint8_t **out, size_t *outlen);
int x509_private_key_info_from_der(X509_KEY *key, const uint8_t **attrs, size_t *attrslen,
 const uint8_t **in, size_t *inlen);




int x509_private_key_info_encrypt_to_der(const X509_KEY *x509_key, const char *pass,
 uint8_t **out, size_t *outlen);
int x509_private_key_info_decrypt_from_der(X509_KEY *x509_key,
 const uint8_t **attrs, size_t *attrs_len,
 const char *pass, const uint8_t **in, size_t *inlen);


int x509_private_key_info_encrypt_to_pem(const X509_KEY *key, const char *pass, FILE *fp);
int x509_private_key_info_decrypt_from_pem(X509_KEY *key, const uint8_t **attrs, size_t *attrslen, const char *pass, FILE *fp);
# 133 "/usr/local/include/gmssl/x509_key.h"
typedef union {
 uint8_t sm2_sig[72];
 LMS_SIGNATURE lms_sig;
 HSS_SIGNATURE hss_sig;
 XMSS_SIGNATURE xmss_sig;
 XMSSMT_SIGNATURE xmssmt_sig;
 SPHINCS_SIGNATURE sphincs_sig;
 uint8_t ecdsa_sig[72];
} X509_SIGNATURE;




typedef struct {
 union {
  SM2_SIGN_CTX sm2_sign_ctx;
  SM2_VERIFY_CTX sm2_verify_ctx;
  HSS_SIGN_CTX hss_sign_ctx;
  XMSS_SIGN_CTX xmss_sign_ctx;
  XMSSMT_SIGN_CTX xmssmt_sign_ctx;
  SPHINCS_SIGN_CTX sphincs_sign_ctx;
  ECDSA_SIGN_CTX ecdsa_sign_ctx;
 } u;
 int sign_algor;
 uint8_t sig[sizeof(X509_SIGNATURE)];
 size_t siglen;
} X509_SIGN_CTX;
# 172 "/usr/local/include/gmssl/x509_key.h"
int x509_key_get_sign_algor(const X509_KEY *key, int *algor);
int x509_key_get_signature_size(const X509_KEY *key, size_t *siglen);





int x509_sign_init(X509_SIGN_CTX *ctx, X509_KEY *key, const void *args, size_t argslen);
int x509_sign_update(X509_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int x509_sign_finish(X509_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);
int x509_verify_init(X509_SIGN_CTX *ctx, const X509_KEY *key, const void *args, size_t argslen,
 const uint8_t *sig, size_t siglen);
int x509_verify_update(X509_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int x509_verify_finish(X509_SIGN_CTX *ctx);
void x509_sign_ctx_cleanup(X509_SIGN_CTX *ctx);



int x509_key_do_exchange(const X509_KEY *key, const X509_KEY *peer_pub, uint8_t *out, size_t *outlen);
int x509_key_exchange(const X509_KEY *key, const uint8_t *peer_pub, size_t peer_publen, uint8_t *out, size_t *outlen);
# 23 "/usr/local/include/gmssl/x509_cer.h" 2






enum X509_Version {
 X509_version_v1 = 0,
 X509_version_v2 = 1,
 X509_version_v3 = 2,
};

const char *x509_version_name(int version);
int x509_explicit_version_to_der(int index, int version, uint8_t **out, size_t *outlen);
int x509_explicit_version_from_der(int index, int *version, const uint8_t **in, size_t *inlen);
# 46 "/usr/local/include/gmssl/x509_cer.h"
int x509_time_to_der(time_t a, uint8_t **out, size_t *outlen);
int x509_time_from_der(time_t *a, const uint8_t **in, size_t *inlen);
# 57 "/usr/local/include/gmssl/x509_cer.h"
int x509_validity_add_days(time_t *not_after, time_t not_before, int days);
int x509_validity_to_der(time_t not_before, time_t not_after, uint8_t **out, size_t *outlen);
int x509_validity_from_der(time_t *not_before, time_t *not_after, const uint8_t **in, size_t *inlen);
int x509_validity_check(time_t not_before, time_t not_after, time_t now, int max_secs);
int x509_validity_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);
# 74 "/usr/local/include/gmssl/x509_cer.h"
int x509_directory_name_check(int tag, const uint8_t *d, size_t dlen);
int x509_directory_name_check_ex(int tag, const uint8_t *d, size_t dlen, size_t minlen, size_t maxlen);
int x509_directory_name_to_der(int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen);
int x509_directory_name_from_der(int *tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen);
int x509_explicit_directory_name_to_der(int index, int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen);
int x509_explicit_directory_name_from_der(int index, int *tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen);
int x509_directory_name_print(FILE *fp, int fmt, int ind, const char *label, int tag, const uint8_t *d, size_t dlen);
# 105 "/usr/local/include/gmssl/x509_cer.h"
const char *x509_name_type_name(int oid);
int x509_name_type_from_name(const char *name);
int x509_name_type_from_der(int *oid, const uint8_t **in, size_t *inlen);
int x509_name_type_to_der(int oid, uint8_t **out, size_t *outlen);
# 120 "/usr/local/include/gmssl/x509_cer.h"
int x509_attr_type_and_value_check(int oid, int tag, const uint8_t *val, size_t vlen);
int x509_attr_type_and_value_to_der(int oid, int tag, const uint8_t *val, size_t vlen, uint8_t **out, size_t *outlen);
int x509_attr_type_and_value_from_der(int *oid, int *tag, const uint8_t **val, size_t *vlen, const uint8_t **in, size_t *inlen);
int x509_attr_type_and_value_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);




int x509_rdn_to_der(int oid, int tag, const uint8_t *val, size_t vlen, const uint8_t *more, size_t mlen, uint8_t **out, size_t *outlen);
int x509_rdn_from_der(int *oid, int *tag, const uint8_t **val, size_t *vlen, const uint8_t **more, size_t *mlen, const uint8_t **in, size_t *inlen);
int x509_rdn_check(const uint8_t *d, size_t dlen);
int x509_rdn_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);




int x509_name_add_rdn(uint8_t *d, size_t *dlen, size_t maxlen, int oid, int tag, const uint8_t *val, size_t vlen, const uint8_t *more, size_t mlen);
int x509_name_add_country_name(uint8_t *d, size_t *dlen, size_t maxlen, const char val[2] );
int x509_name_add_state_or_province_name(uint8_t *d, size_t *dlen, size_t maxlen, int tag, const uint8_t *val, size_t vlen);
int x509_name_add_locality_name(uint8_t *d, size_t *dlen, size_t maxlen, int tag, const uint8_t *val, size_t vlen);
int x509_name_add_organization_name(uint8_t *d, size_t *dlen, size_t maxlen, int tag, const uint8_t *val, size_t vlen);
int x509_name_add_organizational_unit_name(uint8_t *d, size_t *dlen, size_t maxlen, int tag, const uint8_t *val, size_t vlen);
int x509_name_add_common_name(uint8_t *d, size_t *dlen, size_t maxlen, int tag, const uint8_t *val, size_t vlen);
int x509_name_add_domain_component(uint8_t *d, size_t *dlen, size_t maxlen, const char *val, size_t vlen);

int x509_name_set(uint8_t *d, size_t *dlen, size_t maxlen,
 const char country[2], const char *state, const char *locality,
 const char *org, const char *org_unit, const char *common_name);



int x509_name_check(const uint8_t *d, size_t dlen);
int x509_name_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);
int x509_name_get_value_by_type(const uint8_t *d, size_t dlen, int oid, int *tag, const uint8_t **val, size_t *vlen);
int x509_name_get_common_name(const uint8_t *d, size_t dlen, int *tag, const uint8_t **val, size_t *vlen);
int x509_name_equ(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen);

int x509_names_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);
# 184 "/usr/local/include/gmssl/x509_cer.h"
const char *x509_ext_id_name(int oid);
int x509_ext_id_from_name(const char *name);
int x509_ext_id_from_der(int *oid, uint32_t *nodes, size_t *nodes_count, const uint8_t **in, size_t *inlen);
int x509_ext_id_to_der(int oid, uint8_t **out, size_t *outlen);

int x509_ext_to_der(int oid, int critical, const uint8_t *val, size_t vlen, uint8_t **out, size_t *outlen);
int x509_ext_from_der(int *oid, uint32_t *nodes, size_t *nodes_cnt, int *critical, const uint8_t **val, size_t *vlen, const uint8_t **in, size_t *inlen);
int x509_ext_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);




int x509_explicit_exts_to_der(int index, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen);
int x509_explicit_exts_from_der(int index, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen);



int x509_exts_get_ext_by_oid(const uint8_t *d, size_t dlen, int oid,
 int *critical, const uint8_t **val, size_t *vlen);
int x509_exts_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);
# 223 "/usr/local/include/gmssl/x509_cer.h"
int x509_tbs_cert_to_der(
 int version,
 const uint8_t *serial, size_t serial_len,
 int signature_algor,
 const uint8_t *issuer, size_t issuer_len,
 time_t not_before, time_t not_after,
 const uint8_t *subject, size_t subject_len,
 const X509_KEY *subject_public_key,
 const uint8_t *issuer_unique_id, size_t issuer_unique_id_len,
 const uint8_t *subject_unique_id, size_t subject_unique_id_len,
 const uint8_t *exts, size_t exts_len,
 uint8_t **out, size_t *outlen);
int x509_tbs_cert_from_der(
 int *version,
 const uint8_t **serial, size_t *serial_len,
 int *signature_algor,
 const uint8_t **issuer, size_t *issuer_len,
 time_t *not_before, time_t *not_after,
 const uint8_t **subject, size_t *subject_len,
 X509_KEY *subject_public_key,
 const uint8_t **issuer_unique_id, size_t *issuer_unique_id_len,
 const uint8_t **subject_unique_id, size_t *subject_unique_id_len,
 const uint8_t **exts, size_t *exts_len,
 const uint8_t **in, size_t *inlen);
int x509_tbs_cert_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);







int x509_certificate_to_der(
 const uint8_t *tbs, size_t tbslen,
 int signature_algor,
 const uint8_t *sig, size_t siglen,
 uint8_t **out, size_t *outlen);
int x509_certificate_from_der(
 const uint8_t **tbs, size_t *tbslen,
 int *signature_algor,
 const uint8_t **sig, size_t *siglen,
 const uint8_t **in, size_t *inlen);

int x509_signed_from_der(
 const uint8_t **tbs, size_t *tbslen,
 int *signature_algor,
 const uint8_t **sig, size_t *siglen,
 const uint8_t **in, size_t *inlen);
int x509_signed_verify(const uint8_t *a, size_t alen, const X509_KEY *pub_key,
 const char *signer_id, size_t signer_id_len);
int x509_signed_verify_by_ca_cert(const uint8_t *a, size_t alen, const uint8_t *cacert, size_t cacertlen,
 const char *signer_id, size_t signer_id_len);


int x509_cert_sign_to_der(
 int version,
 const uint8_t *serial, size_t serial_len,
 int signature_algor,
 const uint8_t *issuer, size_t issuer_len,
 time_t not_before, time_t not_after,
 const uint8_t *subject, size_t subject_len,
 const X509_KEY *subject_public_key,
 const uint8_t *issuer_unique_id, size_t issuer_unique_id_len,
 const uint8_t *subject_unique_id, size_t subject_unique_id_len,
 const uint8_t *exts, size_t exts_len,
 X509_KEY *sign_key, const char *signer_id, size_t signer_id_len,
 uint8_t **out, size_t *outlen);

int x509_cert_to_der(const uint8_t *a, size_t alen, uint8_t **out, size_t *outlen);
int x509_cert_from_der(const uint8_t **a, size_t *alen, const uint8_t **in, size_t *inlen);
int x509_cert_to_pem(const uint8_t *a, size_t alen, FILE *fp);
int x509_cert_from_pem(uint8_t *a, size_t *alen, size_t maxlen, FILE *fp);
int x509_cert_from_pem_by_subject(uint8_t *a, size_t *alen, size_t maxlen, const uint8_t *name, size_t namelen, FILE *fp);
int x509_cert_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen);

int x509_cert_verify_by_ca_cert(const uint8_t *a, size_t alen, const uint8_t *cacert, size_t cacertlen,
 const char *signer_id, size_t signer_id_len);

int x509_cert_get_details(const uint8_t *a, size_t alen,
 int *version,
 const uint8_t **serial_number, size_t *serial_number_len,
 int *inner_signature_algor,
 const uint8_t **issuer, size_t *issuer_len,
 time_t *not_before, time_t *not_after,
 const uint8_t **subject, size_t *subject_len,
 X509_KEY *subject_public_key,
 const uint8_t **issuer_unique_id, size_t *issuer_unique_id_len,
 const uint8_t **subject_unique_id, size_t *subject_unique_id_len,
 const uint8_t **extensions, size_t *extensions_len,
 int *signature_algor,
 const uint8_t **signature, size_t *signature_len);


typedef enum {
 X509_cert_server_auth,
 X509_cert_client_auth,
 X509_cert_server_key_encipher,
 X509_cert_client_key_encipher,
 X509_cert_ca,
 X509_cert_root_ca,
 X509_cert_crl_sign,
} X509_CERT_TYPE;

int x509_cert_check(const uint8_t *cert, size_t certlen, int cert_type, int *path_len_constraint);






int x509_cert_get_issuer_and_serial_number(const uint8_t *a, size_t alen,
 const uint8_t **issuer, size_t *issuer_len,
 const uint8_t **serial_number, size_t *serial_number_len);
int x509_cert_get_issuer(const uint8_t *a, size_t alen, const uint8_t **name, size_t *namelen);
int x509_cert_get_subject(const uint8_t *a, size_t alen, const uint8_t **subj, size_t *subj_len);
int x509_cert_get_subject_public_key(const uint8_t *a, size_t alen, X509_KEY *public_key);
int x509_cert_get_exts(const uint8_t *a, size_t alen, const uint8_t **d, size_t *dlen);

int x509_certs_to_pem(const uint8_t *d, size_t dlen, FILE *fp);
int x509_certs_from_pem(uint8_t *d, size_t *dlen, size_t maxlen, FILE *fp);
int x509_certs_get_count(const uint8_t *d, size_t dlen, size_t *cnt);
int x509_certs_get_cert_by_index(const uint8_t *d, size_t dlen, int index, const uint8_t **cert, size_t *certlen);
int x509_certs_get_cert_by_subject(const uint8_t *d, size_t dlen, const uint8_t *subject, size_t subject_len, const uint8_t **cert, size_t *certlen);
int x509_certs_get_last(const uint8_t *d, size_t dlen, const uint8_t **cert, size_t *certlen);

int x509_certs_get_cert_by_subject_and_key_identifier(const uint8_t *d, size_t dlen,
 const uint8_t *subject, size_t subject_len,
 const uint8_t *key_id, size_t key_id_len,
 const uint8_t **cert, size_t *certlen);
int x509_certs_get_cert_by_issuer_and_serial_number(
 const uint8_t *certs, size_t certs_len,
 const uint8_t *issuer, size_t issuer_len,
 const uint8_t *serial, size_t serial_len,
 const uint8_t **cert, size_t *cert_len);

typedef enum {
 X509_cert_chain_server,
 X509_cert_chain_client,
} X509_CERT_CHAIN_TYPE;


int x509_certs_verify(const uint8_t *certs, size_t certslen, int certs_type,
 const uint8_t *rootcerts, size_t rootcertslen, int depth, int *verify_result);
int x509_certs_verify_tlcp(const uint8_t *certs, size_t certslen, int certs_type,
 const uint8_t *rootcerts, size_t rootcertslen, int depth, int *verify_result);
int x509_certs_get_subjects(const uint8_t *certs, size_t certslen, uint8_t *names, size_t *nameslen);
int x509_certs_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);


int x509_cert_new_from_file(uint8_t **out, size_t *outlen, const char *file);
int x509_certs_new_from_file(uint8_t **out, size_t *outlen, const char *file);
# 15 "/usr/local/include/gmssl/x509.h" 2
# 18 "tls12.c" 2
# 1 "/usr/local/include/gmssl/error.h" 1
# 16 "/usr/local/include/gmssl/error.h"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdio.h" 1 3 4
# 17 "/usr/local/include/gmssl/error.h" 2
# 1 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/stdarg.h" 1 3
# 47 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/stdarg.h" 3
# 1 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/__stdarg_header_macro.h" 1 3
# 48 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/stdarg.h" 2 3



# 1 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/__stdarg___gnuc_va_list.h" 1 3
# 12 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/__stdarg___gnuc_va_list.h" 3
typedef __builtin_va_list __gnuc_va_list;
# 52 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/stdarg.h" 2 3




# 1 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/__stdarg_va_list.h" 1 3
# 12 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/__stdarg_va_list.h" 3
typedef __builtin_va_list va_list;
# 57 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/stdarg.h" 2 3




# 1 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/__stdarg_va_arg.h" 1 3
# 62 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/stdarg.h" 2 3




# 1 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/__stdarg___va_copy.h" 1 3
# 67 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/stdarg.h" 2 3




# 1 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/__stdarg_va_copy.h" 1 3
# 72 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/stdarg.h" 2 3
# 18 "/usr/local/include/gmssl/error.h" 2
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/string.h" 1 3 4
# 19 "/usr/local/include/gmssl/error.h" 2

# 1 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/inttypes.h" 1 3
# 24 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/inttypes.h" 3
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/inttypes.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/inttypes.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_inttypes.h" 1 3 4
# 225 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_inttypes.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 1 3 4
# 226 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_inttypes.h" 2 3 4


# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_wchar_t.h" 1 3 4
# 229 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_inttypes.h" 2 3 4








__attribute__((availability(macosx,introduced=10.4)))
extern intmax_t
imaxabs(intmax_t j);


typedef struct {
 intmax_t quot;
 intmax_t rem;
} imaxdiv_t;

__attribute__((availability(macosx,introduced=10.4)))
extern imaxdiv_t
imaxdiv(intmax_t __numer, intmax_t __denom);


__attribute__((availability(macosx,introduced=10.4)))
extern intmax_t
strtoimax(const char * restrict __nptr,
   char * * restrict __endptr,
   int __base);

__attribute__((availability(macosx,introduced=10.4)))
extern uintmax_t
strtoumax(const char * restrict __nptr,
   char * * restrict __endptr,
   int __base);


__attribute__((availability(macosx,introduced=10.4)))
extern intmax_t
wcstoimax(const wchar_t * restrict __nptr,
   wchar_t * * restrict __endptr,
   int __base);

__attribute__((availability(macosx,introduced=10.4)))
extern uintmax_t
wcstoumax(const wchar_t * restrict __nptr,
   wchar_t * * restrict __endptr,
   int __base);
# 32 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/inttypes.h" 2 3 4
# 25 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/inttypes.h" 2 3
# 21 "/usr/local/include/gmssl/error.h" 2
# 52 "/usr/local/include/gmssl/error.h"
void print_der(const uint8_t *in, size_t inlen);
void print_bytes(const uint8_t *in, size_t inlen);
void print_nodes(const uint32_t *in, size_t inlen);




int format_print(FILE *fp, int format, int indent, const char *str, ...);
int format_bytes(FILE *fp, int format, int indent, const char *str, const uint8_t *data, size_t datalen);
int format_string(FILE *fp, int format, int indent, const char *str, const uint8_t *data, size_t datalen);
# 19 "tls12.c" 2


# 1 "/usr/local/include/gmssl/sm4.h" 1
# 15 "/usr/local/include/gmssl/sm4.h"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/string.h" 1 3 4
# 16 "/usr/local/include/gmssl/sm4.h" 2
# 1 "/usr/local/include/gmssl/ghash.h" 1
# 14 "/usr/local/include/gmssl/ghash.h"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdlib.h" 1 3 4
# 15 "/usr/local/include/gmssl/ghash.h" 2

# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/string.h" 1 3 4
# 17 "/usr/local/include/gmssl/ghash.h" 2
# 1 "/usr/local/include/gmssl/gf128.h" 1
# 16 "/usr/local/include/gmssl/gf128.h"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdio.h" 1 3 4
# 17 "/usr/local/include/gmssl/gf128.h" 2
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdlib.h" 1 3 4
# 18 "/usr/local/include/gmssl/gf128.h" 2
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/string.h" 1 3 4
# 19 "/usr/local/include/gmssl/gf128.h" 2








typedef uint64_t gf128_t[2];

void gf128_set_zero(gf128_t r);
void gf128_set_one(gf128_t r);
void gf128_add(gf128_t r, const gf128_t a, const gf128_t b);
void gf128_mul(gf128_t r, const gf128_t a, const gf128_t b);
void gf128_mul_by_2(gf128_t r, const gf128_t a);
void gf128_from_bytes(gf128_t r, const uint8_t p[16]);
void gf128_to_bytes(const gf128_t a, uint8_t p[16]);
int gf128_from_hex(gf128_t r, const char *s);
int gf128_equ_hex(const gf128_t a, const char *s);
int gf128_print(FILE *fp, int fmt, int ind, const char *label, const gf128_t a);
# 18 "/usr/local/include/gmssl/ghash.h" 2
# 29 "/usr/local/include/gmssl/ghash.h"
void ghash(const uint8_t h[16], const uint8_t *aad, size_t aadlen,
 const uint8_t *c, size_t clen, uint8_t out[16]);

typedef struct {
 gf128_t H;
 gf128_t X;
 size_t aadlen;
 size_t clen;
 uint8_t block[16];
 size_t num;
} GHASH_CTX;

void ghash_init(GHASH_CTX *ctx, const uint8_t h[16], const uint8_t *aad, size_t aadlen);
void ghash_update(GHASH_CTX *ctx, const uint8_t *c, size_t clen);
void ghash_finish(GHASH_CTX *ctx, uint8_t out[16]);
# 17 "/usr/local/include/gmssl/sm4.h" 2
# 28 "/usr/local/include/gmssl/sm4.h"
typedef struct {
 uint32_t rk[(32)];
} SM4_KEY;

void sm4_set_encrypt_key(SM4_KEY *key, const uint8_t raw_key[(16)]);
void sm4_set_decrypt_key(SM4_KEY *key, const uint8_t raw_key[(16)]);
void sm4_encrypt(const SM4_KEY *key, const uint8_t in[(16)], uint8_t out[(16)]);

void sm4_encrypt_blocks(const SM4_KEY *key, const uint8_t *in, size_t nblocks, uint8_t *out);
void sm4_cbc_encrypt_blocks(const SM4_KEY *key, uint8_t iv[(16)],
 const uint8_t *in, size_t nblocks, uint8_t *out);
void sm4_cbc_decrypt_blocks(const SM4_KEY *key, uint8_t iv[(16)],
 const uint8_t *in, size_t nblocks, uint8_t *out);
void sm4_ctr_encrypt_blocks(const SM4_KEY *key, uint8_t ctr[16], const uint8_t *in, size_t nblocks, uint8_t *out);
void sm4_ctr32_encrypt_blocks(const SM4_KEY *key, uint8_t ctr[16], const uint8_t *in, size_t nblocks, uint8_t *out);

int sm4_cbc_padding_encrypt(const SM4_KEY *key, const uint8_t iv[(16)],
 const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_cbc_padding_decrypt(const SM4_KEY *key, const uint8_t iv[(16)],
 const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
void sm4_ctr_encrypt(const SM4_KEY *key, uint8_t ctr[16], const uint8_t *in, size_t inlen, uint8_t *out);
void sm4_ctr32_encrypt(const SM4_KEY *key, uint8_t ctr[16], const uint8_t *in, size_t inlen, uint8_t *out);


typedef struct {
 SM4_KEY sm4_key;
 uint8_t iv[(16)];
 uint8_t block[(16)];
 size_t block_nbytes;
} SM4_CBC_CTX;

int sm4_cbc_encrypt_init(SM4_CBC_CTX *ctx, const uint8_t key[(16)], const uint8_t iv[(16)]);
int sm4_cbc_encrypt_update(SM4_CBC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_cbc_encrypt_finish(SM4_CBC_CTX *ctx, uint8_t *out, size_t *outlen);
int sm4_cbc_decrypt_init(SM4_CBC_CTX *ctx, const uint8_t key[(16)], const uint8_t iv[(16)]);
int sm4_cbc_decrypt_update(SM4_CBC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_cbc_decrypt_finish(SM4_CBC_CTX *ctx, uint8_t *out, size_t *outlen);


void sm4_ctr_encrypt(const SM4_KEY *key, uint8_t ctr[(16)],
 const uint8_t *in, size_t inlen, uint8_t *out);
void sm4_ctr32_encrypt(const SM4_KEY *key, uint8_t ctr[(16)],
 const uint8_t *in, size_t inlen, uint8_t *out);

typedef struct {
 SM4_KEY sm4_key;
 uint8_t ctr[(16)];
 uint8_t block[(16)];
 size_t block_nbytes;
} SM4_CTR_CTX;

int sm4_ctr_encrypt_init(SM4_CTR_CTX *ctx, const uint8_t key[(16)], const uint8_t ctr[(16)]);
int sm4_ctr_encrypt_update(SM4_CTR_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_ctr_encrypt_finish(SM4_CTR_CTX *ctx, uint8_t *out, size_t *outlen);
int sm4_ctr32_encrypt_init(SM4_CTR_CTX *ctx, const uint8_t key[(16)], const uint8_t ctr[(16)]);
int sm4_ctr32_encrypt_update(SM4_CTR_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_ctr32_encrypt_finish(SM4_CTR_CTX *ctx, uint8_t *out, size_t *outlen);
# 106 "/usr/local/include/gmssl/sm4.h"
int sm4_gcm_encrypt(const SM4_KEY *key, const uint8_t *iv, size_t ivlen,
 const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
 uint8_t *out, size_t taglen, uint8_t *tag);
int sm4_gcm_decrypt(const SM4_KEY *key, const uint8_t *iv, size_t ivlen,
 const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
 const uint8_t *tag, size_t taglen, uint8_t *out);


typedef struct {
 SM4_CTR_CTX enc_ctx;
 GHASH_CTX mac_ctx;
 uint8_t Y[16];
 size_t taglen;
 uint8_t mac[16];
 size_t maclen;
 uint64_t encedlen;
} SM4_GCM_CTX;

int sm4_gcm_encrypt_init(SM4_GCM_CTX *ctx,
 const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
 const uint8_t *aad, size_t aadlen, size_t taglen);
int sm4_gcm_encrypt_update(SM4_GCM_CTX *ctx,
 const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_gcm_encrypt_finish(SM4_GCM_CTX *ctx,
 uint8_t *out, size_t *outlen);
int sm4_gcm_decrypt_init(SM4_GCM_CTX *ctx,
 const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
 const uint8_t *aad, size_t aadlen, size_t taglen);
int sm4_gcm_decrypt_update(SM4_GCM_CTX *ctx,
 const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_gcm_decrypt_finish(SM4_GCM_CTX *ctx,
 uint8_t *out, size_t *outlen);
# 22 "tls12.c" 2
# 1 "/usr/local/include/gmssl/pem.h" 1
# 15 "/usr/local/include/gmssl/pem.h"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdio.h" 1 3 4
# 16 "/usr/local/include/gmssl/pem.h" 2
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/string.h" 1 3 4
# 17 "/usr/local/include/gmssl/pem.h" 2
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdlib.h" 1 3 4
# 18 "/usr/local/include/gmssl/pem.h" 2
# 1 "/usr/local/include/gmssl/base64.h" 1
# 16 "/usr/local/include/gmssl/base64.h"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdlib.h" 1 3 4
# 17 "/usr/local/include/gmssl/base64.h" 2






typedef struct {

    int num;





    int length;

    unsigned char enc_data[80];

    int line_num;
    int expect_nl;
} BASE64_CTX;





void base64_encode_init(BASE64_CTX *ctx);
int base64_encode_update(BASE64_CTX *ctx, const uint8_t *in, int inlen, uint8_t *out, int *outlen);
void base64_encode_finish(BASE64_CTX *ctx, uint8_t *out, int *outlen);

void base64_decode_init(BASE64_CTX *ctx);
int base64_decode_update(BASE64_CTX *ctx, const uint8_t *in, int inlen, uint8_t *out, int *outlen);
int base64_decode_finish(BASE64_CTX *ctx, uint8_t *out, int *outlen);


int base64_encode_block(unsigned char *t, const unsigned char *f, int dlen);
int base64_decode_block(unsigned char *t, const unsigned char *f, int n);
# 19 "/usr/local/include/gmssl/pem.h" 2







int pem_read(FILE *fp, const char *name, uint8_t *out, size_t *outlen, size_t maxlen);
int pem_write(FILE *fp, const char *name, const uint8_t *in, size_t inlen);
# 23 "tls12.c" 2
# 1 "/usr/local/include/gmssl/mem.h" 1
# 15 "/usr/local/include/gmssl/mem.h"
# 1 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/stddef.h" 1 3
# 89 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/stddef.h" 3
# 1 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/__stddef_header_macro.h" 1 3
# 90 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/stddef.h" 2 3



# 1 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/__stddef_ptrdiff_t.h" 1 3
# 18 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/__stddef_ptrdiff_t.h" 3
typedef long int ptrdiff_t;
# 94 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/stddef.h" 2 3




# 1 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/__stddef_size_t.h" 1 3
# 99 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/stddef.h" 2 3




# 1 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/__stddef_rsize_t.h" 1 3
# 104 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/stddef.h" 2 3




# 1 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/__stddef_wchar_t.h" 1 3
# 109 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/stddef.h" 2 3




# 1 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/__stddef_null.h" 1 3
# 114 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/stddef.h" 2 3
# 128 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/stddef.h" 3
# 1 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/__stddef_max_align_t.h" 1 3
# 16 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/__stddef_max_align_t.h" 3
typedef long double max_align_t;
# 129 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/stddef.h" 2 3




# 1 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/__stddef_offsetof.h" 1 3
# 134 "/Library/Developer/CommandLineTools/usr/lib/clang/17/include/stddef.h" 2 3
# 16 "/usr/local/include/gmssl/mem.h" 2


void memxor(void *r, const void *a, size_t len);
void gmssl_memxor(void *r, const void *a, const void *b, size_t len);

int gmssl_secure_memcmp(const volatile void * volatile in_a, const volatile void * volatile in_b, size_t len);
void gmssl_secure_clear(void *ptr, size_t len);

int mem_is_zero(const uint8_t *buf, size_t len);
# 24 "tls12.c" 2
# 1 "/usr/local/include/gmssl/tls.h" 1
# 20 "/usr/local/include/gmssl/tls.h"
# 1 "/usr/local/include/gmssl/digest.h" 1
# 17 "/usr/local/include/gmssl/digest.h"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdlib.h" 1 3 4
# 18 "/usr/local/include/gmssl/digest.h" 2
# 31 "/usr/local/include/gmssl/digest.h"
typedef struct DIGEST DIGEST;
typedef struct DIGEST_CTX DIGEST_CTX;






struct DIGEST_CTX {
 union {
  SM3_CTX sm3_ctx;
# 51 "/usr/local/include/gmssl/digest.h"
 } u;
 const DIGEST *digest;
};

struct DIGEST {
 int oid;
 size_t digest_size;
 size_t block_size;
 size_t ctx_size;
 int (*init)(DIGEST_CTX *ctx);
 int (*update)(DIGEST_CTX *ctx, const uint8_t *data, size_t datalen);
 int (*finish)(DIGEST_CTX *ctx, uint8_t *dgst);
};

const DIGEST *DIGEST_sm3(void);
# 78 "/usr/local/include/gmssl/digest.h"
const DIGEST *digest_from_name(const char *name);
const char *digest_name(const DIGEST *digest);
int digest_init(DIGEST_CTX *ctx, const DIGEST *algor);
int digest_update(DIGEST_CTX *ctx, const uint8_t *data, size_t datalen);
int digest_finish(DIGEST_CTX *ctx, uint8_t *dgst, size_t *dgstlen);
int digest(const DIGEST *digest, const uint8_t *data, size_t datalen, uint8_t *dgst, size_t *dgstlen);
# 21 "/usr/local/include/gmssl/tls.h" 2
# 1 "/usr/local/include/gmssl/block_cipher.h" 1
# 14 "/usr/local/include/gmssl/block_cipher.h"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdio.h" 1 3 4
# 15 "/usr/local/include/gmssl/block_cipher.h" 2
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/string.h" 1 3 4
# 16 "/usr/local/include/gmssl/block_cipher.h" 2
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdlib.h" 1 3 4
# 17 "/usr/local/include/gmssl/block_cipher.h" 2
# 33 "/usr/local/include/gmssl/block_cipher.h"
typedef struct BLOCK_CIPHER BLOCK_CIPHER;
typedef struct BLOCK_CIPHER_KEY BLOCK_CIPHER_KEY;

struct BLOCK_CIPHER_KEY {
 union {
  SM4_KEY sm4_key;



 } u;
 const BLOCK_CIPHER *cipher;
};

typedef void (*block_cipher_set_encrypt_key_func)(BLOCK_CIPHER_KEY *key, const uint8_t *raw_key);
typedef void (*block_cipher_set_decrypt_key_func)(BLOCK_CIPHER_KEY *key, const uint8_t *raw_key);
typedef void (*block_cipher_encrypt_func)(const BLOCK_CIPHER_KEY *key, const uint8_t *in, uint8_t *out);
typedef void (*block_cipher_decrypt_func)(const BLOCK_CIPHER_KEY *key, const uint8_t *in, uint8_t *out);

struct BLOCK_CIPHER {
 int oid;
 size_t key_size;
 size_t block_size;
 block_cipher_set_encrypt_key_func set_encrypt_key;
 block_cipher_set_decrypt_key_func set_decrypt_key;
 block_cipher_encrypt_func encrypt;
 block_cipher_decrypt_func decrypt;
};

const BLOCK_CIPHER *BLOCK_CIPHER_sm4(void);




const BLOCK_CIPHER *block_cipher_from_name(const char *name);
const char *block_cipher_name(const BLOCK_CIPHER *cipher);
int block_cipher_set_encrypt_key(BLOCK_CIPHER_KEY *key, const BLOCK_CIPHER *cipher, const uint8_t *raw_key);
int block_cipher_set_decrypt_key(BLOCK_CIPHER_KEY *key, const BLOCK_CIPHER *cipher, const uint8_t *raw_key);
int block_cipher_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *in, uint8_t *out);
int block_cipher_decrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *in, uint8_t *out);
# 22 "/usr/local/include/gmssl/tls.h" 2
# 1 "/usr/local/include/gmssl/socket.h" 1
# 14 "/usr/local/include/gmssl/socket.h"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/string.h" 1 3 4
# 15 "/usr/local/include/gmssl/socket.h" 2

# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/errno.h" 1 3 4
# 23 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/errno.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/errno.h" 1 3 4
# 80 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/errno.h" 3 4
extern int * __error(void);
# 24 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/errno.h" 2 3 4
# 17 "/usr/local/include/gmssl/socket.h" 2
# 43 "/usr/local/include/gmssl/socket.h"
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/fcntl.h" 1 3 4
# 23 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/fcntl.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/fcntl.h" 1 3 4
# 80 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/fcntl.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 1 3 4
# 81 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/fcntl.h" 2 3 4


# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_size_t.h" 1 3 4
# 84 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/fcntl.h" 2 3 4
# 116 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/fcntl.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_o_sync.h" 1 3 4
# 117 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/fcntl.h" 2 3 4
# 149 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/fcntl.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_o_dsync.h" 1 3 4
# 150 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/fcntl.h" 2 3 4
# 370 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/fcntl.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_s_ifmt.h" 1 3 4
# 371 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/fcntl.h" 2 3 4
# 390 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/fcntl.h" 3 4
struct flock {
 off_t l_start;
 off_t l_len;
 pid_t l_pid;
 short l_type;
 short l_whence;
};
# 405 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/fcntl.h" 3 4
struct flocktimeout {
 struct flock fl;
 struct timespec timeout;
};
# 419 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/fcntl.h" 3 4
struct radvisory {
 off_t ra_offset;
 int ra_count;
};
# 432 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/fcntl.h" 3 4
typedef struct fsignatures {
 off_t fs_file_start;
 void *fs_blob_start;
 size_t fs_blob_size;



 size_t fs_fsignatures_size;
 char fs_cdhash[20];
 int fs_hash_type;
} fsignatures_t;

typedef struct fsupplement {
 off_t fs_file_start;
 off_t fs_blob_start;
 size_t fs_blob_size;
 int fs_orig_fd;
} fsupplement_t;
# 463 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/fcntl.h" 3 4
typedef struct fchecklv {
 off_t lv_file_start;
 size_t lv_error_message_size;
 void *lv_error_message;
} fchecklv_t;
# 477 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/fcntl.h" 3 4
typedef struct fgetsigsinfo {
 off_t fg_file_start;
 int fg_info_request;
 int fg_sig_is_platform;
} fgetsigsinfo_t;
# 492 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/fcntl.h" 3 4
typedef struct fstore {
 unsigned int fst_flags;
 int fst_posmode;
 off_t fst_offset;
 off_t fst_length;
 off_t fst_bytesalloc;
} fstore_t;


typedef struct fpunchhole {
 unsigned int fp_flags;
 unsigned int reserved;
 off_t fp_offset;
 off_t fp_length;
} fpunchhole_t;


typedef struct ftrimactivefile {
 off_t fta_offset;
 off_t fta_length;
} ftrimactivefile_t;


typedef struct fspecread {
 unsigned int fsr_flags;
 unsigned int reserved;
 off_t fsr_offset;
 off_t fsr_length;
} fspecread_t;



typedef struct fattributiontag {
 unsigned int ft_flags;
 unsigned long long ft_hash;
 char ft_attribution_name[255];
} fattributiontag_t;
# 556 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/fcntl.h" 3 4
#pragma pack(4)

struct log2phys {
 unsigned int l2p_flags;
 off_t l2p_contigbytes;


 off_t l2p_devoffset;


};

#pragma pack()
# 578 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/fcntl.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_filesec_t.h" 1 3 4
# 30 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_filesec_t.h" 3 4
struct _filesec;
typedef struct _filesec *filesec_t;
# 579 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/fcntl.h" 2 3 4

typedef enum {
 FILESEC_OWNER = 1,
 FILESEC_GROUP = 2,
 FILESEC_UUID = 3,
 FILESEC_MODE = 4,
 FILESEC_ACL = 5,
 FILESEC_GRPUUID = 6,


 FILESEC_ACL_RAW = 100,
 FILESEC_ACL_ALLOCSIZE = 101
} filesec_property_t;






int open(const char *, int, ...) __asm("_" "open" );

int openat(int, const char *, int, ...) __asm("_" "openat" ) __attribute__((availability(macosx,introduced=10.10)));

int creat(const char *, mode_t) __asm("_" "creat" );
int fcntl(int, int, ...) __asm("_" "fcntl" );


int openx_np(const char *, int, filesec_t);




int open_dprotected_np( const char *, int, int, int, ...);
int openat_dprotected_np( int, const char *, int, int, int, ...);
int openat_authenticated_np(int, const char *, int, int);
int flock(int, int);
filesec_t filesec_init(void);
filesec_t filesec_dup(filesec_t);
void filesec_free(filesec_t);
int filesec_get_property(filesec_t, filesec_property_t, void *);
int filesec_query_property(filesec_t, filesec_property_t, int *);
int filesec_set_property(filesec_t, filesec_property_t, const void *);
int filesec_unset_property(filesec_t, filesec_property_t) __attribute__((availability(macosx,introduced=10.6)));
# 24 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/fcntl.h" 2 3 4
# 44 "/usr/local/include/gmssl/socket.h" 2
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netdb.h" 1 3 4
# 87 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netdb.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_size_t.h" 1 3 4
# 88 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netdb.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_socklen_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_socklen_t.h" 3 4
typedef __darwin_socklen_t socklen_t;
# 89 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netdb.h" 2 3 4


# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netinet/in.h" 1 3 4
# 70 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netinet/in.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 1 3 4
# 71 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netinet/in.h" 2 3 4
# 81 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netinet/in.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/socket.h" 1 3 4
# 77 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/socket.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/constrained_ctypes.h" 1 3 4
# 593 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/constrained_ctypes.h" 3 4
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wextra-semi"



#pragma clang diagnostic pop
# 613 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/constrained_ctypes.h" 3 4
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wextra-semi"



#pragma clang diagnostic pop
# 78 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/socket.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/machine/_param.h" 1 3 4
# 34 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/machine/_param.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arm/_param.h" 1 3 4
# 35 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/machine/_param.h" 2 3 4
# 79 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/socket.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/net/net_kev.h" 1 3 4
# 80 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/socket.h" 2 3 4

# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 1 3 4
# 82 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/socket.h" 2 3 4
# 94 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/socket.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_sa_family_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_sa_family_t.h" 3 4
typedef __uint8_t sa_family_t;
# 95 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/socket.h" 2 3 4



# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_size_t.h" 1 3 4
# 99 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/socket.h" 2 3 4







# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_iovec_t.h" 1 3 4
# 30 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_iovec_t.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_size_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_iovec_t.h" 2 3 4
struct iovec {
 void * iov_base;
 size_t iov_len;
};
# 107 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/socket.h" 2 3 4
# 296 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/socket.h" 3 4
typedef __uint32_t sae_associd_t;



typedef __uint32_t sae_connid_t;
# 310 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/socket.h" 3 4
typedef struct sa_endpoints {
 unsigned int sae_srcif;
 const struct sockaddr *sae_srcaddr;
 socklen_t sae_srcaddrlen;
 const struct sockaddr *sae_dstaddr;
 socklen_t sae_dstaddrlen;
} sa_endpoints_t;





struct linger {
 int l_onoff;
 int l_linger;
};
# 340 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/socket.h" 3 4
struct so_np_extensions {
 u_int32_t npx_flags;
 u_int32_t npx_mask;
};
# 414 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/socket.h" 3 4
struct sockaddr {
 __uint8_t sa_len;
 sa_family_t sa_family;
 char sa_data[14];
};
                                                              ;






struct __sockaddr_header {
 __uint8_t sa_len;
 sa_family_t sa_family;
};
# 438 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/socket.h" 3 4
struct sockproto {
 __uint16_t sp_family;
 __uint16_t sp_protocol;
};
# 458 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/socket.h" 3 4
struct sockaddr_storage {
 __uint8_t ss_len;
 sa_family_t ss_family;
 char __ss_pad1[((sizeof(__int64_t)) - sizeof(__uint8_t) - sizeof(sa_family_t))];
 __int64_t __ss_align;
 char __ss_pad2[(128 - sizeof(__uint8_t) - sizeof(sa_family_t) - ((sizeof(__int64_t)) - sizeof(__uint8_t) - sizeof(sa_family_t)) - (sizeof(__int64_t)))];
};
                                                                              ;
# 560 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/socket.h" 3 4
struct msghdr {
 void * msg_name;
 socklen_t msg_namelen;
 struct iovec *msg_iov;
 int msg_iovlen;
 void * msg_control;
 socklen_t msg_controllen;
 int msg_flags;
};
# 606 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/socket.h" 3 4
struct cmsghdr {
 socklen_t cmsg_len;
 int cmsg_level;
 int cmsg_type;

};
# 696 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/socket.h" 3 4
struct sf_hdtr {
 struct iovec *headers;
 int hdr_cnt;
 struct iovec *trailers;
 int trl_cnt;
};






int accept(int, struct sockaddr * restrict, socklen_t * restrict)
__asm("_" "accept" );
int bind(int, const struct sockaddr *, socklen_t) __asm("_" "bind" );
int connect(int, const struct sockaddr *, socklen_t) __asm("_" "connect" );
int getpeername(int, struct sockaddr * restrict, socklen_t * restrict)
__asm("_" "getpeername" );
int getsockname(int, struct sockaddr * restrict, socklen_t * restrict)
__asm("_" "getsockname" );
int getsockopt(int, int, int, void * restrict, socklen_t * restrict);
int listen(int, int) __asm("_" "listen" );
ssize_t recv(int, void *, size_t, int) __asm("_" "recv" );
ssize_t recvfrom(int, void *, size_t, int, struct sockaddr * restrict,
    socklen_t * restrict) __asm("_" "recvfrom" );
ssize_t recvmsg(int, struct msghdr *, int) __asm("_" "recvmsg" );
ssize_t send(int, const void *, size_t, int) __asm("_" "send" );
ssize_t sendmsg(int, const struct msghdr *, int) __asm("_" "sendmsg" );
ssize_t sendto(int, const void *, size_t,
    int, const struct sockaddr *, socklen_t) __asm("_" "sendto" );
int setsockopt(int, int, int, const void *, socklen_t);
int shutdown(int, int);
int sockatmark(int) __attribute__((availability(macosx,introduced=10.5)));
int socket(int, int, int);
int socketpair(int, int, int, int *) __asm("_" "socketpair" );


int sendfile(int, int, off_t, off_t *, struct sf_hdtr *, int);



void pfctlinput(int, struct sockaddr *);

__attribute__((availability(macos,introduced=10.11))) __attribute__((availability(ios,introduced=9.0))) __attribute__((availability(tvos,introduced=9.0))) __attribute__((availability(watchos,introduced=2.0)))
int connectx(int, const sa_endpoints_t *, sae_associd_t, unsigned int,
    const struct iovec *, unsigned int, size_t *, sae_connid_t *);

__attribute__((availability(macos,introduced=10.11))) __attribute__((availability(ios,introduced=9.0))) __attribute__((availability(tvos,introduced=9.0))) __attribute__((availability(watchos,introduced=2.0)))
int disconnectx(int, sae_associd_t, sae_connid_t);
# 82 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netinet/in.h" 2 3 4
# 301 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netinet/in.h" 3 4
struct in_addr {
 in_addr_t s_addr;
};
# 374 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netinet/in.h" 3 4
struct sockaddr_in {
 __uint8_t sin_len;
 sa_family_t sin_family;
 in_port_t sin_port;
 struct in_addr sin_addr;
 char sin_zero[8];
};
# 396 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netinet/in.h" 3 4
struct ip_opts {
 struct in_addr ip_dst;
 char ip_opts[40];
};
# 505 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netinet/in.h" 3 4
struct ip_mreq {
 struct in_addr imr_multiaddr;
 struct in_addr imr_interface;
};






struct ip_mreqn {
 struct in_addr imr_multiaddr;
 struct in_addr imr_address;
 int imr_ifindex;
};

#pragma pack(4)



struct ip_mreq_source {
 struct in_addr imr_multiaddr;
 struct in_addr imr_sourceaddr;
 struct in_addr imr_interface;
};





struct group_req {
 uint32_t gr_interface;
 struct sockaddr_storage gr_group;
};

struct group_source_req {
 uint32_t gsr_interface;
 struct sockaddr_storage gsr_group;
 struct sockaddr_storage gsr_source;
};
# 553 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netinet/in.h" 3 4
struct __msfilterreq {
 uint32_t msfr_ifindex;
 uint32_t msfr_fmode;
 uint32_t msfr_nsrcs;
 uint32_t __msfr_align;
 struct sockaddr_storage msfr_group;
 struct sockaddr_storage *msfr_srcs;
};



#pragma pack()
struct sockaddr;






int setipv4sourcefilter(int, struct in_addr, struct in_addr, uint32_t,
    uint32_t, struct in_addr *) __attribute__((availability(macosx,introduced=10.7)));
int getipv4sourcefilter(int, struct in_addr, struct in_addr, uint32_t *,
    uint32_t *, struct in_addr *) __attribute__((availability(macosx,introduced=10.7)));
int setsourcefilter(int, uint32_t, struct sockaddr *, socklen_t,
    uint32_t, uint32_t, struct sockaddr_storage *) __attribute__((availability(macosx,introduced=10.7)));
int getsourcefilter(int, uint32_t, struct sockaddr *, socklen_t,
    uint32_t *, uint32_t *, struct sockaddr_storage *) __attribute__((availability(macosx,introduced=10.7)));
# 616 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netinet/in.h" 3 4
struct in_pktinfo {
 unsigned int ipi_ifindex;
 struct in_addr ipi_spec_dst;
 struct in_addr ipi_addr;
};
# 657 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netinet/in.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netinet6/in6.h" 1 3 4
# 153 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netinet6/in6.h" 3 4
typedef struct in6_addr {
 union {
  __uint8_t __u6_addr8[16];
  __uint16_t __u6_addr16[8];
  __uint32_t __u6_addr32[4];
 } __u6_addr;
} in6_addr_t;
# 171 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netinet6/in6.h" 3 4
struct sockaddr_in6 {
 __uint8_t sin6_len;
 sa_family_t sin6_family;
 in_port_t sin6_port;
 __uint32_t sin6_flowinfo;
 struct in6_addr sin6_addr;
 __uint32_t sin6_scope_id;
};
# 214 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netinet6/in6.h" 3 4
extern const struct in6_addr in6addr_any;
extern const struct in6_addr in6addr_loopback;

extern const struct in6_addr in6addr_nodelocal_allnodes;
extern const struct in6_addr in6addr_linklocal_allnodes;
extern const struct in6_addr in6addr_linklocal_allrouters;
extern const struct in6_addr in6addr_linklocal_allv2routers;
# 538 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netinet6/in6.h" 3 4
struct ipv6_mreq {
 struct in6_addr ipv6mr_multiaddr;
 unsigned int ipv6mr_interface;
};




struct in6_pktinfo {
 struct in6_addr ipi6_addr;
 unsigned int ipi6_ifindex;
};




struct ip6_mtuinfo {
 struct sockaddr_in6 ip6m_addr;
 uint32_t ip6m_mtu;
};
# 635 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netinet6/in6.h" 3 4
struct cmsghdr;

extern int inet6_option_space(int);
extern int inet6_option_init(void *, struct cmsghdr **, int);
extern int inet6_option_append(struct cmsghdr *, const __uint8_t *, int, int);
extern __uint8_t *inet6_option_alloc(struct cmsghdr *, int, int, int);
extern int inet6_option_next(const struct cmsghdr *, __uint8_t **);
extern int inet6_option_find(const struct cmsghdr *, __uint8_t **, int);

extern size_t inet6_rthdr_space(int, int);
extern struct cmsghdr *inet6_rthdr_init(void *, int);
extern int inet6_rthdr_add(struct cmsghdr *, const struct in6_addr *,
    unsigned int);
extern int inet6_rthdr_lasthop(struct cmsghdr *, unsigned int);



extern int inet6_rthdr_segments(const struct cmsghdr *);
extern struct in6_addr *inet6_rthdr_getaddr(struct cmsghdr *, int);
extern int inet6_rthdr_getflags(const struct cmsghdr *, int);

extern int inet6_opt_init(void *, socklen_t);
extern int inet6_opt_append(void *, socklen_t, int, __uint8_t, socklen_t,
    __uint8_t, void **);
extern int inet6_opt_finish(void *, socklen_t, int);
extern int inet6_opt_set_val(void *, int, void *, socklen_t);

extern int inet6_opt_next(void *, socklen_t, int, __uint8_t *, socklen_t *,
    void **);
extern int inet6_opt_find(void *, socklen_t, int, __uint8_t, socklen_t *,
    void **);
extern int inet6_opt_get_val(void *, int, void *, socklen_t);
extern socklen_t inet6_rth_space(int, int);
extern void *inet6_rth_init(void *, socklen_t, int, int);
extern int inet6_rth_add(void *, const struct in6_addr *);
extern int inet6_rth_reverse(const void *, void *);
extern int inet6_rth_segments(const void *);
extern struct in6_addr *inet6_rth_getaddr(const void *, int);
# 658 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netinet/in.h" 2 3 4





int bindresvport(int, struct sockaddr_in *);
struct sockaddr;
int bindresvport_sa(int, struct sockaddr *);
# 92 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netdb.h" 2 3 4
# 101 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netdb.h" 3 4
extern int h_errno;
# 112 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netdb.h" 3 4
struct hostent {
 char *h_name;
 char **h_aliases;
 int h_addrtype;
 int h_length;
 char **h_addr_list;



};





struct netent {
 char *n_name;
 char **n_aliases;
 int n_addrtype;
 uint32_t n_net;
};

struct servent {
 char *s_name;
 char **s_aliases;
 int s_port;
 char *s_proto;
};

struct protoent {
 char *p_name;
 char **p_aliases;
 int p_proto;
};

struct addrinfo {
 int ai_flags;
 int ai_family;
 int ai_socktype;
 int ai_protocol;
 socklen_t ai_addrlen;
 char *ai_canonname;
 struct sockaddr *ai_addr;
 struct addrinfo *ai_next;
};


struct rpcent {
        char *r_name;
        char **r_aliases;
        int r_number;
};
# 264 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netdb.h" 3 4
void endhostent(void);
void endnetent(void);
void endprotoent(void);
void endservent(void);

void freeaddrinfo(struct addrinfo *);
const char *gai_strerror(int);
int getaddrinfo(const char * restrict, const char * restrict,
       const struct addrinfo * restrict,
       struct addrinfo ** restrict);
struct hostent *gethostbyaddr(const void *, socklen_t, int);
struct hostent *gethostbyname(const char *);
struct hostent *gethostent(void);
int getnameinfo(const struct sockaddr * restrict, socklen_t,
         char * restrict, socklen_t, char * restrict,
         socklen_t, int);
struct netent *getnetbyaddr(uint32_t, int);
struct netent *getnetbyname(const char *);
struct netent *getnetent(void);
struct protoent *getprotobyname(const char *);
struct protoent *getprotobynumber(int);
struct protoent *getprotoent(void);
struct servent *getservbyname(const char *, const char *);
struct servent *getservbyport(int, const char *);
struct servent *getservent(void);
void sethostent(int);

void setnetent(int);
void setprotoent(int);
void setservent(int);


void freehostent(struct hostent *);
struct hostent *gethostbyname2(const char *, int);
struct hostent *getipnodebyaddr(const void *, size_t, int, int *);
struct hostent *getipnodebyname(const char *, int, int, int *);
struct rpcent *getrpcbyname(const char *name);

struct rpcent *getrpcbynumber(int number);



struct rpcent *getrpcent(void);
void setrpcent(int stayopen);
void endrpcent(void);
void herror(const char *);
const char *hstrerror(int);
int innetgr(const char *, const char *, const char *, const char *);
int getnetgrent(char **, char **, char **);
void endnetgrent(void);
void setnetgrent(const char *);
# 45 "/usr/local/include/gmssl/socket.h" 2
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arpa/inet.h" 1 3 4
# 78 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/arpa/inet.h" 3 4
in_addr_t inet_addr(const char *);
char * inet_ntoa(struct in_addr);
const char *inet_ntop(int, const void *, char *, socklen_t __size);
int inet_pton(int, const char *, void *);


int ascii2addr(int, const char *, void *);
char * addr2ascii(int, const void *, int __size, char *);
int inet_aton(const char *, struct in_addr *);
in_addr_t inet_lnaof(struct in_addr);
struct in_addr inet_makeaddr(in_addr_t, in_addr_t);
in_addr_t inet_netof(struct in_addr);
in_addr_t inet_network(const char *);
char * inet_net_ntop(int, const void *, int, char *, __darwin_size_t __size);
int inet_net_pton(int, const char *, void *, __darwin_size_t __size);
char * inet_neta(in_addr_t, char *, __darwin_size_t __size);
unsigned int inet_nsap_addr(const char *, unsigned char *, int __maxlen);
char * inet_nsap_ntoa(int __binlen, const unsigned char *, char *);
# 46 "/usr/local/include/gmssl/socket.h" 2


# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/select.h" 1 3 4
# 114 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/select.h" 3 4
int pselect(int, fd_set * restrict, fd_set * restrict,
    fd_set * restrict, const struct timespec * restrict,
    const sigset_t * restrict)




__asm("_" "pselect" )




;




# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_select.h" 1 3 4
# 43 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_select.h" 3 4
int select(int, fd_set * restrict, fd_set * restrict,
    fd_set * restrict, struct timeval * restrict)





__asm("_" "select" )




;
# 132 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/select.h" 2 3 4
# 49 "/usr/local/include/gmssl/socket.h" 2

# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/unistd.h" 1 3 4
# 73 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/unistd.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/unistd.h" 1 3 4
# 84 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/unistd.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_posix_vdisable.h" 1 3 4
# 85 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/unistd.h" 2 3 4
# 132 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/unistd.h" 3 4
struct accessx_descriptor {
 unsigned int ad_name_offset;
 int ad_flags;
 int ad_pad[2];
};
# 180 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/unistd.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_size_t.h" 1 3 4
# 181 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/unistd.h" 2 3 4



# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 1 3 4
# 185 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/unistd.h" 2 3 4



int getattrlistbulk(int, void *, void *, size_t, uint64_t) __attribute__((availability(macosx,introduced=10.10)));
int getattrlistat(int, const char *, void *, void *, size_t, unsigned long) __attribute__((availability(macosx,introduced=10.10)));
int setattrlistat(int, const char *, void *, void *, size_t, uint32_t) __attribute__((availability(macosx,introduced=10.13))) __attribute__((availability(ios,introduced=11.0))) __attribute__((availability(tvos,introduced=11.0))) __attribute__((availability(watchos,introduced=4.0)));
ssize_t freadlink(int, char * restrict, size_t) __attribute__((availability(macos,introduced=13.0))) __attribute__((availability(ios,introduced=16.0))) __attribute__((availability(tvos,introduced=16.0))) __attribute__((availability(watchos,introduced=9.0)));
# 200 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/unistd.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_size_t.h" 1 3 4
# 201 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/unistd.h" 2 3 4




# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 1 3 4
# 206 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/unistd.h" 2 3 4



int faccessat(int, const char *, int, int) __attribute__((availability(macosx,introduced=10.10)));
int fchownat(int, const char *, uid_t, gid_t, int) __attribute__((availability(macosx,introduced=10.10)));
int linkat(int, const char *, int, const char *, int) __attribute__((availability(macosx,introduced=10.10)));
ssize_t readlinkat(int, const char *, char *, size_t) __attribute__((availability(macosx,introduced=10.10)));
int symlinkat(const char *, int, const char *) __attribute__((availability(macosx,introduced=10.10)));
int unlinkat(int, const char *, int) __attribute__((availability(macosx,introduced=10.10)));
# 74 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/unistd.h" 2 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 1 3 4
# 75 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/unistd.h" 2 3 4
# 90 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/unistd.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_size_t.h" 1 3 4
# 91 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/unistd.h" 2 3 4



# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_null.h" 1 3 4
# 95 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/unistd.h" 2 3 4
# 442 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/unistd.h" 3 4
void _exit(int) __attribute__((__noreturn__));
int access(const char *, int);
unsigned int
  alarm(unsigned int);
int chdir(const char *);
int chown(const char *, uid_t, gid_t);

int close(int) __asm("_" "close" );

int dup(int);
int dup2(int, int);
int execl(const char * __path, const char * __arg0, ...) __attribute__((availability(watchos,unavailable))) __attribute__((availability(tvos,unavailable)));
int execle(const char * __path, const char * __arg0, ...) __attribute__((availability(watchos,unavailable))) __attribute__((availability(tvos,unavailable)));
int execlp(const char * __file, const char * __arg0, ...) __attribute__((availability(watchos,unavailable))) __attribute__((availability(tvos,unavailable)));
int execv(const char * __path, char * const * __argv) __attribute__((availability(watchos,unavailable))) __attribute__((availability(tvos,unavailable)));
int execve(const char * __file, char * const * __argv, char * const * __envp) __attribute__((availability(watchos,unavailable))) __attribute__((availability(tvos,unavailable)));
int execvp(const char * __file, char * const * __argv) __attribute__((availability(watchos,unavailable))) __attribute__((availability(tvos,unavailable)));
pid_t fork(void) __attribute__((availability(watchos,unavailable))) __attribute__((availability(tvos,unavailable)));
long fpathconf(int, int);
char * getcwd(char *, size_t __size);
gid_t getegid(void);
uid_t geteuid(void);
gid_t getgid(void);



int getgroups(int __gidsetsize, gid_t []);

char * getlogin(void);
pid_t getpgrp(void);
pid_t getpid(void);
pid_t getppid(void);
uid_t getuid(void);
int isatty(int);
int link(const char *, const char *);
off_t lseek(int, off_t, int);
long pathconf(const char *, int);

int pause(void) __asm("_" "pause" );

int pipe(int [2]);

ssize_t read(int, void *, size_t __nbyte) __asm("_" "read" );

int rmdir(const char *);
int setgid(gid_t);
int setpgid(pid_t, pid_t);
pid_t setsid(void);
int setuid(uid_t);

unsigned int
  sleep(unsigned int) __asm("_" "sleep" );

long sysconf(int);
pid_t tcgetpgrp(int);
int tcsetpgrp(int, pid_t);
char * ttyname(int);


int ttyname_r(int, char *, size_t __len) __asm("_" "ttyname_r" );




int unlink(const char *);

ssize_t write(int __fd, const void * __buf, size_t __nbyte) __asm("_" "write" );
# 519 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/unistd.h" 3 4
size_t confstr(int, char *, size_t __len) __asm("_" "confstr" );

int getopt(int __argc, char * const [], const char *) __asm("_" "getopt" );

extern char *optarg;
extern int optind, opterr, optopt;
# 552 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/unistd.h" 3 4
__attribute__((__deprecated__)) __attribute__((availability(watchos,unavailable))) __attribute__((availability(tvos,unavailable)))

void * brk(const void *);
int chroot(const char *) ;


char * crypt(const char *, const char *);

void encrypt(char *, int) __asm("_" "encrypt" );



int fchdir(int);
long gethostid(void);
pid_t getpgid(pid_t);
pid_t getsid(pid_t);



int getdtablesize(void) ;
int getpagesize(void) __attribute__((__const__)) ;
char * getpass(const char *) ;




char * getwd(char *) ;


int lchown(const char *, uid_t, gid_t) __asm("_" "lchown" );

int lockf(int, int, off_t) __asm("_" "lockf" );

int nice(int) __asm("_" "nice" );

ssize_t pread(int __fd, void * __buf, size_t __nbyte, off_t __offset) __asm("_" "pread" );

ssize_t pwrite(int __fd, const void * __buf, size_t __nbyte, off_t __offset) __asm("_" "pwrite" );






__attribute__((__deprecated__)) __attribute__((availability(watchos,unavailable))) __attribute__((availability(tvos,unavailable)))

void * sbrk(int);



pid_t setpgrp(void) __asm("_" "setpgrp" );




int setregid(gid_t, gid_t) __asm("_" "setregid" );

int setreuid(uid_t, uid_t) __asm("_" "setreuid" );

void swab(const void * restrict , void * restrict , ssize_t __nbytes);
void sync(void);
int truncate(const char *, off_t);
useconds_t ualarm(useconds_t, useconds_t);
int usleep(useconds_t) __asm("_" "usleep" );


__attribute__((__deprecated__("Use posix_spawn or fork")))

pid_t vfork(void) __attribute__((availability(watchos,unavailable))) __attribute__((availability(tvos,unavailable)));


int fsync(int) __asm("_" "fsync" );

int ftruncate(int, off_t);
int getlogin_r(char *, size_t __namelen);
# 639 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/unistd.h" 3 4
int fchown(int, uid_t, gid_t);
int gethostname(char *, size_t __namelen);
ssize_t readlink(const char * restrict, char * restrict, size_t __bufsize);
int setegid(gid_t);
int seteuid(uid_t);
int symlink(const char *, const char *);
# 657 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/unistd.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_uuid_t.h" 1 3 4
# 31 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/_types/_uuid_t.h" 3 4
typedef __darwin_uuid_t uuid_t;
# 658 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/unistd.h" 2 3 4


void _Exit(int) __attribute__((__noreturn__));
int accessx_np(const struct accessx_descriptor *, size_t __sz, int *, uid_t);
int acct(const char *);
int add_profil(char *, size_t __bufsiz, unsigned long, unsigned int) __attribute__((availability(watchos,unavailable))) __attribute__((availability(tvos,unavailable)));
void endusershell(void);
int execvP(const char * __file, const char * __searchpath, char * const * __argv) __attribute__((availability(watchos,unavailable))) __attribute__((availability(tvos,unavailable)));
char * fflagstostr(unsigned long);
int getdomainname(char *, int __namelen);
int getgrouplist(const char *, int, int *, int *__ngroups);

# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/gethostuuid.h" 1 3 4
# 35 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/gethostuuid.h" 3 4
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/Availability.h" 1 3 4
# 36 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/gethostuuid.h" 2 3 4





int gethostuuid(uuid_t, const struct timespec *) __attribute__((availability(macos,introduced=10.5))) __attribute__((availability(ios,unavailable))) __attribute__((availability(tvos,unavailable))) __attribute__((availability(watchos,unavailable)));
# 671 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/unistd.h" 2 3 4

mode_t getmode(const void *, mode_t);
int getpeereid(int, uid_t *, gid_t *);
int getsgroups_np(int *, uuid_t);
char * getusershell(void);
int getwgroups_np(int *, uuid_t);
int initgroups(const char *, int);
int issetugid(void);
char * mkdtemp(char *);
int mknod(const char *, mode_t, dev_t);
int mkpath_np(const char *path, mode_t omode) __attribute__((availability(macosx,introduced=10.8)));
int mkpathat_np(int dfd, const char *path, mode_t omode)
  __attribute__((availability(macosx,introduced=10.12))) __attribute__((availability(ios,introduced=10.0)))
  __attribute__((availability(tvos,introduced=10.0))) __attribute__((availability(watchos,introduced=3.0)));
int mkstemp(char *);
int mkstemps(char *, int);
char * mktemp(char *);
int mkostemp(char * path, int oflags)
  __attribute__((availability(macosx,introduced=10.12))) __attribute__((availability(ios,introduced=10.0)))
  __attribute__((availability(tvos,introduced=10.0))) __attribute__((availability(watchos,introduced=3.0)));
int mkostemps(char * path, int slen, int oflags)
  __attribute__((availability(macosx,introduced=10.12))) __attribute__((availability(ios,introduced=10.0)))
  __attribute__((availability(tvos,introduced=10.0))) __attribute__((availability(watchos,introduced=3.0)));

int mkstemp_dprotected_np(char * path, int dpclass, int dpflags)
  __attribute__((availability(macosx,unavailable))) __attribute__((availability(ios,introduced=10.0)))
  __attribute__((availability(tvos,introduced=10.0))) __attribute__((availability(watchos,introduced=3.0)));
char * mkdtempat_np(int dfd, char * path)
  __attribute__((availability(macosx,introduced=10.13))) __attribute__((availability(ios,introduced=11.0)))
  __attribute__((availability(tvos,introduced=11.0))) __attribute__((availability(watchos,introduced=4.0)));
int mkstempsat_np(int dfd, char * path, int slen)
  __attribute__((availability(macosx,introduced=10.13))) __attribute__((availability(ios,introduced=11.0)))
  __attribute__((availability(tvos,introduced=11.0))) __attribute__((availability(watchos,introduced=4.0)));
int mkostempsat_np(int dfd, char * path, int slen, int oflags)
  __attribute__((availability(macosx,introduced=10.13))) __attribute__((availability(ios,introduced=11.0)))
  __attribute__((availability(tvos,introduced=11.0))) __attribute__((availability(watchos,introduced=4.0)));
int nfssvc(int, void *);
int profil(char *, size_t __bufsiz, unsigned long, unsigned int);

__attribute__((__deprecated__("Use of per-thread security contexts is error-prone and discouraged.")))
int pthread_setugid_np(uid_t, gid_t);
int pthread_getugid_np(uid_t *, gid_t *);

int reboot(int);
int revoke(const char *);

__attribute__((__deprecated__)) int rcmd(char * *, int, const char *, const char *, const char *, int *);
__attribute__((__deprecated__)) int rcmd_af(char * *, int, const char *, const char *, const char *, int *,
  int);
__attribute__((__deprecated__)) int rresvport(int *);
__attribute__((__deprecated__)) int rresvport_af(int *, int);
__attribute__((__deprecated__)) int iruserok(unsigned long, int, const char *, const char *);
__attribute__((__deprecated__)) int iruserok_sa(const void *, int, int, const char *, const char *);
__attribute__((__deprecated__)) int ruserok(const char *, int, const char *, const char *);

int setdomainname(const char *, int __namelen);
int setgroups(int, const gid_t *);
void sethostid(long);
int sethostname(const char *, int __namelen);

void setkey(const char *) __asm("_" "setkey" );



int setlogin(const char *);
void *setmode(const char *) __asm("_" "setmode" );
int setrgid(gid_t);
int setruid(uid_t);
int setsgroups_np(int, const uuid_t);
void setusershell(void);
int setwgroups_np(int, const uuid_t);
int strtofflags(char * *, unsigned long *, unsigned long *);
int swapon(const char *);
int ttyslot(void);
int undelete(const char *);
int unwhiteout(const char *);
void * valloc(size_t __size);

__attribute__((availability(watchos,unavailable))) __attribute__((availability(tvos,unavailable)))
__attribute__((availability(ios,deprecated=10.0,message="syscall(2) is unsupported; " "please switch to a supported interface. For SYS_kdebug_trace use kdebug_signpost().")))

__attribute__((availability(macosx,deprecated=10.12,message="syscall(2) is unsupported; " "please switch to a supported interface. For SYS_kdebug_trace use kdebug_signpost().")))

int syscall(int, ...);

extern char *suboptarg;
int getsubopt(char * *, char * const *, char * *);



int fgetattrlist(int,void*,void *,size_t __attrBufSize,unsigned int) __attribute__((availability(macosx,introduced=10.6)));
int fsetattrlist(int,void*,void *,size_t __attrBufSize,unsigned int) __attribute__((availability(macosx,introduced=10.6)));
int getattrlist(const char*,void*,void *,size_t __attrBufSize,unsigned int) __asm("_" "getattrlist" );
int setattrlist(const char*,void*,void *,size_t __attrBufSize,unsigned int) __asm("_" "setattrlist" );
int exchangedata(const char*,const char*,unsigned int) __attribute__((availability(watchos,unavailable))) __attribute__((availability(tvos,unavailable)));
int getdirentriesattr(int,void*,void *,size_t __attrBufSize,unsigned int*,unsigned int*,unsigned int*,unsigned int) __attribute__((availability(watchos,unavailable))) __attribute__((availability(tvos,unavailable)));
# 781 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/unistd.h" 3 4
struct fssearchblock;
struct searchstate;

int searchfs(const char *, struct fssearchblock *, unsigned long *, unsigned int, unsigned int, struct searchstate *) __attribute__((availability(watchos,unavailable))) __attribute__((availability(tvos,unavailable)));
int fsctl(const char *,unsigned long,void *,unsigned int);
int ffsctl(int,unsigned long,void *,unsigned int) __attribute__((availability(macosx,introduced=10.6)));




int fsync_volume_np(int, int) __attribute__((availability(macosx,introduced=10.8)));
int sync_volume_np(const char *, int) __attribute__((availability(macosx,introduced=10.8)));

extern int optreset;
# 51 "/usr/local/include/gmssl/socket.h" 2

typedef int tls_socket_t;
typedef ssize_t tls_ret_t;
typedef socklen_t tls_socklen_t;
# 64 "/usr/local/include/gmssl/socket.h"
int tls_socket_lib_init(void);
int tls_socket_lib_cleanup(void);
int tls_socket_create(tls_socket_t *sock, int af, int type, int protocl);
int tls_socket_connect(tls_socket_t sock, const struct sockaddr_in *addr);
int tls_socket_bind(tls_socket_t sock, const struct sockaddr_in *addr);
int tls_socket_listen(tls_socket_t sock, int backlog);
int tls_socket_accept(tls_socket_t sock, struct sockaddr_in *addr, tls_socket_t *conn_sock);
# 23 "/usr/local/include/gmssl/tls.h" 2








typedef uint32_t uint24_t;





void tls_uint8_to_bytes(uint8_t a, uint8_t **out, size_t *outlen);
void tls_uint16_to_bytes(uint16_t a, uint8_t **out, size_t *outlen);
void tls_uint24_to_bytes(uint24_t a, uint8_t **out, size_t *outlen);
void tls_uint32_to_bytes(uint32_t a, uint8_t **out, size_t *outlen);
void tls_array_to_bytes(const uint8_t *data, size_t len, uint8_t **out, size_t *outlen);
void tls_uint8array_to_bytes(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen);
void tls_uint16array_to_bytes(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen);
void tls_uint24array_to_bytes(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen);
int tls_uint8_from_bytes(uint8_t *a, const uint8_t **in, size_t *inlen);
int tls_uint16_from_bytes(uint16_t *a, const uint8_t **in, size_t *inlen);
int tls_uint24_from_bytes(uint24_t *a, const uint8_t **in, size_t *inlen);
int tls_uint32_from_bytes(uint32_t *a, const uint8_t **in, size_t *inlen);
int tls_array_from_bytes(const uint8_t **data, size_t datalen, const uint8_t **in, size_t *inlen);
int tls_uint8array_from_bytes(const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen);
int tls_uint16array_from_bytes(const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen);
int tls_uint24array_from_bytes(const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen);
int tls_length_is_zero(size_t len);


typedef enum {
 TLS_protocol_tlcp = 0x0101,
 TLS_protocol_ssl2 = 0x0002,
 TLS_protocol_ssl3 = 0x0300,
 TLS_protocol_tls1 = 0x0301,
 TLS_protocol_tls11 = 0x0302,
 TLS_protocol_tls12 = 0x0303,
 TLS_protocol_tls13 = 0x0304,
 TLS_protocol_dtls1 = 0xfeff,
 TLS_protocol_dtls12 = 0xfefd,
} TLS_PROTOCOL;

const char *tls_protocol_name(int proto);


typedef enum {
 TLS_cipher_null_with_null_null = 0x0000,


 TLS_cipher_sm4_gcm_sm3 = 0x00c6,
 TLS_cipher_sm4_ccm_sm3 = 0x00c7,


 TLS_cipher_ecdhe_sm4_cbc_sm3 = 0xe011,
 TLS_cipher_ecdhe_sm4_gcm_sm3 = 0xe051,
 TLS_cipher_ecc_sm4_cbc_sm3 = 0xe013,
 TLS_cipher_ecc_sm4_gcm_sm3 = 0xe053,
 TLS_cipher_ibsdh_sm4_cbc_sm3 = 0xe015,
 TLS_cipher_ibsdh_sm4_gcm_sm3 = 0xe055,
 TLS_cipher_ibc_sm4_cbc_sm3 = 0xe017,
 TLS_cipher_ibc_sm4_gcm_sm3 = 0xe057,
 TLS_cipher_rsa_sm4_cbc_sm3 = 0xe019,
 TLS_cipher_rsa_sm4_gcm_sm3 = 0xe059,
 TLS_cipher_rsa_sm4_cbc_sha256 = 0xe01c,
 TLS_cipher_rsa_sm4_gcm_sha256 = 0xe05a,


 TLS_cipher_aes_128_gcm_sha256 = 0x1301,
 TLS_cipher_aes_256_gcm_sha384 = 0x1302,
 TLS_cipher_chacha20_poly1305_sha256 = 0x1303,
 TLS_cipher_aes_128_ccm_sha256 = 0x1304,
 TLS_cipher_aes_128_ccm_8_sha256 = 0x1305,

 TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256 = 0xc023,

 TLS_cipher_empty_renegotiation_info_scsv = 0x00ff,
} TLS_CIPHER_SUITE;

const char *tls_cipher_suite_name(int cipher);
int tls_cipher_suites_select(const uint8_t *client_ciphers, size_t client_ciphers_len,
 const int *server_ciphers, size_t server_ciphers_cnt, int *selected_cipher);
int tls_cipher_suite_in_list(int cipher, const int *list, size_t list_count);


typedef enum {
 TLS_compression_null = 0,
 TLS_compression_default = 1,
} TLS_COMPRESSION_METHOD;

const char *tls_compression_method_name(int meth);


typedef enum {
 TLS_record_invalid = 0,
 TLS_record_change_cipher_spec = 20,
 TLS_record_alert = 21,
 TLS_record_handshake = 22,
 TLS_record_application_data = 23,
 TLS_record_heartbeat = 24,
 TLS_record_tls12_cid = 25,
} TLS_RECORD_TYPE;

const char *tls_record_type_name(int type);


typedef enum {
 TLS_handshake_hello_request = 0,
 TLS_handshake_client_hello = 1,
 TLS_handshake_server_hello = 2,
 TLS_handshake_hello_verify_request = 3,
 TLS_handshake_new_session_ticket = 4,
 TLS_handshake_end_of_early_data = 5,
 TLS_handshake_hello_retry_request = 6,
 TLS_handshake_encrypted_extensions = 8,
 TLS_handshake_certificate = 11,
 TLS_handshake_server_key_exchange = 12,
 TLS_handshake_certificate_request = 13,
 TLS_handshake_server_hello_done = 14,
 TLS_handshake_certificate_verify = 15,
 TLS_handshake_client_key_exchange = 16,
 TLS_handshake_finished = 20,
 TLS_handshake_certificate_url = 21,
 TLS_handshake_certificate_status = 22,
 TLS_handshake_supplemental_data = 23,
 TLS_handshake_key_update = 24,
 TLS_handshake_compressed_certificate = 25,
 TLS_handshake_ekt_key = 26,
 TLS_handshake_message_hash = 254,
} TLS_HANDSHAKE_TYPE;

const char *tls_handshake_type_name(int type);


typedef enum {
 TLS_cert_type_rsa_sign = 1,
 TLS_cert_type_dss_sign = 2,
 TLS_cert_type_rsa_fixed_dh = 3,
 TLS_cert_type_dss_fixed_dh = 4,
 TLS_cert_type_rsa_ephemeral_dh_RESERVED = 5,
 TLS_cert_type_dss_ephemeral_dh_RESERVED = 6,
 TLS_cert_type_fortezza_dms_RESERVED = 20,
 TLS_cert_type_ecdsa_sign = 64,
 TLS_cert_type_rsa_fixed_ecdh = 65,
 TLS_cert_type_ecdsa_fixed_ecdh = 66,
 TLS_cert_type_gost_sign256 = 67,
 TLS_cert_type_gost_sign512 = 68,
 TLS_cert_type_ibc_params = 80,
} TLS_CERTIFICATE_TYPE;

const char *tls_cert_type_name(int type);
int tls_cert_type_from_oid(int oid);

typedef enum {
 TLS_extension_server_name = 0,
 TLS_extension_max_fragment_length = 1,
 TLS_extension_client_certificate_url = 2,
 TLS_extension_trusted_ca_keys = 3,
 TLS_extension_truncated_hmac = 4,
 TLS_extension_status_request = 5,
 TLS_extension_user_mapping = 6,
 TLS_extension_client_authz = 7,
 TLS_extension_server_authz = 8,
 TLS_extension_cert_type = 9,
 TLS_extension_supported_groups = 10,
 TLS_extension_ec_point_formats = 11,
 TLS_extension_srp = 12,
 TLS_extension_signature_algorithms = 13,
 TLS_extension_use_srtp = 14,
 TLS_extension_heartbeat = 15,
 TLS_extension_application_layer_protocol_negotiation= 16,
 TLS_extension_status_request_v2 = 17,
 TLS_extension_signed_certificate_timestamp = 18,
 TLS_extension_client_certificate_type = 19,
 TLS_extension_server_certificate_type = 20,
 TLS_extension_padding = 21,
 TLS_extension_encrypt_then_mac = 22,
 TLS_extension_extended_master_secret = 23,
 TLS_extension_token_binding = 24,
 TLS_extension_cached_info = 25,
 TLS_extension_tls_lts = 26,
 TLS_extension_compress_certificate = 27,
 TLS_extension_record_size_limit = 28,
 TLS_extension_pwd_protect = 29,
 TLS_extension_pwd_clear = 30,
 TLS_extension_password_salt = 31,
 TLS_extension_ticket_pinning = 32,
 TLS_extension_tls_cert_with_extern_psk = 33,
 TLS_extension_delegated_credentials = 34,
 TLS_extension_session_ticket = 35,
 TLS_extension_TLMSP = 36,
 TLS_extension_TLMSP_proxying = 37,
 TLS_extension_TLMSP_delegate = 38,
 TLS_extension_supported_ekt_ciphers = 39,
 TLS_extension_pre_shared_key = 41,
 TLS_extension_early_data = 42,
 TLS_extension_supported_versions = 43,
 TLS_extension_cookie = 44,
 TLS_extension_psk_key_exchange_modes = 46,
 TLS_extension_certificate_authorities = 47,
 TLS_extension_oid_filters = 48,
 TLS_extension_post_handshake_auth = 49,
 TLS_extension_signature_algorithms_cert = 50,
 TLS_extension_key_share = 51,
 TLS_extension_transparency_info = 52,
 TLS_extension_connection_id = 53,
 TLS_extension_external_id_hash = 55,
 TLS_extension_external_session_id = 56,
 TLS_extension_quic_transport_parameters = 57,
 TLS_extension_ticket_request = 58,
 TLS_extension_renegotiation_info = 65281,
} TLS_EXTENSION_TYPE;

const char *tls_extension_name(int ext);


typedef enum {
 TLS_point_uncompressed = 0,
 TLS_point_ansix962_compressed_prime = 1,
 TLS_point_ansix962_compressed_char2 = 2,
} TLS_EC_POINT_FORMAT;

const char *tls_ec_point_format_name(int format);


typedef enum {
 TLS_curve_type_explicit_prime = 1,
 TLS_curve_type_explicit_char2 = 2,
 TLS_curve_type_named_curve = 3,
} TLS_CURVE_TYPE;

const char *tls_curve_type_name(int type);


typedef enum {
 TLS_curve_secp256k1 = 22,
 TLS_curve_secp256r1 = 23,
 TLS_curve_secp384r1 = 24,
 TLS_curve_secp521r1 = 25,
 TLS_curve_brainpoolp256r1 = 26,
 TLS_curve_brainpoolp384r1 = 27,
 TLS_curve_brainpoolp512r1 = 28,
 TLS_curve_x25519 = 29,
 TLS_curve_x448 = 30,
 TLS_curve_brainpoolp256r1tls13 = 31,
 TLS_curve_brainpoolp384r1tls13 = 32,
 TLS_curve_brainpoolp512r1tls13 = 33,
 TLS_curve_sm2p256v1 = 41,
} TLS_NAMED_CURVE;

const char *tls_named_curve_name(int named_curve);
int tls_named_curve_oid(int named_curve);


typedef enum {
 TLS_sig_rsa_pkcs1_sha1 = 0x0201,
 TLS_sig_ecdsa_sha1 = 0x0203,
 TLS_sig_rsa_pkcs1_sha256 = 0x0401,
 TLS_sig_ecdsa_secp256r1_sha256 = 0x0403,
 TLS_sig_rsa_pkcs1_sha256_legacy = 0x0420,
 TLS_sig_rsa_pkcs1_sha384 = 0x0501,
 TLS_sig_ecdsa_secp384r1_sha384 = 0x0503,
 TLS_sig_rsa_pkcs1_sha384_legacy = 0x0520,
 TLS_sig_rsa_pkcs1_sha512 = 0x0601,
 TLS_sig_ecdsa_secp521r1_sha512 = 0x0603,
 TLS_sig_rsa_pkcs1_sha512_legacy = 0x0620,
 TLS_sig_sm2sig_sm3 = 0x0708,
 TLS_sig_rsa_pss_rsae_sha256 = 0x0804,
 TLS_sig_rsa_pss_rsae_sha384 = 0x0805,
 TLS_sig_rsa_pss_rsae_sha512 = 0x0806,
 TLS_sig_ed25519 = 0x0807,
 TLS_sig_ed448 = 0x0808,
 TLS_sig_rsa_pss_pss_sha256 = 0x0809,
 TLS_sig_rsa_pss_pss_sha384 = 0x080A,
 TLS_sig_rsa_pss_pss_sha512 = 0x080B,
 TLS_sig_ecdsa_brainpoolP256r1tls13_sha256 = 0x081A,
 TLS_sig_ecdsa_brainpoolP384r1tls13_sha384 = 0x081B,
 TLS_sig_ecdsa_brainpoolP512r1tls13_sha512 = 0x081C,
} TLS_SIGNATURE_SCHEME;

const char *tls_signature_scheme_name(int scheme);
int tls_signature_scheme_match_cipher_suite(int sig_alg, int cipher_suite);


typedef enum {
 TLS_change_cipher_spec = 1,
} TLS_CHANGE_CIPHER_SPEC_TYPE;


typedef enum {
 TLS_alert_level_undefined = 0,
 TLS_alert_level_warning = 1,
 TLS_alert_level_fatal = 2,
} TLS_ALERT_LEVEL;

const char *tls_alert_level_name(int level);


typedef enum {
 TLS_alert_close_notify = 0,
 TLS_alert_unexpected_message = 10,
 TLS_alert_bad_record_mac = 20,
 TLS_alert_decryption_failed = 21,
 TLS_alert_record_overflow = 22,
 TLS_alert_decompression_failure = 30,
 TLS_alert_handshake_failure = 40,
 TLS_alert_no_certificate = 41,
 TLS_alert_bad_certificate = 42,
 TLS_alert_unsupported_certificate = 43,
 TLS_alert_certificate_revoked = 44,
 TLS_alert_certificate_expired = 45,
 TLS_alert_certificate_unknown = 46,
 TLS_alert_illegal_parameter = 47,
 TLS_alert_unknown_ca = 48,
 TLS_alert_access_denied = 49,
 TLS_alert_decode_error = 50,
 TLS_alert_decrypt_error = 51,
 TLS_alert_export_restriction = 60,
 TLS_alert_protocol_version = 70,
 TLS_alert_insufficient_security = 71,
 TLS_alert_internal_error = 80,
 TLS_alert_user_canceled = 90,
 TLS_alert_no_renegotiation = 100,
 TLS_alert_unsupported_extension = 110,
 TLS_alert_unsupported_site2site = 200,
 TLS_alert_no_area = 201,
 TLS_alert_unsupported_areatype = 202,
 TLS_alert_bad_ibcparam = 203,
 TLS_alert_unsupported_ibcparam = 204,
 TLS_alert_identity_need = 205,
} TLS_ALERT_DESCRIPTION;

const char *tls_alert_description_text(int description);


int tls_prf(const uint8_t *secret, size_t secretlen, const char *label,
 const uint8_t *seed, size_t seedlen,
 const uint8_t *more, size_t morelen,
 size_t outlen, uint8_t *out);
int tls13_hkdf_extract(const DIGEST *digest, const uint8_t salt[32], const uint8_t in[32], uint8_t out[32]);
int tls13_hkdf_expand_label(const DIGEST *digest, const uint8_t secret[32],
 const char *label, const uint8_t *context, size_t context_len,
 size_t outlen, uint8_t *out);
int tls13_derive_secret(const uint8_t secret[32], const char *label, const DIGEST_CTX *dgst_ctx, uint8_t out[32]);

int tls_cbc_encrypt(const SM3_HMAC_CTX *hmac_ctx, const SM4_KEY *enc_key,
 const uint8_t seq_num[8], const uint8_t header[5],
 const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int tls_cbc_decrypt(const SM3_HMAC_CTX *hmac_ctx, const SM4_KEY *dec_key,
 const uint8_t seq_num[8], const uint8_t header[5],
 const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int tls_record_encrypt(const SM3_HMAC_CTX *hmac_ctx, const SM4_KEY *cbc_key,
 const uint8_t seq_num[8], const uint8_t *in, size_t inlen,
 uint8_t *out, size_t *outlen);
int tls_record_decrypt(const SM3_HMAC_CTX *hmac_ctx, const SM4_KEY *cbc_key,
 const uint8_t seq_num[8], const uint8_t *in, size_t inlen,
 uint8_t *out, size_t *outlen);

int tls_seq_num_incr(uint8_t seq_num[8]);
int tls_random_generate(uint8_t random[32]);
int tls_random_print(FILE *fp, const uint8_t random[32], int format, int indent);
int tls_pre_master_secret_generate(uint8_t pre_master_secret[48], int protocol);
int tls_pre_master_secret_print(FILE *fp, const uint8_t pre_master_secret[48], int format, int indent);

int tls_secrets_print(FILE *fp,
 const uint8_t *pre_master_secret, size_t pre_master_secret_len,
 const uint8_t client_random[32], const uint8_t server_random[32],
 const uint8_t master_secret[48],
 const uint8_t *key_block, size_t key_block_len,
 int format, int indent);


typedef struct {
 uint8_t type;
 uint8_t protocol[2];
 uint8_t data_length[2];
} TLS_RECORD_HEADER;
# 416 "/usr/local/include/gmssl/tls.h"
int tls_record_set_type(uint8_t *record, int type);
int tls_record_set_protocol(uint8_t *record, int protocol);
int tls_record_set_data_length(uint8_t *record, size_t length);
int tls_record_set_data(uint8_t *record, const uint8_t *data, size_t datalen);




int tls_record_print(FILE *fp, const uint8_t *record, size_t recordlen, int format, int indent);
int tlcp_record_print(FILE *fp, const uint8_t *record, size_t recordlen, int format, int indent);

int tls_record_send(const uint8_t *record, size_t recordlen, tls_socket_t sock);
int tls_record_recv(uint8_t *record, size_t *recordlen, tls_socket_t sock);
int tls12_record_recv(uint8_t *record, size_t *recordlen, tls_socket_t sock);



typedef struct {
 uint8_t type;
 uint8_t length[3];
} TLS_HANDSHAKE_HEADER;
# 445 "/usr/local/include/gmssl/tls.h"
int tls_record_set_handshake(uint8_t *record, size_t *recordlen,
 int type, const uint8_t *data, size_t datalen);
int tls_record_get_handshake(const uint8_t *record,
 int *type, const uint8_t **data, size_t *datalen);
int tls_handshake_print(FILE *fp, const uint8_t *handshake, size_t handshakelen, int format, int indent);


int tls_hello_request_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);





int tls_record_set_handshake_client_hello(uint8_t *record, size_t *recordlen,
 int client_protocol, const uint8_t random[32],
 const uint8_t *session_id, size_t session_id_len,
 const int *cipher_suites, size_t cipher_suites_count,
 const uint8_t *exts, size_t exts_len);
int tls_record_get_handshake_client_hello(const uint8_t *record,
 int *client_protocol, const uint8_t **random,
 const uint8_t **session_id, size_t *session_id_len,
 const uint8_t **cipher_suites, size_t *cipher_suites_len,
 const uint8_t **exts, size_t *exts_len);
int tls_client_hello_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);

int tls_record_set_handshake_server_hello(uint8_t *record, size_t *recordlen,
 int server_protocol, const uint8_t random[32],
 const uint8_t *session_id, size_t session_id_len,
 int cipher_suite, const uint8_t *exts, size_t exts_len);
int tls_record_get_handshake_server_hello(const uint8_t *record,
 int *protocol, const uint8_t **random, const uint8_t **session_id, size_t *session_id_len,
 int *cipher_suite, const uint8_t **exts, size_t *exts_len);
int tls_server_hello_print(FILE *fp, const uint8_t *server_hello, size_t len, int format, int indent);


int tls_ec_point_formats_ext_to_bytes(const int *formats, size_t formats_cnt,
 uint8_t **out, size_t *outlen);
int tls_process_client_ec_point_formats(const uint8_t *ext_data, size_t ext_datalen,
 uint8_t **out, size_t *outlen);
int tls_process_server_ec_point_formats(const uint8_t *ext_data, size_t ext_datalen);

int tls_supported_groups_ext_to_bytes(const int *groups, size_t groups_cnt,
 uint8_t **out, size_t *outlen);
int tls_process_client_supported_groups(const uint8_t *ext_data, size_t ext_datalen,
 uint8_t **out, size_t *outlen);
int tls_process_server_supported_groups(const uint8_t *ext_data, size_t ext_datalen);

int tls_signature_algorithms_ext_to_bytes_ex(int ext_type, const int *algs, size_t algs_cnt,
 uint8_t **out, size_t *outlen);
int tls_signature_algorithms_ext_to_bytes(const int *algs, size_t algs_cnt,
 uint8_t **out, size_t *outlen);
int tls13_signature_algorithms_cert_ext_to_bytes(const int *algs, size_t algs_cnt,
 uint8_t **out, size_t *outlen);
int tls_process_client_signature_algorithms(const uint8_t *ext_data, size_t ext_datalen,
 uint8_t **out, size_t *outlen);
int tls_process_server_signature_algors(const uint8_t *ext_data, size_t ext_datalen);

int tls13_supported_versions_ext_to_bytes(int handshake_type, const int *protos, size_t protos_cnt,
 uint8_t **out, size_t *outlen);
int tls13_process_client_supported_versions(const uint8_t *ext_data, size_t ext_datalen,
 uint8_t **out, size_t *outlen);

int tls13_process_server_supported_versions(const uint8_t *ext_data, size_t ext_datalen);

int tls13_key_share_entry_to_bytes(const SM2_Z256_POINT *point, uint8_t **out, size_t *outlen);
int tls13_client_key_share_ext_to_bytes(const SM2_Z256_POINT *point, uint8_t **out, size_t *outlen);
int tls13_server_key_share_ext_to_bytes(const SM2_Z256_POINT *point, uint8_t **out, size_t *outlen);
int tls13_process_client_key_share(const uint8_t *ext_data, size_t ext_datalen,
 const SM2_KEY *server_ecdhe_key, SM2_Z256_POINT *client_ecdhe_public,
 uint8_t **out, size_t *outlen);
int tls13_process_server_key_share(const uint8_t *ext_data, size_t ext_datalen, SM2_Z256_POINT *point);


int tls13_certificate_authorities_ext_to_bytes(const uint8_t *ca_names, size_t ca_names_len,
 uint8_t **out, size_t *outlen);

int tls_ext_from_bytes(int *type, const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen);
int tls_process_client_exts(const uint8_t *exts, size_t extslen, uint8_t *out, size_t *outlen, size_t maxlen);
int tls_process_server_exts(const uint8_t *exts, size_t extslen,
 int *ec_point_format, int *supported_group, int *signature_algor);



int tls_record_set_handshake_certificate(uint8_t *record, size_t *recordlen,
 const uint8_t *certs, size_t certslen);


int tls_record_get_handshake_certificate(const uint8_t *record, uint8_t *certs, size_t *certslen);


int tls_server_key_exchange_print(FILE *fp, const uint8_t *ske, size_t skelen, int format, int indent);


int tls_sign_server_ecdh_params(const SM2_KEY *server_sign_key,
 const uint8_t client_random[32], const uint8_t server_random[32],
 int curve, const SM2_Z256_POINT *point, uint8_t *sig, size_t *siglen);
int tls_verify_server_ecdh_params(const SM2_KEY *server_sign_key,
 const uint8_t client_random[32], const uint8_t server_random[32],
 int curve, const SM2_Z256_POINT *point, const uint8_t *sig, size_t siglen);
int tls_record_set_handshake_server_key_exchange_ecdhe(uint8_t *record, size_t *recordlen,
 int curve, const SM2_Z256_POINT *point, const uint8_t *sig, size_t siglen);
int tls_record_get_handshake_server_key_exchange_ecdhe(const uint8_t *record,
 int *curve, SM2_Z256_POINT *point, const uint8_t **sig, size_t *siglen);
int tls_server_key_exchange_ecdhe_print(FILE *fp, const uint8_t *data, size_t datalen,
 int format, int indent);

int tlcp_record_set_handshake_server_key_exchange_pke(uint8_t *record, size_t *recordlen,
 const uint8_t *sig, size_t siglen);
int tlcp_record_get_handshake_server_key_exchange_pke(const uint8_t *record,
 const uint8_t **sig, size_t *siglen);
int tlcp_server_key_exchange_pke_print(FILE *fp, const uint8_t *sig, size_t siglen, int format, int indent);







int tls_authorities_from_certs(uint8_t *ca_names, size_t *ca_names_len, size_t maxlen, const uint8_t *certs, size_t certslen);
int tls_authorities_issued_certificate(const uint8_t *ca_names, size_t ca_namelen, const uint8_t *certs, size_t certslen);
int tls_cert_types_accepted(const uint8_t *types, size_t types_len, const uint8_t *client_certs, size_t client_certs_len);

int tls_record_set_handshake_certificate_request(uint8_t *record, size_t *recordlen,
 const uint8_t *cert_types, size_t cert_types_len,
 const uint8_t *ca_names, size_t ca_names_len);
int tls_record_get_handshake_certificate_request(const uint8_t *record,
 const uint8_t **cert_types, size_t *cert_types_len,
 const uint8_t **ca_names, size_t *ca_names_len);
int tls_certificate_request_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);



int tls_record_set_handshake_server_hello_done(uint8_t *record, size_t *recordlen);
int tls_record_get_handshake_server_hello_done(const uint8_t *record);
int tls_server_hello_done_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);


int tls_record_set_handshake_client_key_exchange_pke(uint8_t *record, size_t *recordlen,
 const uint8_t *enced_pms, size_t enced_pms_len);
int tls_record_get_handshake_client_key_exchange_pke(const uint8_t *record,
 const uint8_t **enced_pms, size_t *enced_pms_len);
int tls_client_key_exchange_pke_print(FILE *fp, const uint8_t *cke, size_t ckelen, int format, int indent);
int tls_client_key_exchange_print(FILE *fp, const uint8_t *cke, size_t ckelen, int format, int indent);

int tls_record_set_handshake_client_key_exchange_ecdhe(uint8_t *record, size_t *recordlen,
 const SM2_Z256_POINT *point);
int tls_record_get_handshake_client_key_exchange_ecdhe(const uint8_t *record, SM2_Z256_POINT *point);
int tls_client_key_exchange_ecdhe_print(FILE *fp, const uint8_t *data, size_t datalen,
 int format, int indent);


int tls_record_set_handshake_certificate_verify(uint8_t *record, size_t *recordlen,
 const uint8_t *sig, size_t siglen);
int tls_record_get_handshake_certificate_verify(const uint8_t *record,
 const uint8_t **sig, size_t *siglen);
int tls_certificate_verify_print(FILE *fp, const uint8_t *p, size_t len, int format, int indent);

typedef enum {
 TLS_client_verify_client_hello = 0,
 TLS_client_verify_server_hello = 1,
 TLS_client_verify_server_certificate = 2,
 TLS_client_verify_server_key_exchange = 3,
 TLS_client_verify_cert_request = 4,
 TLS_client_verify_server_hello_done = 5,
 TLS_client_verify_client_certificate = 6,
 TLS_client_verify_client_key_exchange = 7,
} TLS_CLIENT_VERIFY_INDEX;
# 628 "/usr/local/include/gmssl/tls.h"
typedef struct {
 TLS_CLIENT_VERIFY_INDEX index;
 uint8_t *handshake[8];
 size_t handshake_len[8];
} TLS_CLIENT_VERIFY_CTX;

int tls_client_verify_init(TLS_CLIENT_VERIFY_CTX *ctx);
int tls_client_verify_update(TLS_CLIENT_VERIFY_CTX *ctx, const uint8_t *handshake, size_t handshake_len);
int tls_client_verify_finish(TLS_CLIENT_VERIFY_CTX *ctx, const uint8_t *sig, size_t siglen, const SM2_KEY *public_key);
void tls_client_verify_cleanup(TLS_CLIENT_VERIFY_CTX *ctx);
# 648 "/usr/local/include/gmssl/tls.h"
int tls_record_set_handshake_finished(uint8_t *record, size_t *recordlen,
 const uint8_t *verify_data, size_t verify_data_len);
int tls_record_get_handshake_finished(const uint8_t *record,
 const uint8_t **verify_data, size_t *verify_data_len);
int tls_finished_print(FILE *fp, const uint8_t *a, size_t len, int format, int indent);



typedef struct {
 uint8_t level;
 uint8_t description;
} TLS_ALERT;



int tls_record_set_alert(uint8_t *record, size_t *recordlen, int alert_level, int alert_description);
int tls_record_get_alert(const uint8_t *record, int *alert_level, int *alert_description);
int tls_alert_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);



typedef struct {
 uint8_t type;
} TLS_CHANGE_CIPHER_SPEC;

const char *tls_change_cipher_spec_text(int change_cipher_spec);
int tls_change_cipher_spec_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);
int tls_record_set_change_cipher_spec(uint8_t *record, size_t *recordlen);
int tls_record_get_change_cipher_spec(const uint8_t *record);


int tls_record_set_application_data(uint8_t *record, size_t *recordlen,
 const uint8_t *data, size_t datalen);
int tls_record_get_application_data(uint8_t *record,
 const uint8_t **data, size_t *datalen);
int tls_application_data_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);



enum {
 TLS_server_mode = 0,
 TLS_client_mode = 1,
};



typedef struct {
 int protocol;
 int is_client;
 int cipher_suites[64];
 size_t cipher_suites_cnt;
 uint8_t *cacerts;
 size_t cacertslen;
 uint8_t *certs;
 size_t certslen;

 X509_KEY signkey;
 X509_KEY kenckey;

 int verify_depth;

 int quiet;
} TLS_CTX;

int tls_ctx_init(TLS_CTX *ctx, int protocol, int is_client);
int tls_ctx_set_cipher_suites(TLS_CTX *ctx, const int *cipher_suites, size_t cipher_suites_cnt);
int tls_ctx_set_ca_certificates(TLS_CTX *ctx, const char *cacertsfile, int depth);
int tls_ctx_set_certificate_and_key(TLS_CTX *ctx, const char *chainfile,
 const char *keyfile, const char *keypass);
int tls_ctx_set_tlcp_server_certificate_and_keys(TLS_CTX *ctx, const char *chainfile,
 const char *signkeyfile, const char *signkeypass,
 const char *kenckeyfile, const char *kenckeypass);
void tls_ctx_cleanup(TLS_CTX *ctx);
# 743 "/usr/local/include/gmssl/tls.h"
typedef struct {
 int protocol;
 int is_client;


 int cipher_suites[64];
 size_t cipher_suites_cnt;
 tls_socket_t sock;

 uint8_t enced_record[((1 + 2 + 2) + ((1 << 14) + 2048))];
 size_t enced_record_len;


 uint8_t record[((1 + 2 + 2) + ((1 << 14) + 2048))];
 size_t record_offset;

 int record_state;

 size_t recordlen;

 uint8_t databuf[((1 + 2 + 2) + ((1 << 14) + 2048))];
 uint8_t *data;
 size_t datalen;

 int cipher_suite;
 uint8_t session_id[32];
 size_t session_id_len;
 uint8_t server_certs[2048];
 size_t server_certs_len;
 uint8_t client_certs[2048];
 size_t client_certs_len;
 uint8_t ca_certs[2048];
 size_t ca_certs_len;

 X509_KEY sign_key;
 X509_KEY kenc_key;

 int verify_result;
 uint8_t master_secret[48];
 uint8_t key_block[96];

 SM3_HMAC_CTX client_write_mac_ctx;
 SM3_HMAC_CTX server_write_mac_ctx;
 SM4_KEY client_write_enc_key;
 SM4_KEY server_write_enc_key;
 uint8_t client_seq_num[8];
 uint8_t server_seq_num[8];

 uint8_t client_write_iv[12];
 uint8_t server_write_iv[12];
 BLOCK_CIPHER_KEY client_write_key;
 BLOCK_CIPHER_KEY server_write_key;

 int quiet;



 int state;
 SM3_CTX sm3_ctx;
 SM2_SIGN_CTX sign_ctx;
 TLS_CLIENT_VERIFY_CTX client_verify_ctx;
 uint8_t client_random[32];
 uint8_t server_random[32];
 uint8_t server_exts[512];
 size_t server_exts_len;



 uint16_t sig_alg;




 uint16_t server_sig_alg;



 uint16_t ecdh_named_curve;

 X509_KEY ecdh_key;
 uint8_t peer_ecdh_point[65];
 size_t peer_ecdh_point_len;

 int client_certificate_verify;

 int verify_depth;

} TLS_CONNECT;





int tls_init(TLS_CONNECT *conn, const TLS_CTX *ctx);
int tls_set_socket(TLS_CONNECT *conn, tls_socket_t sock);
int tls_do_handshake(TLS_CONNECT *conn);
int tls_send(TLS_CONNECT *conn, const uint8_t *in, size_t inlen, size_t *sentlen);
int tls_recv(TLS_CONNECT *conn, uint8_t *out, size_t outlen, size_t *recvlen);
int tls_shutdown(TLS_CONNECT *conn);
void tls_cleanup(TLS_CONNECT *conn);

int tlcp_do_connect(TLS_CONNECT *conn);
int tlcp_do_accept(TLS_CONNECT *conn);
int tls12_do_connect(TLS_CONNECT *conn);
int tls12_do_accept(TLS_CONNECT *conn);





int tls13_do_connect(TLS_CONNECT *conn);
int tls13_do_accept(TLS_CONNECT *conn);

int tls_send_alert(TLS_CONNECT *conn, int alert);
int tls_send_warning(TLS_CONNECT *conn, int alert);

int tls13_send(TLS_CONNECT *conn, const uint8_t *data, size_t datalen, size_t *sentlen);
int tls13_recv(TLS_CONNECT *conn, uint8_t *out, size_t outlen, size_t *recvlen);


int tls13_connect(TLS_CONNECT *conn, const char *hostname, int port, FILE *server_cacerts_fp,
 FILE *client_certs_fp, const SM2_KEY *client_sign_key);
int tls13_accept(TLS_CONNECT *conn, int port,
 FILE *server_certs_fp, const SM2_KEY *server_sign_key,
 FILE *client_cacerts_fp);


int tls13_supported_versions_ext_print(FILE *fp, int fmt, int ind, int handshake_type, const uint8_t *data, size_t datalen);
int tls13_key_share_ext_print(FILE *fp, int fmt, int ind, int handshake_type, const uint8_t *data, size_t datalen);


int tls_process_client_hello_exts(const uint8_t *exts, size_t extslen, uint8_t *out, size_t *outlen, size_t maxlen);
int tls_process_server_hello_exts(const uint8_t *exts, size_t extslen,
 int *ec_point_format, int *supported_group, int *signature_algor);


int tls13_encrypted_extensions_print(FILE *fp, int fmt, int ind, const uint8_t *data, size_t datalen);

int tls13_extension_print(FILE *fp, int fmt, int ind,
 int handshake_type, int ext_type, const uint8_t *ext_data, size_t ext_datalen);
int tls13_extensions_print(FILE *fp, int fmt, int ind,
 int handshake_type, const uint8_t *exts, size_t extslen);

int tls13_certificate_print(FILE *fp, int fmt, int ind, const uint8_t *cert, size_t certlen);
int tls13_certificate_request_print(FILE *fp, int fmt, int ind, const uint8_t *cert, size_t certlen);
int tls13_certificate_verify_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen);
int tls13_record_print(FILE *fp, int format, int indent, const uint8_t *record, size_t recordlen);


int tls13_gcm_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t iv[12],
 const uint8_t seq_num[8], int record_type,
 const uint8_t *in, size_t inlen, size_t padding_len,
 uint8_t *out, size_t *outlen);
int tls13_gcm_decrypt(const BLOCK_CIPHER_KEY *key, const uint8_t iv[12],
 const uint8_t seq_num[8], const uint8_t *in, size_t inlen,
 int *record_type, uint8_t *out, size_t *outlen);
# 917 "/usr/local/include/gmssl/tls.h"
int tls_encrypted_record_print(FILE *fp, const uint8_t *record, size_t recordlen, int format, int indent);
# 25 "tls12.c" 2

# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/fcntl.h" 1 3 4
# 27 "tls12.c" 2
# 1 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/errno.h" 1 3 4
# 28 "tls12.c" 2




static const int tls12_ciphers[] = {
 TLS_cipher_ecdhe_sm4_cbc_sm3,
 TLS_cipher_ecdhe_sm4_gcm_sm3,
 TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256,
};
# 66 "tls12.c"
int tls12_record_print(FILE *fp, const uint8_t *record, size_t recordlen, int format, int indent)
{


 format |= tls12_ciphers[0] << 8;
 return tls_record_print(fp, record, recordlen, format, indent);
}




int tls_send_record(TLS_CONNECT *conn)
{
 size_t left;
 tls_ret_t n;

 left = ((size_t)((1 + 2 + 2) + (((uint16_t)((conn->record)[3]) << 8) | (conn->record)[4]))) - conn->record_offset;
 while (left) {
  n = send(conn->sock,conn->record + conn->record_offset,left,0);
  if (n < 0) {
   if ((*__error()) == 35 && (*__error()) == 35) {
    return -1001;
   } else if ((*__error()) == 4) {
    continue;
   } else {
    do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 91, __FUNCTION__); } while (0);
    return -1;
   }
  }
  conn->record_offset += n;
  left -= n;
 }
 return 1;
}

int tls_recv_record(TLS_CONNECT *conn)
{
 size_t left;
 tls_ret_t n;

 if (conn->record_offset < 5) {
  left = 5 - conn->record_offset;
  while (left) {
   n = recv(conn->sock,conn->record + conn->record_offset,left,0);
   if (n < 0) {
    if ((*__error()) == 35 || (*__error()) == 35) {
     return -1000;
    } else if ((*__error()) == 4) {
     continue;
    } else {
     do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 116, __FUNCTION__); } while (0);


     return -1003;
    }
   } else if (n == 0) {
    do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 122, __FUNCTION__); } while (0);
    return -1002;
   }
   conn->record_offset += n;
   left -= n;
  }
 }

 if (conn->record_offset == 5) {
  if (!tls_record_type_name(((conn->record)[0]))) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 132, __FUNCTION__); } while (0);
   return -1;
  }
  if (!tls_protocol_name((((uint16_t)((conn->record)[1]) << 8) | (conn->record)[2]))) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 136, __FUNCTION__); } while (0);
   return -1;
  }
  if (((size_t)((1 + 2 + 2) + (((uint16_t)((conn->record)[3]) << 8) | (conn->record)[4]))) > ((1 + 2 + 2) + ((1 << 14) + 2048))) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 140, __FUNCTION__); } while (0);
   return -1;
  }
 }

 if (conn->record_offset >= ((size_t)((1 + 2 + 2) + (((uint16_t)((conn->record)[3]) << 8) | (conn->record)[4])))) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 146, __FUNCTION__); } while (0);
  return -1;
 }
 left = ((size_t)((1 + 2 + 2) + (((uint16_t)((conn->record)[3]) << 8) | (conn->record)[4]))) - conn->record_offset;
 while (left) {
  n = recv(conn->sock,conn->record + conn->record_offset,left,0);
  if (n < 0) {
   if ((*__error()) == 35 || (*__error()) == 35) {
    return -1000;
   } else if ((*__error()) == 4) {
    continue;
   } else {
    do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 158, __FUNCTION__); } while (0);
    return -1003;
   }
  } else if (n == 0) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 162, __FUNCTION__); } while (0);
   return -1002;
  }
  conn->record_offset += n;
  left -= n;

 }

 conn->recordlen = conn->record_offset;
 return 1;
}

int tls_named_curve_oid(int named_curve)
{
 switch (named_curve) {
 case TLS_curve_secp256r1: return OID_prime256v1;
 case TLS_curve_sm2p256v1: return OID_sm2;
 }
 return OID_undef;
}

int tls_named_curve_from_oid(int oid)
{
 switch (oid) {
 case OID_prime256v1: return TLS_curve_secp256r1;
 case OID_sm2: return TLS_curve_sm2p256v1;
 }
 return 0;
}

enum {
 TLS_state_handshake_init = 0,
 TLS_state_client_hello,
 TLS_state_server_hello,
 TLS_state_server_certificate,
 TLS_state_server_key_exchange,
 TLS_state_certificate_request,
 TLS_state_server_hello_done,
 TLS_state_client_certificate,
 TLS_state_client_key_exchange,
 TLS_state_certificate_verify,
 TLS_state_generate_keys,
 TLS_state_client_change_cipher_spec,
 TLS_state_client_finished,
 TLS_state_server_change_cipher_spec,
 TLS_state_server_finished,
 TLS_state_handshake_over,
};


const int ec_point_formats[] = { TLS_point_uncompressed };
size_t ec_point_formats_cnt = sizeof(ec_point_formats)/sizeof(ec_point_formats[0]);


const int supported_groups[] = {
 TLS_curve_sm2p256v1,
 TLS_curve_secp256r1,
};
size_t supported_groups_cnt = sizeof(supported_groups)/sizeof(supported_groups[0]);


const int signature_algors[] = {
 TLS_sig_sm2sig_sm3,
 TLS_sig_ecdsa_secp256r1_sha256,
};
size_t signature_algors_cnt = sizeof(signature_algors)/sizeof(signature_algors[0]);



int tls_record_set_handshake_server_key_exchange(uint8_t *record, size_t *recordlen,
 const uint8_t *server_ecdh_params, size_t server_ecdh_params_len,
 uint16_t sig_alg, const uint8_t *sig, size_t siglen)
{
 const int type = TLS_handshake_server_key_exchange;
 uint8_t *p = ((((record)+(1 + 2 + 2))) + 4);
 size_t len = 0;

 if (server_ecdh_params_len != 69) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 240, __FUNCTION__); } while (0);
  return -1;
 }
 if (siglen > 72) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 244, __FUNCTION__); } while (0);
  return -1;
 }
 tls_array_to_bytes(server_ecdh_params, server_ecdh_params_len, &p, &len);
 tls_uint16_to_bytes(sig_alg, &p, &len);
 tls_uint16array_to_bytes(sig, siglen, &p, &len);
 tls_record_set_handshake(record, recordlen, type, ((void*)0), len);
 return 1;
}

int tls_record_get_handshake_server_key_exchange(const uint8_t *record,
 uint8_t *curve_type, uint16_t *named_curve,
 const uint8_t **point_octets, size_t *point_octets_len,
 const uint8_t **server_ecdh_params, size_t *server_ecdh_params_len,
 uint16_t *sig_alg, const uint8_t **sig, size_t *siglen)
{
 int type;
 const uint8_t *p;
 size_t len;

 if (tls_record_get_handshake(record, &type, &p, &len) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 265, __FUNCTION__); } while (0);
  return -1;
 }
 if (type != TLS_handshake_server_key_exchange) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 269, __FUNCTION__); } while (0);
  return -1;
 }

 *server_ecdh_params = p;
 if (tls_uint8_from_bytes(curve_type, &p, &len) != 1
  || tls_uint16_from_bytes(named_curve, &p, &len) != 1
  || tls_uint8array_from_bytes(point_octets, point_octets_len, &p, &len) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 277, __FUNCTION__); } while (0);
  return -1;
 }
 *server_ecdh_params_len = p - *server_ecdh_params;
 if (*server_ecdh_params_len != 69) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 282, __FUNCTION__); } while (0);
  return -1;
 }
 if (tls_uint16_from_bytes(sig_alg, &p, &len) != 1
  || tls_uint16array_from_bytes(sig, siglen, &p, &len) != 1
  || tls_length_is_zero(len) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 288, __FUNCTION__); } while (0);
  return -1;
 }
 if (*curve_type != TLS_curve_type_named_curve) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 292, __FUNCTION__); } while (0);
  return -1;
 }
 if (!tls_named_curve_name(*named_curve)) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 296, __FUNCTION__); } while (0);
  return -1;
 }
 if (!tls_signature_scheme_name(*sig_alg)) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 300, __FUNCTION__); } while (0);
  return -1;
 }
 return 1;
}

int tls_record_set_handshake_client_key_exchange(uint8_t *record, size_t *recordlen,
 const uint8_t *point_octets, size_t point_octets_len)
{
 int type = TLS_handshake_client_key_exchange;
 uint8_t *p = ((((record)+(1 + 2 + 2))) + 4);
 size_t len = 0;

 if (point_octets_len != 65) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 314, __FUNCTION__); } while (0);
  return -1;
 }
 tls_uint8array_to_bytes(point_octets, (uint8_t)point_octets_len, &p, &len);
 tls_record_set_handshake(record, recordlen, type, ((void*)0), len);
 return 1;
}

int tls_record_get_handshake_client_key_exchange(const uint8_t *record,
 const uint8_t **point_octets, size_t *point_octets_len)
{
 int type;
 const uint8_t *p;
 size_t len;

 if (tls_record_get_handshake(record, &type, &p, &len) != 1
  || type != TLS_handshake_client_key_exchange) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 331, __FUNCTION__); } while (0);
  return -1;
 }
 if (tls_uint8array_from_bytes(point_octets, point_octets_len, &p, &len) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 335, __FUNCTION__); } while (0);
  return -1;
 }
 if (*point_octets_len != 65) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 339, __FUNCTION__); } while (0);
  return -1;
 }
 if (len) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 343, __FUNCTION__); } while (0);
  return -1;
 }
 return 1;
}

void tls_clean_record(TLS_CONNECT *conn)
{
 conn->record_offset = 0;
 conn->recordlen = 0;
}





int tls_handshake_init(TLS_CONNECT *conn)
{

 sm3_init(&conn->sm3_ctx);

 if (conn->client_certs_len) {

 }

 return 1;
}

int tls_send_client_hello(TLS_CONNECT *conn)
{
 int ret;
 uint8_t *record = conn->record;

 if (!conn->recordlen) {
  uint8_t client_exts[512];
  uint8_t *p = client_exts;
  size_t client_exts_len = 0;

  tls_record_set_protocol(record, TLS_protocol_tls1);

  if (tls_random_generate(conn->client_random) != 1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 384, __FUNCTION__); } while (0);
   return -1;
  }
  if (tls_ec_point_formats_ext_to_bytes(ec_point_formats, ec_point_formats_cnt, &p, &client_exts_len) != 1
   || tls_supported_groups_ext_to_bytes(supported_groups, supported_groups_cnt, &p, &client_exts_len) != 1
   || tls_signature_algorithms_ext_to_bytes(signature_algors, signature_algors_cnt, &p, &client_exts_len) != 1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 390, __FUNCTION__); } while (0);
   return -1;
  }
  if (tls_record_set_handshake_client_hello(conn->record, &conn->recordlen,
   conn->protocol, conn->client_random, ((void*)0), 0,
   tls12_ciphers, sizeof(tls12_ciphers)/sizeof(tls12_ciphers[0]),
   client_exts, client_exts_len) != 1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 397, __FUNCTION__); } while (0);
   return -1;
  }


                                 ;
                                                                 ;
  sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
 }




 if (conn->client_certificate_verify) {
  sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);
 }

 if ((ret = tls_send_record(conn)) != 1) {
  if (ret != -1001) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 416, __FUNCTION__); } while (0);
  }
  return ret;
 }

 tls_clean_record(conn);
 return 1;
}

const int server_ciphers[] = { TLS_cipher_ecdhe_sm4_cbc_sm3 };
const size_t server_ciphers_cnt = 1;
const int curve = TLS_curve_sm2p256v1;



int tls_recv_client_hello(TLS_CONNECT *conn)
{
 int ret;
 uint8_t *record = conn->record;
 size_t recordlen;

 int client_verify = 0;

 int protocol;
 const uint8_t *client_random;
 const uint8_t *session_id;
 size_t session_id_len;
 const uint8_t *client_ciphers;
 size_t client_ciphers_len;
 const uint8_t *client_exts;
 size_t client_exts_len;

 sm3_init(&conn->sm3_ctx);



 if (conn->ca_certs_len)
  client_verify = 1;


 if (client_verify)
  tls_client_verify_init(&conn->client_verify_ctx);


                                ;

 if ((ret = tls_recv_record(conn)) != 1) {
  if (ret != -1000) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 464, __FUNCTION__); } while (0);
  }
  return ret;
 }
                                                                ;


 if ((((uint16_t)((record)[1]) << 8) | (record)[2]) != conn->protocol
  && (((uint16_t)((record)[1]) << 8) | (record)[2]) != TLS_protocol_tls1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 473, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_protocol_version);
  return -1;
 }

 if (tls_record_get_handshake_client_hello(record,
  &protocol, &client_random, &session_id, &session_id_len,
  &client_ciphers, &client_ciphers_len,
  &client_exts, &client_exts_len) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 482, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unexpected_message);
  return -1;
 }

 if (protocol != conn->protocol) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 488, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_protocol_version);
  return -1;
 }
 __builtin___memcpy_chk (conn->client_random, client_random, 32, __builtin_object_size (conn->client_random, 0));


 if (tls_cipher_suites_select(client_ciphers, client_ciphers_len,
  server_ciphers, server_ciphers_cnt,
  &conn->cipher_suite) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 498, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_insufficient_security);
  return -1;
 }

 switch (conn->cipher_suite) {
 case TLS_cipher_ecdhe_sm4_cbc_sm3:
 case TLS_cipher_ecdhe_sm4_gcm_sm3:
  conn->sig_alg = TLS_sig_sm2sig_sm3;
  conn->ecdh_named_curve = TLS_curve_sm2p256v1;
  break;
 case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
  conn->sig_alg = TLS_sig_ecdsa_secp256r1_sha256;
  conn->ecdh_named_curve = TLS_curve_secp256r1;
  break;
 default:
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 514, __FUNCTION__); } while (0);
  return -1;
 }

 if (client_exts) {

  tls_process_client_hello_exts(client_exts, client_exts_len,
   conn->server_exts, &conn->server_exts_len, sizeof(conn->server_exts));
 }

 sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
 if (client_verify)
  tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);


 fprintf(__stderrp, "end of recv_client_hello\n");
 tls_clean_record(conn);
 return 1;
}

int tls_send_server_hello(TLS_CONNECT *conn)
{
 int ret;
                                ;

 if (conn->recordlen == 0) {
  tls_record_set_protocol(conn->record, conn->protocol);
  if (tls_random_generate(conn->server_random) != 1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 542, __FUNCTION__); } while (0);
   return -1;
  }
  if (tls_record_set_handshake_server_hello(conn->record, &conn->recordlen,
   conn->protocol, conn->server_random, ((void*)0), 0,
   conn->cipher_suite, conn->server_exts, conn->server_exts_len) != 1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 548, __FUNCTION__); } while (0);
   tls_send_alert(conn, TLS_alert_internal_error);
   return -1;
  }
                                                                 ;
 }

 if ((ret = tls_send_record(conn)) != 1) {
  if (ret != -1001) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 557, __FUNCTION__); } while (0);
  }
  return ret;
 }

 sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
 if (conn->ca_certs_len) {
  tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);
 }

 tls_clean_record(conn);
 return 1;
}

int tls_recv_server_hello(TLS_CONNECT *conn)
{
 int ret;
 int protocol;
 int cipher_suite;
 const uint8_t *server_random;
 const uint8_t *session_id;
 size_t session_id_len;
 const uint8_t *server_exts;
 size_t server_exts_len;


 int ec_point_format = -1;
 int supported_group = -1;
 int signature_algor = -1;

 if ((ret = tls_recv_record(conn)) != 1) {
  if (ret != -1000) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 589, __FUNCTION__); } while (0);
  }
  return ret;
 }

                                                                ;
 if ((((uint16_t)((conn->record)[1]) << 8) | (conn->record)[2]) != conn->protocol) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 596, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_protocol_version);
  return -1;
 }

 if (tls_record_get_handshake_server_hello(conn->record,
  &protocol, &server_random, &session_id, &session_id_len, &cipher_suite,
  &server_exts, &server_exts_len) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 604, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unexpected_message);
  return -1;
 }
 if (protocol != conn->protocol) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 609, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_protocol_version);
  return -1;
 }

 if (tls_cipher_suite_in_list(cipher_suite, tls12_ciphers, sizeof(tls12_ciphers)/sizeof(tls12_ciphers[0])) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 615, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_handshake_failure);
  return -1;
 }
 if (!server_exts) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 620, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unexpected_message);
  return -1;
 }
 if (tls_process_server_hello_exts(server_exts, server_exts_len, &ec_point_format, &supported_group, &signature_algor) != 1
  || ec_point_format < 0
  || supported_group < 0
  || signature_algor < 0) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 628, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unexpected_message);
  return -1;
 }

 int a = random;


 __builtin___memcpy_chk (conn->server_random, random, 32, __builtin_object_size (conn->server_random, 0));
 __builtin___memcpy_chk (conn->session_id, session_id, session_id_len, __builtin_object_size (conn->session_id, 0));
 conn->cipher_suite = cipher_suite;
 sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
 if (conn->client_certs_len) {
  sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);
 }

 return 1;
}

int tls_send_server_certificate(TLS_CONNECT *conn)
{
 int ret;
                                      ;

 if (conn->recordlen == 0) {
  if (tls_record_set_handshake_certificate(conn->record, &conn->recordlen,
   conn->server_certs, conn->server_certs_len) != 1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 655, __FUNCTION__); } while (0);
   tls_send_alert(conn, TLS_alert_internal_error);
   return -1;
  }
                                                                 ;
 }

 if ((ret = tls_send_record(conn)) != 1) {
  if (ret != -1001) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 664, __FUNCTION__); } while (0);
  }
  return ret;
 }

 sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
 if (conn->client_certificate_verify) {
  tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);
 }
 return 1;
}

int tls_recv_server_certificate(TLS_CONNECT *conn)
{
 int ret;
 int verify_result;
 const uint8_t *server_cert;
 size_t server_cert_len;
 X509_KEY server_sign_key;


                                      ;

 if ((ret = tls_recv_record(conn)) != 1) {
  if (ret != -1000) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 689, __FUNCTION__); } while (0);
  }
  return ret;
 }
 if ((((uint16_t)((conn->record)[1]) << 8) | (conn->record)[2]) != conn->protocol) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 694, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unexpected_message);
  return -1;
 }
                                                                ;

 if (tls_record_get_handshake_certificate(conn->record,
  conn->server_certs, &conn->server_certs_len) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 702, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unexpected_message);
  return -1;
 }

 if (x509_certs_get_cert_by_index(conn->server_certs, conn->server_certs_len, 0,
  &server_cert, &server_cert_len) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 709, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_bad_certificate);
  return -1;
 }
 if (x509_cert_get_subject_public_key(server_cert, server_cert_len, &server_sign_key) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 714, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_bad_certificate);
  return -1;
 }


 if (server_sign_key.algor != OID_ec_public_key) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 721, __FUNCTION__); } while (0);
  return -1;
 }
 switch (conn->cipher_suite) {
 case TLS_cipher_ecdhe_sm4_cbc_sm3:
 case TLS_cipher_ecdhe_sm4_gcm_sm3:
 case TLS_cipher_ecc_sm4_cbc_sm3:
 case TLS_cipher_ecc_sm4_gcm_sm3:
  if (server_sign_key.algor_param != OID_sm2) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 730, __FUNCTION__); } while (0);
   return -1;
  }
  conn->server_sig_alg = TLS_sig_sm2sig_sm3;
  break;

 case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
  if (server_sign_key.algor_param != OID_prime256v1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 738, __FUNCTION__); } while (0);
   return -1;
  }
  conn->server_sig_alg = TLS_sig_ecdsa_secp256r1_sha256;
  break;
 default:
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 744, __FUNCTION__); } while (0);
  return -1;
 }

 sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
 if (conn->client_certs_len) {
  sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);
 }

 (__builtin_expect(!(conn->verify_depth > 0 && conn->verify_depth < 10), 0) ? __assert_rtn(__func__, "tls12.c", 753, "conn->verify_depth > 0 && conn->verify_depth < 10") : (void)0);


 if (x509_certs_verify(conn->server_certs, conn->server_certs_len, X509_cert_chain_server,
  conn->ca_certs, conn->ca_certs_len, conn->verify_depth, &verify_result) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 758, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_bad_certificate);
  return -1;
 }

 return 1;
}

int tls_send_server_key_exchange(TLS_CONNECT *conn)
{
 int ret;
 uint8_t server_ecdh_params[69];
 uint8_t *p = server_ecdh_params + 4;
 size_t len = 0;
 X509_SIGN_CTX sign_ctx;
 const void *sign_args = ((void*)0);
 size_t sign_argslen = 0;
 uint8_t sig[sizeof(X509_SIGNATURE)];
 size_t siglen;

                                      ;


 if (conn->recordlen == 0) {

  if (x509_key_generate(&conn->ecdh_key,
   OID_ec_public_key, tls_named_curve_oid(conn->ecdh_named_curve)) != 1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 785, __FUNCTION__); } while (0);
   return -1;
  }


  server_ecdh_params[0] = TLS_curve_type_named_curve;
  server_ecdh_params[1] = conn->ecdh_named_curve >> 8;
  server_ecdh_params[2] = conn->ecdh_named_curve;
  server_ecdh_params[3] = 65;
  if (x509_public_key_to_bytes(&conn->ecdh_key, &p, &len) != 1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 795, __FUNCTION__); } while (0);
   return -1;
  }
  if (len != 65) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 799, __FUNCTION__); } while (0);
   return -1;
  }


  if (conn->sign_key.algor == OID_ec_public_key && conn->sign_key.algor_param == OID_sm2) {
   sign_args = "1234567812345678";
   sign_argslen = (sizeof("1234567812345678") - 1);
  }
  if (x509_sign_init(&sign_ctx, &conn->sign_key, sign_args, sign_argslen) != 1
   || x509_sign_update(&sign_ctx, conn->client_random, 32) != 1
   || x509_sign_update(&sign_ctx, conn->server_random, 32) != 1
   || x509_sign_update(&sign_ctx, server_ecdh_params, 69) != 1
   || x509_sign_finish(&sign_ctx, sig, &siglen) != 1) {
   x509_sign_ctx_cleanup(&sign_ctx);
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 814, __FUNCTION__); } while (0);
   return -1;
  }
  x509_sign_ctx_cleanup(&sign_ctx);

  if (tls_record_set_handshake_server_key_exchange(conn->record, &conn->recordlen,
   server_ecdh_params, sizeof(server_ecdh_params),
   conn->sig_alg, sig, siglen) != 1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 822, __FUNCTION__); } while (0);
   tls_send_alert(conn, TLS_alert_internal_error);
   return -1;
  }
                                                                 ;
 }


 if ((ret = tls_send_record(conn)) != 1) {
  if (ret != -1001) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 832, __FUNCTION__); } while (0);
  }
  return ret;
 }

 sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
 if (conn->client_certificate_verify) {
  tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);
 }

 return 1;
}


int tls_curve_match_cipher_suite(int named_curve, int cipher_suite)
{
 switch (named_curve) {
 case TLS_curve_sm2p256v1:
  switch (cipher_suite) {
  case TLS_cipher_ecdhe_sm4_cbc_sm3:
  case TLS_cipher_ecdhe_sm4_gcm_sm3:
   break;
  default:
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 855, __FUNCTION__); } while (0);
   return -1;
  }
  break;
 case TLS_curve_secp256r1:
  if (cipher_suite != TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 861, __FUNCTION__); } while (0);
   return -1;
  }
  break;
 default:
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 866, __FUNCTION__); } while (0);
  return -1;
 }
 return 1;
}

int tls_signature_scheme_match_cipher_suite(int sig_alg, int cipher_suite)
{
 switch (sig_alg) {
 case TLS_sig_sm2sig_sm3:
  switch (cipher_suite) {
  case TLS_cipher_ecdhe_sm4_cbc_sm3:
  case TLS_cipher_ecdhe_sm4_gcm_sm3:
  case TLS_cipher_ecc_sm4_cbc_sm3:
  case TLS_cipher_ecc_sm4_gcm_sm3:
   break;
  default:
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 883, __FUNCTION__); } while (0);
   return -1;
  }
  break;
 case TLS_sig_ecdsa_secp256r1_sha256:
  switch (cipher_suite) {
  case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
   break;
  default:
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 892, __FUNCTION__); } while (0);
   return -1;
  }
  break;
 default:
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 897, __FUNCTION__); } while (0);
  return -1;
 }
 return 1;
}

int tls_recv_server_key_exchange(TLS_CONNECT *conn)
{
 int ret;
 uint8_t curve_type;
 uint16_t named_curve;
 const uint8_t *point_octets;
 size_t point_octets_len;
 const uint8_t *server_ecdh_params;
 size_t server_ecdh_params_len;
 uint16_t sig_alg;
 const uint8_t *sig;
 size_t siglen;


 X509_KEY server_sign_key;

 int server_cert_index = 0;
 const uint8_t *server_cert;
 size_t server_cert_len;

 uint16_t tls_sig_alg;



 X509_SIGN_CTX sign_ctx;
 const void *sign_args = ((void*)0);
 size_t sign_argslen = 0;

                                      ;


 if (tls_record_recv(conn->record, &conn->recordlen, conn->sock) != 1
  || (((uint16_t)((conn->record)[1]) << 8) | (conn->record)[2]) != conn->protocol) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 936, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unexpected_message);
  return -1;
 }
                                                                ;


 if (tls_record_get_handshake_server_key_exchange(conn->record,
  &curve_type, &named_curve, &point_octets, &point_octets_len,
  &server_ecdh_params, &server_ecdh_params_len,
  &sig_alg, &sig, &siglen) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 947, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unexpected_message);
  return -1;
 }
 if (curve_type != TLS_curve_type_named_curve) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 952, __FUNCTION__); } while (0);
  return -1;
 }


 if (tls_curve_match_cipher_suite(named_curve, conn->cipher_suite) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 958, __FUNCTION__); } while (0);
  return -1;
 }
 if (point_octets_len != 65) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 962, __FUNCTION__); } while (0);
  return -1;
 }
 if (tls_signature_scheme_match_cipher_suite(sig_alg, conn->cipher_suite) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 966, __FUNCTION__); } while (0);
  return -1;
 }






 sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
 if (conn->client_certs_len)
  sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);




 if (x509_certs_get_cert_by_index(conn->server_certs, conn->server_certs_len,
  server_cert_index, &server_cert, &server_cert_len) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 984, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_bad_certificate);
  return -1;
 }
 if (x509_cert_get_subject_public_key(server_cert, server_cert_len, &server_sign_key) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 989, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_bad_certificate);
  return -1;
 }





 switch (sig_alg) {
 case TLS_sig_sm2sig_sm3:
  if (server_sign_key.algor != OID_ec_public_key
   || server_sign_key.algor_param != OID_sm2) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1002, __FUNCTION__); } while (0);
   tls_send_alert(conn, TLS_alert_bad_certificate);
   return -1;
  }
  break;
 case TLS_sig_ecdsa_secp256r1_sha256:
  if (server_sign_key.algor != OID_ec_public_key
   || server_sign_key.algor_param != OID_prime256v1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1010, __FUNCTION__); } while (0);
   tls_send_alert(conn, TLS_alert_bad_certificate);
   return -1;
  }
  break;
 default:
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1016, __FUNCTION__); } while (0);
  return -1;
 }

 if (server_sign_key.algor == OID_ec_public_key && server_sign_key.algor_param == OID_sm2) {
  sign_args = "1234567812345678";
  sign_argslen = (sizeof("1234567812345678") - 1);
 }
 if (x509_verify_init(&sign_ctx, &server_sign_key, sign_args, sign_argslen, sig, siglen) != 1
  || x509_verify_update(&sign_ctx, conn->client_random, 32) != 1
  || x509_verify_update(&sign_ctx, conn->server_random, 32) != 1
  || x509_verify_update(&sign_ctx, server_ecdh_params, 69) != 1
  || x509_verify_finish(&sign_ctx) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1029, __FUNCTION__); } while (0);
  return -1;
 }





 return 1;
}

int tls_send_certificate_request(TLS_CONNECT *conn)
{
 int ret;


 const uint8_t cert_types[] = { TLS_cert_type_ecdsa_sign };
 uint8_t ca_names[(((1 << 14) - 4) - 1 - 2)] = {0};
 size_t ca_names_len = 0;


 if (!conn->client_certificate_verify) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1051, __FUNCTION__); } while (0);
  return -1;
 }

 if (conn->recordlen == 0) {
                                        ;
  if (tls_authorities_from_certs(ca_names, &ca_names_len, sizeof(ca_names),
   conn->ca_certs, conn->ca_certs_len) != 1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1059, __FUNCTION__); } while (0);
   tls_send_alert(conn, TLS_alert_internal_error);
   return -1;
  }
  if (tls_record_set_handshake_certificate_request(conn->record, &conn->recordlen,
   cert_types, sizeof(cert_types),
   ca_names, ca_names_len) != 1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1066, __FUNCTION__); } while (0);
   tls_send_alert(conn, TLS_alert_internal_error);
   return -1;
  }
                                                                 ;
 }

 if ((ret = tls_send_record(conn)) != 1) {
  if (ret != -1001) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1075, __FUNCTION__); } while (0);
  }
  return ret;
 }

 sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
 tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);

 return 1;
}



int tls_recv_certificate_request(TLS_CONNECT *conn)
{
 int ret;
 uint8_t *record = conn->record;
 size_t recordlen;
 const uint8_t *cp;
 size_t len;
 int handshake_type;

 const uint8_t *cert_types;
 size_t cert_types_len;
 const uint8_t *ca_names;
 size_t ca_names_len;



 if ((ret = tls_recv_record(conn)) != 1) {
  if (ret != -1000) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1106, __FUNCTION__); } while (0);
  }
  return ret;
 }
 if ((((uint16_t)((conn->record)[1]) << 8) | (conn->record)[2]) != conn->protocol) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1111, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unexpected_message);
  return -1;
 }
 if (tls_record_get_handshake(record, &handshake_type, &cp, &len) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1116, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unexpected_message);
  return -1;
 }
 if (handshake_type != TLS_handshake_certificate_request) {
  conn->client_certs_len = 0;
  return 0;
 }

                                       ;
                                                                ;
 if (tls_record_get_handshake_certificate_request(conn->record,
  &cert_types, &cert_types_len, &ca_names, &ca_names_len) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1129, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unexpected_message);
  return -1;
 }
 if(!conn->client_certs_len) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1134, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_internal_error);
  return -1;
 }
 if (tls_cert_types_accepted(cert_types, cert_types_len, conn->client_certs, conn->client_certs_len) != 1
  || tls_authorities_issued_certificate(ca_names, ca_names_len, conn->client_certs, conn->client_certs_len) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1140, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unsupported_certificate);
  return -1;
 }
 sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
 sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);

 conn->recordlen = 0;
 return 1;
}

int tls_send_server_hello_done(TLS_CONNECT *conn)
{
 int ret;
                                    ;


 if (conn->recordlen == 0) {
  tls_record_set_handshake_server_hello_done(conn->record, &conn->recordlen);
                                                                 ;
 }


 if ((ret = tls_send_record(conn)) != 1) {
  if (ret != -1001) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1165, __FUNCTION__); } while (0);
  }
  return ret;
 }
 sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);

 if (conn->client_certs_len) {
  tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);
 }
 return 1;
}

int tls_recv_server_hello_done(TLS_CONNECT *conn)
{
 int ret;
                                    ;

 if ((ret = tls_recv_record(conn)) != 1) {
  if (ret != -1000) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1184, __FUNCTION__); } while (0);
  }
  return ret;
 }
 if ((((uint16_t)((conn->record)[1]) << 8) | (conn->record)[2]) != conn->protocol) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1189, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unexpected_message);
  return -1;
 }
                                                                ;

 if (tls_record_get_handshake_server_hello_done(conn->record) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1196, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unexpected_message);
  return -1;
 }
 sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
 if (conn->client_certs_len)
  sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);


 return 1;
}

int tls_send_client_certificate(TLS_CONNECT *conn)
{
 int ret;
                                      ;

 if (conn->client_certs_len == 0) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1214, __FUNCTION__); } while (0);
  return -1;
 }

 if (conn->recordlen == 0) {
  if (tls_record_set_handshake_certificate(conn->record, &conn->recordlen,
   conn->client_certs, conn->client_certs_len) != 1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1221, __FUNCTION__); } while (0);
   tls_send_alert(conn, TLS_alert_internal_error);
   return -1;
  }
                                                                 ;
 }

 if ((ret = tls_send_record(conn)) != 1) {
  if (ret != -1001) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1230, __FUNCTION__); } while (0);
  }
  return ret;
 }


 sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
 sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);

 return 1;
}


int tls_recv_client_certificate(TLS_CONNECT *conn)
{
 int ret;
 const int verify_depth = 5;
 int verify_result;

                                      ;

 if (conn->ca_certs_len == 0) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1252, __FUNCTION__); } while (0);
  return -1;
 }

 if ((ret = tls_recv_record(conn)) != 1) {
  if (ret != -1000) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1258, __FUNCTION__); } while (0);
  }
  return ret;
 }
 if ((((uint16_t)((conn->record)[1]) << 8) | (conn->record)[2]) != conn->protocol) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1263, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unexpected_message);
  return -1;
 }
                                                                ;
 if (tls_record_get_handshake_certificate(conn->record, conn->client_certs, &conn->client_certs_len) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1269, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unexpected_message);
  return -1;
 }
 if (x509_certs_verify(conn->client_certs, conn->client_certs_len, X509_cert_chain_client,
  conn->ca_certs, conn->ca_certs_len, verify_depth, &verify_result) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1275, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_bad_certificate);
  return -1;
 }
 sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
 tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);

 return 1;
}

int tls_generate_keys(TLS_CONNECT *conn)
{
 uint8_t pre_master_secret[32];
 size_t pre_master_secret_len;
 uint8_t key_block[96];


 if (x509_key_exchange(&conn->ecdh_key,
  conn->peer_ecdh_point, conn->peer_ecdh_point_len,
  pre_master_secret, &pre_master_secret_len) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1295, __FUNCTION__); } while (0);
  return -1;
 }
 if (pre_master_secret_len != sizeof(pre_master_secret)) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1299, __FUNCTION__); } while (0);
  return -1;
 }

 if (tls_prf(pre_master_secret, 32, "master secret",
   conn->client_random, 32,
   conn->server_random, 32,
   48, conn->master_secret) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1307, __FUNCTION__); } while (0);
  return -1;
 }

 if (tls_prf(conn->master_secret, 48, "key expansion",
   conn->server_random, 32,
   conn->client_random, 32,
   96, conn->key_block) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1315, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_internal_error);
  return -1;
 }

 sm3_hmac_init(&conn->client_write_mac_ctx, conn->key_block, 32);
 sm3_hmac_init(&conn->server_write_mac_ctx, conn->key_block + 32, 32);
 sm4_set_encrypt_key(&conn->client_write_enc_key, conn->key_block + 64);
 sm4_set_decrypt_key(&conn->server_write_enc_key, conn->key_block + 80);


 tls_secrets_print(__stderrp,
  pre_master_secret, 48,
  conn->client_random, conn->server_random,
  conn->master_secret,
  conn->key_block, 96,
  0, 4);

 return 1;
}

int tls_send_client_key_exchange(TLS_CONNECT *conn)
{
 int ret;
 uint8_t point_octets[65];
 uint8_t *p = point_octets;
 size_t len = 0;


 if (conn->recordlen == 0) {
  if (x509_key_generate(&conn->ecdh_key,
   OID_ec_public_key, tls_named_curve_oid(conn->ecdh_named_curve)) != 1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1347, __FUNCTION__); } while (0);
   return -1;
  }
  if (x509_public_key_to_bytes(&conn->ecdh_key, &p, &len) != 1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1351, __FUNCTION__); } while (0);
   return -1;
  }
  if (len != sizeof(point_octets)) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1355, __FUNCTION__); } while (0);
   return -1;
  }

                                       ;
  if (tls_record_set_handshake_client_key_exchange(conn->record, &conn->recordlen,
   point_octets, len) != 1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1362, __FUNCTION__); } while (0);
   tls_send_alert(conn, TLS_alert_internal_error);
   return -1;
  }
                                                                 ;
 }

 if ((ret = tls_send_record(conn)) != 1) {
  if (ret != -1001) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1371, __FUNCTION__); } while (0);
  }
  return ret;
 }

 sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
 if (conn->client_certs_len)
  sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);

 return 1;
}

int tls_recv_client_key_exchange(TLS_CONNECT *conn)
{
 int ret;
 const uint8_t *point_octets;
 size_t point_octets_len;

                                      ;
 if ((ret = tls_recv_record(conn)) != 1) {
  if (ret != -1000) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1392, __FUNCTION__); } while (0);
  }
  return ret;
 }
 if ((((uint16_t)((conn->record)[1]) << 8) | (conn->record)[2]) != conn->protocol) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1397, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unexpected_message);
  return -1;
 }
                                                                ;

 if (tls_record_get_handshake_client_key_exchange(conn->record,
  &point_octets, &point_octets_len) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1405, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unexpected_message);
  return -1;
 }
 if (point_octets_len != 65) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1410, __FUNCTION__); } while (0);
  return -1;
 }

 __builtin___memcpy_chk (conn->peer_ecdh_point, point_octets, point_octets_len, __builtin_object_size (conn->peer_ecdh_point, 0));
 conn->peer_ecdh_point_len = point_octets_len;

 sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
 if (conn->ca_certs_len)
  tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);

 return 1;
}

int tls_send_certificate_verify(TLS_CONNECT *conn)
{
 int ret;
 uint8_t sig[72];
 size_t siglen;

                                      ;

 if (!conn->client_certificate_verify) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1433, __FUNCTION__); } while (0);
  return -1;
 }

 if (conn->recordlen == 0) {
  if (sm2_sign_finish(&conn->sign_ctx, sig, &siglen) != 1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1439, __FUNCTION__); } while (0);
   return -1;
  }
  if (tls_record_set_handshake_certificate_verify(conn->record, &conn->recordlen, sig, siglen) != 1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1443, __FUNCTION__); } while (0);
   tls_send_alert(conn, TLS_alert_internal_error);
   return -1;
  }
                                                                 ;
 }

 if ((ret = tls_send_record(conn)) != 1) {
  if (ret != -1001) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1452, __FUNCTION__); } while (0);
  }
  return ret;
 }

 sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
 return 1;
}

int tls_recv_certificate_verify(TLS_CONNECT *conn)
{
 int ret;
 X509_KEY client_sign_key;

 const uint8_t *sig;
 size_t siglen;

 const uint8_t *client_cert;
 size_t client_cert_len;

 if (!conn->client_certificate_verify) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1473, __FUNCTION__); } while (0);
  return -1;
 }

                                      ;
 if ((ret = tls_recv_record(conn)) != 1) {
  if (ret != -1000) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1480, __FUNCTION__); } while (0);
  }
  return ret;
 }
 if ((((uint16_t)((conn->record)[1]) << 8) | (conn->record)[2]) != conn->protocol) {
  tls_send_alert(conn, TLS_alert_unexpected_message);
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1486, __FUNCTION__); } while (0);
  return -1;
 }
                                                                ;


 if (tls_record_get_handshake_certificate_verify(conn->record, &sig, &siglen) != 1) {
  tls_send_alert(conn, TLS_alert_unexpected_message);
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1494, __FUNCTION__); } while (0);
  return -1;
 }


 if (x509_certs_get_cert_by_index(conn->client_certs, conn->client_certs_len, 0,
  &client_cert, &client_cert_len) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1501, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_bad_certificate);
  return -1;
 }
 if (x509_cert_get_subject_public_key(client_cert, client_cert_len, &client_sign_key) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1506, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_bad_certificate);
  return -1;
 }

 if (client_sign_key.algor != OID_ec_public_key
  || client_sign_key.algor_param != OID_sm2) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1513, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_bad_certificate);
  return -1;
 }

 if (tls_client_verify_finish(&conn->client_verify_ctx, sig, siglen, &client_sign_key.u.sm2_key) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1519, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_decrypt_error);
  return -1;
 }
 sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);

 return 1;
}

int tls_send_change_cipher_spec(TLS_CONNECT *conn)
{
 int ret;
 if (conn->recordlen == 0) {
                                        ;
  if (tls_record_set_change_cipher_spec(conn->record, &conn->recordlen) !=1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1534, __FUNCTION__); } while (0);
   tls_send_alert(conn, TLS_alert_internal_error);
   return -1;
  }
                                                                 ;
 }
 if ((ret = tls_send_record(conn)) != 1) {
  if (ret != -1001) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1542, __FUNCTION__); } while (0);
  }
  return ret;
 }
 return 1;
}

int tls_recv_change_cipher_spec(TLS_CONNECT *conn)
{
 int ret;
 uint8_t *record = conn->record;
 size_t recordlen;

                                       ;
 if ((ret = tls_recv_record(conn)) != 1) {
  if (ret != -1000) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1558, __FUNCTION__); } while (0);
  }
  return ret;
 }
 if ((((uint16_t)((record)[1]) << 8) | (record)[2]) != conn->protocol) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1563, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unexpected_message);
  return -1;
 }
                                                    ;
 if (tls_record_get_change_cipher_spec(record) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1569, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unexpected_message);
  return -1;
 }
 return 1;
}

int tls_send_client_finished(TLS_CONNECT *conn)
{
 int ret;
 uint8_t *record = conn->record;
 size_t recordlen;

 SM3_CTX tmp_sm3_ctx;
 uint8_t sm3_hash[32];
 uint8_t finished_record[(((1 + 2 + 2) + 4 + 12) + (32) + (1 + 255))];
 size_t finished_record_len;
 uint8_t local_verify_data[12];

 if (conn->recordlen == 0) {
                              ;


  __builtin___memcpy_chk (&tmp_sm3_ctx, &conn->sm3_ctx, sizeof(SM3_CTX), __builtin_object_size (&tmp_sm3_ctx, 0));
  sm3_finish(&tmp_sm3_ctx, sm3_hash);

  if (tls_prf(conn->master_secret, 48,
   "client finished", sm3_hash, 32, ((void*)0), 0,
   sizeof(local_verify_data), local_verify_data) != 1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1598, __FUNCTION__); } while (0);
   tls_send_alert(conn, TLS_alert_internal_error);
   return -1;
  }

  if (tls_record_set_handshake_finished(finished_record, &finished_record_len,
   local_verify_data, sizeof(local_verify_data)) != 1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1605, __FUNCTION__); } while (0);
   tls_send_alert(conn, TLS_alert_internal_error);
   return -1;
  }
                                                                        ;

  sm3_update(&conn->sm3_ctx, finished_record + 5, finished_record_len - 5);


  if (tls_record_encrypt(&conn->client_write_mac_ctx, &conn->client_write_enc_key,
   conn->client_seq_num, finished_record, finished_record_len, record, &recordlen) != 1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1616, __FUNCTION__); } while (0);
   tls_send_alert(conn, TLS_alert_internal_error);
   return -1;
  }
                                         ;
                                                           ;
  tls_seq_num_incr(conn->client_seq_num);

 }

 if ((ret = tls_send_record(conn)) != 1) {
  if (ret != -1001) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1628, __FUNCTION__); } while (0);
  }
  return ret;
 }

 return 1;
}

int tls_recv_client_finished(TLS_CONNECT *conn)
{
 int ret;
 uint8_t *record = conn->record;
 size_t recordlen;

 uint8_t finished_record[(((1 + 2 + 2) + 4 + 12) + (32) + (1 + 255))];
 size_t finished_record_len;
 const uint8_t *verify_data;
 size_t verify_data_len;

 uint8_t local_verify_data[12];

 SM3_CTX tmp_sm3_ctx;
 uint8_t sm3_hash[32];


                             ;
 if ((ret = tls_recv_record(conn)) != 1) {
  if (ret != -1000) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1656, __FUNCTION__); } while (0);
  }
  return ret;
 }
 if ((((uint16_t)((record)[1]) << 8) | (record)[2]) != conn->protocol) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1661, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unexpected_message);
  return -1;
 }
 if (recordlen > sizeof(finished_record)) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1666, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unexpected_message);
  return -1;
 }
                                                          ;


                                ;
 if (tls_record_decrypt(&conn->client_write_mac_ctx, &conn->client_write_enc_key,
  conn->client_seq_num, record, recordlen, finished_record, &finished_record_len) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1676, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_bad_record_mac);
  return -1;
 }
                                                                       ;
 tls_seq_num_incr(conn->client_seq_num);
 if (tls_record_get_handshake_finished(finished_record, &verify_data, &verify_data_len) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1683, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_bad_record_mac);
  return -1;
 }
 if (verify_data_len != sizeof(local_verify_data)) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1688, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_bad_record_mac);
  return -1;
 }


 __builtin___memcpy_chk (&tmp_sm3_ctx, &conn->sm3_ctx, sizeof(SM3_CTX), __builtin_object_size (&tmp_sm3_ctx, 0));
 sm3_update(&conn->sm3_ctx, finished_record + 5, finished_record_len - 5);
 sm3_finish(&tmp_sm3_ctx, sm3_hash);
 if (tls_prf(conn->master_secret, 48, "client finished", sm3_hash, 32, ((void*)0), 0,
  sizeof(local_verify_data), local_verify_data) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1699, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_internal_error);
  return -1;
 }
 if (memcmp(verify_data, local_verify_data, sizeof(local_verify_data)) != 0) {
  do { if (1) fprintf(__stderrp, "%s: %d: %s: %s\n", "tls12.c", 1704, __FUNCTION__, "client_finished.verify_data verification failure"); } while (0);
  tls_send_alert(conn, TLS_alert_decrypt_error);
  return -1;
 }

 return 1;
}

int tls_send_server_finished(TLS_CONNECT *conn)
{
 int ret;
 uint8_t *record = conn->record;
 size_t recordlen;
 uint8_t sm3_hash[32];
 uint8_t local_verify_data[12];

 uint8_t finished_record[(((1 + 2 + 2) + 4 + 12) + (32) + (1 + 255))];
 size_t finished_record_len;

 if (conn->recordlen == 0) {
                              ;
  sm3_finish(&conn->sm3_ctx, sm3_hash);
  if (tls_prf(conn->master_secret, 48, "server finished", sm3_hash, 32, ((void*)0), 0,
    sizeof(local_verify_data), local_verify_data) != 1
   || tls_record_set_handshake_finished(finished_record, &finished_record_len,
    local_verify_data, sizeof(local_verify_data)) != 1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1730, __FUNCTION__); } while (0);
   tls_send_alert(conn, TLS_alert_internal_error);
   return -1;
  }
                                                                        ;
  if (tls_record_encrypt(&conn->server_write_mac_ctx, &conn->server_write_enc_key,
   conn->server_seq_num, finished_record, finished_record_len, record, &recordlen) != 1) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1737, __FUNCTION__); } while (0);
   tls_send_alert(conn, TLS_alert_internal_error);
   return -1;
  }
                                 ;
                                                           ;
  tls_seq_num_incr(conn->server_seq_num);
 }

 if ((ret = tls_send_record(conn)) != 1) {
  if (ret != -1001) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1748, __FUNCTION__); } while (0);
  }
  return ret;
 }


 return 1;
}

int tls_recv_server_finished(TLS_CONNECT *conn)
{
 int ret;
 uint8_t *record = conn->record;
 size_t recordlen;

 uint8_t finished_record[(((1 + 2 + 2) + 4 + 12) + (32) + (1 + 255))];
 size_t finished_record_len;

 uint8_t sm3_hash[32];

 const uint8_t *verify_data;
 size_t verify_data_len;
 uint8_t local_verify_data[12];



                             ;
 if ((ret = tls_recv_record(conn)) != 1) {
  if (ret != -1000) {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1777, __FUNCTION__); } while (0);
  }
  return ret;
 }
 if ((((uint16_t)((record)[1]) << 8) | (record)[2]) != conn->protocol) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1782, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unexpected_message);
  return -1;
 }
 if (recordlen > sizeof(finished_record)) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1787, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_bad_record_mac);
  return -1;
 }
                                                          ;
                                ;
 if (tls_record_decrypt(&conn->server_write_mac_ctx, &conn->server_write_enc_key,
  conn->server_seq_num, record, recordlen, finished_record, &finished_record_len) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1795, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_bad_record_mac);
  return -1;
 }
                                                                       ;
 tls_seq_num_incr(conn->server_seq_num);
 if (tls_record_get_handshake_finished(finished_record, &verify_data, &verify_data_len) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1802, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unexpected_message);
  return -1;
 }
 if (verify_data_len != sizeof(local_verify_data)) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1807, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_unexpected_message);
  return -1;
 }
 sm3_finish(&conn->sm3_ctx, sm3_hash);
 if (tls_prf(conn->master_secret, 48, "server finished",
  sm3_hash, 32, ((void*)0), 0, sizeof(local_verify_data), local_verify_data) != 1) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1814, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_internal_error);
  return -1;
 }
 if (memcmp(verify_data, local_verify_data, sizeof(local_verify_data)) != 0) {
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1819, __FUNCTION__); } while (0);
  tls_send_alert(conn, TLS_alert_decrypt_error);
  return -1;
 }

 if (!conn->quiet)
  fprintf(__stderrp, "Connection established!\n");

 return 1;
}
# 1853 "tls12.c"
int tls12_do_client_handshake(TLS_CONNECT *conn)
{
 int ret;
 int next_state;

 switch (conn->state) {
 case TLS_state_client_hello:
  ret = tls_send_client_hello(conn);
  next_state = TLS_state_server_hello;
  break;

 case TLS_state_server_hello:
  ret = tls_recv_server_hello(conn);
  next_state = TLS_state_server_certificate;
  break;

 case TLS_state_server_certificate:
  ret = tls_recv_server_certificate(conn);
  next_state = TLS_state_server_key_exchange;
  break;

 case TLS_state_server_key_exchange:
  ret = tls_recv_server_key_exchange(conn);
  next_state = TLS_state_certificate_request;
  break;


 case TLS_state_certificate_request:
  ret = tls_recv_certificate_request(conn);
  if (ret == 1) conn->client_certificate_verify = 1;
  next_state = TLS_state_server_hello_done;
  break;

 case TLS_state_server_hello_done:
  ret = tls_recv_server_hello_done(conn);
  if (conn->client_certificate_verify)
   next_state = TLS_state_client_certificate;
  else next_state = TLS_state_client_key_exchange;
  break;

 case TLS_state_client_certificate:
  ret = tls_send_client_certificate(conn);
  next_state = TLS_state_client_key_exchange;
  break;

 case TLS_state_client_key_exchange:
  ret = tls_send_client_key_exchange(conn);
  next_state = TLS_state_generate_keys;
  break;

 case TLS_state_generate_keys:
  ret = tls_generate_keys(conn);
  if (conn->client_certificate_verify)
   next_state = TLS_state_certificate_verify;
  else next_state = TLS_state_client_change_cipher_spec;
  break;

 case TLS_state_certificate_verify:
  ret = tls_send_certificate_verify(conn);
  next_state = TLS_state_client_change_cipher_spec;

 case TLS_state_client_change_cipher_spec:
  ret = tls_send_change_cipher_spec(conn);
  next_state = TLS_state_client_finished;
  break;

 case TLS_state_client_finished:
  ret = tls_send_client_finished(conn);
  next_state = TLS_state_server_change_cipher_spec;
  break;

 case TLS_state_server_change_cipher_spec:
  ret = tls_recv_change_cipher_spec(conn);
  next_state = TLS_state_server_finished;
  break;

 case TLS_state_server_finished:
  ret = tls_recv_server_finished(conn);
  next_state = TLS_state_handshake_over;
  break;

 default:
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1935, __FUNCTION__); } while (0);
  return -1;
 }

 if (ret < 1) {
  if (ret == -1000 || ret == -1001) {
   return ret;
  } else {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 1943, __FUNCTION__); } while (0);
   return ret;
  }
 }

 conn->state = next_state;


 if (ret == 1) {
  tls_clean_record(conn);
 }

 return 1;
}

int tls12_do_server_handshake(TLS_CONNECT *conn)
{
 int ret;
 int next_state;

 switch (conn->state) {
 case TLS_state_client_hello:
  ret = tls_recv_client_hello(conn);
  next_state = TLS_state_server_hello;
  break;

 case TLS_state_server_hello:
  ret = tls_send_server_hello(conn);
  next_state = TLS_state_server_certificate;
  break;

 case TLS_state_server_certificate:
  ret = tls_send_server_certificate(conn);
  next_state = TLS_state_server_key_exchange;
  break;

 case TLS_state_server_key_exchange:
  ret = tls_send_server_key_exchange(conn);
  if (conn->client_certificate_verify)
   next_state = TLS_state_certificate_request;
  else next_state = TLS_state_server_hello_done;
  break;

 case TLS_state_certificate_request:
  ret = tls_send_certificate_request(conn);
  next_state = TLS_state_server_hello_done;
  break;

 case TLS_state_server_hello_done:
  ret = tls_send_server_hello_done(conn);
  if (conn->client_certificate_verify)
   next_state = TLS_state_client_certificate;
  else next_state = TLS_state_client_key_exchange;
  break;

 case TLS_state_client_certificate:
  ret = tls_recv_client_certificate(conn);
  next_state = TLS_state_client_key_exchange;
  break;

 case TLS_state_client_key_exchange:
  ret = tls_recv_client_key_exchange(conn);
  if (conn->client_certificate_verify)
   next_state = TLS_state_certificate_verify;
  else next_state = TLS_state_client_change_cipher_spec;
  break;

 case TLS_state_certificate_verify:
  ret = tls_recv_certificate_verify(conn);
  next_state = TLS_state_generate_keys;
  break;

 case TLS_state_generate_keys:
  ret = tls_generate_keys(conn);
  next_state = TLS_state_client_change_cipher_spec;

 case TLS_state_client_change_cipher_spec:
  ret = tls_recv_change_cipher_spec(conn);
  next_state = TLS_state_client_finished;
  break;

 case TLS_state_client_finished:
  ret = tls_recv_client_finished(conn);
  next_state = TLS_state_server_change_cipher_spec;
  break;

 case TLS_state_server_change_cipher_spec:
  ret = tls_send_change_cipher_spec(conn);
  next_state = TLS_state_server_finished;
  break;

 case TLS_state_server_finished:
  ret = tls_send_server_finished(conn);
  next_state = TLS_state_handshake_over;
  break;

 default:
  do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 2040, __FUNCTION__); } while (0);
  return -1;
 }

 if (ret < 1) {
  if (ret == -1000 || ret == -1001) {
   return ret;
  } else {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 2048, __FUNCTION__); } while (0);
   return ret;
  }

 }

 conn->state = next_state;

 tls_clean_record(conn);

 return 1;
}

int tls12_client_handshake(TLS_CONNECT *conn)
{
 int ret;

 conn->state = TLS_state_client_hello;

 while (conn->state != TLS_state_handshake_over) {

  ret = tls12_do_client_handshake(conn);

  if (ret != 1) {
   if (ret != -1000 && ret != -1001) {
    do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 2073, __FUNCTION__); } while (0);
   }
   return ret;
  }
 }



 return 1;
}

int tls12_server_handshake(TLS_CONNECT *conn)
{
 int ret;

 conn->state = TLS_state_client_hello;

 while (conn->state != TLS_state_handshake_over) {

  ret = tls12_do_server_handshake(conn);

  if (ret != 1) {
   if (ret != -1000 && ret != -1001) {
    do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 2096, __FUNCTION__); } while (0);
   }
   return ret;
  }
 }



 return 1;
}





int tls12_do_connect(TLS_CONNECT *conn)
{
 int ret;
 fd_set rfds;
 fd_set wfds;

 while (1) {

  ret = tls12_client_handshake(conn);
  if (ret == 1) {
   break;

  } else if (ret == -1001) {
   __builtin_bzero(&rfds, sizeof(*(&rfds)));
   __builtin_bzero(&wfds, sizeof(*(&wfds)));
   __darwin_fd_set((conn->sock), (&rfds));
   select(conn->sock + 1, &rfds, &wfds, ((void*)0), ((void*)0));

  } else if (ret == -1000) {
   __builtin_bzero(&rfds, sizeof(*(&rfds)));
   __builtin_bzero(&wfds, sizeof(*(&wfds)));
   __darwin_fd_set((conn->sock), (&wfds));
   select(conn->sock + 1, &rfds, &wfds, ((void*)0), ((void*)0));

  } else {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 2136, __FUNCTION__); } while (0);
   return -1;
  }
 }

 return 1;
}

int tls12_do_accept(TLS_CONNECT *conn)
{
 int ret;
 fd_set rfds;
 fd_set wfds;

 while (1) {

  ret = tls12_server_handshake(conn);

  if (ret == 1) {
   break;

  } else if (ret == -1001) {
   __builtin_bzero(&rfds, sizeof(*(&rfds)));
   __builtin_bzero(&wfds, sizeof(*(&wfds)));
   __darwin_fd_set((conn->sock), (&rfds));
   select(conn->sock + 1, &rfds, &wfds, ((void*)0), ((void*)0));

  } else if (ret == -1000) {
   __builtin_bzero(&rfds, sizeof(*(&rfds)));
   __builtin_bzero(&wfds, sizeof(*(&wfds)));
   __darwin_fd_set((conn->sock), (&wfds));
   select(conn->sock + 1, &rfds, &wfds, ((void*)0), ((void*)0));

  } else {
   do { if (1) fprintf(__stderrp, "%s:%d:%s():\n","tls12.c", 2170, __FUNCTION__); } while (0);
   return -1;
  }
 }

 return 1;
}
