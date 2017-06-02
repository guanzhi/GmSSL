/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include "bio_lcl.h"
#include <openssl/crypto.h>

#ifndef OPENSSL_NO_SOCK
#include <openssl/err.h>
#include <openssl/buffer.h>
#include <internal/thread_once.h>
#include <ctype.h>

#ifdef _HPUX_SOURCE
static const char *ossl_hstrerror(int herr)
{
    switch (herr) {
    case -1:
        return strerror(errno);
    case 0:
        return "No error";
    case HOST_NOT_FOUND:
        return "Host not found";
    case NO_DATA:                /* NO_ADDRESS is a synonym */
        return "No data";
    case NO_RECOVERY:
        return "Non recoverable error";
    case TRY_AGAIN:
        return "Try again";
    default:
        break;
    }
    return "unknown error";
}
# define hstrerror(e) ossl_hstrerror(e)
#endif

CRYPTO_RWLOCK *bio_lookup_lock;
static CRYPTO_ONCE bio_lookup_init = CRYPTO_ONCE_STATIC_INIT;

/*
 * Throughout this file and bio_lcl.h, the existence of the macro
 * AI_PASSIVE is used to detect the availability of struct addrinfo,
 * getnameinfo() and getaddrinfo().  If that macro doesn't exist,
 * we use our own implementation instead, using gethostbyname,
 * getservbyname and a few other.
 */

/**********************************************************************
 *
 * Address structure
 *
 */

BIO_ADDR *BIO_ADDR_new(void)
{
    BIO_ADDR *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        BIOerr(BIO_F_BIO_ADDR_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->sa.sa_family = AF_UNSPEC;
    return ret;
}

void BIO_ADDR_free(BIO_ADDR *ap)
{
    OPENSSL_free(ap);
}

void BIO_ADDR_clear(BIO_ADDR *ap)
{
    memset(ap, 0, sizeof(*ap));
    ap->sa.sa_family = AF_UNSPEC;
}

/*
 * BIO_ADDR_make - non-public routine to fill a BIO_ADDR with the contents
 * of a struct sockaddr.
 */
int BIO_ADDR_make(BIO_ADDR *ap, const struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        ap->s_in = *(const struct sockaddr_in *)sa;
        return 1;
    }
#ifdef AF_INET6
    if (sa->sa_family == AF_INET6) {
        ap->s_in6 = *(const struct sockaddr_in6 *)sa;
        return 1;
    }
#endif
#ifdef AF_UNIX
    if (ap->sa.sa_family == AF_UNIX) {
        ap->s_un = *(const struct sockaddr_un *)sa;
        return 1;
    }
#endif

    return 0;
}

int BIO_ADDR_rawmake(BIO_ADDR *ap, int family,
                     const void *where, size_t wherelen,
                     unsigned short port)
{
#ifdef AF_UNIX
    if (family == AF_UNIX) {
        if (wherelen + 1 > sizeof(ap->s_un.sun_path))
            return 0;
        memset(&ap->s_un, 0, sizeof(ap->s_un));
        ap->s_un.sun_family = family;
        strncpy(ap->s_un.sun_path, where, sizeof(ap->s_un.sun_path) - 1);
        return 1;
    }
#endif
    if (family == AF_INET) {
        if (wherelen != sizeof(struct in_addr))
            return 0;
        memset(&ap->s_in, 0, sizeof(ap->s_in));
        ap->s_in.sin_family = family;
        ap->s_in.sin_port = port;
        ap->s_in.sin_addr = *(struct in_addr *)where;
        return 1;
    }
#ifdef AF_INET6
    if (family == AF_INET6) {
        if (wherelen != sizeof(struct in6_addr))
            return 0;
        memset(&ap->s_in6, 0, sizeof(ap->s_in6));
        ap->s_in6.sin6_family = family;
        ap->s_in6.sin6_port = port;
        ap->s_in6.sin6_addr = *(struct in6_addr *)where;
        return 1;
    }
#endif

    return 0;
}

int BIO_ADDR_family(const BIO_ADDR *ap)
{
    return ap->sa.sa_family;
}

int BIO_ADDR_rawaddress(const BIO_ADDR *ap, void *p, size_t *l)
{
    size_t len = 0;
    const void *addrptr = NULL;

    if (ap->sa.sa_family == AF_INET) {
        len = sizeof(ap->s_in.sin_addr);
        addrptr = &ap->s_in.sin_addr;
    }
#ifdef AF_INET6
    else if (ap->sa.sa_family == AF_INET6) {
        len = sizeof(ap->s_in6.sin6_addr);
        addrptr = &ap->s_in6.sin6_addr;
    }
#endif
#ifdef AF_UNIX
    else if (ap->sa.sa_family == AF_UNIX) {
        len = strlen(ap->s_un.sun_path);
        addrptr = &ap->s_un.sun_path;
    }
#endif

    if (addrptr == NULL)
        return 0;

    if (p != NULL) {
        memcpy(p, addrptr, len);
    }
    if (l != NULL)
        *l = len;

    return 1;
}

unsigned short BIO_ADDR_rawport(const BIO_ADDR *ap)
{
    if (ap->sa.sa_family == AF_INET)
        return ap->s_in.sin_port;
#ifdef AF_INET6
    if (ap->sa.sa_family == AF_INET6)
        return ap->s_in6.sin6_port;
#endif
    return 0;
}

/*-
 * addr_strings - helper function to get host and service names
 * @ap: the BIO_ADDR that has the input info
 * @numeric: 0 if actual names should be returned, 1 if the numeric
 * representation should be returned.
 * @hostname: a pointer to a pointer to a memory area to store the
 * host name or numeric representation.  Unused if NULL.
 * @service: a pointer to a pointer to a memory area to store the
 * service name or numeric representation.  Unused if NULL.
 *
 * The return value is 0 on failure, with the error code in the error
 * stack, and 1 on success.
 */
static int addr_strings(const BIO_ADDR *ap, int numeric,
                        char **hostname, char **service)
{
    if (BIO_sock_init() != 1)
        return 0;

    if (1) {
#ifdef AI_PASSIVE
        int ret = 0;
        char host[NI_MAXHOST] = "", serv[NI_MAXSERV] = "";
        int flags = 0;

        if (numeric)
            flags |= NI_NUMERICHOST | NI_NUMERICSERV;

        if ((ret = getnameinfo(BIO_ADDR_sockaddr(ap),
                               BIO_ADDR_sockaddr_size(ap),
                               host, sizeof(host), serv, sizeof(serv),
                               flags)) != 0) {
# ifdef EAI_SYSTEM
            if (ret == EAI_SYSTEM) {
                SYSerr(SYS_F_GETNAMEINFO, get_last_socket_error());
                BIOerr(BIO_F_ADDR_STRINGS, ERR_R_SYS_LIB);
            } else
# endif
            {
                BIOerr(BIO_F_ADDR_STRINGS, ERR_R_SYS_LIB);
                ERR_add_error_data(1, gai_strerror(ret));
            }
            return 0;
        }

        /* VMS getnameinfo() has a bug, it doesn't fill in serv, which
         * leaves it with whatever garbage that happens to be there.
         * However, we initialise serv with the empty string (serv[0]
         * is therefore NUL), so it gets real easy to detect when things
         * didn't go the way one might expect.
         */
        if (serv[0] == '\0') {
            BIO_snprintf(serv, sizeof(serv), "%d",
                         ntohs(BIO_ADDR_rawport(ap)));
        }

        if (hostname != NULL)
            *hostname = OPENSSL_strdup(host);
        if (service != NULL)
            *service = OPENSSL_strdup(serv);
    } else {
#endif
        if (hostname != NULL)
            *hostname = OPENSSL_strdup(inet_ntoa(ap->s_in.sin_addr));
        if (service != NULL) {
            char serv[6];        /* port is 16 bits => max 5 decimal digits */
            BIO_snprintf(serv, sizeof(serv), "%d", ntohs(ap->s_in.sin_port));
            *service = OPENSSL_strdup(serv);
        }
    }

    if ((hostname != NULL && *hostname == NULL)
            || (service != NULL && *service == NULL)) {
        if (hostname != NULL) {
            OPENSSL_free(*hostname);
            *hostname = NULL;
        }
        if (service != NULL) {
            OPENSSL_free(*service);
            *service = NULL;
        }
        BIOerr(BIO_F_ADDR_STRINGS, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    return 1;
}

char *BIO_ADDR_hostname_string(const BIO_ADDR *ap, int numeric)
{
    char *hostname = NULL;

    if (addr_strings(ap, numeric, &hostname, NULL))
        return hostname;

    return NULL;
}

char *BIO_ADDR_service_string(const BIO_ADDR *ap, int numeric)
{
    char *service = NULL;

    if (addr_strings(ap, numeric, NULL, &service))
        return service;

    return NULL;
}

char *BIO_ADDR_path_string(const BIO_ADDR *ap)
{
#ifdef AF_UNIX
    if (ap->sa.sa_family == AF_UNIX)
        return OPENSSL_strdup(ap->s_un.sun_path);
#endif
    return NULL;
}

/*
 * BIO_ADDR_sockaddr - non-public routine to return the struct sockaddr
 * for a given BIO_ADDR.  In reality, this is simply a type safe cast.
 * The returned struct sockaddr is const, so it can't be tampered with.
 */
const struct sockaddr *BIO_ADDR_sockaddr(const BIO_ADDR *ap)
{
    return &(ap->sa);
}

/*
 * BIO_ADDR_sockaddr_noconst - non-public function that does the same
 * as BIO_ADDR_sockaddr, but returns a non-const.  USE WITH CARE, as
 * it allows you to tamper with the data (and thereby the contents
 * of the input BIO_ADDR).
 */
struct sockaddr *BIO_ADDR_sockaddr_noconst(BIO_ADDR *ap)
{
    return &(ap->sa);
}

/*
 * BIO_ADDR_sockaddr_size - non-public function that returns the size
 * of the struct sockaddr the BIO_ADDR is using.  If the protocol family
 * isn't set or is something other than AF_INET, AF_INET6 or AF_UNIX,
 * the size of the BIO_ADDR type is returned.
 */
socklen_t BIO_ADDR_sockaddr_size(const BIO_ADDR *ap)
{
    if (ap->sa.sa_family == AF_INET)
        return sizeof(ap->s_in);
#ifdef AF_INET6
    if (ap->sa.sa_family == AF_INET6)
        return sizeof(ap->s_in6);
#endif
#ifdef AF_UNIX
    if (ap->sa.sa_family == AF_UNIX)
        return sizeof(ap->s_un);
#endif
    return sizeof(*ap);
}

/**********************************************************************
 *
 * Address info database
 *
 */

const BIO_ADDRINFO *BIO_ADDRINFO_next(const BIO_ADDRINFO *bai)
{
    if (bai != NULL)
        return bai->bai_next;
    return NULL;
}

int BIO_ADDRINFO_family(const BIO_ADDRINFO *bai)
{
    if (bai != NULL)
        return bai->bai_family;
    return 0;
}

int BIO_ADDRINFO_socktype(const BIO_ADDRINFO *bai)
{
    if (bai != NULL)
        return bai->bai_socktype;
    return 0;
}

int BIO_ADDRINFO_protocol(const BIO_ADDRINFO *bai)
{
    if (bai != NULL) {
        if (bai->bai_protocol != 0)
            return bai->bai_protocol;

#ifdef AF_UNIX
        if (bai->bai_family == AF_UNIX)
            return 0;
#endif

        switch (bai->bai_socktype) {
        case SOCK_STREAM:
            return IPPROTO_TCP;
        case SOCK_DGRAM:
            return IPPROTO_UDP;
        default:
            break;
        }
    }
    return 0;
}

/*
 * BIO_ADDRINFO_sockaddr_size - non-public function that returns the size
 * of the struct sockaddr inside the BIO_ADDRINFO.
 */
socklen_t BIO_ADDRINFO_sockaddr_size(const BIO_ADDRINFO *bai)
{
    if (bai != NULL)
        return bai->bai_addrlen;
    return 0;
}

/*
 * BIO_ADDRINFO_sockaddr - non-public function that returns bai_addr
 * as the struct sockaddr it is.
 */
const struct sockaddr *BIO_ADDRINFO_sockaddr(const BIO_ADDRINFO *bai)
{
    if (bai != NULL)
        return bai->bai_addr;
    return NULL;
}

const BIO_ADDR *BIO_ADDRINFO_address(const BIO_ADDRINFO *bai)
{
    if (bai != NULL)
        return (BIO_ADDR *)bai->bai_addr;
    return NULL;
}

void BIO_ADDRINFO_free(BIO_ADDRINFO *bai)
{
    if (bai == NULL)
        return;

#ifdef AI_PASSIVE
# ifdef AF_UNIX
#  define _cond bai->bai_family != AF_UNIX
# else
#  define _cond 1
# endif
    if (_cond) {
        freeaddrinfo(bai);
        return;
    }
#endif

    /* Free manually when we know that addrinfo_wrap() was used.
     * See further comment above addrinfo_wrap()
     */
    while (bai != NULL) {
        BIO_ADDRINFO *next = bai->bai_next;
        OPENSSL_free(bai->bai_addr);
        OPENSSL_free(bai);
        bai = next;
    }
}

/**********************************************************************
 *
 * Service functions
 *
 */

/*-
 * The specs in hostserv can take these forms:
 *
 * host:service         => *host = "host", *service = "service"
 * host:*               => *host = "host", *service = NULL
 * host:                => *host = "host", *service = NULL
 * :service             => *host = NULL, *service = "service"
 * *:service            => *host = NULL, *service = "service"
 *
 * in case no : is present in the string, the result depends on
 * hostserv_prio, as follows:
 *
 * when hostserv_prio == BIO_PARSE_PRIO_HOST
 * host                 => *host = "host", *service untouched
 *
 * when hostserv_prio == BIO_PARSE_PRIO_SERV
 * service              => *host untouched, *service = "service"
 *
 */
int BIO_parse_hostserv(const char *hostserv, char **host, char **service,
                       enum BIO_hostserv_priorities hostserv_prio)
{
    const char *h = NULL; size_t hl = 0;
    const char *p = NULL; size_t pl = 0;

    if (*hostserv == '[') {
        if ((p = strchr(hostserv, ']')) == NULL)
            goto spec_err;
        h = hostserv + 1;
        hl = p - h;
        p++;
        if (*p == '\0')
            p = NULL;
        else if (*p != ':')
            goto spec_err;
        else {
            p++;
            pl = strlen(p);
        }
    } else {
        const char *p2 = strrchr(hostserv, ':');
        p = strchr(hostserv, ':');

        /*-
         * Check for more than one colon.  There are three possible
         * interpretations:
         * 1. IPv6 address with port number, last colon being separator.
         * 2. IPv6 address only.
         * 3. IPv6 address only if hostserv_prio == BIO_PARSE_PRIO_HOST,
         *    IPv6 address and port number if hostserv_prio == BIO_PARSE_PRIO_SERV
         * Because of this ambiguity, we currently choose to make it an
         * error.
         */
        if (p != p2)
            goto amb_err;

        if (p != NULL) {
            h = hostserv;
            hl = p - h;
            p++;
            pl = strlen(p);
        } else if (hostserv_prio == BIO_PARSE_PRIO_HOST) {
            h = hostserv;
            hl = strlen(h);
        } else {
            p = hostserv;
            pl = strlen(p);
        }
    }

    if (p != NULL && strchr(p, ':'))
        goto spec_err;

    if (h != NULL && host != NULL) {
        if (hl == 0
            || (hl == 1 && h[0] == '*')) {
            *host = NULL;
        } else {
            *host = OPENSSL_strndup(h, hl);
            if (*host == NULL)
                goto memerr;
        }
    }
    if (p != NULL && service != NULL) {
        if (pl == 0
            || (pl == 1 && p[0] == '*')) {
            *service = NULL;
        } else {
            *service = OPENSSL_strndup(p, pl);
            if (*service == NULL)
                goto memerr;
        }
    }

    return 1;
 amb_err:
    BIOerr(BIO_F_BIO_PARSE_HOSTSERV, BIO_R_AMBIGUOUS_HOST_OR_SERVICE);
    return 0;
 spec_err:
    BIOerr(BIO_F_BIO_PARSE_HOSTSERV, BIO_R_MALFORMED_HOST_OR_SERVICE);
    return 0;
 memerr:
    BIOerr(BIO_F_BIO_PARSE_HOSTSERV, ERR_R_MALLOC_FAILURE);
    return 0;
}

/* addrinfo_wrap is used to build our own addrinfo "chain".
 * (it has only one entry, so calling it a chain may be a stretch)
 * It should ONLY be called when getaddrinfo() and friends
 * aren't available, OR when dealing with a non IP protocol
 * family, such as AF_UNIX
 *
 * the return value is 1 on success, or 0 on failure, which
 * only happens if a memory allocation error occurred.
 */
static int addrinfo_wrap(int family, int socktype,
                         const void *where, size_t wherelen,
                         unsigned short port,
                         BIO_ADDRINFO **bai)
{
    OPENSSL_assert(bai != NULL);

    *bai = OPENSSL_zalloc(sizeof(**bai));
    if (*bai == NULL)
        return 0;

    (*bai)->bai_family = family;
    (*bai)->bai_socktype = socktype;
    if (socktype == SOCK_STREAM)
        (*bai)->bai_protocol = IPPROTO_TCP;
    if (socktype == SOCK_DGRAM)
        (*bai)->bai_protocol = IPPROTO_UDP;
#ifdef AF_UNIX
    if (family == AF_UNIX)
        (*bai)->bai_protocol = 0;
#endif
    {
        /* Magic: We know that BIO_ADDR_sockaddr_noconst is really
           just an advanced cast of BIO_ADDR* to struct sockaddr *
           by the power of union, so while it may seem that we're
           creating a memory leak here, we are not.  It will be
           all right. */
        BIO_ADDR *addr = BIO_ADDR_new();
        if (addr != NULL) {
            BIO_ADDR_rawmake(addr, family, where, wherelen, port);
            (*bai)->bai_addr = BIO_ADDR_sockaddr_noconst(addr);
        }
    }
    (*bai)->bai_next = NULL;
    if ((*bai)->bai_addr == NULL) {
        BIO_ADDRINFO_free(*bai);
        *bai = NULL;
        return 0;
    }
    return 1;
}

DEFINE_RUN_ONCE_STATIC(do_bio_lookup_init)
{
    OPENSSL_init_crypto(0, NULL);
    bio_lookup_lock = CRYPTO_THREAD_lock_new();
    return bio_lookup_lock != NULL;
}

/*-
 * BIO_lookup - look up the node and service you want to connect to.
 * @node: the node you want to connect to.
 * @service: the service you want to connect to.
 * @lookup_type: declare intent with the result, client or server.
 * @family: the address family you want to use.  Use AF_UNSPEC for any, or
 *  AF_INET, AF_INET6 or AF_UNIX.
 * @socktype: The socket type you want to use.  Can be SOCK_STREAM, SOCK_DGRAM
 *  or 0 for all.
 * @res: Storage place for the resulting list of returned addresses
 *
 * This will do a lookup of the node and service that you want to connect to.
 * It returns a linked list of different addresses you can try to connect to.
 *
 * When no longer needed you should call BIO_ADDRINFO_free() to free the result.
 *
 * The return value is 1 on success or 0 in case of error.
 */
int BIO_lookup(const char *host, const char *service,
               enum BIO_lookup_type lookup_type,
               int family, int socktype, BIO_ADDRINFO **res)
{
    int ret = 0;                 /* Assume failure */

    switch(family) {
    case AF_INET:
#ifdef AF_INET6
    case AF_INET6:
#endif
#ifdef AF_UNIX
    case AF_UNIX:
#endif
#ifdef AF_UNSPEC
    case AF_UNSPEC:
#endif
        break;
    default:
        BIOerr(BIO_F_BIO_LOOKUP, BIO_R_UNSUPPORTED_PROTOCOL_FAMILY);
        return 0;
    }

#ifdef AF_UNIX
    if (family == AF_UNIX) {
        if (addrinfo_wrap(family, socktype, host, strlen(host), 0, res))
            return 1;
        else
            BIOerr(BIO_F_BIO_LOOKUP, ERR_R_MALLOC_FAILURE);
        return 0;
    }
#endif

    if (BIO_sock_init() != 1)
        return 0;

    if (1) {
        int gai_ret = 0;
#ifdef AI_PASSIVE
        struct addrinfo hints;
        memset(&hints, 0, sizeof hints);

        hints.ai_family = family;
        hints.ai_socktype = socktype;

        if (lookup_type == BIO_LOOKUP_SERVER)
            hints.ai_flags |= AI_PASSIVE;

        /* Note that |res| SHOULD be a 'struct addrinfo **' thanks to
         * macro magic in bio_lcl.h
         */
        switch ((gai_ret = getaddrinfo(host, service, &hints, res))) {
# ifdef EAI_SYSTEM
        case EAI_SYSTEM:
            SYSerr(SYS_F_GETADDRINFO, get_last_socket_error());
            BIOerr(BIO_F_BIO_LOOKUP, ERR_R_SYS_LIB);
            break;
# endif
        case 0:
            ret = 1;             /* Success */
            break;
        default:
            BIOerr(BIO_F_BIO_LOOKUP, ERR_R_SYS_LIB);
            ERR_add_error_data(1, gai_strerror(gai_ret));
            break;
        }
    } else {
#endif
        const struct hostent *he;
/*
 * Because struct hostent is defined for 32-bit pointers only with
 * VMS C, we need to make sure that '&he_fallback_address' and
 * '&he_fallback_addresses' are 32-bit pointers
 */
#if defined(OPENSSL_SYS_VMS) && defined(__DECC)
# pragma pointer_size save
# pragma pointer_size 32
#endif
        /* Windows doesn't seem to have in_addr_t */
#ifdef OPENSSL_SYS_WINDOWS
        static uint32_t he_fallback_address;
        static const char *he_fallback_addresses[] =
            { (char *)&he_fallback_address, NULL };
#else
        static in_addr_t he_fallback_address;
        static const char *he_fallback_addresses[] =
            { (char *)&he_fallback_address, NULL };
#endif
        static const struct hostent he_fallback =
            { NULL, NULL, AF_INET, sizeof(he_fallback_address),
              (char **)&he_fallback_addresses };
#if defined(OPENSSL_SYS_VMS) && defined(__DECC)
# pragma pointer_size restore
#endif

        struct servent *se;
        /* Apparently, on WIN64, s_proto and s_port have traded places... */
#ifdef _WIN64
        struct servent se_fallback = { NULL, NULL, NULL, 0 };
#else
        struct servent se_fallback = { NULL, NULL, 0, NULL };
#endif

        if (!RUN_ONCE(&bio_lookup_init, do_bio_lookup_init)) {
            BIOerr(BIO_F_BIO_LOOKUP, ERR_R_MALLOC_FAILURE);
            ret = 0;
            goto err;
        }

        CRYPTO_THREAD_write_lock(bio_lookup_lock);
        he_fallback_address = INADDR_ANY;
        if (host == NULL) {
            he = &he_fallback;
            switch(lookup_type) {
            case BIO_LOOKUP_CLIENT:
                he_fallback_address = INADDR_LOOPBACK;
                break;
            case BIO_LOOKUP_SERVER:
                he_fallback_address = INADDR_ANY;
                break;
            default:
                OPENSSL_assert(("We forgot to handle a lookup type!" == 0));
                break;
            }
        } else {
            he = gethostbyname(host);

            if (he == NULL) {
#ifndef OPENSSL_SYS_WINDOWS
                BIOerr(BIO_F_BIO_LOOKUP, ERR_R_SYS_LIB);
                ERR_add_error_data(1, hstrerror(h_errno));
#else
                SYSerr(SYS_F_GETHOSTBYNAME, WSAGetLastError());
#endif
                ret = 0;
                goto err;
            }
        }

        if (service == NULL) {
            se_fallback.s_port = 0;
            se_fallback.s_proto = NULL;
            se = &se_fallback;
        } else {
            char *endp = NULL;
            long portnum = strtol(service, &endp, 10);

/*
 * Because struct servent is defined for 32-bit pointers only with
 * VMS C, we need to make sure that 'proto' is a 32-bit pointer.
 */
#if defined(OPENSSL_SYS_VMS) && defined(__DECC)
# pragma pointer_size save
# pragma pointer_size 32
#endif
            char *proto = NULL;
#if defined(OPENSSL_SYS_VMS) && defined(__DECC)
# pragma pointer_size restore
#endif

            switch (socktype) {
            case SOCK_STREAM:
                proto = "tcp";
                break;
            case SOCK_DGRAM:
                proto = "udp";
                break;
            }

            if (endp != service && *endp == '\0'
                    && portnum > 0 && portnum < 65536) {
                se_fallback.s_port = htons(portnum);
                se_fallback.s_proto = proto;
                se = &se_fallback;
            } else if (endp == service) {
                se = getservbyname(service, proto);

                if (se == NULL) {
#ifndef OPENSSL_SYS_WINDOWS
                    BIOerr(BIO_F_BIO_LOOKUP, ERR_R_SYS_LIB);
                    ERR_add_error_data(1, hstrerror(h_errno));
#else
                    SYSerr(SYS_F_GETSERVBYNAME, WSAGetLastError());
#endif
                    goto err;
                }
            } else {
                BIOerr(BIO_F_BIO_LOOKUP, BIO_R_MALFORMED_HOST_OR_SERVICE);
                goto err;
            }
        }

        *res = NULL;

        {
/*
 * Because hostent::h_addr_list is an array of 32-bit pointers with VMS C,
 * we must make sure our iterator designates the same element type, hence
 * the pointer size dance.
 */
#if defined(OPENSSL_SYS_VMS) && defined(__DECC)
# pragma pointer_size save
# pragma pointer_size 32
#endif
            char **addrlistp;
#if defined(OPENSSL_SYS_VMS) && defined(__DECC)
# pragma pointer_size restore
#endif
            size_t addresses;
            BIO_ADDRINFO *tmp_bai = NULL;

            /* The easiest way to create a linked list from an
               array is to start from the back */
            for(addrlistp = he->h_addr_list; *addrlistp != NULL;
                addrlistp++)
                ;

            for(addresses = addrlistp - he->h_addr_list;
                addrlistp--, addresses-- > 0; ) {
                if (!addrinfo_wrap(he->h_addrtype, socktype,
                                   *addrlistp, he->h_length,
                                   se->s_port, &tmp_bai))
                    goto addrinfo_malloc_err;
                tmp_bai->bai_next = *res;
                *res = tmp_bai;
                continue;
             addrinfo_malloc_err:
                BIO_ADDRINFO_free(*res);
                *res = NULL;
                BIOerr(BIO_F_BIO_LOOKUP, ERR_R_MALLOC_FAILURE);
                ret = 0;
                goto err;
            }

            ret = 1;
        }
     err:
        CRYPTO_THREAD_unlock(bio_lookup_lock);
    }

    return ret;
}

#endif /* OPENSSL_NO_SOCK */
