#include "randombytes.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

/* lazy unsafe emulation of SUPERCOP's randombytes() */
void randombytes (unsigned char *x, unsigned long long xlen) {
    static int fd = -1;
    if (fd == -1) fd = open ("/dev/urandom", O_RDONLY);
    read (fd, x, xlen);
}
