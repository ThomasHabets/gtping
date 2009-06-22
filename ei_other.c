/** gtping/ei_other.c
 *
 */
#ifdef __linux__
/* ei_linux.c */
#else

#include <stdio.h>

#include "getaddrinfo.h"

/**
 *
 */
void
errInspectionInit(int fd, const struct addrinfo *addrs)
{
}

/**
 *
 */
void
handleRecvErr(int fd, const char *reason)
{
        fd = fd;
        if (reason) {
                printf("%s\n", reason);
        } else {
                printf("Destination unreachable "
                       "(closed, filtered or TTL exceeded)\n");
        }
}
#endif
