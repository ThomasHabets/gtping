/** gtping/ei_other.c
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef __linux__
/* ei_linux.c */
#else

#include <stdio.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

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
