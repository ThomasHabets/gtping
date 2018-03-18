/** gtping/ei_generic.c
 *
 *  By Thomas Habets <thomas@habets.se> 2009
 *
 * Without MSG_ERRQUEUE we don't know the details of what happened, so not
 * much is extracted in this file.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "gtping.h"

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
errInspectionPrintSummary()
{
}

/**
 * return:
 *      0 if no error
 *      1 if TTL exceeded
 *     >1 if other icmp-like error
 */
int
handleRecvErr(int fd, const char *reason, double lastPingTime)
{
        fd = fd;
        if (reason) {
                printf("%s\n", reason);
        } else {
                printf("Destination unreachable "
                       "(closed, filtered or TTL exceeded)\n");
        }
        return 0;
}

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
