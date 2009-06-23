/** gtping/ei_generic.c
 *
 *  By Thomas Habets <thomas@habets.pp.se> 2009
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

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
