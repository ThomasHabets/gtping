/** gtping/dorecv_generic.c
 *
 *  By Thomas Habets <thomas@habets.pp.se> 2009
 *
 * This provides the recv*() wrapper for systems that don't seem to export
 * ToS or TTL on a packet-by-packet basis at all.
 *
 * Systems known to use this code: Solaris
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "gtping.h"

/**
 * 
 */
ssize_t
doRecv(int sock, void *data, size_t len, int *ttl, int *tos)
{
        *ttl = -1;
        *tos = -1;
        return recv(sock, data, len, 0);
}
