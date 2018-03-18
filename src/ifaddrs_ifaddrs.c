/** gtping/ifaddrs_ifaddrs.c
 *
 *  By Thomas Habets <thomas@habets.se> 2010
 *
 * Systems known to use this code: Linux, OpenBSD
 *
 * getIfAddrs(dest): return a struct addrinfo linked list of local addresses
 * that can be used when trying to connect to 'dest'.
 * Interface name must match options.source.
 *
 * Return 0 on error (or no matches).
 *
 * Caller frees using freeaddrinfo()
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "gtping.h"

/**
 *
 */
struct addrinfo*
getIfAddrs(const struct addrinfo *dest)
{
        struct addrinfo *ret = 0;
        struct addrinfo *curout = 0;
        struct addrinfo *newout;
        struct ifaddrs *ifa = NULL;
        struct ifaddrs *curifa;
        int err;

        if (!options.source) {
                return 0;
        }

        err = getifaddrs(&ifa);
        if (err != 0) {
                return ret;
        }
        for (curifa = ifa;
             curifa;
             curifa = curifa->ifa_next) {
                if (curifa->ifa_addr->sa_family != dest->ai_family) {
                        continue;
                }
                if (options.verbose > 1) {
                        char host[NI_MAXHOST];
                        int l;
                        printf("Found iface %s: ", curifa->ifa_name);
                        l = sockaddrlen(dest->ai_family);
                        if ((err = getnameinfo(curifa->ifa_addr,
                                               l,
                                               host, sizeof(host),
                                               NULL, 0,
                                               NI_NUMERICHOST))) {
                                printf("\n");
                                fprintf(stderr,
                                        "%s: getnameinfo(): %s\n",
                                        argv0,
                                        gai_strerror(err));
                        } else {
                                printf("%s\n", host);
                        }
                }
                if (strcasecmp(curifa->ifa_name, options.source)) {
                        continue;
                }

                newout = malloc(sizeof(struct addrinfo));
                if (!newout) {
                        fprintf(stderr,
                                "%s: malloc(): %s\n",
                                argv0,
                                strerror(errno));
                        continue;
                }

                memset(newout, 0, sizeof(struct addrinfo));
                newout->ai_family = dest->ai_family;
                newout->ai_socktype = dest->ai_socktype;
                newout->ai_protocol = dest->ai_protocol;
                newout->ai_addrlen = sockaddrlen(newout->ai_family);
                if (!newout->ai_addrlen) {
                        free(newout);
                        continue;
                }
                newout->ai_addr = malloc(newout->ai_addrlen);
                if (!newout->ai_addr) {
                        fprintf(stderr,
                                "%s: malloc(): %s\n",
                                argv0,
                                strerror(errno));
                        free(newout);
                        continue;
                }
                memcpy(newout->ai_addr,
                       curifa->ifa_addr,
                       newout->ai_addrlen);

                if (ret) {
                        curout->ai_next = newout;
                } else {
                        ret = newout;
                }
                curout = newout;
        }
        return ret;
}

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
