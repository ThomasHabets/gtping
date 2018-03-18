/** gtping/dorecv_cmsg.c
 *
 *  By Thomas Habets <thomas@habets.se> 2009
 *
 * This provides the recv*() wrapper for systems that export ToS and TTL
 * data via msghdr.msg_control
 *
 * Systems known to use this code: Linux, FreeBSD, Solaris.
 *
 * FreeBSD and Solaris don't seem to have IP_RECVTOS or equivalent, so
 * just TTL for them.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* For Solaris we need some defines */
#if defined (__SVR4) && defined (__sun)
/* SUS (XPG4v2) */
# define _XOPEN_SOURCE
# define _XOPEN_SOURCE_EXTENDED 1
/* IPV6_TCLASS needs __EXTENSIONS__ */
# define __EXTENSIONS__ 1
#endif

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>

#include <sys/types.h>
#include <sys/socket.h>

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#include "gtping.h"

#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif

#ifndef SOL_IPV6
#define SOL_IPV6 IPPROTO_IPV6
#endif

/**
 * 
 */
ssize_t
doRecv(int sock, void *data, size_t len, int *ttl, int *tos)
{
        struct msghdr msgh;
        struct cmsghdr *cmsg;
        struct iovec iov;
        char msgcontrol[10000];
        ssize_t n;

	if (options.verbose > 2) {
		fprintf(stderr, "%s: doRecv[cmsg]()\n", argv0);
	}

        *ttl = -1;
        *tos = -1;

        memset(&iov, 0, sizeof(iov));
        iov.iov_base = data;
        iov.iov_len = len;

        memset(&msgh, 0, sizeof(msgh));
        
        msgh.msg_iov = &iov;
        msgh.msg_iovlen = 1;
        msgh.msg_control = msgcontrol;
        msgh.msg_controllen = sizeof(msgcontrol);

        n = recvmsg(sock, &msgh, MSG_WAITALL);

        for (cmsg = CMSG_FIRSTHDR(&msgh);
             (0 < n) && (cmsg != NULL);
             cmsg = CMSG_NXTHDR(&msgh,cmsg)) {
                if (cmsg->cmsg_level == SOL_IP
                    || cmsg->cmsg_level == SOL_IPV6) {
                        switch(cmsg->cmsg_type) {
                        case IP_TOS:
#ifdef IP_RECVTOS
                        case IP_RECVTOS:
#endif
#ifdef IPV6_TCLASS
                        case IPV6_TCLASS:
#endif
#ifdef IPV6_RECVTCLASS
                        case IPV6_RECVTCLASS:
#endif
                                if (tos) {
                                        *tos=*(unsigned char*)CMSG_DATA(cmsg);
                                }
                                break;
                        case IP_TTL:
                        case IP_RECVTTL:
                        case IPV6_HOPLIMIT:
#ifdef IPV6_RECVHOPLIMIT
                        case IPV6_RECVHOPLIMIT:
#endif
                                if (ttl) {
                                        *ttl=*(unsigned char*)CMSG_DATA(cmsg);
                                }
                                break;
                        default:
                                fprintf(stderr,
                                        "%s: Unknown cmsg: %d\n",
                                        argv0, cmsg->cmsg_type);
                        }
                }
        }

	if (options.verbose > 2) {
		fprintf(stderr, "%s: doRecv[cmsg]() = %d\n", argv0, (int)n);
	}

        return n;
}

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
