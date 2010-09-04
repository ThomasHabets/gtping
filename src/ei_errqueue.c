/** gtping/ei_errqueue.c
 *
 *  By Thomas Habets <thomas@habets.pp.se> 2009
 *
 * Handle icmp errors delivered via recvmsg() with MSG_ERRQUEUE.
 *
 * Systems known to use this code: Linux
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <netdb.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "getaddrinfo.h"

#include "gtping.h"

/* linux-specific stuff */
#ifdef __linux__
# define __u8 uint8_t
# define __u32 uint32_t
# include <linux/errqueue.h>
# undef __u8
# undef __u32
 /* Sometimes these constants are wrong in the headers, so we check both the
  * ones in the header files and the ones I found are correct.
  * from /usr/include/linux/in6.h */
# define REAL_IPV6_RECVHOPLIMIT       51
# define REAL_IPV6_HOPLIMIT           52
#endif

static unsigned int icmpError = 0;

void
errInspectionPrintSummary()
{
        printf(", %u ICMP error", icmpError);
}

/**
 *
 */
void
errInspectionInit(int fd, const struct addrinfo *addrs)
{
	if (addrs->ai_family == AF_INET) {
		int on = 1;
		if (setsockopt(fd, SOL_IP, IP_RECVERR, &on, sizeof(on))) {
			fprintf(stderr,
				"%s: setsockopt(%d, SOL_IP, IP_RECVERR, on): "
				"%s\n", argv0, fd, strerror(errno));
		}
	}
	if (addrs->ai_family == AF_INET6) {
		int on = 1;
		if (setsockopt(fd,
			       SOL_IPV6,
			       IPV6_RECVERR,
			       &on,
			       sizeof(on))) {
			fprintf(stderr,
				"%s: setsockopt(%d, SOL_IPV6, "
				"IPV6_RECVERR, on): %s\n",
				argv0, fd, strerror(errno));
		}

		/* sometimes needed because IPV6_RECVHOPLIMIT can be bad */
		if (setsockopt(fd,
			       SOL_IPV6,
			       REAL_IPV6_RECVHOPLIMIT,
			       &on,
			       sizeof(on))) {
			fprintf(stderr,
				"%s: setsockopt(%d, SOL_IPV6, "
				"IPV6_RECVHOPLIMIT, on): %s\n",
				argv0, fd, strerror(errno));
		}
	}
}

/**
 * return:
 *      0 if no error
 *      1 if TTL exceeded
 *     >1 if other icmp-like error
 */
static int
handleRecvErrSEE(struct sock_extended_err *see,
                 int returnttl,
                 const char *tos,
                 double lastPingTime)
{
	int isicmp = 0;
        int ret = 0;

	if (!see) {
		fprintf(stderr, "%s: Error, but no error info\n", argv0);
		return ret;
	}

	/* print "From ...: */
        if (see->ee_origin == SO_EE_ORIGIN_LOCAL) {
		printf("From local system: ");
	} else {
		struct sockaddr *offender = SO_EE_OFFENDER(see);
		char abuf[NI_MAXHOST];
		int err;
		
		if (offender->sa_family == AF_UNSPEC) {
                        if (!options.traceroute) { printf("From "); }
                        printf("<unknown>: ");
		} else if ((err = getnameinfo(offender,
					      sizeof(struct sockaddr_storage),
					      abuf, NI_MAXHOST,
					      NULL, 0,
					      NI_NUMERICHOST))) {
			fprintf(stderr, "%s: getnameinfo(): %s\n",
				argv0, gai_strerror(err));
                        if (!options.traceroute) { printf("From "); }
                        printf("<unknown>");
                        if (tos) {
                                printf(" %s", tos);
                        }
                        if (returnttl > 0) {
                                printf(" ttl=%d", returnttl);
                        }
                        printf(": ");
		} else {
                        if (!options.traceroute) { printf("From "); }
                        printf("%s", abuf);
                        if (tos) {
                                printf(" %s", tos);
                        }
                        if (returnttl > 0) {
                                printf(" ttl=%d", returnttl);
                        }
                        if (lastPingTime) {
                                printf(" time=%.2f ms",
                                       1000*(monotonic_get_dbl()-lastPingTime));
                        }
                        printf(": ");
		}
	}
	
	if (see->ee_origin == SO_EE_ORIGIN_ICMP6
	    || see->ee_origin == SO_EE_ORIGIN_ICMP) {
		isicmp = 1;
	}

	/* Print error message */
	switch (see->ee_errno) {
	case ECONNREFUSED:
		printf("Port closed");
                ret = 2;
		break;
	case EMSGSIZE:
		printf("PMTU %d", see->ee_info);
                ret = 2;
		break;
	case EPROTO:
		printf("Protocol error");
                ret = 2;
		break;
	case ENETUNREACH:
		printf("Network unreachable");
                ret = 2;
		break;
	case EACCES:
		printf("Access denied");
                ret = 2;
		break;
	case EHOSTUNREACH:
		if (isicmp && see->ee_type == 11 && see->ee_code == 0) {
                        printf("TTL exceeded");
                        ret = 1;
                } else {
			printf("Host unreachable");
                        ret = 2;
		}
		break;
	default:
		printf("%s", strerror(see->ee_errno));
                ret = 2;
		break;
	}
        icmpError++;
	if (options.verbose && (0 < returnttl)) {
		printf(". return TTL: %d.", returnttl);
	}
	printf("\n");
        return ret;
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
	struct msghdr msg;
	struct cmsghdr *cmsg;
	char cbuf[512];
	char buf[5120];
	struct sockaddr_storage sa;
	struct iovec iov;
	int n;
	int returnttl = -1;
        char *tos = 0;
        int ret = 0;

        /* ignore reason, we know better */
        reason = reason;

	/* get error data */
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (char*)&sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	
	if (0 > (n = recvmsg(fd, &msg, MSG_ERRQUEUE))) {
		if (errno == EAGAIN) {
                        goto errout;
		}
		fprintf(stderr, "%s: recvmsg(%d, ..., MSG_ERRQUEUE): %s\n",
			argv0, fd, strerror(errno));
                goto errout;
	}

	/* First find ttl */
	for (cmsg = CMSG_FIRSTHDR(&msg);
	     cmsg;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if ((cmsg->cmsg_level == SOL_IP
		     || cmsg->cmsg_level == SOL_IPV6)
		    && (cmsg->cmsg_type == IP_TTL
			|| cmsg->cmsg_type == IPV6_HOPLIMIT
			|| cmsg->cmsg_type == REAL_IPV6_HOPLIMIT
			)) {
			returnttl = *(int*)CMSG_DATA(cmsg);
		}
	}
	for (cmsg = CMSG_FIRSTHDR(&msg);
	     cmsg;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_level == SOL_IP
		    || cmsg->cmsg_level == SOL_IPV6) {
			switch(cmsg->cmsg_type) {
                        case IP_TOS:
#ifdef IPV6_TCLASS
                        case IPV6_TCLASS:
#endif
                                {
                                        char scratch[128];
                                        free(tos);
                                        if (!(tos = malloc(128))) {
                                                fprintf(stderr,
                                                        "%s: "
                                                        "malloc(128): %s\n",
                                                        argv0,
                                                        strerror(errno));
                                                goto errout;
                                        }
                                        snprintf(tos, 128,
                                                 "%s",
                                                 tos2String(*(unsigned char*)
                                                            CMSG_DATA(cmsg),
                                                            scratch,
                                                            sizeof(scratch)));
                                        break;
                                }
			case IP_RECVERR:
			case IPV6_RECVERR:
                                ret = handleRecvErrSEE((struct
                                                        sock_extended_err*)
                                                       CMSG_DATA(cmsg),
                                                       returnttl,
                                                       tos,
                                                       lastPingTime);
				break;
			case IP_TTL:
#if IPV6_HOPLIMIT != REAL_IPV6_HOPLIMIT
			case REAL_IPV6_HOPLIMIT:
#endif
			case IPV6_HOPLIMIT:
				/* ignore */
				break;
			default:
				fprintf(stderr,
					"%s: Got cmsg type: %d",
					argv0,
					cmsg->cmsg_type);
				if (0 < returnttl) {
					fprintf(stderr, ". Return TTL: %d",
						returnttl);
				}
				printf("\n");
			}

		}
	}
 errout:;
        free(tos);
        return ret;
}

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
