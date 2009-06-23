/** gtping/ei_errqueue.c
 *
 *  By Thomas Habets <thomas@habets.pp.se> 2009
 *
 * Handle 
 *
 * Systems known to use this code: Linux, FreeBSD
 *
 * FreeBSD doesn't seem to have IP_RECVTOS or equivalent, so just TTL.
 */
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
 *
 */
static void
handleRecvErrSEE(struct sock_extended_err *see,
                 int returnttl,
                 const char *tos)
{
	int isicmp = 0;

	if (!see) {
		fprintf(stderr, "%s: Error, but no error info\n", argv0);
		return;
	}

	/* print "From ...: */
        if (see->ee_origin == SO_EE_ORIGIN_LOCAL) {
		printf("From local system: ");
	} else {
		struct sockaddr *offender = SO_EE_OFFENDER(see);
		char abuf[NI_MAXHOST];
		int err;
		
		if (offender->sa_family == AF_UNSPEC) {
			printf("From <unknown>: ");
		} else if ((err = getnameinfo(offender,
					      sizeof(struct sockaddr_storage),
					      abuf, NI_MAXHOST,
					      NULL, 0,
					      NI_NUMERICHOST))) {
			fprintf(stderr, "%s: getnameinfo(): %s\n",
				argv0, gai_strerror(err));
                        printf("From <unknown>");
                        if (tos) {
                                printf(" %s", tos);
                        }
                        printf(": ");
		} else {
                        printf("From %s", abuf);
                        if (tos) {
                                printf(" %s", tos);
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
		break;
	case EMSGSIZE:
		printf("PMTU %d", see->ee_info);
		break;
	case EPROTO:
		printf("Protocol error");
		break;
	case ENETUNREACH:
		printf("Network unreachable");
		break;
	case EACCES:
		printf("Access denied");
		break;
	case EHOSTUNREACH:
		if (isicmp && see->ee_type == 11 && see->ee_code == 0) {
                        printf("Time to live exceeded");
                } else {
			printf("Host unreachable");
		}
		break;
	default:
		printf("%s", strerror(see->ee_errno));
		break;
	}
        icmpError++;
	if (options.verbose && (0 < returnttl)) {
		printf(". return TTL: %d.", returnttl);
	}
	printf("\n");
}

/**
 *
 */
void
handleRecvErr(int fd, const char *reason)
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

	/* Find ttl */
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
                        case IPV6_TCLASS: {
                                char scratch[128];
                                free(tos);
                                tos = malloc(128);
                                snprintf(tos, 128,
                                         "ToS=%s",
                                         tos2String(*(unsigned char*)
                                                    CMSG_DATA(cmsg),
                                                    scratch,
                                                    sizeof(scratch)));
                                break;
                        }
			case IP_RECVERR:
			case IPV6_RECVERR:
				handleRecvErrSEE((struct sock_extended_err*)
						 CMSG_DATA(cmsg),
						 returnttl,
                                                 tos);
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
}

