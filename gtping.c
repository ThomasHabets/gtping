/** gtping/gtping.c
 *
 * GTP Ping
 *
 * By Thomas Habets <thomas@habets.pp.se> 2008-2009
 *
 * Send GTP Ping and time the reply.
 *
 *
 */
/*
 *  Copyright (C) 2008-2009 Thomas Habets <thomas@habets.pp.se>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
#include <math.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif

#ifndef SOL_IPV6
#define SOL_IPV6 IPPROTO_IPV6
#endif


/**
 * In-depth error handling only implemented for linux so far
 */
#ifdef __linux__
# define __u8 unsigned char
# define __u32 unsigned int
# include <linux/errqueue.h>
# undef __u8
# undef __u32
# define ERR_INSPECTION 1
#else
# define ERR_INSPECTION 0
#endif

/**
 * Sometimes these constants are wrong in the headers, so we check both the
 * ones in the header files and the ones I found are correct.
 */
#ifdef __linux__
/* from /usr/include/linux/in6.h */
# define REAL_IPV6_RECVHOPLIMIT       51
# define REAL_IPV6_HOPLIMIT           52
#else
/* non-Linux */
# define REAL_IPV6_RECVHOPLIMIT IPV6_RECVHOPLIMIT
# define REAL_IPV6_HOPLIMIT IPV6_HOPLIMIT
#endif

/* pings older than TRACKPINGS_SIZE * the_wait_time are ignored.
 * They are old and are considered lost.
 */
#define TRACKPINGS_SIZE 1000

/* For those OSs that don't read RFC3493, even though their manpage
 * points to it. */
#ifndef AI_ADDRCONFIG
# define AI_ADDRCONFIG 0
#endif

/* GTP packet as used with GTP Echo */
#pragma pack(1)
struct GtpEcho {
        char flags;
        char msg;
        uint16_t len;   
        uint32_t teid;
        uint16_t seq;
        char npdu;
        char next;
};
#pragma pack()

/**
 * options
 */
#define DEFAULT_PORT "2123"
#define DEFAULT_VERBOSE 0
#define DEFAULT_INTERVAL 1.0
#define DEFAULT_WAIT 10.0
struct Options {
        const char *port;
        int verbose;
        int flood;
        double interval;
        double wait;
        int autowait;
        unsigned int count;
        uint32_t teid;
        const char *target;  /* what is on the cmdline */
        char *targetip;      /* IPv* address string */
        int ttl;
        int tos;
};

static const char *version = PACKAGE_VERSION;

static volatile int time_to_die = 0;
static unsigned int curSeq = 0;
static double startTime;
static double sendTimes[TRACKPINGS_SIZE]; /* RTT data*/
static int gotIt[TRACKPINGS_SIZE];        /* duplicate-check scratchpad  */
static unsigned int totalTimeCount = 0;
static double totalTime = 0;
static double totalTimeSquared = 0;
static double totalMin = -1;
static double totalMax = -1;
static unsigned int dups = 0;
static unsigned int reorder = 0;
static unsigned int highestSeq = 0;
#if ERR_INSPECTION
static unsigned int icmperror = 0;
#endif
static unsigned int connectionRefused = 0;

/* from cmdline */
static const char *argv0 = 0;
static struct Options options = {
        port: DEFAULT_PORT,
        verbose: DEFAULT_VERBOSE,
        
        flood: 0,

        /* if still <0, set to DEFAULT_INTERVAL.
         * set this way to make -f work with -i  */
        interval: -1, 
        
        wait: -1,    /* -w */
        autowait: 0,

        count: 0,    /* -c */
        target: 0,   /* arg */
        targetip: 0, /* resolved arg */
        ttl: -1,     /* -T */
        tos: -1,     /* -Q (not implemented yet) */
        teid: 0,     /* -t */
};

static double gettimeofday_dbl();

/**
 *
 */
static void
sigint(int unused)
{
	unused = unused;
	time_to_die = 1;
}

/**
 * Create socket and "connect" it to target
 * allocates and sets options.targetip
 *
 * return fd, or <0 (-errno) on error
 */
static int
setupSocket()
{
	int fd = -1;
	int err = 0;
	struct addrinfo *addrs = 0;
	struct addrinfo hints;

	if (options.verbose > 2) {
		fprintf(stderr, "%s: setupSocket(%s)\n",
			argv0, options.target);
	}
	if (!(options.targetip = malloc(NI_MAXHOST))) {
		err = errno;
		fprintf(stderr, "%s: malloc(NI_MAXHOST): %s\n",
			argv0, strerror(err));
		goto errout;
	}

	/* resolve to sockaddr */
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_ADDRCONFIG;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	if (0 > (err = getaddrinfo(options.target,
				   options.port,
				   &hints,
				   &addrs))) {
		int gai_err;
		gai_err = err;
		if (gai_err == EAI_SYSTEM) {
			err = errno;
		} else {
			err = EINVAL;
		}
		if (gai_err == EAI_NONAME) {
			fprintf(stderr, "%s: unknown host %s\n",
				argv0, options.target);
			err = EINVAL;
			goto errout;
		}
		fprintf(stderr, "%s: getaddrinfo(): %s\n",
			argv0, gai_strerror(gai_err));
		goto errout;
	}

	/* get ip address string options.targetip */
	if ((err = getnameinfo(addrs->ai_addr,
			       addrs->ai_addrlen,
			       options.targetip,
			       NI_MAXHOST,
			       NULL, 0,
			       NI_NUMERICHOST))) {
		int gai_err;
		gai_err = err;
		if (gai_err == EAI_SYSTEM) {
			err = errno;
		} else {
			err = EINVAL;
		}
		fprintf(stderr, "%s: getnameinfo(): %s\n",
			argv0,	gai_strerror(gai_err));
		goto errout;
	}
	if (options.verbose > 1) {
		fprintf(stderr, "%s: target=<%s> targetip=<%s>\n",
			argv0,
			options.target,
			options.targetip);
	}

	/* socket() */
	if (0 > (fd = socket(addrs->ai_family,
			     addrs->ai_socktype,
			     addrs->ai_protocol))) {
		err = errno;
		fprintf(stderr, "%s: socket(%d, %d, %d): %s\n",
			argv0,
			addrs->ai_family,
			addrs->ai_socktype,
			addrs->ai_protocol,
			strerror(err));
		goto errout;
	}

#if ERR_INSPECTION
	if (addrs->ai_family == AF_INET) {
		int on = 1;
		if (setsockopt(fd, SOL_IP, IP_RECVERR, &on, sizeof(on))) {
			fprintf(stderr,
				"%s: setsockopt(%d, SOL_IP, IP_RECVERR, on): "
				"%s\n", argv0, fd, strerror(errno));
		}
		if (setsockopt(fd,
			       SOL_IP,
			       IP_RECVTTL,
			       &on,
			       sizeof(on))) {
			fprintf(stderr,
				"%s: setsockopt(%d, SOL_IP, "
				"IP_RECVTTL, on): %s\n",
				argv0, fd, strerror(errno));
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
#endif
	if (addrs->ai_family == AF_INET) {
		if (options.ttl > 0) {
			if (setsockopt(fd,
				       SOL_IP,
				       IP_TTL,
				       &options.ttl,
				       sizeof(options.ttl))) {
				fprintf(stderr,
					"%s: setsockopt(%d, SOL_IP, IP_TTL, "
					"%d): %s\n", argv0, fd, options.ttl,
					strerror(errno));
			}
		}
		if (options.tos >= 0) {
			if (setsockopt(fd,
				       SOL_IP,
				       IP_TOS,
				       &options.tos,
				       sizeof(options.tos))) {
				fprintf(stderr,
					"%s: setsockopt(%d, SOL_IP, IP_TOS, "
					"%d): %s\n", argv0, fd, options.tos,
					strerror(errno));
			}
		}
	}
	if (addrs->ai_family == AF_INET6) {
		if (options.ttl > 0) {
			if (setsockopt(fd,
				       SOL_IPV6,
				       IPV6_HOPLIMIT,
				       &options.ttl,
				       sizeof(options.ttl))) {
				fprintf(stderr,
					"%s: setsockopt(%d, SOL_IPV6, "
					"IPV6_HOPLIMIT, %d): %s\n",
					argv0, fd, options.ttl,
					strerror(errno));
			}
		}
                /* FIXME: set tos */
	}

	/* connect() */
	if (connect(fd,
		    addrs->ai_addr,
		    addrs->ai_addrlen)) {
		err = errno;
		fprintf(stderr, "%s: connect(%d, ...): %s\n",
			argv0, fd, strerror(err));
		close(fd);
		goto errout;
	}

	freeaddrinfo(addrs);
	return fd;
 errout:
	if (addrs) {
		freeaddrinfo(addrs);
		addrs = 0;
	}
	if (options.targetip) {
		free(options.targetip);
		options.targetip = 0;
	}
	if (err == 0) {
		err = -EINVAL;
	}
	if (fd >= 0) {
		close(fd);
		fd = -1;
	}
	if (err > 0) {
		err = -err;
	}
	return err;
}

/**
 * return 0 on succes, <0 on fail (nothing sent), >0 on sent, but something
 * failed (do increment sent counter)
 */
static int
sendEcho(int fd, int seq)
{
	int err;
	struct GtpEcho gtp;

	if (options.verbose > 2) {
		fprintf(stderr, "%s: sendEcho(%d, %d)\n", argv0, fd, seq);
	}

	if (options.verbose > 1) {
		fprintf(stderr,	"%s: Sending GTP ping with seq=%d size %d\n",
			argv0, curSeq, sizeof(struct GtpEcho));
	}

	memset(&gtp, 0, sizeof(struct GtpEcho));
	gtp.flags = 0x32;
	gtp.msg = 0x01;
	gtp.len = htons(4);
	gtp.teid = htonl(options.teid);
	gtp.seq = htons(seq);
	gtp.npdu = 0x00;
	gtp.next = 0x00;

        sendTimes[seq % TRACKPINGS_SIZE] = gettimeofday_dbl();
        gotIt[seq % TRACKPINGS_SIZE] = 0;

	if (sizeof(struct GtpEcho) != send(fd, (void*)&gtp,
					   sizeof(struct GtpEcho), 0)) {
		err = errno;
		if (err == ECONNREFUSED) {
                        printf("Connection refused\n");
                        connectionRefused++;
			return err;
		}
                fprintf(stderr, "%s: send(%d, ...): %s\n",
                        argv0, fd, strerror(errno));
		return -err;
	}
	return 0;
}

#if ERR_INSPECTION
static void
handleRecvErrSEE(struct sock_extended_err *see, int returnttl)
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
			printf("From <unknown>: ");
		} else {
			printf("From %s: ", abuf);
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
        icmperror++;
	if (options.verbose && (0 < returnttl)) {
		printf(". return TTL: %d.", returnttl);
	}
	printf("\n");
}

static void
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
			return;
		}
		fprintf(stderr, "%s: recvmsg(%d, ..., MSG_ERRQUEUE): %s\n",
			argv0, fd, strerror(errno));
		return;
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
			case IP_RECVERR:
			case IPV6_RECVERR:
				handleRecvErrSEE((struct sock_extended_err*)
						 CMSG_DATA(cmsg),
						 returnttl);
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
}

#else
static void
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

/**
 * return 0 on success/got reply,
 *        <0 on fail. Errno returned.
 *        >0 on success, but no packet (EINTR or dup packet)
 */
static int
recvEchoReply(int fd)
{
	int err;
	struct GtpEcho gtp;
	int n;
	double now;
	char lag[128];
        int isDup = 0;
        int isReorder = 0;

	if (options.verbose > 2) {
		fprintf(stderr, "%s: recvEchoReply()\n", argv0);
	}

	now = gettimeofday_dbl();
	
	memset(&gtp, 0, sizeof(struct GtpEcho));

	if (0 > (n = recv(fd, (void*)&gtp, sizeof(struct GtpEcho), 0))) {
		switch(errno) {
                case ECONNREFUSED:
                        connectionRefused++;
			handleRecvErr(fd, "Port closed");
                        return 1;
		case EINTR:
			return 1;
                case EHOSTUNREACH:
			handleRecvErr(fd, "Host unreachable or TTL exceeded");
                        return 1;
		default:
			err = errno;
			fprintf(stderr, "%s: recv(%d, ...): %s\n",
				argv0, fd, strerror(errno));
			return err;
		}
	}

	/* replies use teid 0 */
	if (0) {
		if (gtp.teid != htonl(options.teid)) {
			return 1;
		}
	}
	if (gtp.msg != 0x02) {
		fprintf(stderr,
			"%s: Got non-EchoReply type of msg (type: %d)\n",
			argv0, gtp.msg);
		return 0;
	}

        if (curSeq - htons(gtp.seq) >= TRACKPINGS_SIZE) {
		strcpy(lag, "Inf");
	} else {
                int pos = htons(gtp.seq) % TRACKPINGS_SIZE;
                double lagf = now - sendTimes[pos];
                if (gotIt[pos]) {
                        isDup = 1;
                }
                gotIt[pos]++;
		snprintf(lag, sizeof(lag), "%.2f ms", 1000 * lagf);
                if (!isDup) {
                        totalTime += lagf;
                        totalTimeSquared += lagf * lagf;
                        totalTimeCount++;
                        if ((0 > totalMin) || (lagf < totalMin)) {
                                totalMin = lagf;
                        }
                        if ((0 > totalMax) || (lagf > totalMax)) {
                                totalMax = lagf;
                        }
                }
                if (options.autowait) {
                        options.wait = 2 * (totalTime / totalTimeCount);
                        if (options.verbose) {
                                fprintf(stderr,
                                        "%s: Adjusting waittime to %.6f\n",
                                        argv0, options.wait);
                        }
                }
	}

        /* detect packet reordering */
        if (!isDup) {
                if (highestSeq > htons(gtp.seq)) {
                        reorder++;
                        isReorder = 1;
                } else {
                        highestSeq = htons(gtp.seq);
                }
        }

        if (options.flood) {
                if (!isDup) {
                        printf("\b \b");
                }
        } else {
                printf("%u bytes from %s: seq=%u time=%s%s%s\n",
                       n,
                       options.targetip,
                       htons(gtp.seq),
                       lag,
                       isDup ? " (DUP)" : "",
                       isReorder ? " (out of order)" : "");
        }
        if (isDup) {
                dups++;
        }
	return isDup;
}

/**
 *
 */
static double
tv2dbl(const struct timeval *tv)
{
        return tv->tv_sec + tv->tv_usec / 1000000.0;
}

/**
 *
 */
static double
gettimeofday_dbl()
{
	struct timeval tv;
        if (gettimeofday(&tv, NULL)) {
		fprintf(stderr,"%s: gettimeofday(): %s\n",
			argv0,strerror(errno));
		return time(0);
	}
	return tv2dbl(&tv);
}

/**
 * return value is sent directly to return value of main()
 */
static int
mainloop(int fd)
{
	unsigned sent = 0;
	unsigned recvd = 0;
	double lastping = 0;
	double curping;
        double lastRecv = 0;

	if (options.verbose > 2) {
		fprintf(stderr, "%s: mainloop(%d)\n", argv0, fd);
	}

	startTime = gettimeofday_dbl();

	printf("GTPING %s (%s) %u bytes of data.\n",
	       options.target,
	       options.targetip,
	       (int)sizeof(struct GtpEcho));

	for(;!time_to_die;) {
		struct pollfd fds;
		double timewait;
		int n;

                /* time to send yet? */
		curping = gettimeofday_dbl();
		if (curping > lastping + options.interval) {
			if (options.count && (curSeq == options.count)) {
				if (lastRecv + options.wait < curping) {
                                        break;
                                }
			} else if (0 <= sendEcho(fd, curSeq++)) {
				sent++;
				lastping = curping;
                                if (options.flood) {
                                        printf(".");
                                        fflush(stdout);
                                }
			}
		}

		fds.fd = fd;
		fds.events = POLLIN;
		fds.revents = 0;
		
                /* max waittime: until it's time to send the next one */
		timewait = (lastping + options.interval) - gettimeofday_dbl();
		if (timewait < 0) {
			timewait = 0;
		}
                timewait *= 0.5; /* leave room for overhead */
		switch ((n = poll(&fds, 1, (int)(timewait * 1000)))) {
		case 1: /* read ready */
			if (fds.revents & POLLERR && ERR_INSPECTION) {
				handleRecvErr(fd, NULL);
			}
			if (fds.revents & POLLIN) {
				n = recvEchoReply(fd);
			}
			if (!n) {
				recvd++;
                                lastRecv = gettimeofday_dbl();
			} else if (n > 0) {
				/* still ok, but no reply */
			} else {
				return 1;
			}
			break;
		case 0: /* timeout */
			break;
		case -1: /* error */
			switch (errno) {
			case EINTR:
			case EAGAIN:
				break;
			default:
				fprintf(stderr, "%s: poll([%d], 1, %d): %s\n",
					argv0,
					fd,
					(int)(timewait*1000),
					strerror(errno));
				exit(2);
			}
			break;
		default: /* can't happen */
			fprintf(stderr, "%s: poll() returned %d!\n", argv0, n);
			exit(2);
			break;
		}
			
	}
	printf("\n--- %s GTP ping statistics ---\n"
               "%u packets transmitted, %u received, "
               "%d%% packet loss, "
               "time %dms\n"
               "%u out of order, %u dups, "
#if ERR_INSPECTION
               "%u ICMP error, "
#endif
               "%u connection refused\n",
	       options.target,
               sent, recvd,
	       (int)((100.0*(sent-recvd))/sent),
               (int)(1000*(gettimeofday_dbl()-startTime)),
               reorder, dups,
#if ERR_INSPECTION
               icmperror,
#endif
               connectionRefused);
	if (totalTimeCount) {
		printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms",
		       1000*totalMin,
		       1000*(totalTime / totalTimeCount),
		       1000*totalMax,
		       1000*sqrt((totalTimeSquared -
				  (totalTime * totalTime)
				  /totalTimeCount)/totalTimeCount));
	}
	printf("\n");
	return recvd == 0;
}

/**
 *
 */
static char*
argv0lenSpaces()
{
        static char buf[20];
        size_t n;

        memset(buf, ' ', sizeof(buf));
        buf[sizeof(buf)-1] = 0;

        n = strlen(argv0);

        if (n < sizeof(buf)) {
                buf[n] = 0;
        } else {
                buf[strlen("gtping")] = 0;
        }
        return buf;
}


/**
 *
 */
static void
usage(int err)
{
        printf("Usage: %s "
               "[ -hfvV ] "
               "[ -c <count> ] "
               "[ -i <time> ] "
               "[ -p <port> ] "
               "\n       %s "
               "[ -t <teid> ] "
               "[ -T <ttl> ] "
               "[ -w <time> ] "
               "<target>\n"
               "\n"
               "\t-c <count>       Stop after sending count pings "
               "(default: 0=Infinite)\n"
               "\t-f <count>       Flood ping mode (limit with -i)\n"
               "\t-h, --help       Show this help text\n"
               "\t-i <time>        Time between pings (default: %.1f)\n"
               "\t-p <port>        GTP-C UDP port to ping (default: %s)\n"
               "\t-Q <dscp>        Set ToS/DSCP bit (default: don't set)\n"
               "\t-t <teid>        Transaction ID (default: 0)\n"
               "\t-T <ttl>         IP TTL (default: system default)\n"
               "\t-v               Increase verbosity level (default: %d)\n"
               "\t-V, --version    Show version info and exit\n"
               "\t-w <time>        Time to wait for a response "
               "(default: 2*RTT or %.2fs)\n"
               "\n"
               "Report bugs to: thomas@habets.pp.se\n"
               "gtping home page: "
               "<http://www.habets.pp.se/synscan/programs.php?prog=gtping>\n",
               argv0, argv0lenSpaces(),
               DEFAULT_INTERVAL, DEFAULT_PORT, DEFAULT_VERBOSE, DEFAULT_WAIT);
        exit(err);
}

/**
 *
 */
static void
printVersion()
{
        printf("Copyright (C) 2008-2009 Thomas Habets\n"
               "License GPLv2: GNU GPL version 2 or later "
               "<http://gnu.org/licenses/gpl-2.0.html>\n"
               "This is free software: you are free to change and "
               "redistribute it.\n"
               "There is NO WARRANTY, to the extent permitted by law.\n");
        exit(0);
}


/**
 *
 * return -1 on error, or 8bit number to put in IP ToS-field.
 */
static int
parseQos(const char *instr)
{
        static const char *tos[][2] = {
                {"ef","0x46"},
                {"be","0"},
                {(char*)NULL,(char*)NULL}
        };
        char *lv;
        const char *rets = NULL;
        int ret = -1;
        char *p;
        const char *cp;
        int c;

        /* check for empty string. Not allowed */
        if (!strlen(instr)) {
                return -1;
        }

        /* check for special case instr = zeroes because strtol() can't.
         * This code depends on instr not being empty (checked above) */
        for (cp = instr; ; cp++) {
                if (*cp != '0') {
                        break;  
                }
                if (*cp == 0) {
                        return 0;
                }
        }

        /* lowercase input */
        lv = strdup(instr);
        if (!lv) {
                fprintf(stderr, "%s: strdup(\"%s\") failed\n", argv0, instr);
                return -1;
        }
        for (p = lv; *p; p++) {
                *p = tolower(*p);
        }

        /* find match in table */
        for (c = 0; tos[c][0]; c++) {
                const char **cur = tos[c];
                if (!strcmp(lv, cur[0])) {
                        rets = cur[1];
                }
        }
        
        
        if (rets) {
                /* if match was found, translate to number */
                ret = (int)strtol(rets, NULL, NULL);
        } else {
                /* if no match, try to parse as a number directly */
                ret = strtol(lv, NULL, NULL);
                if (!ret) {
                        /* the real case of -Q 0 is handled above */
                        ret = -1;
                }
        }
        free(lv);
        if (ret > 255) {
                ret = -1;
        }
        return ret;
}

/**
 *
 */
int
main(int argc, char **argv)
{
	int fd;

	printf("GTPing %s\n", version);

	argv0 = argv[0];

        { /* handle GNU options */
                int c;
                for (c = 1; c < argc; c++) {
                        
                        if (!strcmp(argv[c], "--")) {
                                break;
                        } else if (!strcmp(argv[c], "--help")) {
                                usage(0);
                        } else if (!strcmp(argv[c], "--version")) {
                                printVersion();
                        }
                }
        }

        /* arbitrary teid. Should be 0, so randomize is off */
	if (0) {
		srand(getpid() ^ time(0));

		/* don't know what RAND_MAX is,
		   so just assume at least 8bits */
		options.teid = ((((rand() & 0xff) * 256
				  + (rand() & 0xff)) * 256
				 + (rand() & 0xff)) * 256
				+ (rand() & 0xff));
	}

        /* parse options */
	{
		int c;
		while (-1 != (c = getopt(argc, argv, "c:fhi:p:Q:t:T:vVw:"))) {
			switch(c) {
			case 'c':
				options.count = strtoul(optarg, 0, 0);
				break;
                        case 'f':
                                options.flood = 1;
                                if (0 > options.interval) {
                                        options.interval = 0;
                                        fprintf(stderr,
                                                "%s: invalid interval \"%s\", "
                                                "set to 0\n",
                                                argv0, optarg);
                                }
                                break;
			case 'h':
				usage(0);
				break;
			case 'p':
				options.port = optarg;
				break;
			case 't':
				options.teid = strtoul(optarg, 0, 0);
				break;
			case 'T':
				options.ttl = strtoul(optarg, 0, 0);
				break;
			case 'v':
				options.verbose++;
				break;
                        case 'V':
                                printVersion();
			case 'i':
				options.interval = atof(optarg);
				break;
			case 'w':
				options.wait = atof(optarg);
				break;
                        case 'Q':
                                if (-1 == (options.tos = parseQos(optarg))) {
                                        fprintf(stderr,
                                                "%s: invalid ToS/DSCP \"%s\", "
                                                "left as-is.\n", argv0,optarg);
                                        fprintf(stderr, "%s: "
                                                "Valid are "
                                                "BE,EF,AF[1-4][1-3],CS[0-7] "
                                                "and numeric (0x for hex).\n",
                                                argv0);
                                }
                                break;
			case '?':
			default:
				usage(2);
			}
		}
	}
        if (0 > options.interval) {
                options.interval = DEFAULT_INTERVAL;
        }
        if (0 > options.wait) {
                options.wait = DEFAULT_WAIT;
                options.autowait = 1;
        }
	if (options.verbose) {
		fprintf(stderr, "%s: transaction id: %.8x\n",
			argv0, options.teid);
	}

	if (optind + 1 != argc) {
		usage(2);
	}

	options.target = argv[optind];

	if (SIG_ERR == signal(SIGINT, sigint)) {
		fprintf(stderr, "%s: signal(SIGINT, ...): %s\n",
			argv0, strerror(errno));
		return 1;
	}

	if (0 > (fd = setupSocket())) {
		return 1;
	}

	return mainloop(fd);
}

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
