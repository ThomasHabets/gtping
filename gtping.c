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

/* In-depth error handling only implemented for linux so far */
#define ERR_INSPECTION 0

#ifdef __linux__
#define __u8 unsigned char
#define __u32 unsigned int
#include <linux/errqueue.h>
#undef __u8
#undef __u32
#undef ERR_INSPECTION
#define ERR_INSPECTION 1

/* from /usr/include/linux/in6.h */
#define REAL_IPV6_RECVHOPLIMIT       51
#define REAL_IPV6_HOPLIMIT           52

#else
/* non-Linux */
#define REAL_IPV6_RECVHOPLIMIT IPV6_RECVHOPLIMIT
#define REAL_IPV6_HOPLIMIT IPV6_HOPLIMIT
#endif

/* pings older than TRACKPINGS_SIZE * the_wait_time are ignored.
 * They are old and are considered lost.
 */
#define TRACKPINGS_SIZE 1000

/* For those OSs that don't read RFC3493, even though their manpage
 * points to it. */
#ifndef AI_ADDRCONFIG
#define AI_ADDRCONFIG 0
#endif

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

#define DEFAULT_PORT "2123"
#define DEFAULT_VERBOSE 0
#define DEFAULT_INTERVAL 1.0
struct Options {
        const char *port;
        int verbose;
        double interval;
        unsigned int count;
        uint32_t teid;
        const char *target;  /* what is on the cmdline */
        char *targetip;      /* IPv* address string */
        int ttl;
        int tos;
};

static const double version = 0.12f;

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


/* from cmdline */
static const char *argv0 = 0;
static struct Options options = {
        port: DEFAULT_PORT,
        verbose: DEFAULT_VERBOSE,
        interval: DEFAULT_INTERVAL,
        count: 0,
        target: 0,
        targetip: 0,
        ttl: -1,
        tos: -1,
        teid: 0,
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
					"%d): %s", argv0, fd, options.ttl,
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
					"%d): %s", argv0, fd, options.ttl,
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
					"IPV6_HOPLIMIT, %d): %s",
					argv0, fd, options.ttl,
					strerror(errno));
			}
		}
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
		fprintf(stderr,	"%s: Sending GTP ping with seq=%d\n",
			argv0, curSeq);
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
		fprintf(stderr, "%s: send(%d, ...): %s\n",
			argv0, fd, strerror(errno));
		if (err == ECONNREFUSED) {
			return err;
		}
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
	if (options.verbose && (0 < returnttl)) {
		printf(". return TTL: %d.", returnttl);
	}
	printf("\n");
}

static void
handleRecvErr(int fd)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	char cbuf[512];
	char buf[5120];
	struct sockaddr_storage sa;
	struct iovec iov;
	int n;
	int returnttl = -1;

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
handleRecvErr(int fd)
{
	fd = fd;
	printf("Destination unreachable (closed, filtered or TTL exceeded)\n");
}
#endif

/**
 * return 0 on success/got reply,
 *        <0 on fail
 *        >1 on success, but no packet (EINTR or dup packet)
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

	if (options.verbose > 2) {
		fprintf(stderr, "%s: recvEchoReply()\n", argv0);
	}

	now = gettimeofday_dbl();
	
	memset(&gtp, 0, sizeof(struct GtpEcho));

	if (0 > (n = recv(fd, (void*)&gtp, sizeof(struct GtpEcho), 0))) {
		switch(errno) {
                case ECONNREFUSED: {
                        static int haswarned = 0;
                        if (!haswarned) {
                                fprintf(stderr,
                                        "%s: recv() returned ECONNREFUSED. "
                                        "That's strange.\n",
                                        argv0);
                                haswarned = 1;
                        }
			handleRecvErr(fd);
                }
		case EINTR:
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
	}
	printf("%u bytes from %s: seq=%u time=%s%s\n",
	       n,
	       options.targetip,
	       htons(gtp.seq),
	       lag,
               isDup ? " (DUP)" : "");
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

		curping = gettimeofday_dbl();
		if (curping > lastping + options.interval) {
			if (options.count && (curSeq == options.count)) {
				break;
			}
			if (0 <= sendEcho(fd, curSeq++)) {
				sent++;
				lastping = curping;
			}
		}

		fds.fd = fd;
		fds.events = POLLIN;
		fds.revents = 0;
		
		timewait = (lastping + options.interval) - gettimeofday_dbl();
		if (timewait < 0) {
			timewait = 0;
		}
		switch ((n = poll(&fds, 1, (int)(timewait * 1000)))) {
		case 1: /* read ready */
			if (fds.revents & POLLERR && ERR_INSPECTION) {
				handleRecvErr(fd);
			}
			if (fds.revents & POLLIN) {
				n = recvEchoReply(fd);
			}
			if (!n) {
				recvd++;
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
	       "%u packets transmitted, %u received, %u dups, "
	       "%d%% packet loss, time %dms\n",
	       options.target,
	       sent, recvd, dups,
	       (int)((100.0*(sent-recvd))/sent),
	       (int)(1000*(gettimeofday_dbl()-startTime)));
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
static void
usage(int err)
{
	printf("Usage: %s [ -hv ] [ -c <count> ] [ -p <port> ] "
	       "[ -w <time> ] [ -T <ttl> ] <target>\n"
	       "\t-c <count>  Stop after sending count pings. "
	       "(default: 0=Infinite)\n"
	       "\t-h          Show this help text\n"
	       "\t-p <port>   GTP-C UDP port to ping (default: %s)\n"
	       "\t-t          Transaction ID (default: 0)\n"
	       "\t-T          IP TTL (default: system default)\n"
	       "\t-v          Increase verbosity level (default: %d)\n"
	       "\t-w <time>   Time between pings (default: %.1f)\n",
	       argv0, DEFAULT_PORT, DEFAULT_VERBOSE, DEFAULT_INTERVAL);
	exit(err);
}

/**
 *
 */
int
main(int argc, char **argv)
{
	int fd;

	printf("GTPing %.2f, By Thomas Habets <thomas@habets.pp.se>\n",
	       version);

	argv0 = argv[0];

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
		while (-1 != (c = getopt(argc, argv, "c:hp:t:T:vw:"))) {
			switch(c) {
			case 'c':
				options.count = strtoul(optarg, 0, 0);
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
			case 'w':
				options.interval = atof(optarg);
				break;
			case '?':
			default:
				usage(2);
			}
		}
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
