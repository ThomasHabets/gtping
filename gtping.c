/** gtping/gtping.c
 *
 * GTP Ping
 *
 * By Thomas Habets <thomas@habets.pp.se> 2008
 *
 * Send GTP Ping and time the reply.
 *
 *
 */
/*
 *  Copyright (C) 2008 Thomas Habets <thomas@habets.pp.se>
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
#undef ERR_INSPECTION
#define ERR_INSPECTION 1
#endif

/* pings older than SENDTIMES_SIZE * the_wait_time are ignored */
#define SENDTIMES_SIZE 100

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
};

static const double version = 0.12f;

static volatile int time_to_die = 0;
static unsigned int curSeq = 0;
static double startTime;
static double sendTimes[SENDTIMES_SIZE];
static unsigned int totalTimeCount = 0;
static double totalTime = 0;
static double totalTimeSquared = 0;
static double totalMin = -1;
static double totalMax = -1;

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

	if (options.verbose > 1) {
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
	if (options.verbose) {
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
	{
		int on = 1;
		if (setsockopt(fd, SOL_IP, IP_RECVERR, &on, sizeof(on))) {
			fprintf(stderr,
				"%s: setsockopt(%d, SOL_IP, IP_RECVERR, on): "
				"%s\n", argv0, fd, strerror(errno));
		}
		on = 1;
		if (setsockopt(fd, SOL_IP, IPV6_RECVERR, &on, sizeof(on))) {
			fprintf(stderr,
				"%s: setsockopt(%d, SOL_IP, IPV6_RECVERR, "
				"on): %s\n", argv0, fd, strerror(errno));
		}
		if (setsockopt(fd, SOL_IP, IP_RECVTTL, &on, sizeof(on))) {
			fprintf(stderr,
				"%s: setsockopt(%d, SOL_IP, IP_RECVTTL, on): "
				"%s\n", argv0, fd, strerror(errno));
		}
	}
#endif
	if (options.ttl > 0) {
		if (setsockopt(fd, SOL_IP,
			       IP_TTL,
			       &options.ttl,sizeof(options.ttl))) {
			fprintf(stderr,
				"%s: setsockopt(%d, SOL_IP, IP_TTL, "
				"%d): %s", argv0, fd, options.ttl,
				strerror(errno));
		}
	}

	/* FIXME TOS */

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

	if (options.verbose > 1) {
		fprintf(stderr, "%s: sendEcho(%d, %d)\n", argv0, fd, seq);
	}

	if (options.verbose) {
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

	sendTimes[seq % SENDTIMES_SIZE] = gettimeofday_dbl();

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
handleRecvErr(int fd)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	char cbuf[512];
	char buf[5120];
	struct sockaddr_storage sa;
	struct iovec iov;
        struct sock_extended_err *see = 0;
	int rethops = -1;
	int isicmp = 0;
	int n;
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

	/* Find err struct & ttl */
	for (cmsg = CMSG_FIRSTHDR(&msg);
	     cmsg;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_level == SOL_IP) {
                        if (cmsg->cmsg_type == IP_RECVERR
			    || cmsg->cmsg_type == IPV6_RECVERR) {
				see = (struct sock_extended_err*)
					CMSG_DATA(cmsg);
			} else if (cmsg->cmsg_type == IP_TTL) {
                                rethops = *(int*)CMSG_DATA(cmsg);
			} else {
				fprintf(stderr,
					"%s: Got cmsg type: %d\n",
					argv0, cmsg->cmsg_type);
			}

		}
	}
	if (options.verbose > 1) {
		fprintf(stderr, "%s: TTL: %d\n", argv0, rethops);
	}
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
		printf("Port closed\n");
		break;
	case EMSGSIZE:
		printf("PMTU %d\n", see->ee_info);
		break;
	case EPROTO:
		printf("Protocol error\n");
		break;
	case ENETUNREACH:
		printf("Network unreachable\n");
		break;
	case EACCES:
		printf("Access denied\n");
		break;
	case EHOSTUNREACH:
		if (isicmp && see->ee_type == 11 && see->ee_code == 0) {
                        printf("Time to live exceeded\n");
                } else {
			printf("Host unreachable\n");
		}
		break;
	default:
		printf("Unhandled type of error %d\n", see->ee_errno);
		break;
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
 * return 0 on success/got reply, <0 on fail, >1 on success, no packet
 */
static int
recvEchoReply(int fd)
{
	int err;
	struct GtpEcho gtp;
	int n;
	double now;
	char lag[128];

	if (options.verbose > 1) {
		fprintf(stderr, "%s: recvEchoReply()\n", argv0);
	}

	now = gettimeofday_dbl();
	
	memset(&gtp, 0, sizeof(struct GtpEcho));

	if (0 > (n = recv(fd, (void*)&gtp, sizeof(struct GtpEcho), 0))) {
		switch(errno) {
		case ECONNREFUSED:
			printf("FIXME: test this code path!\n");
			handleRecvErr(fd);
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

	if (curSeq - htons(gtp.seq) >= SENDTIMES_SIZE) {
		strcpy(lag, "Inf");
	} else {
		double lagf = (now-sendTimes[htons(gtp.seq)%SENDTIMES_SIZE]);
		snprintf(lag, sizeof(lag), "%.2f ms", 1000 * lagf);
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
	printf("%u bytes from %s: seq=%u time=%s\n",
	       n,
	       options.targetip,
	       htons(gtp.seq),
	       lag);
	return 0;
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

	if (options.verbose > 1) {
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
	       "%u packets transmitted, %u received, "
	       "%d%% packet loss, time %dms\n",
	       options.target,
	       sent, recvd,
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

	/* arbitrary teid */
	if (0) {
		srand(getpid() ^ time(0));

		/* don't know what RAND_MAX is,
		   so just assume at least 8bits */
		options.teid = ((((rand() & 0xff) * 256
				  + (rand() & 0xff)) * 256
				 + (rand() & 0xff)) * 256
				+ (rand() & 0xff));
	}

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
 * End:
 */
