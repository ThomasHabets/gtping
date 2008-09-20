/**
 * GTP Ping.
 * By: Thomas Habets <thomas@habets.pp.se> 2008
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

#pragma pack(1)
struct GtpEcho {
	char flags;
	char msg;
	u_int16_t len;	
	u_int32_t teid;
	u_int16_t seq;
	char npdu;
	char next;
};
#pragma pack()

#define DEFAULT_PORT 2123
#define DEFAULT_VERBOSE 0
#define DEFAULT_INTERVAL 1.0
struct Options {
	int port;
	int verbose;
	double interval;
	const char *target;
	const char *targetip;
};

static double version = 0.10f;

static volatile int time_to_die = 0;
static int curSeq = 0;
#define SENDTIMES_SIZE 100
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
	target: 0,
	targetip: 0,
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
 *
 * return fd, or <0 on error
 */
static int
setupSocket()
{
	int fd;
	int err;
	struct sockaddr_in sa;

	if (options.verbose > 1) {
		fprintf(stderr, "%s: setupSocket(%s)\n",
			argv0, options.target);
	}

	if (0 > (fd = socket(PF_INET, SOCK_DGRAM, 0))) {
		err = errno;
		fprintf(stderr, "%s: socket(FD_INET, SOCK_DGRAM, 0): %s",
			argv0, strerror(errno));
		return -err;
	}
	
	memset(&sa, 0, sizeof(struct sockaddr_in));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(options.port);
	sa.sin_addr.s_addr = inet_addr(options.target);
	if (connect(fd, (struct sockaddr*)&sa, sizeof(struct sockaddr_in))) {
		err = errno;
		fprintf(stderr, "%s: connect(%d, ...): %s",
			argv0, fd, strerror(errno));
		close(fd);
		return -err;
	}
	return fd;
}

/**
 * return 0 on succes, <0 on fail
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
	gtp.teid = 0;
	gtp.seq = htons(seq);
	gtp.npdu = 0x00;
	gtp.next = 0x00;

	sendTimes[seq % SENDTIMES_SIZE] = gettimeofday_dbl();

	if (sizeof(struct GtpEcho) != send(fd, (void*)&gtp,
					   sizeof(struct GtpEcho), 0)) {
		err = errno;
		fprintf(stderr, "%s: send(%d, ...): %s",
			argv0, fd, strerror(errno));
		return -err;
	}
	return 0;
}

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
		case EINTR:
			printf("ICMP destination unreachable\n");
			return 1;
		default:
			errno = err;
			fprintf(stderr, "%s: recv(%d, ...): %s",
				argv0, fd, strerror(errno));
			return -err;
		}
	}
	if (gtp.msg != 0x02) {
		fprintf(stderr, "%s: Got non-EchoReply type of msg (%d)\n",
			argv0, gtp.msg);
		return 0;
	}

	if (curSeq - htons(gtp.seq) >= SENDTIMES_SIZE) {
		strcpy(lag, "Inf");
	} else {
		double lagf = (now-sendTimes[htons(gtp.seq)%SENDTIMES_SIZE]);
		snprintf(lag, sizeof(lag), "%.1f ms", 1000 * lagf);
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
		fprintf(stderr,"%s: gettimeofday(): %s",argv0,strerror(errno));
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

	printf("GTPING %s (%s) %d bytes of data.\n",
	       options.target,
	       options.targetip,
	       sizeof(struct GtpEcho));

	for(;!time_to_die;) {
		struct pollfd fds;
		double timewait;
		int n;

		curping = gettimeofday_dbl();
		if (curping > lastping + options.interval) {
			if (0 > sendEcho(fd, curSeq++)) {
				return 1;
			}
			sent++;
			lastping = curping;
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
			n = recvEchoReply(fd);
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
		       totalMin,
		       100.0*(totalTime / totalTimeCount),
		       totalMax,
		       sqrt((totalTimeSquared -
			     (totalTime * totalTime)
			     /totalTimeCount)/totalTimeCount));
	}
	printf("\n");
	return recvd > 0;
}

/**
 *
 */
static void
usage(int err)
{
	printf("Usage: %s [ -hv ] [ -p <port> ] [ -w <time> ] <target>\n"
	       "\t-h         Show this help text\n"
	       "\t-p <port>  GTP-C UDP port to ping (default: %d)\n"
	       "\t-v         Increase verbosity level (default: %d)\n"
	       "\t-w <time>  Time between pings (default: %.1f)\n",
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
	{
		int c;
		while (-1 != (c = getopt(argc, argv, "hp:vw:"))) {
			switch(c) {
			case 'h':
				usage(0);
				break;
			case 'p':
				options.port = atoi(optarg);
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

	if (optind + 1 != argc) {
		usage(2);
	}

	options.target = options.targetip = argv[optind];

	if (SIG_ERR == signal(SIGINT, sigint)) {
		fprintf(stderr, "%s: signal(SIGINT, ...): %s",
			argv0, strerror(errno));
		return 1;
	}

	if (0 > (fd = setupSocket())) {
		return 1;
	}

	return mainloop(fd);
}
