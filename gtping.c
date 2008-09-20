/**
 * GTP Ping.
 * By: Thomas Habets <thomas@habets.pp.se> 2008
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <poll.h>
#include <math.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>

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

static double version = 0.10f;

static volatile int time_to_die = 0;
static int curSeq = 0;
#define SENDTIMES_SIZE 100
static double sendTimes[SENDTIMES_SIZE];

/* from cmdline */
static int verbose = 0;
static const char *argv0 = 0;
static const char *target = 0, *targetip = 0;
static double interval = 1;


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
 */
static int
setupSocket(const char *target)
{
	int fd;
	int err;
	struct sockaddr_in sa;

	if (0 > (fd = socket(PF_INET, SOCK_DGRAM, 0))) {
		err = errno;
		perror("socket()");
		return -err;
	}
	
	memset(&sa, 0, sizeof(struct sockaddr_in));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(2123);
	sa.sin_addr.s_addr = inet_addr(target);
	if (connect(fd, (struct sockaddr*)&sa, sizeof(struct sockaddr_in))) {
		err = errno;
		perror("connect()");
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
		perror("send()");
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
			perror("recv()");
			return -err;
		}
	}
	if (gtp.msg != 0x02) {
		printf("Got other type of msg?! %d\n", gtp.msg);
		return 0;
	}

	if (curSeq - htons(gtp.seq) >= SENDTIMES_SIZE) {
		strcpy(lag, "Inf");
	} else {
		snprintf(lag, sizeof(lag), "%.1f ms", 
			 1000*(now-sendTimes[htons(gtp.seq)%SENDTIMES_SIZE]));
	}
	printf("%u bytes from %s: seq=%u time=%s\n",
	       n,
	       targetip,
	       htons(gtp.seq),lag);
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
		perror("gettimeofday()");
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

	printf("GTPING %s (%s) %d bytes of data.\n",
	       target,targetip,
	       sizeof(struct GtpEcho));

	for(;!time_to_die;) {
		struct pollfd fds;
		double timewait;
		int n;

		curping = gettimeofday_dbl();
		if (curping > lastping + interval) {
			if (verbose) {
				printf("Sending ping seq %d...\n", curSeq);
			}
			if (0 > sendEcho(fd, curSeq++)) {
				return 1;
			}
			sent++;
			lastping = curping;
		}

		fds.fd = fd;
		fds.events = POLLIN;
		fds.revents = 0;
		
		timewait = (lastping + interval) - gettimeofday_dbl();
		if (timewait < 0) {
			timewait = 0;
		}
		switch ((n = poll(&fds, 1, (int)(timewait * 1000)))) {
		case 1: /* read ready */
			if (verbose) {
				printf("recv()\n");
			}
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
				perror("poll");
			}
			break;
		default: /* can't happen */
			fprintf(stderr, "poll returned %d!\n", n);
			break;
		}
			
	}
	printf("\n--- %s GTP ping statistics ---\n"
	       "%u packets transmitted, %u received, "
	       "%d packet loss, time %dms\n"
	       "rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
	       target, sent, recvd, -1, -1, -1.0, -1.0,-1.0, -1.0);
	return 0;
}

/**
 *
 */
static void
usage(int err)
{
	printf("Usage: %s <target>\n", argv0);
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
	if (argc < 2) {
		usage(1);
	}
	/* FIXME: parse options */
	target = targetip = argv[1];
	interval = 0.5;
	verbose = 1;

	if (SIG_ERR == signal(SIGINT, sigint)) {
		perror("signal(SIGINT)");
		return 1;
	}

	if (0 > (fd = setupSocket(target))) {
		return 1;
	}

	return mainloop(fd);
}
