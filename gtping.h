/** gtping/gtping.h
 *
 *  By Thomas Habets <thomas@habets.pp.se> 2009
 *
 */
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "getaddrinfo.h"

/* GTP packet as used with GTP Echo */
#pragma pack(1)
struct GtpEchoV1 {
        union {
                uint8_t flags;
                struct {
                        int n_pdu_flag:1;
                        int seq_flag:1;
                        int ext_head_flag:1;
                        int res1:1;
                        int proto_type:1;
                        int version:3;
                } s;
        } u;
        uint8_t msg;
        uint16_t len;
        uint32_t teid;
        uint16_t seq;
        uint8_t npdu;
        uint8_t next;
};
#pragma pack()
#pragma pack(1)
struct GtpEchoV2 {
        union {
                uint8_t flags;
                struct {
                        int spare2:3;
                        int has_teid:1;
                        int spare:1;
                        int version:3;
                } s;
        } u;
        uint8_t msg;
        uint16_t len;
        uint16_t seq;
        uint16_t spare;
};
#pragma pack()


enum {
        GTPMSG_ECHO = 1,
        GTPMSG_ECHOREPLY = 2,
};

/**
 * options
 */
#define DEFAULT_PORT "2123"
#define DEFAULT_VERBOSE 0
#define DEFAULT_GTPVERSION 1
#define DEFAULT_INTERVAL 1.0
#define DEFAULT_WAIT 10.0
#define DEFAULT_TRACEROUTEHOPS 3
struct Options {
        const char *port;
        int verbose;
        int flood;
        double interval;
        double wait;
        int autowait;
        unsigned long count;
        uint32_t teid;
        const char *target;
        char *targetip;
        int ttl;
        int tos;
        int af;
        unsigned int version;
        int traceroute;
        int traceroutehops;
};

extern struct Options options;
extern const char *argv0;

ssize_t doRecv(int sock, void *data, size_t len, int *ttl, int *tos);

void errInspectionPrintSummary();
void errInspectionInit(int fd, const struct addrinfo *addrs);
int handleRecvErr(int fd, const char *reason, double lastPingTime);
const char *tos2String(int tos, char *buf, size_t buflen);
double gettimeofday_dbl();

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
