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
        int has_npdu:1;
        int has_seq:1;
        int has_ext_head:1;
        int res1:1;
        int proto_type:1;
        int version:3;

        uint8_t msg;
        uint16_t len;
        uint32_t teid;
        uint16_t seq;
        uint8_t npdu;
        uint8_t next;
};
#pragma pack()
#pragma pack(1)
#define GTPECHOv2_LEN_WITHOUT_TEID 8
struct GtpEchoV2 {
        int spare1:3;
        int has_teid:1;
        int piggyback:1;
        int version:3;

        uint8_t msg;
        uint16_t len;
        union {
                uint16_t seq;
                struct {
                        uint32_t teid;
                        uint16_t seq;
                } s;
        } u2;
        uint16_t spare2;
};
#pragma pack()
struct GtpReply {
        int ok;

        int version;
        int msg;
        int len;

        int has_seq;
        uint16_t seq;

        int has_teid;
        uint32_t teid;

        int has_npdu;
        uint8_t npdu;

        int has_ext_head;
        uint8_t next;
};

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
        int has_teid;
        uint32_t teid;
        const char *target;
        char *targetip;
        int ttl;
        int tos;
        int af;
        unsigned int version;
        int traceroute;
        int traceroutehops;
        const char *source;
        const char *source_port;
};

extern struct Options options;
extern const char *argv0;

ssize_t doRecv(int sock, void *data, size_t len, int *ttl, int *tos);

void errInspectionPrintSummary();
void errInspectionInit(int fd, const struct addrinfo *addrs);
int handleRecvErr(int fd, const char *reason, double lastPingTime);
const char *tos2String(int tos, char *buf, size_t buflen);
struct addrinfo* getIfAddrs(const struct addrinfo *dest);
int sockaddrlen(int af);
double clock_get_dbl();

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */

