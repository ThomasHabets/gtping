/** gtping/gtping.h
 *
 *  By Thomas Habets <thomas@habets.pp.se> 2009
 *
 */
#include <stdint.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "getaddrinfo.h"

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
        unsigned long count;
        uint32_t teid;
        const char *target;
        char *targetip;
        int ttl;
        int tos;
        int af;
};

extern struct Options options;
extern const char *argv0;

ssize_t doRecv(int sock, void *data, size_t len, int *ttl, int *tos);

void errInspectionPrintSummary();
void errInspectionInit(int fd, const struct addrinfo *addrs);
int handleRecvErr(int fd, const char *reason);
const char *tos2String(int tos, char *buf, size_t buflen);

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
