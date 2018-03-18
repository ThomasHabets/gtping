/** gtping/src/monotonic_clock.c
 *
 *  By Thomas Habets <thomas@habets.se> 2010
 *
 * get monotonic clock with clock_gettime(CLOCK_MONOTONIC,)
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include<time.h>
#include<stdio.h>
#include<errno.h>
#include<string.h>
#include<sys/time.h>

#include"gtping.h"

/**
 *
 */
double
clock_get_dbl()
{
        struct timespec ts;
        struct timeval tv;

        /* try clock_gettime() */
        if (!clock_gettime(CLOCK_MONOTONIC, &ts)) {
                return ts.tv_sec + ts.tv_nsec / 1000000000.0;
        }
        fprintf(stderr, "%s: clock_gettime(CLOCK_MONOTONIC,): %s\n",
                argv0, strerror(errno));

        /* try gettimeofday() */
        if (!gettimeofday(&tv, NULL)) {
                return tv.tv_sec + tv.tv_usec / 1000000.0;
        }
        fprintf(stderr, "%s: gettimeofday(): %s\n", argv0, strerror(errno));

        return time(0);
}

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
