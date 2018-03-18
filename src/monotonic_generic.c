/** gtping/src/monotonic_generic.c
 *
 *  By Thomas Habets <thomas@habets.se> 2010
 *
 * get clock from gettimeofday() as if it were monotonic
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include<stdio.h>
#include<string.h>
#include<errno.h>
#include<sys/time.h>

#include"gtping.h"

/**
 *
 */
double
clock_get_dbl()
{
        struct timeval tv;
        if (gettimeofday(&tv, NULL)) {
                fprintf(stderr, "%s: gettimeofday(): %s\n",
                        argv0, strerror(errno));
                return time(0);
        }
        return tv.tv_sec + tv.tv_usec / 1000000.0;
}

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
