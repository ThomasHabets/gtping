# gtping/src/Makefile.am

include $(top_srcdir)/Makefile.am.common

bin_PROGRAMS = gtping
gtping_SOURCES = gtping.c
if HAVE_CONTROL_IN_MSGHDR
gtping_SOURCES += dorecv_cmsg.c
else
gtping_SOURCES += dorecv_generic.c
endif

if HAVE_MSG_ERRQUEUE
gtping_SOURCES += ei_errqueue.c
else
gtping_SOURCES += ei_generic.c
endif

if HAVE_CLOCK_MONOTONIC
gtping_SOURCES += monotonic_clock.c
else
gtping_SOURCES += monotonic_generic.c
endif

if HAVE_IFADDRS_H
gtping_SOURCES += ifaddrs_ifaddrs.c
else
gtping_SOURCES += ifaddrs_generic.c
endif

LDADD = $(LIBOBJS)

