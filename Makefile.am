# gtping/Makefile.am

# Don't complain about "missing" standard GNU files
AUTOMAKE_OPTIONS = foreign
AM_CFLAGS=-Wall -DINET6=1

bin_PROGRAMS = gtping
man_MANS = gtping.8
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

LDADD = $(LIBOBJS)

GIT=git
GPG=gpg
GZIP=gzip

V=@VERSION@
signed-dist:
	$(GIT) archive --format=tar --prefix=gtping-$(V)/ gtping-$(V) | $(GZIP) -9 > gtping-$(V).tar.gz
	$(GPG) -b -a gtping-$(V).tar.gz

doc: gtping.8

gtping.8:
	yodl2man -o gtping.8 gtping.yodl

mrproper: maintainer-clean
	rm -f aclocal.m4 configure.scan depcomp missing install-sh config.h.in
	rm -f Makefile.in configure autoscan*.log
