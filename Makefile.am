# gtping/Makefile.am

# Don't complain about "missing" standard GNU files
AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = gtping
man_MANS = gtping.8
gtping_SOURCES = gtping.c

GIT=git
GPG=gpg
GZIP=gzip

V=@VERSION@
signed-dist:
	$(GIT) archive --format=tar --prefix=gtping-$(V)/ gtping-$(V) | $(GZIP) -9 > gtping-$(V).tar.gz
	$(GPG) -b -a gtping-$(V).tar.gz

doc: gtping.8

gtping.8: gtping.yodl
	yodl2man -o gtping.8 gtping.yodl

mrproper: maintainer-clean
	rm -f aclocal.m4 configure.scan depcomp missing install-sh config.h.in
	rm -f Makefile.in configure autoscan*.log
