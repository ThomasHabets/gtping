# gtping/Makefile.am

# Don't complain about "missing" standard GNU files
include $(top_srcdir)/Makefile.am.common

SUBDIRS=src doc

mrproper: maintainer-clean
        rm -f aclocal.m4 configure.scan depcomp missing install-sh config.h.in
        rm -f Makefile.in configure autoscan*.log config.guess config.sub
        rm -f ltmain.sh configure.in

GIT=git
GPG=gpg
GZIP=gzip

V=@VERSION@
signed-dist:
	$(GIT) archive --format=tar --prefix=gtping-$(V)/ gtping-$(V) | $(GZIP) -9 > gtping-$(V).tar.gz
	$(GPG) -b -a gtping-$(V).tar.gz

mrproper: maintainer-clean
	rm -f aclocal.m4 configure.scan depcomp missing install-sh config.h.in
	rm -f Makefile.in configure autoscan*.log debian/debhelper.log
	rm -f debian/substvars debian/files
	rm -fr debian/tmp
	rm -fr config
	mkdir config
