# gtping/Makefile
#
CFLAGS=-g -Wall -W -O2 -pipe
LDLIBS=-lm
RM=rm
SED=sed
GPG=gpg
GREP=grep
GIT=git

all: gtping

V=$(shell $(GREP) version gtping.c|$(GREP) const|$(SED) 's:[a-z =]*::;s:f;::')
dist:
	$(GIT) archive --format=tar --prefix=gtping-$(V)/ gtping-$(V) | gzip -9 > gtping-$(V).tar.gz
	$(GPG) -b -a $(DFILE)

clean:
	$(RM) -f *.o gtping
