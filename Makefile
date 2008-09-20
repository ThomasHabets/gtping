CFLAGS=-g -Wall -W -O2 -pipe
LDLIBS=-lm

all: gtping

clean:
	rm -f *.o gtping
