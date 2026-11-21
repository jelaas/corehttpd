CC      = musl-gcc
CFLAGS  = -O2 -Wall -Wextra -static -std=c11
LDFLAGS = -static
LIBS    = -ljansson

all: corehttpd

corehttpd: corehttpd.c tls.c corehttpd.h
	$(CC) $(CFLAGS) -o $@ corehttpd.c tls.c $(LIBS) $(LDFLAGS)

clean:
	rm -f corehttpd