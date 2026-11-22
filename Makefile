CC      = musl-gcc
CFLAGS  = -O2 -Wall -Wextra -static -std=c11
LDFLAGS = -static
LIBS    = -ljansson

all: corehttpd corehttpd-acme

corehttpd: corehttpd.c tls.c corehttpd.h
	$(CC) $(CFLAGS) -o $@ corehttpd.c tls.c $(LIBS) $(LDFLAGS)

corehttpd-acme: acme.c
	$(CC) $(CFLAGS) -o $@ acme.c $(LIBS) $(LDFLAGS)

clean:
	rm -f corehttpd corehttpd-acme
