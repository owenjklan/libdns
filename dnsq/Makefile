CC=gcc
CFLAGS=-Wall -O2 -g -ggdb
LDFLAGS= -L. -ldns
OBJS=dnsq.o

.c.o:
	$(CC) -c $< -o $@ $(CFLAGS)

all: $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) $(LDFLAGS) -o dnsq

clean:
	rm -f dnsq
	rm -f *.o
	rm -f ./*~

install: all
	cp dnsq /usr/local/bin
