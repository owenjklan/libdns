CC=gcc
CFLAGS=-Wall -O0 -g -ggdb
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

valgrind:
	valgrind --track-origins=yes --leak-check=full ./dnsq 8.8.8.8 dns.google
