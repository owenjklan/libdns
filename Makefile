#CC=mipsel-linux-gnu-gcc
CC=gcc
# Using -O0 at valgrind's suggestion while hunting memory leaks
CFLAGS=-Wall -O0 -fPIC -static
OBJS= dns.o dns_str.o dns_tcp.o dns_udp.o
RELEASE= 0.1

.c.o:
	$(CC) -c $< -o $@ $(CFLAGS)


all: $(OBJS) dns.h
	$(CC) $(OBJS) -fPIC -O2 -Wall -shared -o libdns.$(RELEASE).so
	ar r libdns.a $(OBJS)
	ranlib libdns.a

clean:
	rm -f libdns.a
	rm -f *.o
	rm -f ./*~

install: all
	mkdir -p /usr/include/libdns && cp dns.h /usr/include/libdns
	install libdns.a /usr/local/lib
	install libdns.$(RELEASE).so /usr/local/lib
	install libdns.man /usr/share/man/man3/libdns.3
