.PHONY: clean

CFLAGS=-O3 -I../include

main: libnfqueue.so

libnfqueue.so: CFLAGS+=-fPIC -shared
libnfqueue.so: nfqueue.c ../include/nfqueue.h
	$(CC) $(CFLAGS) -o libnfqueue.so nfqueue.c

clean:
	rm -f libnfqueue.so
