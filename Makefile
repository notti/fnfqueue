.PHONY: clean

CFLAGS="-O3"

main: libnfqueue.so

libnfqueue.so: CFLAGS+=-fPIC -shared
libnfqueue.so: nfqueue.c nfqueue.h
	$(CC) $(CFLAGS) -o libnfq.so nfqueue.so

clean:
	rm -f libnfqueue.so
