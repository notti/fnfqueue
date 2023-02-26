.PHONY: clean

CFLAGS=-O3 -I../include

main: libfnfqueue.so

libfnfqueue.so: CFLAGS+=-fPIC -shared
libfnfqueue.so: fnfqueue.c ../include/fnfqueue.h
	$(CC) $(CFLAGS) -o libfnfqueue.so fnfqueue.c

clean:
	rm -f libfnfqueue.so
