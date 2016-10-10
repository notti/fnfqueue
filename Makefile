.PHONY: clean

CC=clang

main: libnfq.so

libnfq.so: nfq_main.c nfq_main.h
	$(CC) -shared -O3 -fPIC -o libnfq.so nfq_main.c

nfq_test: nfq_test.c libnfq.so nfq_main.h
	$(CC) -g -L. -lnfq -O3 -o nfq_test nfq_test.c

clean:
	rm -f nfq_test libnfq.so
