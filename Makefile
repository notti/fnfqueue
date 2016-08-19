nfq_main: nfq_main.c nfq_test.c
	clang -g -lpthread -o nfq_main nfq_main.c nfq_test.c

