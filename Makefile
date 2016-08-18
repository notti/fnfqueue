nfq_main: nfq_main.c nfq_test.c
	clang -lpthread -o nfq_main nfq_main.c nfq_test.c

