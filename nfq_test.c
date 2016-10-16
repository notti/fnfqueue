#include "nfq_main.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int main(int argc, char *argv[]) {

	struct nfq_connection conn;
	struct buffer *buf;
	struct nfq_packet **packets;
	int i;
	int num;
	int id = 1;
	int res;
	int chunk;

	if (argc == 1) {
		chunk = 10;
	} else {
		chunk = atoi(argv[1]);
	}

	packets = malloc(sizeof(struct nfq_packet*)*chunk);

	init_connection(&conn);
	for(i = 0; i < chunk; i++) {
		packets[i] = malloc(sizeof(struct nfq_packet));
		packets[i]->buffer = malloc(20*4096);
		packets[i]->len = 20*4096;
	}

	bind_queue(&conn, id);
	set_mode(&conn, id, 0xffff, NFQNL_COPY_PACKET);

	printf("started\n");
	fflush(stdout);

	for(;;) {
		num = receive(&conn, packets, chunk);
		if(num == -1) {
			perror("Receive failed");
		}
		for(i=0; i<num; i++) {
			res = parse_packet(packets[i]);
			if (res == 0)
				set_verdict(&conn, packets[i], NF_ACCEPT, MANGLE_PAYLOAD);
			else {
				errno = res;
				perror("error from kernel");
			}
		}
	}

	close_connection(&conn);
	for(i = 0; i < 10; i++) {
		free(packets[i]->buffer);
		free(packets[i]);
	}
	free(packets);

	return 0;
}

