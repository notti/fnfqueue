#include "nfq_main.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int main(int argc, char *argv[]) {

	struct nfq_connection conn;
	struct buffer *buf;
	struct nfq_packet *packets[10];
	int i;
	int num;
	int id = 1;
	int res;

	init_connection(&conn);
	for(i = 0; i < 10; i++) {
		packets[i] = malloc(sizeof(struct nfq_packet));
		packets[i]->buffer = malloc(20*4096);
		packets[i]->len = 20*4096;
	}

	bind_queue(&conn, id);
	set_mode(&conn, id, 0xffff, NFQNL_COPY_PACKET);

	for(;;) {
		num = receive(&conn, packets, 10);
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

	return 0;
}

