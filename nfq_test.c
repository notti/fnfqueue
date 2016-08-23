#include "nfq_main.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct buffer {
	struct nfq_packet *packets;
	int num;
	struct buffer *next;
};

void cb(struct nfq_connection *conn, void *data) {
	struct buffer *buf = data;
	int i;
	printf("queue empty\n");
	while(buf->next != NULL)
		buf = buf->next;
	buf->next = malloc(sizeof(struct buffer));
	buf = buf->next;
	buf->packets = malloc(3 * sizeof(struct nfq_packet));
	buf->num = 3;
	buf->next = NULL;
	for(i = 0; i < 3; i++) {
		buf->packets[i].buffer = malloc(8192);
		buf->packets[i].len = 8192;
	}
	add_empty(conn, buf->packets, 3);
}

int main(int argc, char *argv[]) {

	struct nfq_connection conn;
	struct buffer *buf;
	struct nfq_packet *packet;
	int i;
	int id = 1;

	init_connection(&conn, 0);
	buf = malloc(sizeof(struct buffer));
	buf->packets = malloc(3 * sizeof(struct nfq_packet));
	buf->num = 3;
	buf->next = NULL;
	for(i = 0; i < 3; i++) {
		buf->packets[i].buffer = malloc(8192);
		buf->packets[i].len = 8192;
	}
	add_empty(&conn, buf->packets, 3);
	set_empty_cb(&conn, cb, buf);

	printf("bind: %s\n", strerror(bind_queue(&conn, id)));
	printf("set_mode: %s\n", strerror(set_mode(&conn, id, 1000, NFQNL_COPY_PACKET)));


	for(int i=0; i<3; i++) {
		printf("get_packet: %d ", get_packet(&conn, &packet, 1));
		printf("seq: %d\n", packet->seq);
		for (int j=0; j<packet->attr[NFQA_PAYLOAD].len; j++)
			printf(" %02X", ((char *)packet->attr[NFQA_PAYLOAD].buffer)[j] & 0xFF);
		printf("\n");
	//	printf("verdict: %s\n", strerror(set_verdict(&conn, packet, NF_ACCEPT, MANGLE_PAYLOAD)));
		add_empty(&conn, packet, 1);
	}

	close_connection(&conn);

	struct buffer *prev = NULL;

	do {
		if(prev != NULL)
			free(prev);
		for(i=0; i<buf->num; i++)
			free(buf->packets[i].buffer);
		free(buf->packets);
		prev = buf;
		buf = buf->next;
	} while(buf != NULL);
	free(prev);

	return 0;
}

