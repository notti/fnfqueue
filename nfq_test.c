#include "nfq_main.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {

	struct nfq_connection conn;
	struct nfq_packet packets[3];
	struct nfq_packet *packet;
	int i;
	int id = 1;

	init_connection(&conn, 0);
	for(i = 0; i < 3; i++) {
		packets[i].buffer = malloc(8192);
		packets[i].len = 8192;
		add_empty(&conn, &packets[i]);
	}

	/* must take care of message sequence numbers in order to
		reliably track acknowledgements.*/
	struct nfqnl_msg_config_cmd cmd = {
		NFQNL_CFG_CMD_BIND
	};
	send_msg(&conn, id, NFQA_CFG_CMD, &cmd, sizeof(cmd)); //check ret

	struct nfqnl_msg_config_params params = {
		htonl(1000),
		NFQNL_COPY_PACKET
	};
	send_msg(&conn, id, NFQA_CFG_PARAMS, &params, sizeof(params));

	for(int i=0; i<3; i++) {
		get_packet(&conn, &packet);
		for (int j=0; j<packet->attr[NFQA_PAYLOAD].len; j++)
			printf(" %02X", ((char *)packet->attr[NFQA_PAYLOAD].buffer)[j] & 0xFF);
		printf("\n");
		add_empty(&conn, packet);
	}

	close_connection(&conn);

	for(i = 0; i < 3; i++) {
		free(packets[i].buffer);
	}

	return 0;
}


