#include "nfq_main.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {

	struct nfq_queue queue;

	init_queue(&queue, 1);

	/* must take care of message sequence numbers in order to
		reliably track acknowledgements.*/

	struct nfqnl_msg_config_params params = {
		htonl(1000),
		NFQNL_COPY_PACKET
	};
	send_msg(&queue, NFQA_CFG_PARAMS, &params, sizeof(params));

	sleep(10);

	stop_queue(&queue);

	return 0;
}


