#include "nfq_main.h"
#include <sys/socket.h>

#include <stdlib.h> //remove
#include <string.h> //remove
#include <stdio.h> //remove

ssize_t send_msg(struct nfq_queue *queue, __u16 type, void *data, size_t len) {
	char buf[BASE_SIZE];
	ssize_t ret;
	void *buf_ass = buf;
	struct nlmsghdr *nh = buf_ass;
	*nh = (struct nlmsghdr){
		.nlmsg_len = BASE_SIZE + NLMSG_ALIGN(len),
		.nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG,
		.nlmsg_flags = NLM_F_REQUEST,// | NLM_F_ACK,
		.nlmsg_seq = queue->seq++,
	};
	buf_ass += NLMSG_ALIGN(sizeof(struct nlmsghdr));
	struct nfgenmsg *nfg = buf_ass;
	*nfg = (struct nfgenmsg){
		.nfgen_family = AF_UNSPEC,
		.version = NFNETLINK_V0,
		.res_id = htons(queue->id)
	};
	buf_ass += NLMSG_ALIGN(sizeof(struct nfgenmsg));
	struct nlattr *attr = buf_ass;
	*attr = (struct nlattr){
		.nla_len = NLMSG_ALIGN(sizeof(struct nlattr)) + len,
		.nla_type = type
	};

	struct iovec iov[] = {
		{buf, BASE_SIZE},
		{data, len},
		{buf, NLMSG_ALIGN(len) - len}
	};
	struct sockaddr_nl sa = { AF_NETLINK };
	struct msghdr msg = { &sa, sizeof(sa), iov, 3, NULL, 0, 0 };

	if ((ret = sendmsg(queue->fd, &msg, 0)) == -1) {
		return ret;
	}

	// wait for result
	
	return 0;
}

void *process(void *arg) {
	int len;
	struct nfq_queue *queue = arg;
	char buf[4096];
	struct iovec iov = { buf, sizeof(buf) };
	struct sockaddr_nl sa = { AF_NETLINK };
	struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
	struct nlmsghdr *nh;
	struct nlmsgerr *err;
	struct nlattr *attr;
	struct nfgenmsg *nfg;

	for(;;) {

		len = recvmsg(queue->fd, &msg, 0);
		nh = (struct nlmsghdr *) buf;
		if (nh->nlmsg_type == NLMSG_ERROR) {
			err = (struct nlmsgerr *) NLMSG_DATA(nh);
			printf("Error %d %s!\n", err->error,
					strerror(-1*err->error));
			continue;
		}
		if (nh->nlmsg_type != ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET)) {
			printf("Unknown type %d!\n", err->error);
			continue;
		}
		nfg = (struct nfgenmsg *) NLMSG_DATA(nh);
		printf("queue: %d ", ntohs(nfg->res_id));
		for(attr = (struct nlattr *)(NLMSG_DATA(nh) + NLMSG_ALIGN(sizeof(struct nfgenmsg)));
				(attr < (struct nlattr*)(nh + nh->nlmsg_len)) && (attr->nla_len >= sizeof(struct nlattr));
				attr = (struct nlattr *)((void *)attr + NLMSG_ALIGN(attr->nla_len))) {
			if (attr->nla_type == NFQA_PAYLOAD) {
				for (char *buffer=(char *)((void*)attr + NLMSG_ALIGN(sizeof(struct nlattr)));
						buffer < (char *)((void*)attr + attr->nla_len);
						buffer++)
					printf(" %02X", *buffer & 0xFF);
			}
		}
		printf("\n");
	}
}

void init_queue(struct nfq_queue *queue, uint16_t id) {
	struct sockaddr_nl sa = { AF_NETLINK };

	if ((queue->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)) == -1) {
		perror("socket failed");
		exit(-1);
	}
	if (bind(queue->fd, (struct sockaddr *) &sa, sizeof(sa))) {
		perror("bind failed");
		exit(-1);
	}

	queue->seq = 0;
	queue->id = id;

	struct nfqnl_msg_config_cmd cmd = {
		NFQNL_CFG_CMD_BIND
	};
	send_msg(queue, NFQA_CFG_CMD, &cmd, sizeof(cmd)); //check ret

	if (pthread_create(&(queue->processing), NULL, process, queue)) {
		perror("pthread failed");
		exit(-1);
	}
}


void stop_queue(struct nfq_queue *queue) {
	pthread_cancel(queue->processing);
	pthread_join(queue->processing, NULL);
	close(queue->fd);
}

