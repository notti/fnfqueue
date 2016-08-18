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
	int ignore;
	struct nfq_queue *queue = arg;
	struct iovec iov;
	struct sockaddr_nl sa = { AF_NETLINK };
	struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
	struct nlmsghdr *nh;
	struct nlmsgerr *err;
	struct nlattr *attr;
	struct nfgenmsg *nfg;
	struct nfq_packet *packet;

	for(;;) {
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &ignore);
		pthread_mutex_lock(&queue->empty.mutex);
		for(;;) {
			if (queue->empty.head != NULL) {
				packet = queue->empty.head;
				queue->empty.head = packet->next;
				if (queue->empty.head == NULL) {
					queue->empty.last = NULL;
				}
				break;
			}
			pthread_cond_wait(&queue->empty.cond, &queue->empty.mutex);
		}
		pthread_mutex_unlock(&queue->empty.mutex);
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &ignore);
		
		iov.iov_base = packet->buffer;
		iov.iov_len = packet->len;

		len = recvmsg(queue->fd, &msg, 0);

		nh = (struct nlmsghdr *) packet->buffer;

/*		//FIXME
 		if (nh->nlmsg_type == NLMSG_ERROR) {
			err = (struct nlmsgerr *) NLMSG_DATA(nh);
			printf("Error %d %s!\n", err->error,
					strerror(-1*err->error));
			continue;
		}
		//FIXME
		if (nh->nlmsg_type != ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET)) {
			printf("Unknown type %d!\n", err->error);
			continue;
		} */

		nfg = (struct nfgenmsg *) NLMSG_DATA(nh);

		for(attr = (struct nlattr *)(NLMSG_DATA(nh) + NLA_ALIGN(sizeof(struct nfgenmsg)));
				(attr < (struct nlattr*)(nh + nh->nlmsg_len)) && (attr->nla_len >= sizeof(struct nlattr));
				attr = (struct nlattr *)((void *)attr + NLA_ALIGN(attr->nla_len))) {
			packet->attr[attr->nla_type].buffer = (void*)attr +
				NLA_HDRLEN;
			packet->attr[attr->nla_type].len = attr->nla_len -
				NLA_HDRLEN;
		}

		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &ignore);
		pthread_mutex_lock(&queue->msg.mutex);
		packet->next = NULL;
		if (queue->msg.head == NULL) {
			queue->msg.head = packet;
		}
		if (queue->msg.last != NULL) {
			queue->msg.last->next = packet;
		}
		queue->msg.last = packet;
		pthread_cond_broadcast(&queue->msg.cond);
		pthread_mutex_unlock(&queue->msg.mutex);
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &ignore);
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

	queue->empty.head = NULL;
	queue->empty.last = NULL;
	queue->msg.head = NULL;
	queue->msg.last = NULL;
	queue->error.head = NULL;
	queue->error.last = NULL;

	pthread_mutex_init(&queue->empty.mutex,  NULL);
	pthread_cond_init(&queue->empty.cond, NULL);
	pthread_mutex_init(&queue->msg.mutex,  NULL);
	pthread_cond_init(&queue->msg.cond, NULL);
	pthread_mutex_init(&queue->error.mutex,  NULL);
	pthread_cond_init(&queue->error.cond, NULL);

	struct nfqnl_msg_config_cmd cmd = {
		NFQNL_CFG_CMD_BIND
	};
	send_msg(queue, NFQA_CFG_CMD, &cmd, sizeof(cmd)); //check ret

	if (pthread_create(&queue->processing, NULL, process, queue)) {
		perror("pthread failed");
		exit(-1);
	}
}


void stop_queue(struct nfq_queue *queue) {
	pthread_cancel(queue->processing);
	pthread_join(queue->processing, NULL);

	close(queue->fd);

	pthread_mutex_destroy(&queue->empty.mutex);
	pthread_cond_destroy(&queue->empty.cond);
	pthread_mutex_destroy(&queue->msg.mutex);
	pthread_cond_destroy(&queue->msg.cond);
	pthread_mutex_destroy(&queue->error.mutex);
	pthread_cond_destroy(&queue->error.cond);
}

void get_packet(struct nfq_queue *queue, struct nfq_packet **packet) {
	pthread_mutex_lock(&queue->msg.mutex);
	for(;;) {
		if (queue->msg.head != NULL) {
			*packet = queue->msg.head;
			queue->msg.head = (*packet)->next;
			if (queue->msg.head == NULL) {
				queue->msg.last = NULL;
			}
			break;
		}
		pthread_cond_wait(&queue->msg.cond, &queue->msg.mutex);
	}
	pthread_mutex_unlock(&queue->msg.mutex);
}

void add_empty(struct nfq_queue *queue, struct nfq_packet *packet) {
	for(int i=0; i<=NFQA_MAX; i++) {
		packet->attr[i].buffer = NULL;
		packet->attr[i].len = 0;
	}
	packet->error = 0;
	packet->seq = 0;
	packet->next = NULL;
	
	pthread_mutex_lock(&queue->empty.mutex);
	if (queue->empty.head == NULL) {
		queue->empty.head = packet;
	}
	if (queue->empty.last != NULL) {
		queue->empty.last->next = packet;
	}
	queue->empty.last = packet;
	pthread_cond_broadcast(&queue->empty.cond);
	pthread_mutex_unlock(&queue->empty.mutex);
}
