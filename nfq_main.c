#include "nfq_main.h"
#include <sys/socket.h>

#include <stdlib.h> //remove
#include <string.h> //remove
#include <stdio.h> //remove

ssize_t send_msg(struct nfq_connection *conn, uint16_t id, __u16 type,
		void *data, size_t len) {
	char buf[BASE_SIZE];
	ssize_t ret;
	void *buf_ass = buf;
	struct nlmsghdr *nh = buf_ass;
	*nh = (struct nlmsghdr){
		.nlmsg_len = BASE_SIZE + NLMSG_ALIGN(len),
		.nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG,
		.nlmsg_flags = NLM_F_REQUEST,// | NLM_F_ACK,
		.nlmsg_seq = conn->seq++,
	};
	buf_ass += NLMSG_ALIGN(sizeof(struct nlmsghdr));
	struct nfgenmsg *nfg = buf_ass;
	*nfg = (struct nfgenmsg){
		.nfgen_family = AF_UNSPEC,
		.version = NFNETLINK_V0,
		.res_id = htons(id)
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

	if ((ret = sendmsg(conn->fd, &msg, 0)) == -1) {
		return ret;
	}

	// wait for result
	
	return 0;
}

void *process(void *arg) {
	int len;
	int ignore;
	struct nfq_connection *conn = arg;
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
		pthread_mutex_lock(&conn->empty.mutex);
		for(;;) {
			if (conn->empty.head != NULL) {
				packet = conn->empty.head;
				conn->empty.head = packet->next;
				if (conn->empty.head == NULL) {
					conn->empty.last = NULL;
				}
				break;
			}
			pthread_cond_wait(&conn->empty.cond, &conn->empty.mutex);
		}
		pthread_mutex_unlock(&conn->empty.mutex);
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &ignore);
		
		iov.iov_base = packet->buffer;
		iov.iov_len = packet->len;

		len = recvmsg(conn->fd, &msg, 0);

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
		pthread_mutex_lock(&conn->msg.mutex);
		packet->next = NULL;
		if (conn->msg.head == NULL) {
			conn->msg.head = packet;
		}
		if (conn->msg.last != NULL) {
			conn->msg.last->next = packet;
		}
		conn->msg.last = packet;
		pthread_cond_broadcast(&conn->msg.cond);
		pthread_mutex_unlock(&conn->msg.mutex);
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &ignore);
	}
}

void init_connection(struct nfq_connection *conn, int flags) {
	struct sockaddr_nl sa = { AF_NETLINK };

	if ((conn->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)) == -1) {
		perror("socket failed");
		exit(-1);
	}
	if (bind(conn->fd, (struct sockaddr *) &sa, sizeof(sa))) {
		perror("bind failed");
		exit(-1);
	}

	conn->seq = 0;

	conn->empty.head = NULL;
	conn->empty.last = NULL;
	conn->msg.head = NULL;
	conn->msg.last = NULL;
	conn->error.head = NULL;
	conn->error.last = NULL;

	pthread_mutex_init(&conn->empty.mutex,  NULL);
	pthread_cond_init(&conn->empty.cond, NULL);
	pthread_mutex_init(&conn->msg.mutex,  NULL);
	pthread_cond_init(&conn->msg.cond, NULL);
	pthread_mutex_init(&conn->error.mutex,  NULL);
	pthread_cond_init(&conn->error.cond, NULL);

	if (pthread_create(&conn->processing, NULL, process, conn)) {
		perror("pthread failed");
		exit(-1);
	}
}


void close_connection(struct nfq_connection *conn) {
	pthread_cancel(conn->processing);
	pthread_join(conn->processing, NULL);

	close(conn->fd);

	pthread_mutex_destroy(&conn->empty.mutex);
	pthread_cond_destroy(&conn->empty.cond);
	pthread_mutex_destroy(&conn->msg.mutex);
	pthread_cond_destroy(&conn->msg.cond);
	pthread_mutex_destroy(&conn->error.mutex);
	pthread_cond_destroy(&conn->error.cond);
}

void get_packet(struct nfq_connection *conn, struct nfq_packet **packet) {
	pthread_mutex_lock(&conn->msg.mutex);
	for(;;) {
		if (conn->msg.head != NULL) {
			*packet = conn->msg.head;
			conn->msg.head = (*packet)->next;
			if (conn->msg.head == NULL) {
				conn->msg.last = NULL;
			}
			break;
		}
		pthread_cond_wait(&conn->msg.cond, &conn->msg.mutex);
	}
	pthread_mutex_unlock(&conn->msg.mutex);
}

void add_empty(struct nfq_connection *conn, struct nfq_packet *packet) {
	for(int i=0; i<=NFQA_MAX; i++) {
		packet->attr[i].buffer = NULL;
		packet->attr[i].len = 0;
	}
	packet->error = 0;
	packet->seq = 0;
	packet->next = NULL;
	
	pthread_mutex_lock(&conn->empty.mutex);
	if (conn->empty.head == NULL) {
		conn->empty.head = packet;
	}
	if (conn->empty.last != NULL) {
		conn->empty.last->next = packet;
	}
	conn->empty.last = packet;
	pthread_cond_broadcast(&conn->empty.cond);
	pthread_mutex_unlock(&conn->empty.mutex);
}
