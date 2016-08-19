#include "nfq_main.h"
#include <sys/socket.h>
#include <errno.h>

#include <stdlib.h> //remove
#include <string.h> //remove
#include <stdio.h> //remove

int send_msg(struct nfq_connection *conn, uint16_t id, uint16_t type,
		struct nfq_attr *attr, int n) {
	char buf[NFQ_BASE_SIZE];
	ssize_t ret;
	void *buf_ass = buf;
	struct nlmsghdr *nh = buf_ass;

	conn->seq++;
	if (conn->seq == 0)
		conn->seq = 1;

	*nh = (struct nlmsghdr){
		.nlmsg_len = NFQ_BASE_SIZE,
		.nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | type,
		.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
		.nlmsg_seq = conn->seq,
	};
	buf_ass += NLMSG_ALIGN(sizeof(struct nlmsghdr));
	struct nfgenmsg *nfg = buf_ass;
	*nfg = (struct nfgenmsg){
		.nfgen_family = AF_UNSPEC,
		.version = NFNETLINK_V0,
		.res_id = htons(id)
	};
	buf_ass += NLMSG_ALIGN(sizeof(struct nfgenmsg));

	void *attr_buf = malloc(n * NLA_HDRLEN);
	struct nlattr *a;
	struct iovec *iov = malloc((n*3+1)*sizeof(struct iovec));

	iov[0] = (struct iovec){buf, NFQ_BASE_SIZE};

	for(int i=0; i<n; i++) {
		a = &attr_buf[i * NLA_HDRLEN];
		a->nla_len = NLA_HDRLEN + attr[i].len;
		a->nla_type = attr[i].type;
		iov[1 + i*3] = (struct iovec){&attr_buf[i*NLA_HDRLEN],
			NLA_HDRLEN};
		iov[1 + i*3 + 1] = (struct iovec){attr[i].buffer,
			attr[i].len};
		iov[1 + i*3 + 2] = (struct iovec){buf,
			NLA_ALIGN(a->nla_len) - a->nla_len};
		nh->nlmsg_len += NLA_ALIGN(a->nla_len);
		printf("len: %d\n", a->nla_type);
	}

	struct sockaddr_nl sa = { AF_NETLINK };
	struct msghdr msg = { &sa, sizeof(sa), iov, 1 + n*3, NULL, 0, 0 };

	if ((ret = sendmsg(conn->fd, &msg, 0)) == -1) {
		return ret;
	}

	free(attr_buf);
	free(iov);

	struct nfq_packet *cur, *prev;

	pthread_mutex_lock(&conn->error.mutex);
	for(;;) {
		prev = NULL;
		for (cur=conn->error.head; cur; prev = cur, cur=cur->next) {
			if (cur->seq == conn->seq) {
				if (prev == NULL)
					conn->error.head = cur->next;
				else
					prev->next = cur->next;
				if (conn->error.head == NULL)
					conn->error.last = NULL;
				else if(conn->error.last == cur)
					conn->error.last = prev;
				break;
			}
		}
		if (cur && (cur->seq == conn->seq))
			break;
		pthread_cond_wait(&conn->error.cond, &conn->error.mutex);
	}
	pthread_mutex_unlock(&conn->error.mutex);

	ret = cur->error;

	add_empty(conn, cur, 1);

	if (ret == 1) //ACK
		return 0;
	return ret;
}

int bind_queue(struct nfq_connection *conn, uint16_t queue_id) {
	struct nfqnl_msg_config_cmd cmd = {
		NFQNL_CFG_CMD_BIND
	};
	struct nfq_attr attr = {
		&cmd,
		sizeof(cmd),
		NFQA_CFG_CMD
	};
	return send_msg(conn, queue_id, NFQNL_MSG_CONFIG, &attr, 1);
}

int unbind_queue(struct nfq_connection *conn, uint16_t queue_id) {
	struct nfqnl_msg_config_cmd cmd = {
		NFQNL_CFG_CMD_UNBIND
	};
	struct nfq_attr attr = {
		&cmd,
		sizeof(cmd),
		NFQA_CFG_CMD
	};
	return send_msg(conn, queue_id, NFQNL_MSG_CONFIG, &attr, 1);
}

int set_mode(struct nfq_connection *conn, uint16_t queue_id, uint32_t range,
		uint8_t mode) {
	struct nfqnl_msg_config_params params = {
		htonl(range),
		mode
	};
	struct nfq_attr attr = {
		&params,
		sizeof(params),
		NFQA_CFG_PARAMS
	};
	return send_msg(conn, queue_id, NFQNL_MSG_CONFIG, &attr, 1);
}

int set_verdict(struct nfq_connection *conn, struct nfq_packet *packet,
		uint32_t verdict, uint32_t mangle) {
	int n = 1;
	struct nfqnl_msg_packet_hdr *hdr = packet->attr[NFQA_PACKET_HDR].buffer;
	struct nfqnl_msg_verdict_hdr verdict_hdr = {
		htonl(verdict),
		hdr->packet_id
	};
	struct nfq_attr attr[MANGLE_MAX+1] = {
	{
		&verdict_hdr,
		sizeof(verdict_hdr),
		NFQA_VERDICT_HDR
	},
	};
	if (mangle & MANGLE_MARK) {
		attr[n] = packet->attr[NFQA_MARK];
		n++;
	}
	if (mangle & MANGLE_PAYLOAD) {
		attr[n] = packet->attr[NFQA_PAYLOAD];
		n++;
	}
	if (mangle & MANGLE_CT) {
		attr[n] = packet->attr[NFQA_CT];
		n++;
	}
	if (mangle & MANGLE_EXP) {
		attr[n] = packet->attr[NFQA_EXP];
		n++;
	}
	if (mangle & MANGLE_VLAN) {
		attr[n] = packet->attr[NFQA_VLAN];
		n++;
	}
	return send_msg(conn, packet->queue_id, NFQNL_MSG_VERDICT, attr, n);
}

void parse_packet(struct msghdr *msg, struct nfq_packet *packet) {
	struct nlmsghdr *nh = packet->buffer;
	struct nfgenmsg *nfg;
	struct nlattr *attr;

	packet->seq = nh->nlmsg_seq;

	if (msg->msg_flags & MSG_TRUNC) {
		packet->error = -ENOMEM;
		return;
	}

	if (nh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = NLMSG_DATA(nh);
		packet->error = -err->error;
		if (packet->error == 0)
			packet->error = 1;
		return;
	}

	if (nh->nlmsg_type != ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET)) {
		packet->error = -EBADMSG;
		return;
	}

	nfg = (struct nfgenmsg *) NLMSG_DATA(nh);
	packet->queue_id = ntohs(nfg->res_id);

	for(attr = (struct nlattr *)(NLMSG_DATA(nh) + NLA_ALIGN(sizeof(struct nfgenmsg)));
			(attr < (struct nlattr*)(nh + nh->nlmsg_len)) && (attr->nla_len >= sizeof(struct nlattr));
			attr = (struct nlattr *)((void *)attr + NLA_ALIGN(attr->nla_len))) {
		packet->attr[attr->nla_type & NLA_TYPE_MASK].buffer = (void*)attr + NLA_HDRLEN;
		packet->attr[attr->nla_type & NLA_TYPE_MASK].len = attr->nla_len - NLA_HDRLEN;
	}
}

void *process(void *arg) {
	int len;
	int ignore;
	struct nfq_connection *conn = arg;
	struct iovec iov;
	struct sockaddr_nl sa = { AF_NETLINK };
	struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
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

		parse_packet(&msg, packet);

		packet->next = NULL;

		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &ignore);
		if (packet->error && packet->seq) {
			pthread_mutex_lock(&conn->error.mutex);
			if (conn->error.head == NULL) {
				conn->error.head = packet;
			}
			if (conn->error.last != NULL) {
				conn->error.last->next = packet;
			}
			conn->error.last = packet;
			pthread_cond_broadcast(&conn->error.cond);
			pthread_mutex_unlock(&conn->error.mutex);
		} else {
			pthread_mutex_lock(&conn->msg.mutex);
			if (conn->msg.head == NULL) {
				conn->msg.head = packet;
			}
			if (conn->msg.last != NULL) {
				conn->msg.last->next = packet;
			}
			conn->msg.last = packet;
			pthread_cond_broadcast(&conn->msg.cond);
			pthread_mutex_unlock(&conn->msg.mutex);
		}
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

int get_packet(struct nfq_connection *conn, struct nfq_packet **packet, int n) {
	int i;
	struct nfq_packet *p;

	pthread_mutex_lock(&conn->msg.mutex);
	for(;;) {
		if (conn->msg.head != NULL) {
			for (p=conn->msg.head, i=0; p && (i<n);
					p = p->next, i++)
				packet[i] = p;
			conn->msg.head = p;
			if (conn->msg.head == NULL) {
				conn->msg.last = NULL;
			}
			break;
		}
		pthread_cond_wait(&conn->msg.cond, &conn->msg.mutex);
	}
	pthread_mutex_unlock(&conn->msg.mutex);

	return i;
}

void add_empty(struct nfq_connection *conn, struct nfq_packet *packet, int n) {
	int i,j;
	for (j=0; j<n; j++) {
		for(i=0; i<=NFQA_MAX; i++) {
			packet[j].attr[i].buffer = NULL;
			packet[j].attr[i].len = 0;
			packet[j].attr[i].type = i;
		}
		packet[j].error = 0;
		packet[j].seq = 0;
		if (j == (n - 1))
			packet[j].next = NULL;
		else
			packet[j].next = &packet[j+1];
	}

	pthread_mutex_lock(&conn->empty.mutex);
	if (conn->empty.head == NULL) {
		conn->empty.head = &packet[0];
	}
	if (conn->empty.last != NULL) {
		conn->empty.last->next = &packet[0];
	}
	conn->empty.last = &packet[n-1];
	pthread_cond_broadcast(&conn->empty.cond);
	pthread_mutex_unlock(&conn->empty.mutex);
}

