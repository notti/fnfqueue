#define _GNU_SOURCE //we want recvmmsg
#include "nfq_main.h"
#include <sys/socket.h>
#include <errno.h>

#include <alloca.h>

#include <stdlib.h> //remove
#include <string.h> //remove
#include <stdio.h> //remove

int send_msg(struct nfq_connection *conn, uint16_t id, uint16_t type,
		struct nfq_attr *attr, int n) {
	//Add synchronous version
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
		.nlmsg_flags = NLM_F_REQUEST, // | NLM_F_ACK,
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
	}

	struct sockaddr_nl sa = { AF_NETLINK };
	struct msghdr msg = { &sa, sizeof(sa), iov, 1 + n*3, NULL, 0, 0 };

	if ((ret = sendmsg(conn->fd, &msg, 0)) == -1) {
		return ret;
	}

	free(attr_buf);
	free(iov);

	return 0;
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
	struct nfqnl_msg_verdict_hdr verdict_hdr = {
		htonl(verdict),
		htonl(packet->id)
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
		attr[n].type = NFQA_MARK;
		n++;
	}
	if (mangle & MANGLE_PAYLOAD) {
		attr[n] = packet->attr[NFQA_PAYLOAD];
		attr[n].type = NFQA_PAYLOAD;
		n++;
	}
	if (mangle & MANGLE_CT) {
		attr[n] = packet->attr[NFQA_CT];
		attr[n].type = NFQA_CT;
		n++;
	}
	if (mangle & MANGLE_EXP) {
		attr[n] = packet->attr[NFQA_EXP];
		attr[n].type = NFQA_EXP;
		n++;
	}
	if (mangle & MANGLE_VLAN) {
		attr[n] = packet->attr[NFQA_VLAN];
		attr[n].type = NFQA_VLAN;
		n++;
	}
	return send_msg(conn, packet->queue_id, NFQNL_MSG_VERDICT, attr, n);
}

void parse_packet(struct msghdr *msg, struct nfq_packet *packet, ssize_t len) {
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
		packet->error = err->error;
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
			(attr < (struct nlattr*)(nh + nh->nlmsg_len)) &&
			(attr->nla_len >= sizeof(struct nlattr)) &&
			(void*)attr < (packet->buffer + len);
			attr = (struct nlattr *)((void *)attr + NLA_ALIGN(attr->nla_len))) {
		packet->attr[attr->nla_type & NLA_TYPE_MASK].buffer = (void*)attr + NLA_HDRLEN;
		packet->attr[attr->nla_type & NLA_TYPE_MASK].len = attr->nla_len - NLA_HDRLEN;
	}

	struct nfqnl_msg_packet_hdr *hdr = packet->attr[NFQA_PACKET_HDR].buffer;
	packet->id = ntohl(hdr->packet_id);
}

int receive(struct nfq_connection *conn, struct nfq_packet *packets[], int num) {
	int len;
	int i, j;
	struct sockaddr_nl sa = { AF_NETLINK };


	if (num == 1) {
		struct iovec iov;
		struct msghdr msg = {&sa, sizeof(sa), &iov, 1, NULL, 0, 0};
		for(j=0; j<=NFQA_MAX; j++) {
			packets[0]->attr[j].buffer = NULL;
			packets[0]->attr[j].len = 0;
		}
		packets[0]->error = 0;

		iov.iov_base = packets[0]->buffer;
		iov.iov_len = packets[0]->len;

		len = recvmsg(conn->fd, &msg, 0);

		if (len == -1)
			return -errno;

		parse_packet(&msg, packets[0], len);

		return 1;
	}

	struct iovec *iov = alloca(num * sizeof(struct iovec));
	struct mmsghdr *mmsg = alloca(num * sizeof(struct mmsghdr));

	for(i=0; i<num; i++) {
		for(j=0; j<=NFQA_MAX; j++) {
			packets[i]->attr[j].buffer = NULL;
			packets[i]->attr[j].len = 0;
		}
		packets[i]->error = 0;
	}

	for(i=0; i<num; i++) {
		iov[i].iov_base = packets[i]->buffer;
		iov[i].iov_len = packets[i]->len;

		mmsg[i].msg_hdr = (struct msghdr){&sa, sizeof(sa), &iov[i], 1, NULL, 0, 0};
	}

	len = recvmmsg(conn->fd, mmsg, num, MSG_WAITFORONE, NULL);

	if (len == -1) {
		return -errno;
	}

	for(i=0; i<len; i++) {
		parse_packet(&mmsg[i].msg_hdr, packets[i], mmsg[i].msg_len);
	}
	return len;
}

int init_connection(struct nfq_connection *conn, int flags) {
	struct sockaddr_nl sa = { AF_NETLINK };

	if ((conn->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)) == -1) {
		return -1;
	}
	if (bind(conn->fd, (struct sockaddr *) &sa, sizeof(sa))) {
		close(conn->fd);
		return -1;
	}
	int buf = 21299200;
	setsockopt(conn->fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
	setsockopt(conn->fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));

	conn->seq = 0;

	return 0;
}

void close_connection(struct nfq_connection *conn) {
	close(conn->fd);
}

