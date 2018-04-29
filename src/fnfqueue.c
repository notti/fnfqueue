#define _GNU_SOURCE //we want recvmmsg
#include "fnfqueue.h"
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <alloca.h>

ssize_t send_msg(struct nfq_connection *conn, uint16_t id, uint16_t type,
		struct nfq_attr *attr, int n, int ack, uint32_t seq) {
	char buf[NFQ_BASE_SIZE];
	void *buf_ass = buf;
	struct nlmsghdr *nh = buf_ass;

	*nh = (struct nlmsghdr){
		.nlmsg_len = NFQ_BASE_SIZE,
		.nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | type,
		.nlmsg_flags = NLM_F_REQUEST,
		.nlmsg_seq = seq,
	};
	if (ack)
		nh->nlmsg_flags |= NLM_F_ACK;
	buf_ass += NLMSG_ALIGN(sizeof(struct nlmsghdr));
	struct nfgenmsg *nfg = buf_ass;
	*nfg = (struct nfgenmsg){
		.nfgen_family = AF_UNSPEC,
		.version = NFNETLINK_V0,
		.res_id = htons(id)
	};
	buf_ass += NLMSG_ALIGN(sizeof(struct nfgenmsg));

	struct nlattr *attr_buf = alloca(n * NLA_HDRLEN);
	struct iovec *iov = alloca((n*3+1)*sizeof(struct iovec));

	iov[0] = (struct iovec){buf, NFQ_BASE_SIZE};

	int i;
	for(i=0; i<n; i++) {
		attr_buf[i * NLA_HDRLEN].nla_len = NLA_HDRLEN + attr[i].len;
		attr_buf[i * NLA_HDRLEN].nla_type = attr[i].type;
		iov[1 + i*3] = (struct iovec){&attr_buf[i*NLA_HDRLEN],
			NLA_HDRLEN};
		iov[1 + i*3 + 1] = (struct iovec){attr[i].buffer,
			attr[i].len};
		iov[1 + i*3 + 2] = (struct iovec){buf,
			NLA_ALIGN(attr_buf[i * NLA_HDRLEN].nla_len) -
				attr_buf[i * NLA_HDRLEN].nla_len};
		nh->nlmsg_len += NLA_ALIGN(attr_buf[i * NLA_HDRLEN].nla_len);
	}

	struct sockaddr_nl sa = { AF_NETLINK };
	struct msghdr msg = { &sa, sizeof(sa), iov, 1 + n*3, NULL, 0, 0 };

	if (sendmsg(conn->fd, &msg, 0) == -1) {
		return -1;
	}

	return 0;
}

int bind_queue(struct nfq_connection *conn, uint16_t queue_id, int ack,
		uint32_t seq) {
	struct nfqnl_msg_config_cmd cmd = {
		NFQNL_CFG_CMD_BIND
	};
	struct nfq_attr attr = {
		&cmd,
		sizeof(cmd),
		NFQA_CFG_CMD
	};
	return send_msg(conn, queue_id, NFQNL_MSG_CONFIG, &attr, 1, ack, seq);
}

int unbind_queue(struct nfq_connection *conn, uint16_t queue_id, int ack,
		uint32_t seq) {
	struct nfqnl_msg_config_cmd cmd = {
		NFQNL_CFG_CMD_UNBIND
	};
	struct nfq_attr attr = {
		&cmd,
		sizeof(cmd),
		NFQA_CFG_CMD
	};
	return send_msg(conn, queue_id, NFQNL_MSG_CONFIG, &attr, 1, ack, seq);
}

int set_mode(struct nfq_connection *conn, uint16_t queue_id, uint32_t range,
		uint8_t mode, int ack, uint32_t seq) {
	struct nfqnl_msg_config_params params = {
		htonl(range),
		mode
	};
	struct nfq_attr attr = {
		&params,
		sizeof(params),
		NFQA_CFG_PARAMS
	};
	return send_msg(conn, queue_id, NFQNL_MSG_CONFIG, &attr, 1, ack, seq);
}

int set_flags(struct nfq_connection *conn, uint16_t queue_id, uint32_t flags,
		uint32_t mask, int ack, uint32_t seq) {
	uint32_t f = htonl(flags);
	uint32_t m = htonl(mask);
	struct nfq_attr attr[2] = {{
		&f,
		sizeof(f),
		NFQA_CFG_FLAGS
	},{
		&m,
		sizeof(m),
		NFQA_CFG_MASK
	}};
	return send_msg(conn, queue_id, NFQNL_MSG_CONFIG, attr, 2, ack, seq);
}

int set_maxlen(struct nfq_connection *conn, uint16_t queue_id, uint32_t len,
		int ack, uint32_t seq) {
	uint32_t l = htonl(len);
	struct nfq_attr attr = {
		&l,
		sizeof(l),
		NFQA_CFG_QUEUE_MAXLEN
	};
	return send_msg(conn, queue_id, NFQNL_MSG_CONFIG, &attr, 1, ack, seq);
}

int set_verdict(struct nfq_connection *conn, struct nfq_packet *packet,
		uint32_t verdict, uint32_t mangle, int ack, uint32_t seq) {
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
#if NFQA_MAX >= 15
	if (mangle & MANGLE_EXP) {
		attr[n] = packet->attr[NFQA_EXP];
		attr[n].type = NFQA_EXP;
		n++;
	}
#endif
#if NFQA_MAX >= 20
	if (mangle & MANGLE_VLAN) {
		attr[n] = packet->attr[NFQA_VLAN];
		attr[n].type = NFQA_VLAN;
		n++;
	}
#endif
	return send_msg(conn, packet->queue_id, NFQNL_MSG_VERDICT, attr, n, ack,
			seq);
}

int set_verdict_batch(struct nfq_connection *conn, struct nfq_packet *packet,
		uint32_t verdict, uint32_t mangle, int ack, uint32_t seq) {
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
	return send_msg(conn, packet->queue_id, NFQNL_MSG_VERDICT_BATCH, attr,
			n, ack, seq);
}

int parse_packet(struct nfq_packet *packet) {
	struct nlmsghdr *nh = packet->buffer;
	struct nfgenmsg *nfg;
	struct nlattr *attr;

	if (packet->msg_flags & MSG_TRUNC) {
		return ENOMEM;
	}

	if (nh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = NLMSG_DATA(nh);
		if (err->error == 0)
			return -1;
		return -err->error;
	}

	if (nh->nlmsg_type != ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET)) {
		return EBADMSG;
	}

	nfg = (struct nfgenmsg *) NLMSG_DATA(nh);
	packet->queue_id = ntohs(nfg->res_id);

	memset(packet->attr, 0, sizeof(struct nfq_attr)*NFQA_MAX);

	for(attr = (struct nlattr *)(NLMSG_DATA(nh) + NLA_ALIGN(sizeof(struct nfgenmsg)));
			(attr < (struct nlattr*)(nh + nh->nlmsg_len)) &&
			(attr->nla_len >= sizeof(struct nlattr)) &&
			(void*)attr < (packet->buffer + packet->msg_len);
			attr = (struct nlattr *)((void *)attr + NLA_ALIGN(attr->nla_len))) {
		packet->attr[attr->nla_type & NLA_TYPE_MASK].buffer = (void*)attr + NLA_HDRLEN;
		packet->attr[attr->nla_type & NLA_TYPE_MASK].len = attr->nla_len - NLA_HDRLEN;
	}

	struct nfqnl_msg_packet_hdr *hdr = packet->attr[NFQA_PACKET_HDR].buffer;
	packet->id = ntohl(hdr->packet_id);
	packet->hw_protocol = ntohs(hdr->hw_protocol);
	packet->hook = hdr->hook;
	return 0;
}

int receive(struct nfq_connection *conn, struct nfq_packet *packets[], int num) {
	int len;
	int i;
	struct sockaddr_nl sa = { AF_NETLINK };
	struct iovec *iov = alloca(num * sizeof(struct iovec));
	struct mmsghdr *mmsg = alloca(num * sizeof(struct mmsghdr));

	for(i=0; i<num; i++) {
		iov[i].iov_base = packets[i]->buffer;
		iov[i].iov_len = packets[i]->len;

		mmsg[i].msg_hdr = (struct msghdr){&sa, sizeof(sa), &iov[i], 1, NULL, 0, 0};
	}

	len = recvmmsg(conn->fd, mmsg, num, MSG_WAITFORONE, NULL);

	if (len == -1) {
		return -1;
	}

	for(i=0; i<len; i++) {
		packets[i]->msg_flags = mmsg[i].msg_hdr.msg_flags;
		packets[i]->msg_len = mmsg[i].msg_len;
		packets[i]->seq = ((struct nlmsghdr *)packets[i]->buffer)->nlmsg_seq;
	}

	return len;
}

int init_connection(struct nfq_connection *conn) {
	struct sockaddr_nl sa = { AF_NETLINK };

	if ((conn->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)) == -1) {
		return -1;
	}
	if (bind(conn->fd, (struct sockaddr *) &sa, sizeof(sa))) {
		close(conn->fd);
		return -1;
	}
	return 0;
}

void close_connection(struct nfq_connection *conn) {
	close(conn->fd);
}

