#ifndef NFQ_MAIN_H
#define NFQ_MAIN_H

#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <arpa/inet.h>

#define NF_DROP 0
#define NF_ACCEPT 1
#define NF_STOLEN 2
#define NF_QUEUE 3
#define NF_REPEAT 4
#define NF_STOP 5

#define MANGLE_MARK    (1 << 0)
#define MANGLE_PAYLOAD (1 << 1)
#define MANGLE_CT      (1 << 2)
#define MANGLE_EXP     (1 << 3)
#define MANGLE_VLAN    (1 << 4)

#define MANGLE_MAX     5


struct nfq_attr {
	void *buffer;
	size_t len;
	uint16_t type;
};

struct nfq_packet {
	void *buffer;
	size_t len;
	int error;
	uint32_t  seq;
	uint16_t queue_id;
	uint32_t id;
	struct nfq_attr attr[NFQA_MAX + 1];
	struct nfq_packet *next;
};

struct nfq_list {
	struct nfq_packet *head;
	struct nfq_packet *last;
	pthread_mutex_t mutex;
	int cond;
};

struct nfq_connection {
	int fd;
	uint32_t seq;
// synchronous version?
	pthread_t processing;
	void (*empty_cb)(struct nfq_connection *, void*);
	void *empty_data;
	struct nfq_list empty;
	struct nfq_list msg;
	struct nfq_list error;
};

#define NFQ_BASE_SIZE (NLMSG_ALIGN(sizeof(struct nlmsghdr)) + \
		       NLMSG_ALIGN(sizeof(struct nfgenmsg)))

int send_msg(struct nfq_connection *conn, uint16_t id, uint16_t type,
		struct nfq_attr *attr, int n);
void parse_packet(struct msghdr *msg, struct nfq_packet *packet);
int init_connection(struct nfq_connection *conn, int flags);
void close_connection(struct nfq_connection *conn);
void set_empty_cb(struct nfq_connection *conn,
		void (*cb)(struct nfq_connection*, void*), void *data);

int bind_queue(struct nfq_connection *conn, uint16_t queue_id);
int unbind_queue(struct nfq_connection *conn, uint16_t queue_id);
int set_mode(struct nfq_connection *conn, uint16_t queue_id, uint32_t range,
		uint8_t mode);
//maxlen
//flags
//batch_verdict

void add_empty(struct nfq_connection *conn, struct nfq_packet *packet, int n);
int get_packet(struct nfq_connection *conn, struct nfq_packet **packet, int n);
int set_verdict(struct nfq_connection *conn, struct nfq_packet *packet,
		uint32_t verdict, uint32_t mangle);

#define HAS_ATTR(packet, x) (packet->attr[x].buffer != NULL)


#endif
