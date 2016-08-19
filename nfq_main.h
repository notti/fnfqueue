#ifndef NFQ_MAIN_H
#define NFQ_MAIN_H

#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <arpa/inet.h>

struct nfq_attr {
	void *buffer;
	size_t len;
};

struct nfq_packet {
	void *buffer;
	size_t len;
	int error;
	uint32_t  seq;
	uint16_t queue_id;
	struct nfq_attr attr[NFQA_MAX + 1];
	struct nfq_packet *next;
};

struct nfq_list {
	struct nfq_packet *head;
	struct nfq_packet *last;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
};

struct nfq_connection {
	int fd;
	uint32_t seq;
// synchronous version?
	pthread_t processing;
	struct nfq_list empty;
	struct nfq_list msg;
	struct nfq_list error;
};

#define NFQ_BASE_SIZE (NLMSG_ALIGN(sizeof(struct nlmsghdr)) + \
		       NLMSG_ALIGN(sizeof(struct nfgenmsg)) + \
		       NLMSG_ALIGN(sizeof(struct nlattr)))

int send_msg(struct nfq_connection *conn, uint16_t queue_id, uint16_t type,
		void *data, size_t len);
void parse_packet(struct msghdr *msg, struct nfq_packet *packet);
void init_connection(struct nfq_connection *conn, int flags);
void close_connection(struct nfq_connection *conn);

int bind_queue(struct nfq_connection *conn, uint16_t queue_id);
int unbind_queue(struct nfq_connection *conn, uint16_t queue_id);
int set_mode(struct nfq_connection *conn, uint16_t queue_id, uint32_t range,
		uint8_t mode);
//maxlen
//flags
//verdict

void add_empty(struct nfq_connection *conn, struct nfq_packet *packet, int n);
int get_packet(struct nfq_connection *conn, struct nfq_packet **packet, int n);


#endif
