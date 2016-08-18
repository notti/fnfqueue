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
	__u32 seq;
	struct nfq_attr attr[NFQA_MAX + 1];
	struct nfq_packet *next;
};

struct nfq_list {
	struct nfq_packet *head;
	struct nfq_packet *last;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
};

struct nfq_queue {
	int fd;
	uint16_t id;
	__u32 seq;
// synchronous version?
	pthread_t processing;
	struct nfq_list empty;
	struct nfq_list msg;
	struct nfq_list error;
};

#define BASE_SIZE (NLMSG_ALIGN(sizeof(struct nlmsghdr)) + \
		   NLMSG_ALIGN(sizeof(struct nfgenmsg)) + \
		   NLMSG_ALIGN(sizeof(struct nlattr)))

ssize_t send_msg(struct nfq_queue *queue, __u16 type, void *data, size_t len);
void init_queue(struct nfq_queue *queue, uint16_t id);
void stop_queue(struct nfq_queue *queue);

void add_empty(struct nfq_queue *queue, struct nfq_packet *packet);
void get_packet(struct nfq_queue *queue, struct nfq_packet **packet);


#endif
