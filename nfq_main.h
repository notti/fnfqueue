#ifndef NFQ_MAIN_H
#define NFQ_MAIN_H

#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <arpa/inet.h>

struct nfq_queue {
	int fd;
	uint16_t id;
	__u32 seq;
// synchronous version?
	pthread_t processing;
//	error_queue
//	msg_queue
	pthread_mutex_t msg_mutex;
	pthread_cond_t msg_cond;
};


#define BASE_SIZE (NLMSG_ALIGN(sizeof(struct nlmsghdr)) + \
		   NLMSG_ALIGN(sizeof(struct nfgenmsg)) + \
		   NLMSG_ALIGN(sizeof(struct nlattr)))

ssize_t send_msg(struct nfq_queue *queue, __u16 type, void *data, size_t len);
void init_queue(struct nfq_queue *queue, uint16_t id);
void stop_queue(struct nfq_queue *queue);
void get_packet(struct nfq_queue *queue);


#endif
