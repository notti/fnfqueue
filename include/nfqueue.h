#ifndef NFQUEUE_MAIN_H
#define NFQUEUE_MAIN_H

#include <stdint.h>
#include <unistd.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <arpa/inet.h>


/* Netfilter actions; Copied from linux kernel - can't be used via include due
 * to conflicts :( */
#define NF_DROP 0
#define NF_ACCEPT 1
#define NF_STOLEN 2
#define NF_QUEUE 3
#define NF_REPEAT 4
#define NF_STOP 5

/* mangle flags for set_verdict */
#define MANGLE_MARK    (1 << 0)             /* Mangle NFQA_MARK */
#define MANGLE_PAYLOAD (1 << 1)             /* Mangle NFQA_PAYLOAD */
#define MANGLE_CT      (1 << 2)             /* Mangle NFQA_CT */
#define MANGLE_EXP     (1 << 3)             /* Mangle NFQA_EXP */
#define MANGLE_VLAN    (1 << 4)             /* Mangle NFQA_VLAN */

#define MANGLE_MAX     5

// support older kernel versions
#if NFQA_MAX < 12
#define NFQA_CT			11
#define NFQA_CT_INFO		12
#endif
#if NFQA_MAX < 13
#define NFQA_CAP_LEN		13
#endif
#if NFQA_MAX < 14
#define NFQA_SKB_INFO           14
#endif
#if NFQA_MAX < 15
#define NFQA_EXP                15
#endif
#if NFQA_MAX < 17
#define NFQA_UID                16
#define NFQA_GID                17
#endif
#if NFQA_MAX < 18
#define NFQA_SECCTX             18
#endif
#if NFQA_MAX < 20
#define NFQA_VLAN               19
#define NFQA_L2HDR              20
#endif

#ifndef NFQA_CFG_F_FAIL_OPEN
#define NFQA_CFG_F_FAIL_OPEN	(1 << 0)
#endif

#ifndef NFQA_CFG_F_CONNTRACK
#define NFQA_CFG_F_CONNTRACK    (1 << 1)
#endif

#ifndef NFQA_CFG_F_GSO
#define NFQA_CFG_F_GSO          (1 << 2)
#endif

#ifndef NFQA_CFG_F_UID_GID
#define NFQA_CFG_F_UID_GID	(1 << 3)
#endif 

#ifndef NFQA_CFG_F_SECCTX
#define NFQA_CFG_F_SECCTX	(1 << 4)
#endif

#ifndef NFQA_CFG_F_MAX
#define NFQA_CFG_F_MAX          (1 << 5)
#endif

#if NFQA_CFG_F_MAX < (1 << 5)
#undef NFQA_CFG_F_MAX
#define NFQA_CFG_F_MAX          (1 << 5)
#endif

struct nfq_attr {
	void *buffer;                       /* pointer to place in packet buffer
					       containing attribute */
	size_t len;			    /* length of attribute */

	//internal flags; DO NOT TOUCH
	uint16_t type;			    /* attribute type */
};

struct nfq_packet {
	void *buffer;                       /* buffer for storing netlink message */
	size_t len;                         /* size of buffer */
	uint16_t queue_id;                  /* nfqueue id packet belongs to; DO NOT MODIFY */
	uint32_t id;                        /* packet id; DO NOT MODIFY */
	uint16_t hw_protocol;               /* hw protocol id */
	uint8_t hook;			    /* filter hook id */
	struct nfq_attr attr[NFQA_MAX + 1]; /* attributes */
	size_t seq;			    /* sequence number;
					       seq number of command used or 0
					       if message is from kernel */

	// internal flags; DO NOT TOUCH
	int msg_flags;			    /* msg_flags of received packet */
	unsigned int msg_len;		    /* length of received message */
};

struct nfq_connection {
	int fd;                             /* file descriptor of netlink socket*/
};

/**
 * init_connection - creates connection to nfnetlink_queue
 * @conn: netlink connection
 *
 * Returns 0 on success, -1 otherwise. Sets errno.
 */
int init_connection(struct nfq_connection *conn);

/**
 * close_connection - closes connection to nfnetlink_queue
 * @conn: netlink connection
 */
void close_connection(struct nfq_connection *conn);

// All of the following is threadsafe given that conn and packet is not modified
// during function duration.

/**
 * send_msg - send nfnetlink_queue message to connection
 * @conn: netlink connection
 * @id: packet id
 * @type: message type
 * @attr: array of attributes to send
 * @n: number of attributes to send
 * @ack: request acknowledgement from kernel
 * @seq: sequence number to use
 *
 * Returns 0 on success, -1 otherwise. Sets errno.
 * Look at bind_queue, unbind_queue, set_mode, set_flags, set_maxlen,
 * set_verdict, set_verdict_batch for specialised calls.
 * Only errors occuring during sending the message are reported. Errors
 * caused by the message in the kernel need to be received with receive.
 */
ssize_t send_msg(struct nfq_connection *conn, uint16_t id, uint16_t type,
		struct nfq_attr *attr, int n, int ack, uint32_t seq);

/**
 * bind_queue - bind to specific queue
 * @conn: netlink connection
 * @queue_id: id to bind to
 * @ack: request acknowledgement from kernel
 * @seq: sequence number to use
 *
 * Returns 0 on success, -1 otherwise. Sets errno.
 * Only errors occuring during sending the message are reported. Errors
 * caused by the message in the kernel need to be received with receive.
 */
int bind_queue(struct nfq_connection *conn, uint16_t queue_id, int ack,
		uint32_t seq);

/**
 * unbind_queue - unbind from specific queue
 * @conn: netlink connection
 * @queue_id: id to unbind from
 * @ack: request acknowledgement from kernel
 * @seq: sequence number to use
 *
 * Returns 0 on success, -1 otherwise. Sets errno.
 * Only errors occuring during sending the message are reported. Errors
 * caused by the message in the kernel need to be received with receive.
 */
int unbind_queue(struct nfq_connection *conn, uint16_t queue_id, int ack,
		uint32_t seq);

/**
 * set_mode - set copy mode and range for queue
 * @conn: netlink connection
 * @queue_id: queue id
 * @range: payload range to copy. If payload of recieved packet is bigger than
 *  this, then the attribute NFQA_CAP_LEN containing the actual len is set.
 * @mode: copy mode. One of:
 *  NFQNL_COPY_NONE: Packet won't be copied on arrival = this lib won't received
 *     anything (default).
 *  NFQNL_COPY_META: Omits payload.
 *  NFQNL_COPY_PACKET: Copies everything.
 * @ack: request acknowledgement from kernel
 * @seq: sequence number to use
 *
 * Returns 0 on success, -1 otherwise. Sets errno.
 * Only errors occuring during sending the message are reported. Errors
 * caused by the message in the kernel need to be received with receive.
 */
int set_mode(struct nfq_connection *conn, uint16_t queue_id, uint32_t range,
		uint8_t mode, int ack, uint32_t seq);

/**
 * set_flags - set queue flags
 * @conn: netlink connection
 * @queue_id: queue id
 * @flags: queue flags |= flags
 * @mask: queue flags &= mask
 * @ack: request acknowledgement from kernel
 * @seq: sequence number to use
 *
 * Returns 0 on success, -1 otherwise. Sets errno.
 * Only errors occuring during sending the message are reported. Errors
 * caused by the message in the kernel need to be received with receive.
 */
int set_flags(struct nfq_connection *conn, uint16_t queue_id, uint32_t flags,
		uint32_t mask, int ack, uint32_t seq);

/**
 * set_maxlen - sets maximum number of packets waiting for verdict (=enqueued in
 *              kernel)
 * @conn: netlink connection
 * @queue_id: queue id
 * @len: new length
 * @ack: request acknowledgement from kernel
 * @seq: sequence number to use
 *
 * Returns 0 on success, -1 otherwise. Sets errno.
 * Only errors occuring during sending the message are reported. Errors
 * caused by the message in the kernel need to be received with receive.
 */
int set_maxlen(struct nfq_connection *conn, uint16_t queue_id, uint32_t len,
		int ack, uint32_t seq);

/**
 * set_verdict - sets verdict on packet and optionally mangles attributes
 * @conn: netlink connection
 * @packet: packet to set the verdict
 * @verdict: Netfilter verdict (NF_DROP, NF_ACCEPT, NF_STOLEN, NF_QUEUE,
 *  NF_REPEAT, or NF_STOP)
 * @mangle: Mask of packet attributes to mangle. Can be any combination of
 *  MANGLE_MARK, MANGLE_PAYLOAD, MANGLE_CT, MANGLE_EXP, or MANGLE_VLAN.
 * @ack: request acknowledgement from kernel
 * @seq: sequence number to use
 *
 * Returns 0 on success, -1 otherwise. Sets errno.
 * Only errors occuring during sending the message are reported. Errors
 * caused by the message in the kernel need to be received with receive.
 */
int set_verdict(struct nfq_connection *conn, struct nfq_packet *packet,
		uint32_t verdict, uint32_t mangle, int ack, uint32_t seq);

/**
 * set_verdict_batch - sets verdict on all packets with id smaller than packet
 *  (including packet)
 * @conn: netlink connection
 * @packet: packet to set the verdict
 * @verdict: Netfilter verdict (NF_DROP, NF_ACCEPT, NF_STOLEN, NF_QUEUE,
 *  NF_REPEAT, or NF_STOP)
 * @mangle: Mask of packet attributes to mangle. Can be only MANGLE_MARK.
 * @ack: request acknowledgement from kernel
 * @seq: sequence number to use
 *
 * Returns 0 on success, -1 otherwise. Sets errno.
 * Only errors occuring during sending the message are reported. Errors
 * caused by the message in the kernel need to be received with receive.
 */
int set_verdict_batch(struct nfq_connection *conn, struct nfq_packet *packet,
		uint32_t verdict, uint32_t mangle, int ack, uint32_t seq);

/**
 * receive - Receive packets/errors from netfilter queue
 * @conn: netlink connection
 * @packets: array of pointer to preallocated packets. Buffer of packet needs to
 *  point to an allocated buffer and len to the length of the buffer. Rest of
 *  struct is ignored.
 * @num: number of given packets.
 *
 * Returns number of received packets on success, -1 otherwise. Sets errno.
 * Packets need to be parsed with parse_packet before they can be used. This
 * function already sets the seq attribute of the packets.
 */
int receive(struct nfq_connection *conn, struct nfq_packet *packets[], int num);

/**
 * parse_packet - Parse error/attributes from packet and store info in packet
 * @packet: packet
 *
 * Returns 0 on success or errno if packet contains an error. packet->seq can
 * be used to match the error with the command responsible for causing the
 * error.
 */
int parse_packet(struct nfq_packet *packet);


#define NFQ_BASE_SIZE (NLMSG_ALIGN(sizeof(struct nlmsghdr)) + \
		       NLMSG_ALIGN(sizeof(struct nfgenmsg)))

#define HAS_ATTR(packet, x) (packet->attr[x].buffer != NULL)


#endif
