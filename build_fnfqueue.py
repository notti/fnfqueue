#!/usr/bin/python

from cffi import FFI

ffibuilder = FFI()

ffibuilder.set_source(
    "fnfqueue._fnfqueue",
    """
    #include "fnfqueue.h"
    """,
    sources=["src/fnfqueue.c"],
    extra_compile_args=["-O3"],
    include_dirs=["include"],
)

ffibuilder.cdef(
    """
#define NF_DROP           ...
#define NF_ACCEPT         ...
#define NF_STOLEN         ...
#define NF_QUEUE          ...
#define NF_REPEAT         ...
#define NF_STOP           ...

#define MANGLE_MARK       ...
#define MANGLE_PAYLOAD    ...
#define MANGLE_CT         ...
#define MANGLE_EXP        ...
#define MANGLE_VLAN       ...

#define NFQNL_COPY_NONE   ...
#define NFQNL_COPY_META   ...
#define NFQNL_COPY_PACKET ...

#define NFQA_PACKET_HDR         ...
#define NFQA_VERDICT_HDR        ...
#define NFQA_MARK               ...
#define NFQA_TIMESTAMP          ...
#define NFQA_IFINDEX_INDEV      ...
#define NFQA_IFINDEX_OUTDEV     ...
#define NFQA_IFINDEX_PHYSINDEV  ...
#define NFQA_IFINDEX_PHYSOUTDEV ...
#define NFQA_HWADDR             ...
#define NFQA_PAYLOAD            ...
#define NFQA_CT                 ...
#define NFQA_CT_INFO            ...
#define NFQA_CAP_LEN            ...
#define NFQA_SKB_INFO           ...
#define NFQA_EXP                ...
#define NFQA_UID                ...
#define NFQA_GID                ...
#define NFQA_SECCTX             ...
#define NFQA_VLAN               ...
#define NFQA_L2HDR              ...

#define NFQA_CFG_F_FAIL_OPEN ...
#define NFQA_CFG_F_CONNTRACK ...
#define NFQA_CFG_F_GSO       ...
#define NFQA_CFG_F_UID_GID   ...
#define NFQA_CFG_F_SECCTX    ...
#define NFQA_CFG_F_MAX       ...

struct nfq_attr {
	void *buffer;
	size_t len;
        ...;
};

struct nfq_packet {
	void *buffer;
	size_t len;
	uint16_t queue_id;
	uint32_t id;
	uint16_t hw_protocol;
	uint8_t hook;
	struct nfq_attr attr[...];
	size_t seq;
	...;
};

struct nfq_connection {
    int fd;
    ...;
};

struct nfqnl_msg_packet_timestamp {
        uint64_t  sec;
        uint64_t  usec;
};

uint64_t be64toh(uint64_t big_endian_64bits);

int init_connection(struct nfq_connection *conn);
void close_connection(struct nfq_connection *conn);
ssize_t send_msg(struct nfq_connection *conn, uint16_t id, uint16_t type,
		struct nfq_attr *attr, int n, int ack, uint32_t seq);
int bind_queue(struct nfq_connection *conn, uint16_t queue_id, int ack,
		uint32_t seq);
int unbind_queue(struct nfq_connection *conn, uint16_t queue_id, int ack,
		uint32_t seq);
int set_mode(struct nfq_connection *conn, uint16_t queue_id, uint32_t range,
		uint8_t mode, int ack, uint32_t seq);
int set_flags(struct nfq_connection *conn, uint16_t queue_id, uint32_t flags,
		uint32_t mask, int ack, uint32_t seq);
int set_maxlen(struct nfq_connection *conn, uint16_t queue_id, uint32_t len,
		int ack, uint32_t seq);
int set_verdict(struct nfq_connection *conn, struct nfq_packet *packet,
		uint32_t verdict, uint32_t mangle, int ack, uint32_t seq);
int set_verdict_batch(struct nfq_connection *conn, struct nfq_packet *packet,
		uint32_t verdict, uint32_t mangle, int ack, uint32_t seq);
int receive(struct nfq_connection *conn, struct nfq_packet *packets[], int num);
int parse_packet(struct nfq_packet *packet);
"""
)

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
