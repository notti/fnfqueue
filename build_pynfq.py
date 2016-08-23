#!/usr/bin/python
    
from cffi import FFI
ffibuilder = FFI()

ffibuilder.set_source("_pynfq",
    """
    #include "nfq_main.h"
    """, libraries=["nfq"], library_dirs=['.'])

ffibuilder.cdef("""
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

#define NFQA_PAYLOAD      ...

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
	struct nfq_attr attr[...];
	...;
};

struct nfq_connection {
    ...;
};

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

extern "Python" void empty_cb(struct nfq_connection *, void *);
""")

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
