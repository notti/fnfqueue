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
#define NFQA_CAP_LEN      ...

struct nfq_attr {
	void *buffer;
	size_t len;
        ...;
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
int init_connection(struct nfq_connection *conn, int flags);
void close_connection(struct nfq_connection *conn);

int bind_queue(struct nfq_connection *conn, uint16_t queue_id);
int unbind_queue(struct nfq_connection *conn, uint16_t queue_id);
int set_mode(struct nfq_connection *conn, uint16_t queue_id, uint32_t range,
		uint8_t mode);
//maxlen
//flags
//batch_verdict

int set_verdict(struct nfq_connection *conn, struct nfq_packet *packet,
		uint32_t verdict, uint32_t mangle);
int receive(struct nfq_connection *conn, struct nfq_packet *packets[], int num);
""")

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
