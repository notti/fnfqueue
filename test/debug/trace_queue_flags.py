from bcc import BPF

prog = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>


struct nfqnl_instance {
        struct hlist_node hlist;                /* global list of queues */
        struct rcu_head rcu;

        u32 peer_portid;
        unsigned int queue_maxlen;
        unsigned int copy_range;
        unsigned int queue_dropped;
        unsigned int queue_user_dropped;


        u_int16_t queue_num;                    /* number of this queue */
        u_int8_t copy_mode;
        u_int32_t flags;                        /* Set using NFQA_CFG_FLAGS */
/*
 * Following fields are dirtied for each queued packet,
 * keep them in same cache line if possible.
 */
        spinlock_t      lock;
        unsigned int    queue_total;
        unsigned int    id_sequence;            /* 'sequence' of pkt ids */
        struct list_head queue_list;            /* packets in queue */
};


int kprobe____nfqnl_enqueue_packet(struct pt_regs *ctx, struct net *net, struct nfqnl_instance *queue, struct nf_queue_entry *entry)
{
    bpf_trace_printk("flags %x\\n", queue->flags);
};
"""

BPF(text=prog).trace_print()
