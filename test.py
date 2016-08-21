import pynfq
from scapy.all import *

queue = 1

conn = pynfq.Connection()

conn.bind(queue)
conn.set_mode(queue, 1000, pynfq.lib.NFQNL_COPY_PACKET)

for packet in conn:
    buf = pynfq.ffi.buffer(pynfq.ffi.cast("char *", packet.packet[0].attr[pynfq.lib.NFQA_PAYLOAD].buffer),
            packet.packet[0].attr[pynfq.lib.NFQA_PAYLOAD].len)
    buf[79:84] = b'\x00'*5
    x = IP(bytes(buf))
    del x[ICMP].chksum
    buf[:] = bytes(x)
    packet.verdict(pynfq.lib.NF_ACCEPT, pynfq.lib.MANGLE_PAYLOAD)

conn.close()
