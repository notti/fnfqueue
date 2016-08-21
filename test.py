import pynfq
from scapy.all import *

queue = 1

conn = pynfq.Connection()

conn.bind(queue)
conn.set_mode(queue, 1000, pynfq.lib.NFQNL_COPY_PACKET)

for packet in conn:
    packet.payload[79:84] = b'\x00'*5
    x = IP(bytes(packet.payload))
    del x[ICMP].chksum
    packet.payload[:] = bytes(x)
    packet.verdict(pynfq.lib.NF_ACCEPT, pynfq.lib.MANGLE_PAYLOAD)

conn.close()
