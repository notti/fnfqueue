import fnfqueue
from scapy.all import *

queue = 1

conn = fnfqueue.Connection()

conn.bind(queue)
conn.queue[queue].set_mode(1000, fnfqueue.COPY_PACKET)

print('OK', flush=True)

for packet in conn:
    x = IP(packet.payload)
    x[ICMP].load = x[ICMP].load[:-2] + b'\x00'*5
    del x[ICMP].chksum
    del x[IP].len
    packet.payload = bytes(x)
    packet.mangle()

conn.close()
