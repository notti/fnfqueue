import fnfqueue
import dpkt

queue = 1

conn = fnfqueue.Connection()

conn.bind(queue)
conn.queue[queue].set_mode(1000, fnfqueue.COPY_PACKET)

print('OK', flush=True)

for packet in conn:
    ip = dpkt.ip.IP(packet.payload)
    if isinstance(ip.data, dpkt.icmp.ICMP):
        icmp = ip.data
        icmp.data = bytes(icmp.data)[:-2] + b'\x00'*5
        icmp.sum = 0
        ip.sum = 0
        packet.payload = bytes(ip)
        packet.mangle()
    else:
        packet.accept()

conn.close()
