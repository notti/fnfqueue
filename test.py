from _pynfq import ffi, lib
from scapy.all import *

num = 4
queue = 1

conn = ffi.new("struct nfq_connection *");
packets = ffi.new("struct nfq_packet[]", num);
buffers = []

lib.init_connection(conn, 0)

for i in range(num):
    b = ffi.new("char []", 8192)
    buffers.append(b)
    packets[i].buffer = b
    packets[i].len = 8192

lib.add_empty(conn, packets, num)

print(lib.bind_queue(conn, queue))
print(lib.set_mode(conn, queue, 1000, lib.NFQNL_COPY_PACKET))

for i in range(100):
    p = ffi.new("struct nfq_packet * *")
    print(lib.get_packet(conn, p, 1))
    buf = ffi.buffer(ffi.cast("char *", p[0].attr[lib.NFQA_PAYLOAD].buffer), p[0].attr[lib.NFQA_PAYLOAD].len)
    buf[79:84] = b'\x00'*5
    x = IP(bytes(buf))
    del x[ICMP].chksum
    buf[:] = bytes(x)
    print(lib.set_verdict(conn, p[0], lib.NF_ACCEPT, lib.MANGLE_PAYLOAD))
    lib.add_empty(conn, p[0], 1)

lib.close_connection(conn)
