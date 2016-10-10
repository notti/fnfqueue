import pynfq
from scapy.all import *

queue = 1

conn = pynfq.Connection(200, 100)

conn.bind(queue)
conn.set_mode(queue, 0xffff, pynfq.COPY_PACKET)

while True:
    try:
        for packet in conn:
            try:
                packet.payload = bytes(packet.payload) #IP(packet.payload))
                packet.mangle()
            except pynfq.BufferToSmallException:
                packet.drop()
                print("drop")
    except OSError:
        print("buffer error")
        pass

conn.close()
