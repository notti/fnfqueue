import pynfq
from scapy.all import *

queue = 1

conn = pynfq.Connection()

conn.bind(queue)
conn.set_mode(queue, 0xffff, pynfq.COPY_PACKET)

while True:
    try:
        for packet in conn:
            try:
                packet.payload = bytes(packet.payload) #IP(packet.payload))
                packet.mangle()
            except pynfq.PayloadTruncatedException:
                packet.drop()
                print("drop")
    except pynfq.BufferOverflowException:
        print("buffer error")
        pass

conn.close()
