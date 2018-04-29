import nfqueue
import sys

queue = 1

conn = nfqueue.Connection()

q = conn.bind(queue)
q.set_mode(0xffff, nfqueue.COPY_PACKET)

print("OK", flush=True)

while True:
    try:
        for packet in conn:
            packet.payload = packet.payload
            packet.accept(nfqueue.MANGLE_PAYLOAD)
    except nfqueue.BufferOverflowException:
        print("buffer error")
        pass

conn.close()
