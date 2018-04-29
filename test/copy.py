import fnfqueue
import sys

queue = 1

conn = fnfqueue.Connection()

q = conn.bind(queue)
q.set_mode(0xffff, fnfqueue.COPY_PACKET)

print("OK", flush=True)

while True:
    try:
        for packet in conn:
            packet.payload = packet.payload
            packet.accept(fnfqueue.MANGLE_PAYLOAD)
    except fnfqueue.BufferOverflowException:
        print("buffer error")
        pass

conn.close()
