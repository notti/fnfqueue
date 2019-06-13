from __future__ import print_function
import fnfqueue
import sys

def out(*args, **kwargs):
    print(*args, **kwargs)
    sys.stdout.flush()

queue = 1

conn = fnfqueue.Connection()

q = conn.bind(queue)
q.set_mode(0xffff, fnfqueue.COPY_PACKET)

out("OK")

while True:
    try:
        for packet in conn:
            packet.payload = packet.payload
            packet.accept(fnfqueue.MANGLE_PAYLOAD)
    except fnfqueue.BufferOverflowException:
        out("buffer error")
        pass

conn.close()
