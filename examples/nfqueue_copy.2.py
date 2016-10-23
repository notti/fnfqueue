"""Re-set payload from python. Can be used for speed testing. Python 2 version."""

from __future__ import print_function
import nfqueue

queue = 1

conn = nfqueue.Connection()

try:
    q = conn.bind(queue)
    q.set_mode(0xffff, nfqueue.COPY_PACKET)
except OSError:
    print("Access denied; Do I have root rights or the needed capabilities?")
    sys.exit(-1)

while True:
    try:
        for packet in conn:
            packet.payload = packet.payload
            packet.mangle()
    except nfqueue.BufferOverflowException:
        print("buffer error")
        pass

conn.close()
