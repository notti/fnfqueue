"""Re-set payload from python. Can be used for speed testing."""

import fnfqueue

queue = 1

conn = fnfqueue.Connection()

try:
    q = conn.bind(queue)
    q.set_mode(0xffff, fnfqueue.COPY_PACKET)
except PermissionError:
    print("Access denied; Do I have root rights or the needed capabilities?")
    sys.exit(-1)

while True:
    try:
        for packet in conn:
            packet.payload = packet.payload
            packet.mangle()
    except fnfqueue.BufferOverflowException:
        print("buffer error")
        pass

conn.close()
