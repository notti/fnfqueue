import nfqueue
import sys

queue = 1

conn = nfqueue.Connection(alloc_size=int(sys.argv[1]), chunk_size=int(sys.argv[2]))

conn.bind(queue)
conn.set_mode(queue, 0xffff, pynfq.COPY_PACKET)

print("run", flush=True)

while True:
    try:
        for packet in conn:
            try:
                packet.payload = packet.payload
                packet.accept(pynfq.MANGLE_PAYLOAD)
            except pynfq.PayloadTruncatedException:
                packet.drop()
                print("drop")
    except pynfq.BufferOverflowException:
        print("buffer error")
        pass

conn.close()
