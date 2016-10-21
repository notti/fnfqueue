import nfqueue
import sys

queue = 1

conn = nfqueue.Connection(alloc_size=int(sys.argv[1]), chunk_size=int(sys.argv[2]))

conn.bind(queue)
conn.set_mode(queue, 0xffff, nfqueue.COPY_PACKET)

print("run", flush=True)

while True:
    try:
        for packet in conn:
            try:
                packet.payload = packet.payload
                packet.accept(nfqueue.MANGLE_PAYLOAD)
            except nfqueue.PayloadTruncatedException:
                packet.drop()
                print("drop")
    except nnfqueue.BufferOverflowException:
        print("buffer error")
        pass

conn.close()
