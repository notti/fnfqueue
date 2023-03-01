fnfqueue
========

[![Build Status](https://github.com/notti/fnfqueue/actions/workflows/main.yml/badge.svg)](https://github.com/notti/fnfqueue/actions)
[![Python Versions](https://img.shields.io/pypi/pyversions/fnfqueue.svg)](https://pypi.org/project/fnfqueue/)
[![PyPI - License](https://img.shields.io/pypi/l/fnfqueue.svg)](https://pypi.org/project/fnfqueue/)

Fast netfilter nfqueue python and C interface. Gets the speed from

- avoiding memory allocation
- batching reads (uses `recv_mmsg`)

It also does not use the callback-like interface of libnetfilter-queue and provides a more python like iterator interface. Additionally, it doesn't assume anything and therefore doesn't automatically set verdicts on packets (unlike python-nfqueue in debian which accepts everything after you return from the callback...)

It can handle `ping -f` (even `iperf` if the moon is in the right spot) to localhost from within python.

Focus is on a python like interface.

Short example for mangling packets:

```bash
iptables -A OUTPUT <filter here> -j NFQUEUE --queue-num 1
```

```python
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
            packet.payload = packet.payload # modify the packet here
            packet.mangle()
    except fnfqueue.BufferOverflowException:
        print("buffer error")
        pass

conn.close() # this can be called concurrently to cancel the above for loop
```

Help is provided as python docs.

No C libraries are needed. Needs cffi for building. Kernel and libc must be recent enough to support `nfqueue` and `recvmmsg` (linux 2.6.33, glibc 2.12 - more recent kernels provide better performance).
