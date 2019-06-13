#!/usr/bin/python3

from __future__ import print_function
import fnfqueue
import sys
import os
import threading
import time

def out(*args, **kwargs):
    print(*args, **kwargs)
    sys.stdout.flush()

out('close test: ', end='')

queue = 1
conn = fnfqueue.Connection()

conn.bind(queue)
conn.queue[queue].set_mode(1000, fnfqueue.COPY_PACKET)

def stop():
    time.sleep(3)
    conn.close()
    time.sleep(3)
    out('FAILED')
    os._exit(-1)

stopper = threading.Thread(target=stop)
stopper.daemon = True
stopper.start()

for packet in conn:
    out('Got unexpected packet... Failed')
    os._exit(-1)

out('OK')
sys.exit(0)
