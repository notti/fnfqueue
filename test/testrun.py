from cffi import FFI
import subprocess
import time
import os
import functools
import re
import csv
import sys

ffi = FFI()
ffi.cdef("""
        int clone(int (*fn)(void *), void *child_stack,
                  int flags, void *arg, ...
                  /* pid_t *ptid, struct user_desc *tls, pid_t *ctid */ );
        """)
C = ffi.dlopen(None)

CLONE_NEWNET  = 0x40000000

@ffi.callback("int(*)(void *)")
def cb(fun):
    ffi.from_handle(fun)()
    return 0

STACK_LEN = 1024*1024

def clone_net(fun):
    stack = ffi.new("char []", STACK_LEN)
    handle = ffi.new_handle(fun)
    return C.clone(cb, ffi.cast("void *", stack) + STACK_LEN, CLONE_NEWNET, handle)

def test(tester, ping, r, w):
    os.close(r)
    w = open(w, 'wb')
    subprocess.run(["ip", "link", "set", "dev", "lo", "up"], check=True)
    if tester is not None:
        subprocess.run(["iptables", "-A", "INPUT", "--dst", "127.0.0.1", "-j", "NFQUEUE", "--queue-num", "1"], check=True)
        p = tester()
        p.stdout.readline()
    res = subprocess.run(["ping",] + ping + ["-q", "127.0.0.1"], stdout=subprocess.PIPE)
    if tester is not None:
        p.terminate()
    w.write(res.stdout)
    w.close()

ping_re = re.compile(b"(?P<transmitted>\d+) packets transmitted, (?P<received>\d+) received.* = (?P<min>[\d.]+)/(?P<avg>[\d.]+)/(?P<max>[\d.]+)/(?P<mdev>[\d.]+)", re.M | re.S)

def do(prog, ping):
    (r, w) = os.pipe()
    clone_net(functools.partial(test, prog, ping, r, w))
    os.close(w)
    r = open(r, "rb")
    p = r.read()
    r.close()
    return {k:v.decode('ascii') for k, v in ping_re.search(p).groupdict().items()}

def speedtestpy(alloc, chunk):
    return subprocess.Popen(["python3", "nfqueue_copy.py", alloc, chunk], env={"PYTHONPATH": ".."}, stdout=subprocess.PIPE)
def speedtestC(chunk):
    return subprocess.Popen(["./nfqueue_test", chunk], env={"LD_LIBRARY_PATH": ".."}, stdout=subprocess.PIPE)

def do_one(t, alloc, chunk, ping):
    alloc = str(alloc)
    chunk = str(chunk)
    if t == 'C':
        f = functools.partial(speedtestC, chunk)
        alloc = ""
    if t == 'py':
        f = functools.partial(speedtestpy, alloc, chunk)
    if t == '':
        f = None
        alloc = ""
        chunk = ""

    ret = do(f, ping)
    ret['ping'] = ' '.join(ping)
    ret['alloc'] = alloc
    ret['chunk'] = chunk
    ret['type'] = t
    return ret

fieldnames = ['ping', 'type', 'chunk', 'alloc', 'transmitted', 'received', 'min', 'max', 'avg', 'mdev']
writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)

writer.writeheader()
sys.stdout.flush()
writer.writerow(do_one(*sys.argv[1:4], sys.argv[4:]))
