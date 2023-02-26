#!/usr/bin/python3

from __future__ import print_function
import subprocess
import sys


def out(*args, **kwargs):
    print(*args, **kwargs)
    sys.stdout.flush()


out("ping mangle: ", end="")

mangler = subprocess.Popen((sys.executable, "ping_mangle.py"), stdout=subprocess.PIPE)

mangler.stdout.readline()

# run not available in 3.4
ping = subprocess.check_output(("ping", "-c", "1", "127.0.0.2"))
mangler.terminate()

if b"wrong data byte" in ping:
    out("OK")
    sys.exit(0)
else:
    out("FAILED")
    sys.exit(-1)
