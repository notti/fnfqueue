#!/usr/bin/python3

from __future__ import print_function
import subprocess
import sys


def out(*args, **kwargs):
    print(*args, **kwargs)
    sys.stdout.flush()


num = "100000"

if len(sys.argv) > 1 and sys.argv[1] == "short":
    num = "1000"

out("flood test: ", end="")

mangler = subprocess.Popen((sys.executable, "copyPacket.py"), stdout=subprocess.PIPE)

mangler.stdout.readline()

# run not available in 3.4
ping = subprocess.check_output(("ping", "-q", "-f", "-c", "100000", "127.0.0.2"))
mangler.terminate()

if b"0% packet loss" in ping:
    out("OK")
    sys.exit(0)
else:
    out("FAILED")
    sys.exit(-1)
