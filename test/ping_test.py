#!/usr/bin/python3

from __future__ import print_function
import subprocess
import sys

print('ping mangle: ', end='', flush=True)

mangler = subprocess.Popen((sys.executable, 'ping_mangle.py'), stdout=subprocess.PIPE)

mangler.stdout.readline()

# run not available in 3.4
ping = subprocess.check_output(('ping', '-c', '1', '127.0.0.2'))
mangler.terminate()

if b'wrong data byte' in ping:
    print('OK', flush=True)
    sys.exit(0)
else:
    print('FAILED', flush=True)
    sys.exit(-1)
