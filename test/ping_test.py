#!/usr/bin/python3

import subprocess
import sys

print('ping mangle: ', end='', flush=True)

mangler = subprocess.Popen(('python3', 'ping_mangle.py'), stdout=subprocess.PIPE)

mangler.stdout.readline()

ping = subprocess.run(('ping', '-c', '1', '127.0.0.2'), stdout=subprocess.PIPE)
mangler.terminate()

if b'wrong data byte' in ping.stdout:
    print('OK', flush=True)
    sys.exit(0)
else:
    print('FAILED', flush=True)
    sys.exit(-1)
