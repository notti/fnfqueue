#!/usr/bin/python3

import subprocess
import sys

print('flood test: ', end='', flush=True)

mangler = subprocess.Popen(('python3', 'nfqueue_copy.py'), stdout=subprocess.PIPE)

mangler.stdout.readline()

ping = subprocess.run(('ping', '-q', '-f', '-c', '100000', '127.0.0.2'), stdout=subprocess.PIPE)
mangler.terminate()
 
if b'0% packet loss' in ping.stdout:
    print('OK', flush=True)
    sys.exit(0)
else:
    print('FAILED', flush=True)
    sys.exit(-1)

