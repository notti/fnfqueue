#!/usr/bin/python3

import subprocess
import sys

num = '100000'

if len(sys.argv) > 1 and sys.argv[1] == 'short':
    num = '1000'

print('flood test: ', end='', flush=True)

mangler = subprocess.Popen((sys.executable, 'copyPacket.py'), stdout=subprocess.PIPE)

mangler.stdout.readline()

ping = subprocess.run(('ping', '-q', '-f', '-c', '100000', '127.0.0.2'), stdout=subprocess.PIPE)
mangler.terminate()
 
if b'0% packet loss' in ping.stdout:
    print('OK', flush=True)
    sys.exit(0)
else:
    print('FAILED', flush=True)
    sys.exit(-1)

