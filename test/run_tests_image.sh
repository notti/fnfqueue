#!/bin/bash

set -e

cd /io

python3 setup.py install
pip3 install scapy

cd test

iptables -A INPUT -j NFQUEUE -i lo --dst 127.0.0.2 --queue-num 1

./ping_test.py
./flood_test.py

