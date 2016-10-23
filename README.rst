Netfilter nfqueue python interface.

Uses recv_mmsg and thus can handle ping -f (even iperf if the moon is in the right spot).
Focuses on a python like interface.

See examples and help().

No C libraries are needed. Needs cffi for building.
