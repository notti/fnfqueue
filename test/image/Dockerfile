FROM debian:stretch

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        iptables \
        python3-cffi \
        python3-dev \
        python3-pip \
        python3-setuptools \
        python3-wheel \
&& rm -rf /var/lib/apt/lists/*
