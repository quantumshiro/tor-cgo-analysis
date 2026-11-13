FROM debian:bookworm

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    autoconf automake build-essential ca-certificates curl gdb git libevent-dev \
    liblzma-dev libseccomp-dev libscrypt-dev libssl-dev libtool libzstd-dev \
    pkg-config python3 python3-pip python3-venv zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/chutney-venv \
    && /opt/chutney-venv/bin/pip install --no-cache-dir \
       'cryptography~=3.4' 'networkx~=3.4.2' 'paramiko~=4.0' \
       'rpyc~=6.0.2' 'typeguard==4.3.0' 'tomli-w~=1.2.0'

ENV PATH="/opt/chutney-venv/bin:${PATH}"

WORKDIR /work
