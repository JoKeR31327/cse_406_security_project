FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    iptables \
    iproute2 \
    net-tools \
    iputils-ping \
    tcpdump \
    python3 \
    python3-pip \
    build-essential \
    libnetfilter-queue-dev \
    libnfnetlink-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir \
    NetfilterQueue==1.1.0 \
    scapy \
    pytest

WORKDIR /app
