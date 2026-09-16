FROM python:3.10-slim

RUN apt-get update && apt-get install -y \
    iproute2 \
    net-tools \
    iputils-ping \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir \
    scapy \
    pytest

WORKDIR /app
