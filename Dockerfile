FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake build-essential libssl-dev ca-certificates curl iputils-ping iproute2 speedtest-cli softether-vpncmd\
    && rm -rf /var/lib/apt/lists/*
WORKDIR /se
