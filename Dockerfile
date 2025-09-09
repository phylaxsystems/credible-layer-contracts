# syntax=docker/dockerfile:1.2
FROM ubuntu:24.04 AS base
ARG VERSION=v1.3.4

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download forge and cast to be present
RUN wget https://github.com/foundry-rs/foundry/releases/download/${VERSION}/foundry_${VERSION}_alpine_amd64.tar.gz && \
    tar -xvzf foundry_${VERSION}_alpine_amd64.tar.gz -C /usr/local/bin forge cast && \
    rm foundry_${VERSION}_alpine_amd64.tar.gz

FROM base AS builder
WORKDIR /app

COPY . .

RUN forge install && forge build

LABEL org.opencontainers.image.title="credible-utility"
LABEL org.opencontainers.image.description="Image containing utilities for Credible Smart contracts"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.authors="devops@phylax.watch"
LABEL org.opencontainers.image.url="git@github.com:phylaxsystems/credible-layer-contracts"
LABEL org.opencontainers.image.source="git@github.com:phylaxsystems/credible-layer-contracts"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.vendor="Phylax Systems"
LABEL maintainer="devops@phylax.watch"
LABEL version="0.1.0"
LABEL description="mage containing utilities for Credible Smart contracts"

CMD ["bash"]