# syntax=docker/dockerfile:1.2
FROM --platform=$BUILDPLATFORM ubuntu:24.04 AS base
ARG VERSION=v1.3.4
ARG TARGETARCH

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download forge and cast to be present
RUN curl -L https://foundry.paradigm.xyz | bash && \
    /root/.foundry/bin/foundryup

ENV PATH="$PATH:/root/.foundry/bin"

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
