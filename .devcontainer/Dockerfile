FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

RUN apt-get update && apt-get upgrade -y && \
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    linux-tools-generic linux-tools-$(uname -r) linux-headers-$(uname -r) clang pkg-config libelf-dev clang-format libbpf-dev && \
  rm -rf /var/lib/apt/lists/*
