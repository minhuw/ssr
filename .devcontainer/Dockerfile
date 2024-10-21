FROM mcr.microsoft.com/devcontainers/base:ubuntu

RUN apt-get update && apt-get upgrade -y && \
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    linux-tools-generic linux-tools-$(uname -r) clang pkg-config libelf-dev clang-format && \
  rm -rf /var/lib/apt/lists/*
