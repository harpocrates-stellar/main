# Harpocrates Development Container Dockerfile
# Pinned versions match:
# - Noir & Barretenberg: zk/toolchain.lock.json (nargo 1.0.0-beta.9, bb 0.87.0)
# - Node.js: package.json engines / CI pinned version (v22.x)
# - Python: backend / devx / zk runtime (3.12)
# - Rust: contracts workspace (1.85.0 stable with wasm32-unknown-unknown target)
# - Stellar CLI: contracts compilation and testing

FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

ARG DEBIAN_FRONTEND=noninteractive

# Pin toolchain versions
ENV NODE_MAJOR=22 \
    RUST_VERSION=1.85.0 \
    NARGO_VERSION=1.0.0-beta.9 \
    BB_VERSION=0.87.0 \
    STELLAR_CLI_VERSION=22.5.0

# Base dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    gnupg \
    jq \
    libssl-dev \
    pkg-config \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    sudo \
    tar \
    unzip \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 22.x
RUN mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list && \
    apt-get update && apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

# Install Rust toolchain for vscode user
USER vscode
ENV RUSTUP_HOME=/home/vscode/.rustup \
    CARGO_HOME=/home/vscode/.cargo \
    NARGO_HOME=/home/vscode/.nargo \
    BB_HOME=/home/vscode/.bb \
    PATH=/home/vscode/.cargo/bin:/home/vscode/.nargo/bin:/home/vscode/.bb:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain ${RUST_VERSION} \
    && rustup target add wasm32-unknown-unknown wasm32v1-none \
    && rustup component add clippy rustfmt llvm-tools-preview

# Install Stellar CLI
USER root
RUN curl -fsSL https://github.com/stellar/stellar-cli/releases/latest/download/stellar-cli-ubuntu-x86_64.tar.gz \
    | tar -xz -C /usr/local/bin stellar \
    && chmod +x /usr/local/bin/stellar

# Install Nargo and Barretenberg for vscode user
USER vscode
RUN curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash \
    && /home/vscode/.nargo/bin/noirup --version ${NARGO_VERSION}

RUN curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash \
    && /home/vscode/.bb/bbup --version ${BB_VERSION}

USER vscode
WORKDIR /workspace
