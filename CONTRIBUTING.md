# Contributing Guide

Welcome! Thank you for taking the time to contribute. This repository is a multi-workspace project encompassing four core technology layers:

1. **Frontend** (Web Interface / UI)
2. **Backend** (API & Services)
3. **Soroban Contracts** (Stellar Smart Contracts)
4. **Noir Circuits** (Zero-Knowledge Proof Circuits)

To keep contributions consistent and high quality, please follow the guidelines below.

---

## 1. Prerequisites & Environment Setup

Ensure you have the following toolchains installed locally before working in any workspace:

| Layer | Dependency | Recommended Version | Verification Command |
| :--- | :--- | :--- | :--- |
| **Frontend & Backend** | Node.js / npm | Node v20.x+ | `node -v` |
| **Soroban Contracts** | Rust & Cargo | Rust 1.78+ | `rustup --version` |
| **Soroban Contracts** | WASM Target | `wasm32-unknown-unknown` | `rustup target list \| grep installed` |
| **Soroban Contracts** | Stellar CLI | Latest | `stellar --version` |
| **Noir Circuits** | Nargo (Noir CLI) | v0.25.0+ | `nargo --version` |

### Installing Toolchain Components

```bash
# Install WASM compilation target for Rust
rustup target add wasm32-unknown-unknown

# Install Stellar CLI for Soroban contract compilation
cargo install --locked stellar-cli

# Install Nargo for Noir ZK circuit compilation
noirup
