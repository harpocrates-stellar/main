# Contributing to the Repository

Thank you for contributing! This guide outlines the development workflow across our four core layers: **Frontend**, **Backend**, **Soroban Contracts**, and **Noir Circuits**.

---

## 1. Prerequisites & Toolchain Setup

Before getting started, ensure your environment meets the toolchain requirements for all workspaces:

* **Node.js**: `v20.x` or later (`npm` or `pnpm`)
* **Rust**: `1.78+` with `wasm32-unknown-unknown` target (`rustup target add wasm32-unknown-unknown`)
* **Stellar CLI**: Installed via `cargo install --locked stellar-cli`
* **Nargo (Noir CLI)**: `v0.25.0+` (Installed via `noirup`)

---

## 2. Workspace Setup & Build Commands

### Setup Workspace
Install base dependencies across all workspaces:
```bash
npm install
