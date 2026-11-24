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
```


## 2. Workspace Setup, Build, and Test Commands

### 2.1 Workspace Installation
There is no root npm workspace. Install the JavaScript workspaces from their
own directories and install the Python backend requirements separately:

```bash
cd frontend && npm ci
cd ../cli && npm ci
cd .. && python -m pip install -r backend/requirements.txt
```

## 2.2 Frontend Workspace

Run frontend commands from `frontend/`:

```bash
# Build frontend
cd frontend
npm run build

# Run linter
npm run lint

# Run component/unit tests
npm run test
```

## 2.3 Backend Workspace

The backend is a Flask/Python service, not an npm workspace. Run its checks
from `backend/`:

```bash
cd backend
python -m pip install -r requirements.txt -r requirements-dev.txt pytest pytest-cov

# Run unit/integration tests
python -m unittest discover -v
python -m pytest -v
```

## 2.4 Soroban Smart Contracts (/contracts)

```bash
# Compile contracts to WASM targets
stellar contract build

# Run Rust smart contract unit & integration tests
cargo test

# Check formatting
cargo fmt --check
```

## 2.5 Noir ZK Circuits (/circuits)
```bash
# Compile Noir circuits
nargo compile

# Execute Noir circuit test suite
nargo test
```

## 2.6 Coverage Thresholds

Each workspace with a test suite publishes its minimum coverage bar as a
declarative JSON file under `devx/coverage/thresholds/<workspace>.json` (see
`devx/coverage/README.md`). CI checks a workspace's coverage report against
its thresholds file with the same entry point contributors run locally:

```bash
python3 devx/coverage/check_coverage.py --workspace backend --report backend/coverage.json
python3 devx/coverage/check_coverage.py --lint-thresholds
python3 -m pytest devx/coverage/test_check_coverage.py -v
```

## 3. Contributor Workflow Guidelines

### 3.1 Branch Naming Convention
Branches must use one of the following standard prefixes:

```bash
feat/<short-description> — New features or functional enhancements

fix/<short-description> — Bug fixes or security patches

docs/<short-description> — Documentation updates and guides

refactor/<short-description> — Code restructuring without logic changes

test/<short-description> — Adding or updating unit/integration tests
```

### 3.2 Conventional Commits
All commit messages must strictly adhere to the Conventional Commits format:
```bash
<type>(<scope>): <short description>

[optional body]
```

## 4. Pull Request Requirements

```bash
Every Pull Request must satisfy the following checklist before being merged:

✅ Closes #N Requirement: The PR description MUST contain Closes #N or Fixes #N (where N is the issue number) to enable automatic issue closing upon merge.

✅ Screenshots Required: If your PR modifies UI layouts, CSS, or component rendering on the Frontend, you MUST attach before/after screenshots or a short GIF.

✅ Security Notes Required: If your PR modifies authentication logic, cryptography/key handling, Soroban contract storage/permissions, or Noir ZK circuit constraints, you MUST include a Security Notes section in your PR description explaining the safety implications.

✅ Test Evidence: Include terminal execution logs or test output showing that all impacted workspace tests pass.
```

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold these standards. 

For protocol vocabulary see [docs/glossary.md](docs/glossary.md).

Please report unacceptable behavior to `conduct@<your-organization-domain>.com`.

## 5. Local Pre-commit Checks

To catch formatting, lint, and secret issues before they reach CI, install [pre-commit](https://pre-commit.com/):

```bash
pip install pre-commit
pre-commit install
```

Then, on every commit, the hooks defined in `.pre-commit-config.yaml` will run automatically on relevant files. To check the whole repository:

```bash
pre-commit run --all-files
```

The configuration includes:

- Standard checks (trailing whitespace, YAML/JSON validity, etc.)
- Ruff for Python files in `backend/`, `devx/`, and `zk/`
- ESLint for staged TypeScript/JavaScript files
- `cargo fmt --check` for Rust contracts
- The project's `devx/secret_scanner.py`

These hooks complement (but do not replace) the existing CI jobs.

### 5.1 Documented command check

The contributor command check verifies that the commands in this guide and the
linked contributor docs still reference committed entry points. It reports
obsolete commands with the source document and line number, and runs in the
release gate and before commits that touch contributor docs or `devx/`:

```bash
python3 devx/check_contributor_commands.py
python3 -m pytest devx/test_check_contributor_commands.py -q
```
