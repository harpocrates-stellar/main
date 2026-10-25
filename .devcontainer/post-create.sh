#!/usr/bin/env bash
set -euo pipefail

echo "=== Running post-create setup ==="

# 1. Install frontend npm dependencies
if [ -d "frontend" ] && [ -f "frontend/package.json" ]; then
    echo "Installing frontend dependencies..."
    (cd frontend && npm ci)
fi

# 2. Install cli npm dependencies
if [ -d "cli" ] && [ -f "cli/package.json" ]; then
    echo "Installing cli dependencies..."
    (cd cli && npm ci)
fi

# 3. Create backend virtual environment and install dependencies
if [ -d "backend" ] && [ -f "backend/requirements.txt" ]; then
    echo "Setting up backend virtual environment..."
    python3 -m venv backend/.venv
    backend/.venv/bin/pip install --upgrade pip
    backend/.venv/bin/pip install -r backend/requirements.txt
    if [ -f "backend/requirements-dev.txt" ]; then
        backend/.venv/bin/pip install -r backend/requirements-dev.txt
    fi
fi

# 4. Verify dependency pins
if [ -f "devx/check_dependency_pins.py" ]; then
    echo "Checking repository dependency pins..."
    python3 devx/check_dependency_pins.py
fi

echo "=== Post-create setup complete ==="
