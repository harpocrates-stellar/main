default: build

all: test

test: build
	cargo test

build:
	stellar contract build
	@ls -l target/wasm32v1-none/release/*.wasm

# Wasm size budget gate (#346). Builds the artifact when it is missing and
# fails closed when it violates the budget in devx/wasm_size_budget.json.
wasm-budget:
	python3 ../../devx/wasm_size_budget.py --check --target wasm32v1-none

# Record the measured artifact size/digest as the new baseline (explicit,
# reviewable baseline migration).
wasm-budget-record:
	python3 ../../devx/wasm_size_budget.py --record

fmt:
	cargo fmt --all

clean:
	cargo clean
