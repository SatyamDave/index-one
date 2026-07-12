# IndexOne — reproducible build, test, and attack-artifact runner.
#
# `make reproduce` is the single entry point for a reviewer: it builds the core,
# runs every test, regenerates the flag-plant exploits (self-asserting), runs the
# cross-draft conformance suite, and runs the real-upstream side-by-sides. The
# deterministic Rust artifacts are hard failures; the real AIP side-by-side
# soft-skips if `agent-identity-protocol` isn't installed (see `deps-python`).
#
# Honesty (docs/CLAIM_TO_ATTACK.md): the real upstream SDK runs only for AIP;
# the AP2 side is a faithful SD-JWT-VC reimplementation, not Google's reference
# SDK. A witness anchors what was reported, not ground truth.

CORE        := core/Cargo.toml
EXPLOITS    := exploits/Cargo.toml
CONFORMANCE := conformance/Cargo.toml
INTEGRATIONS:= integrations
CARGO       := cargo
PYTHON      := python3

.DEFAULT_GOAL := help
.PHONY: help reproduce build test exploits conformance sidebyside demo py-test deps-python require-real clean fmt lint

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

reproduce: build test exploits conformance sidebyside ## Full reproduce: build + test + exploits + conformance + real-upstream side-by-sides
	@echo ""
	@echo "──────────────────────────────────────────────────────────────────────"
	@echo "REPRODUCE COMPLETE — deterministic Rust artifacts all passed."
	@echo "See docs/CLAIM_TO_ATTACK.md for what is real-upstream vs modeled."
	@echo "──────────────────────────────────────────────────────────────────────"

build: ## Build the core workspace (release)
	$(CARGO) build --workspace --manifest-path $(CORE)

test: ## Run the core workspace tests
	$(CARGO) test --workspace --manifest-path $(CORE)

exploits: ## Regenerate the flag-plant exploits (each self-asserts; non-zero on failure)
	@echo ">> omission_3hop (the Day-12 lead case: omission + self-report)"
	$(CARGO) run --quiet --manifest-path $(EXPLOITS) --bin omission_3hop
	@echo ">> ap2_attribution (supporting: single-hop mandate blind to cross-org attribution)"
	$(CARGO) run --quiet --manifest-path $(EXPLOITS) --bin ap2_attribution

conformance: ## Run the cross-draft adversarial conformance suite
	$(CARGO) run --quiet --manifest-path $(CONFORMANCE)

sidebyside: ## Real-upstream side-by-sides (AIP: real SDK if installed; AP2: faithful SD-JWT-VC)
	@echo ">> real AP2 SD-JWT-VC vs IndexOne (real ES256/P-256 crypto)"
	$(PYTHON) exploits/real_ap2/sidebyside.py
	@echo ">> real AIP reference SDK vs IndexOne (soft-skips if SDK not installed)"
	$(PYTHON) exploits/real_aip/sidebyside.py

demo: ## End-to-end demo: cross-org chain → witness → composed verify (catches omission + self-report) + live witness service
	$(CARGO) build --manifest-path $(CORE) -p indexone-cli
	INDEXONE_CLI=$$(pwd)/core/target/debug/indexone-cli PYTHONPATH=sdk/python/src $(PYTHON) demos/e2e_demo.py

py-test: ## Run the Python integrations test suite
	cd $(INTEGRATIONS) && PYTHONPATH=src $(PYTHON) -m pytest -q

deps-python: ## Install the hash-pinned Python upstreams for the full artifact (real AIP + crypto)
	$(PYTHON) -m pip install --require-hashes -r exploits/real_aip/requirements.lock.txt
	$(PYTHON) -m pip install -r exploits/real_ap2/requirements.txt

require-real: deps-python ## Hard before/after check against the real AIP SDK (as CI runs it)
	$(PYTHON) exploits/real_aip/sidebyside.py --require-real
	$(PYTHON) exploits/real_ap2/sidebyside.py

fmt: ## Format the Rust workspace
	$(CARGO) fmt --manifest-path $(CORE) --all

lint: ## Clippy the core workspace with warnings-as-errors
	$(CARGO) clippy --workspace --manifest-path $(CORE) --all-targets -- -D warnings

clean: ## Remove build artifacts
	$(CARGO) clean --manifest-path $(CORE)
