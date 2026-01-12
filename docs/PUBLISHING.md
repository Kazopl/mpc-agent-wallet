# Publishing Guide

This guide explains how to publish all MPC Agent Wallet SDK packages to their registries.

## Package Overview

| Package | Registry | Name | Security |
|---------|----------|------|----------|
| Rust Core | crates.io | `mpc-wallet-core` | Token-based |
| Rust Relay | crates.io | `mpc-wallet-relay` | Token-based |
| WASM Bindings | npm | `@mpc-wallet/wasm` | Provenance attestation |
| TypeScript SDK | npm | `@mpc-wallet/sdk` | Provenance attestation |
| Python SDK | PyPI | `mpc-wallet` | Trusted Publishing (OIDC) |

## Rust 2024 Edition

This project uses Rust 2024 edition (stable since Feb 2025 with Rust 1.85.0). Notable features:
- Let chains in `if` and `while` statements
- Better async/await patterns
- Better pattern matching

Make sure you have Rust 1.85+ installed:
```bash
rustup update stable
rustc --version  # Should be 1.85.0 or later
```

---

## Trusted Publishing

Trusted Publishing removes the need for long-lived API tokens. It uses OpenID Connect (OIDC) to issue short-lived tokens during CI/CD.

### Why use it
- No API tokens to manage or store in GitHub Secrets
- Short-lived tokens are harder to exploit
- Clear audit trail of who published what

### Registry Support

| Registry | Trusted Publishing | Status |
|----------|-------------------|--------|
| PyPI | Full support | Recommended |
| npm | Provenance attestation | Supported |
| crates.io | Coming July 2025+ | Use token for now |

---

## Automated Publishing with GitHub Actions

### Setup Trusted Publishing for PyPI

1. Go to PyPI, then Your project, then Settings, then Publishing

2. Add a trusted publisher:
   - Owner: `Kazopl`
   - Repository: `mpc-agent-wallet`
   - Workflow: `release.yml`
   - Environment: `pypi`

3. Create GitHub environment:
   - Go to Repository Settings, then Environments
   - Create environment named `pypi`
   - Add protection rules if needed

4. No secrets needed. The workflow uses OIDC.

### Required GitHub Secrets

For registries that don't support OIDC yet:

| Secret | Registry | Where to get it |
|--------|----------|-----------------|
| `CARGO_REGISTRY_TOKEN` | crates.io | https://crates.io/settings/tokens |
| `NPM_TOKEN` | npm | https://www.npmjs.com/settings/tokens (Automation type) |

### Trigger a Release

```bash
# 1. Update version numbers
# 2. Update CHANGELOG.md

# 3. Create and push tag
git tag v0.1.0
git push origin v0.1.0

# 4. Create GitHub Release from the tag
# The workflow runs automatically
```

### Manual Trigger (Dry Run)

Go to Actions, then Release, then Run workflow, then enable "Dry run"

---

## Manual Publishing

### Prerequisites

```bash
# Rust 1.85+ for edition 2024
rustup update stable

# crates.io authentication
cargo login

# npm authentication
npm login

# wasm-pack
cargo install wasm-pack --locked

# Python build tools
pip install build twine
```

### Using the Publish Script

```bash
# Dry run to verify without publishing
./scripts/publish.sh --dry-run

# Publish all packages
./scripts/publish.sh

# Publish specific package
./scripts/publish.sh --package core
./scripts/publish.sh --package relay
./scripts/publish.sh --package wasm
./scripts/publish.sh --package sdk
./scripts/publish.sh --package python

# Skip tests
./scripts/publish.sh --skip-tests --dry-run
```

### Manual Step-by-Step

#### 1. Rust Core (mpc-wallet-core)

```bash
cd crates/mpc-wallet-core

# Verify build
cargo build --release

# Dry run
cargo publish --dry-run

# Publish
cargo publish
```

Wait 45 seconds for the crates.io index to update.

#### 2. Rust Relay (mpc-wallet-relay)

```bash
cd crates/mpc-wallet-relay

# Publish (depends on mpc-wallet-core)
cargo publish
```

#### 3. WASM Bindings (@mpc-wallet/wasm)

```bash
cd crates/mpc-wallet-wasm

# Build WASM
wasm-pack build --target web --scope mpc-wallet

cd pkg

# Publish with provenance
npm publish --access public --provenance
```

#### 4. TypeScript SDK (@mpc-wallet/sdk)

```bash
cd packages/mpc-wallet-sdk

npm ci
npm run build
npm publish --access public --provenance
```

#### 5. Python SDK (mpc-wallet)

**Option A: Trusted Publishing (CI only)**
```yaml
# In GitHub Actions with id-token: write permission
- uses: pypa/gh-action-pypi-publish@release/v1
```

**Option B: Token-based (local)**
```bash
cd packages/mpc-wallet-python
python -m build

# Using API token
export TWINE_USERNAME=__token__
export TWINE_PASSWORD=pypi-your-token
twine upload dist/*
```

---

## Version Management

Update versions in all packages:

```bash
# Cargo.toml (workspace)
[workspace.package]
version = "0.2.0"

# packages/mpc-wallet-sdk/package.json
npm version 0.2.0 --no-git-tag-version

# packages/mpc-wallet-python/pyproject.toml
version = "0.2.0"
```

---

## Publishing Order

Packages must be published in this order due to dependencies:

```
mpc-wallet-core    <- No dependencies
       |
   +---+---+
   |       |
   v       v
 relay    wasm     <- Both depend on core
           |
           v
          sdk      <- Depends on wasm

Python (parallel)  <- Independent
```

---

## Pre-publish Checklist

- [ ] All tests pass (`cargo test`, `npm test`, `pytest`)
- [ ] No linting errors (`cargo clippy`, `npm run lint`, `ruff check`)
- [ ] Rust version is 1.85+ for edition 2024
- [ ] Documentation is up to date
- [ ] CHANGELOG.md is updated
- [ ] Version numbers are consistent
- [ ] No uncommitted changes
- [ ] CI is passing on main branch

---

## Troubleshooting

### Rust: "edition 2024 not supported"
```bash
rustup update stable
rustc --version  # Should be 1.85.0+
```

### crates.io: "crate version already exists"
Version already published. Bump the version number.

### npm: "E403 Forbidden"
- Check `npm whoami`
- Use `--access public` for scoped packages
- Verify npm token permissions

### PyPI: "Invalid or non-existent authentication"
- For Trusted Publishing: Check OIDC configuration on PyPI
- For token auth: Verify `TWINE_USERNAME=__token__`

### WASM: Build fails
```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack --locked --force
```

---

## Post-publish Verification

```bash
# Rust
cargo search mpc-wallet-core

# npm
npm view @mpc-wallet/sdk
npm view @mpc-wallet/wasm

# PyPI
pip index versions mpc-wallet
```

---

## Security

1. Use Trusted Publishing where available (PyPI)
2. Enable npm provenance with `--provenance` flag
3. Use GitHub environments with protection rules
4. Never commit tokens to the repository
5. Rotate tokens periodically for crates.io and npm
6. Enable 2FA on all registry accounts

---

## CI/CD Workflow Reference

The release workflow (`.github/workflows/release.yml`) handles:

```yaml
# Triggered on GitHub Release
on:
  release:
    types: [published]

# Jobs run in order:
# 1. publish-rust      -> crates.io (core then relay)
# 2. publish-wasm      -> npm (depends on rust)
# 3. publish-typescript -> npm (depends on wasm)
# 4. publish-python    -> PyPI (parallel, uses OIDC)
# 5. release-notes     -> Updates GitHub release
```

Key permissions:
```yaml
permissions:
  contents: read
  id-token: write  # Required for OIDC/Trusted Publishing
```
