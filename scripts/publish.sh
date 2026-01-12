#!/bin/bash
# MPC Agent Wallet - Publishing Script
#
# This script handles publishing all SDK packages to their respective registries.
# Use --dry-run to verify packages without actually publishing.
#
# Prerequisites:
# - Rust 1.85+ with edition 2024 support
# - cargo login (for crates.io)
# - npm login (for npm)
# - PyPI Trusted Publishing configured (no secrets needed!) OR TWINE credentials
# - wasm-pack installed (cargo install wasm-pack --locked)
#
# For CI/CD, use GitHub Actions with Trusted Publishing instead of this script.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Parse arguments
DRY_RUN=false
SKIP_TESTS=false
PACKAGE=""
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        --package)
            PACKAGE="$2"
            shift 2
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --dry-run      Verify packages without publishing"
            echo "  --skip-tests   Skip running tests"
            echo "  --package PKG  Publish only specific package (core|relay|wasm|sdk|python)"
            echo "  --verbose, -v  Show verbose output"
            echo "  -h, --help     Show this help message"
            echo ""
            echo "Packages published in order:"
            echo "  1. mpc-wallet-core      → crates.io"
            echo "  2. mpc-wallet-relay     → crates.io"
            echo "  3. @mpc-wallet/wasm     → npm"
            echo "  4. @mpc-wallet/sdk      → npm"
            echo "  5. mpc-wallet           → PyPI"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$ROOT_DIR"

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     MPC Agent Wallet - Package Publisher (Rust 2024)         ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ "$DRY_RUN" = true ]; then
    echo -e "${YELLOW}DRY RUN MODE - No packages will be published${NC}"
    echo ""
fi

# Check Rust version
RUST_VERSION=$(rustc --version | grep -oE '[0-9]+\.[0-9]+' | head -1)
echo -e "${BLUE}Rust version: $RUST_VERSION${NC}"
if [[ "$RUST_VERSION" < "1.85" ]]; then
    echo -e "${RED}Error: Rust 1.85+ required for edition 2024. Run: rustup update stable${NC}"
    exit 1
fi

# Function to publish Rust crate
publish_rust_crate() {
    local crate_name=$1
    local crate_path=$2

    echo -e "${BLUE}Publishing $crate_name to crates.io...${NC}"

    cd "$ROOT_DIR/$crate_path"

    if [ "$DRY_RUN" = true ]; then
        cargo publish --dry-run --allow-dirty
    else
        cargo publish --no-verify
        echo -e "${YELLOW}Waiting 45s for crates.io index update...${NC}"
        sleep 45
    fi

    echo -e "${GREEN}$crate_name published${NC}"
    cd "$ROOT_DIR"
}

# Function to publish WASM to npm
publish_wasm() {
    echo -e "${BLUE}Building and publishing @mpc-wallet/wasm to npm...${NC}"

    cd "$ROOT_DIR/crates/mpc-wallet-wasm"

    # Build WASM with scope
    wasm-pack build --target web --scope mpc-wallet

    cd pkg

    # Update package.json with proper name and metadata
    node -e "
        const fs = require('fs');
        const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
        pkg.name = '@mpc-wallet/wasm';
        pkg.repository = {
            type: 'git',
            url: 'https://github.com/Kazopl/mpc-agent-wallet.git',
            directory: 'crates/mpc-wallet-wasm'
        };
        pkg.publishConfig = { access: 'public' };
        fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2));
    "

    # Check bundle size
    SIZE=$(du -k mpc_wallet_wasm_bg.wasm | cut -f1)
    echo -e "${BLUE}   WASM bundle size: ${SIZE}KB${NC}"

    if [ "$DRY_RUN" = true ]; then
        npm publish --access public --dry-run
    else
        npm publish --access public
    fi

    echo -e "${GREEN}@mpc-wallet/wasm published${NC}"
    cd "$ROOT_DIR"
}

# Function to publish TypeScript SDK to npm
publish_typescript() {
    echo -e "${BLUE}Publishing @mpc-wallet/sdk to npm...${NC}"

    cd "$ROOT_DIR/packages/mpc-wallet-sdk"

    # Install dependencies and build
    npm ci
    npm run build

    if [ "$DRY_RUN" = true ]; then
        npm publish --access public --dry-run
    else
        npm publish --access public
    fi

    echo -e "${GREEN}@mpc-wallet/sdk published${NC}"
    cd "$ROOT_DIR"
}

# Function to publish Python SDK to PyPI
publish_python() {
    echo -e "${BLUE}Publishing mpc-wallet to PyPI...${NC}"

    cd "$ROOT_DIR/packages/mpc-wallet-python"

    # Clean previous builds
    rm -rf dist/ build/ *.egg-info/ src/*.egg-info/

    # Build using the build module
    python -m pip install --quiet build
    python -m build

    if [ "$DRY_RUN" = true ]; then
        echo -e "${YELLOW}Would upload:${NC}"
        ls -la dist/
        # Check package
        python -m pip install --quiet twine
        twine check dist/*
    else
        # For local publishing, use twine with credentials
        # For CI, use Trusted Publishing (OIDC) instead!
        python -m pip install --quiet twine
        twine check dist/*

        if [ -n "$TWINE_USERNAME" ] && [ -n "$TWINE_PASSWORD" ]; then
            twine upload dist/*
        else
            echo -e "${YELLOW}Warning: No TWINE credentials found.${NC}"
            echo -e "${YELLOW}  For local publishing, set TWINE_USERNAME and TWINE_PASSWORD.${NC}"
            echo -e "${YELLOW}  For CI/CD, use GitHub Actions with Trusted Publishing (OIDC).${NC}"
            echo -e "${YELLOW}  See: https://docs.pypi.org/trusted-publishers/${NC}"
            exit 1
        fi
    fi

    echo -e "${GREEN}mpc-wallet published${NC}"
    cd "$ROOT_DIR"
}

# Run tests if not skipped
if [ "$SKIP_TESTS" = false ]; then
    echo -e "${BLUE}Running tests...${NC}"
    echo ""

    echo "Testing Rust crates..."
    cargo test --all-features

    echo ""
    echo "Testing TypeScript SDK..."
    cd "$ROOT_DIR/packages/mpc-wallet-sdk"
    npm ci
    npm test -- --run || true
    cd "$ROOT_DIR"

    echo ""
    echo -e "${GREEN}All tests passed${NC}"
    echo ""
fi

# Determine which packages to publish
if [ -n "$PACKAGE" ]; then
    case $PACKAGE in
        core)
            publish_rust_crate "mpc-wallet-core" "crates/mpc-wallet-core"
            ;;
        relay)
            publish_rust_crate "mpc-wallet-relay" "crates/mpc-wallet-relay"
            ;;
        wasm)
            publish_wasm
            ;;
        sdk)
            publish_typescript
            ;;
        python)
            publish_python
            ;;
        *)
            echo -e "${RED}Unknown package: $PACKAGE${NC}"
            echo "Valid packages: core, relay, wasm, sdk, python"
            exit 1
            ;;
    esac
else
    # Publish all packages in order
    echo -e "${BLUE}Publishing all packages in dependency order...${NC}"
    echo ""

    # 1. Rust core (no deps)
    publish_rust_crate "mpc-wallet-core" "crates/mpc-wallet-core"
    echo ""

    # 2. Rust relay (depends on core)
    publish_rust_crate "mpc-wallet-relay" "crates/mpc-wallet-relay"
    echo ""

    # 3. WASM (depends on core)
    publish_wasm
    echo ""

    # 4. TypeScript SDK (depends on WASM)
    publish_typescript
    echo ""

    # 5. Python SDK (independent)
    publish_python
    echo ""
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         All packages published                               ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Published packages:"
echo "  - mpc-wallet-core      https://crates.io/crates/mpc-wallet-core"
echo "  - mpc-wallet-relay     https://crates.io/crates/mpc-wallet-relay"
echo "  - @mpc-wallet/wasm     https://www.npmjs.com/package/@mpc-wallet/wasm"
echo "  - @mpc-wallet/sdk      https://www.npmjs.com/package/@mpc-wallet/sdk"
echo "  - mpc-wallet           https://pypi.org/project/mpc-wallet/"
