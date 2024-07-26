#!/bin/bash
# This script follows steps written in README.md
# Using the rust file specified as the unique argument.
# Call at the top directory of the nexus-zkvm project
# For example:
# ./assets/scripts/test_sdk.sh examples/src/bin/fib3.rs
# Every command needs to succeed
set -e

ORIGINAL_DIR=$(pwd)
PROJECT_NAME="/tmp/nexus-host-ci"

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <file.rs>"
    exit 1
fi

if [ ! -f "$1" ]; then
    echo "Usage: $0 <file.rs>"
    echo "where <file.rs> is a path to a file."
    exit 1
fi

if [ -e "$PROJECT_NAME" ]; then
    echo "Error: Directory '$PROJECT_NAME' already exists."
    exit 1
fi

set -x

cleanup() {
    cd "$ORIGINAL_DIR"
    rm -rf "$PROJECT_NAME"
}

trap cleanup SIGINT

error_handler() {
    echo "Error occurred in test_sdk.sh on line ${1}. Exiting."
    cleanup
    exit 1
}

trap 'error_handler $LINENO' ERR

# Builds current cargo-nexus tool from current commit
cargo build --release --package cargo-nexus --bin cargo-nexus
./target/release/cargo-nexus nexus host "$PROJECT_NAME"
# Copy the test source file to guest program
cp "$1" "$PROJECT_NAME/src/guest/src/main.rs"
cd "$PROJECT_NAME"

# Link the test program to the current sdk commit
sed -e "s#nexus-sdk = { git = \"https://github.com/nexus-xyz/nexus-zkvm.git\", version = \"0.2.0\" }#nexus-sdk = { path = \"$ORIGINAL_DIR/sdk\"}#" Cargo.toml > Cargo.tmp && mv Cargo.tmp Cargo.toml

cargo update
cargo run --release

cleanup
