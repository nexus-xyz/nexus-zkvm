#!/bin/bash
# This script follows steps written in README.md
# Using the rust file specified as the unique argument.
# Call at the top directory of the nexus-zkvm project
# For example:
# ./assets/scripts/smoke.sh examples/src/bin/fib3.rs
# Every command needs to succeed
set -e

ORIGINAL_DIR=$(pwd)
PROJECT_NAME="/tmp/nexus-project-ci"

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
    echo "Error occurred in smoke.sh on line ${1}. Exiting."
    cleanup
    exit 1
}

trap 'error_handler $LINENO' ERR

cargo build --release --package cargo-nexus --bin cargo-nexus
./target/release/cargo-nexus nexus new "$PROJECT_NAME"
cp "$1" "$PROJECT_NAME/src/main.rs"
cd "$PROJECT_NAME"
cargo update

ls -lab .

cargo version -v
cat Cargo.lock

# Link the test program to the latest runtime code
sed -e "s#git = \"https://github.com/nexus-xyz/nexus-zkvm.git\"#path = \"$ORIGINAL_DIR/runtime\"#" Cargo.toml > Cargo.tmp && mv Cargo.tmp Cargo.toml

"$ORIGINAL_DIR/target/release/cargo-nexus" nexus run -v
"$ORIGINAL_DIR/target/release/cargo-nexus" nexus prove
"$ORIGINAL_DIR/target/release/cargo-nexus" nexus verify

# cleanup
