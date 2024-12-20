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

# Define a reusable variable to avoid repeating the same path multiple times.
CARGO_NEXUS="$ORIGINAL_DIR/target/release/cargo-nexus"

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

# Handle script interruptions and clean up resources properly.
trap cleanup SIGINT
# Provide error details when the script encounters an issue.
trap 'error_handler $LINENO' ERR

error_handler() {
    echo "Error occurred in smoke.sh on line ${1}. Exiting."
    cleanup
    exit 1
}

# Build the nexus CLI tool with the required configuration.
cargo build --release --package cargo-nexus --bin cargo-nexus

# Create a new temporary project using the nexus CLI.
"$CARGO_NEXUS" nexus new "$PROJECT_NAME"

# Copy the provided Rust file into the new project as the main file.
cp "$1" "$PROJECT_NAME/src/main.rs"
cd "$PROJECT_NAME"

# Remove the existing Cargo.lock file to ensure Cargo generates a fresh lockfile.
# This prevents compatibility issues with dependency versioning changes.
rm -f "Cargo.lock"

# Update the Cargo.toml file to link the test program to the local runtime instead of the Git repository.
sed -e "s#git = \"https://github.com/nexus-xyz/nexus-zkvm.git\"#path = \"$ORIGINAL_DIR/runtime\"#" Cargo.toml > Cargo.tmp && mv Cargo.tmp Cargo.toml

# Run the test program, generate proofs, and verify them using the nexus CLI.
"$CARGO_NEXUS" nexus run -v
"$CARGO_NEXUS" nexus prove
"$CARGO_NEXUS" nexus verify

# Clean up resources after the script finishes successfully.
cleanup
