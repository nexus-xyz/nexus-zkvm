#!/bin/bash
set -e

ORIGINAL_DIR=$(pwd)
PROJECT_NAME="/tmp/nexus-host-ci"

function usage() {
    echo "Usage: $0 <file.rs>"
    echo "where <file.rs> is a path to an existing Rust file."
    exit 1
}

function cleanup() {
    cd "$ORIGINAL_DIR"
    rm -rf "$PROJECT_NAME"
}

function error_handler() {
    echo "Error occurred in test_sdk.sh on line ${1}. Exiting."
    cleanup
    exit 1
}

function check_arguments() {
    if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
        usage
    fi
}

function check_project_directory() {
    if [ -e "$PROJECT_NAME" ]; then
        echo "Error: Directory '$PROJECT_NAME' already exists."
        exit 1
    fi
}

function build_cargo_nexus() {
cargo build --release --package cargo-nexus --bin cargo-nexus
}

function create_nexus_project() {
./target/release/cargo-nexus nexus host "$PROJECT_NAME"
}

function copy_test_file() {
cp "$1" "$PROJECT_NAME/src/guest/src/main.rs"
}

function update_dependencies() {
    # Link host SDK in Cargo.toml to the current SDK commit
    sed -i.bak "s#nexus-sdk = { git = \"https://github.com/nexus-xyz/nexus-zkvm.git\", version = \"0.2.1\" }#nexus-sdk = { path = \"$ORIGINAL_DIR/sdk\"}#" Cargo.toml
    cd src/guest
    # Link guest runtime in Cargo.toml to the current commit runtime
    sed -i.bak "s#nexus-rt = { git = \"https://github.com/nexus-xyz/nexus-zkvm.git\", version = \"0.2.1\" }#nexus-rt = { path = \"$ORIGINAL_DIR/runtime\" }#" Cargo.toml
    cd ../../
}

function run_project() {
cargo update
cargo run --release
}

trap cleanup SIGINT
trap 'error_handler $LINENO' ERR

check_arguments "$@"
check_project_directory

set -x

build_cargo_nexus
create_nexus_project
copy_test_file "$1"
cd "$PROJECT_NAME"
update_dependencies
run_project

cleanup
