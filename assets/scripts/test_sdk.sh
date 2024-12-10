#!/bin/bash
set -e

ORIGINAL_DIR=$(pwd)
PROJECT_NAME="/tmp/nexus-host-ci"
CARGO_NEXUS="$(pwd)/target/release/cargo-nexus"

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
    if [[ -z "${GITHUB_SHA}" ]]; then
        $CARGO_NEXUS nexus host "$PROJECT_NAME"
    else
        $CARGO_NEXUS nexus host "$PROJECT_NAME" --rev "${GITHUB_SHA}"
    fi
}

function copy_test_file() {
cp "$1" "$PROJECT_NAME/src/guest/src/main.rs"
}

function run_project() {
# Test the cycles feature inside the guest project
pushd src/guest
$CARGO_NEXUS nexus run
popd

cargo run --release
}

trap cleanup SIGINT
trap 'error_handler $LINENO' ERR

check_arguments "$@"
check_project_directory

set -x

build_cargo_nexus
create_nexus_project

# remove the guest lockfile so that Cargo regenerates it, to keep up with updates to lockfile versioning
rm -f "$PROJECT_NAME/Cargo.lock"

copy_test_file "$1"
cd "$PROJECT_NAME"

run_project

cleanup
