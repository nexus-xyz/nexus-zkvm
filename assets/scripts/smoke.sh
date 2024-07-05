#! /bin/bash

# This script follows steps written in README.md
# Using the rust file specified as the unique argument.

# Call at the top directory of the nexus-zkvm project
# For example:
# ./assets/scripts/e2e.sh examples/src/bin/fib3.rs

# Every command needs to succeed
set -e

ORIGINAL_DIR=`pwd`
PROJECT_NAME="nexus-project-ci"

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <file.rs>"
    exit 1
fi

if [ ! -f "$1" ]; then
    echo "Usage: $0 <file.rs>"
    echo "where <file.rs> is a path to a file."
    exit 1
fi

if [ -e $PROJECT_NAME ]; then
    echo "Error: Directory 'nexus-project-ci' already exists."
    exit 1
fi

set -x

cp -n Cargo.toml Cargo.toml.bkp

error_handler() {
    echo "Error occured in e2e.sh: : ${1}. Exiting."
    cd $ORIGINAL_DIR
    rm -rf $PROJECT_NAME
    mv -f Cargo.toml.bkp Cargo.toml
    exit 1
}
trap 'error_handler ${LINENO}' ERR

cargo build --release --package nexus-tools --bin cargo-nexus
./target/release/cargo-nexus nexus new $PROJECT_NAME
cp $1 $PROJECT_NAME/src/main.rs
cd $PROJECT_NAME
../target/release/cargo-nexus nexus run
../target/release/cargo-nexus nexus prove
../target/release/cargo-nexus nexus verify
cd $ORIGINAL_DIR
rm -rf $PROJECT_NAME
mv -f Cargo.toml.bkp Cargo.toml
