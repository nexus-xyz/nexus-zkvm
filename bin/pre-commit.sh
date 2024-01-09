#!/bin/sh

# This script runs the same checks as the github CI;
#  it can be used a a pre-commit hook.

set -e

cargo fmt --all --check
cargo build
cargo clippy --all-targets
cargo test -r
