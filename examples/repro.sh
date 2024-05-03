#!/usr/bin/env zsh

SCRIPT_PATH="${0:A:h}"

pushd .

pushd "${SCRIPT_PATH}/.."
cargo build --release --package nexus-tools --bin cargo-nexus

pushd "${SCRIPT_PATH}"
../target/release/cargo-nexus nexus run --bin display_bug $@
STATUS=$?

popd
popd
popd

exit $STATUS
