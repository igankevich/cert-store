#!/bin/sh
set -ex
#git config --global --add safe.directory "$PWD"
cargo clippy --workspace --all-features --all-targets
cargo test --workspace --all-features
