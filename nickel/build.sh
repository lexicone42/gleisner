#!/bin/sh
set -e

# Build gleisner workspace in release mode.
# In a minimal environment, the rust toolchain is provided
# as a build_dep and already in PATH.
cargo build --release \
  -p gleisner-cli \
  -p gleisner-tui \
  -p gleisner-sandbox-init

# Install binaries to the output directory
mkdir -pv "$OUTPUT_DIR/usr/bin"
cp -v target/release/gleisner "$OUTPUT_DIR/usr/bin/gleisner"
cp -v target/release/gleisner-tui "$OUTPUT_DIR/usr/bin/gleisner-tui"
cp -v target/release/gleisner-sandbox-init "$OUTPUT_DIR/usr/bin/gleisner-sandbox-init"
