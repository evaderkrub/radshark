#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Dave Robins

set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
build="${RADSHARK_BUILD_DIR:-$HOME/buildfiles/radshark}"
cmake -S "$root" -B "$build" -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo "$@"
cmake --build "$build"
