#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

cd "$(dirname "$0")"

check_hash() {
  local path="$1"
  local expected="$2"
  local actual
  actual="$(sha256sum "$path")"
  actual="${actual%% *}"
  if [[ "$actual" != "$expected" ]]; then
    echo "$path differs from the reviewed executable reconfiguration slice" >&2
    exit 1
  fi
  echo "$path=$actual"
}

if grep -R -n -E \
    '(^|[^[:alnum:]_])(sorry|admit)([^[:alnum:]_]|$)' \
    CCFRaft/Model.lean CCFRaft/HandlerProofs.lean CCFRaft/Simulation.lean; then
  echo "executable reconfiguration sources contain a proof placeholder" >&2
  exit 1
fi

check_hash \
  CCFRaft/Model.lean \
  8b97d62c37b0f2905b3c2f244ecb81df6d98dbb6df4ae5b6b990672371daa73a
check_hash \
  CCFRaft/HandlerProofs.lean \
  14e75abe119294022fdca13ec943f4e81b2bc5ef320ccd2de722f8bfc5859911
check_hash \
  CCFRaft/Simulation.lean \
  e04f3e6b292e7e6794e0a68318b1c295de6d551d7367f368ce5339271049a6b3

nice -n 10 ionice -c 3 lake build \
  CCFRaft.Model CCFRaft.HandlerProofs CCFRaft.Simulation ccf-raft-simulator \
  >/dev/null

actual="$(
  .lake/build/bin/ccf-raft-simulator \
    replay CCFRaft/reconfiguration-5-to-5.trace
)"
for expected in \
    "replayed 49 arbitrary-term Raft actions" \
    "max term=2" \
    "commit indices=[2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0]" \
    "leaders=[0, 5]" \
    "current configuration indices=[1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]" \
    "leader current configurations=[(0, [5, 6, 7, 8, 9]), (5, [5, 6, 7, 8, 9])]" \
    "active configuration indices=[[1], [0, 1], [0, 1], [0], [0], [1], [0, 1], [0, 1], [0], [0], [0], [0], [0], [0], [0]]" \
    "joined=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]"; do
  if [[ "$actual" != *"$expected"* ]]; then
    echo "reconfiguration trace omitted expected state: $expected" >&2
    echo "$actual" >&2
    exit 1
  fi
done

stacked="$(
  .lake/build/bin/ccf-raft-simulator \
    replay CCFRaft/reconfiguration-5-to-5-to-5.trace
)"
for expected in \
    "replayed 125 arbitrary-term Raft actions" \
    "max term=3" \
    "commit indices=[2, 0, 0, 0, 0, 4, 2, 2, 0, 0, 4, 2, 2, 0, 0]" \
    "leaders=[0, 5, 10]" \
    "leader current configurations=[(0, [5, 6, 7, 8, 9]), (5, [10, 11, 12, 13, 14]), (10, [10, 11, 12, 13, 14])]" \
    "joined=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]"; do
  if [[ "$stacked" != *"$expected"* ]]; then
    echo "stacked reconfiguration trace omitted expected state: $expected" >&2
    echo "$stacked" >&2
    exit 1
  fi
done

expect_disabled() {
  local trace="$1"
  local expected="$2"
  local output
  if output="$(
      .lake/build/bin/ccf-raft-simulator replay "$trace" 2>&1
    )"; then
    echo "$trace unexpectedly replayed" >&2
    exit 1
  fi
  if [[ "$output" != "$expected" ]]; then
    echo "$trace failed for an unexpected reason: $output" >&2
    exit 1
  fi
  echo "$trace=$output"
}

expect_disabled \
  CCFRaft/reconfiguration-old-quorum-only.trace \
  "disabled action: commit,0"
expect_disabled \
  CCFRaft/reconfiguration-new-quorum-only.trace \
  "disabled action: commit,0"
expect_disabled \
  CCFRaft/reconfiguration-rejoin.trace \
  "disabled action: reconfigure,0,0,5,6,7,8"

echo "$actual"
echo "$stacked"
echo "result=passed"
