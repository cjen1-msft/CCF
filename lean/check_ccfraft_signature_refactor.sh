#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")"

expected_model_hash="8c840c5eb7228ad1562e13150d9083287448764ab48202a8788446c9dedb15d8"
model_hash="$(sha256sum CCFRaft/Model.lean)"
model_hash="${model_hash%% *}"
if [[ "$model_hash" != "$expected_model_hash" ]]; then
  echo "CCFRaft/Model.lean differs from the signature-refactor baseline" >&2
  exit 1
fi

reachable_theorems=(
  reachableSystemInductiveInvariant
  reachableCommittedLogsPrefix
  reachableCommittedFrontierIsSignature
  reachableLogMatching
  reachableMonoLog
  reachableElectionSafety
  reachableLeaderCompleteness
  reachableConsensusSafety
)

for theorem in "${reachable_theorems[@]}"; do
  if ! grep -Fq "#print axioms CCFRaft.$theorem" CCFRaft.lean; then
    echo "CCFRaft.lean does not audit CCFRaft.$theorem" >&2
    exit 1
  fi
done

if grep -R -n -E \
    '(^|[^[:alnum:]_])(sorry|admit)([^[:alnum:]_]|$)' \
    CCFRaft.lean CCFRaft --include='*.lean'; then
  echo "CCFRaft sources contain a proof placeholder" >&2
  exit 1
fi

nice -n 10 ionice -c 3 lake build CCFRaft ccf-raft-simulator

simulator=".lake/build/bin/ccf-raft-simulator"

check_trace() {
  local trace="$1"
  local expected="$2"
  local actual
  actual="$("$simulator" replay "$trace")"
  if [[ "$actual" != "$expected" ]]; then
    echo "unexpected final state for $trace" >&2
    echo "expected: $expected" >&2
    echo "actual:   $actual" >&2
    exit 1
  fi
}

check_trace \
  CCFRaft/signature-commit.trace \
  "replayed 15 arbitrary-term Raft actions; max term=1; commit indices=[2, 0, 0, 0, 0]"
check_trace \
  CCFRaft/arbitrary-terms.trace \
  "replayed 68 arbitrary-term Raft actions; max term=4; commit indices=[2, 4, 6, 0, 0]"
check_trace \
  CCFRaft/delayed-ack.trace \
  "replayed 25 arbitrary-term Raft actions; max term=2; commit indices=[2, 0, 0, 0, 0]"
check_trace \
  CCFRaft/follower-overcommit.trace \
  "replayed 98 arbitrary-term Raft actions; max term=3; commit indices=[6, 0, 4, 2, 2]"
