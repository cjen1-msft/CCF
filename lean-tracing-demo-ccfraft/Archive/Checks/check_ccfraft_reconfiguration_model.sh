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
    CCFRaft/Model.lean CCFRaft/HandlerProofs.lean CCFRaft/Simulation.lean \
    CCFRaft/Properties.lean CCFRaft/ReconfigurationPreservation.lean \
    CCFRaft/Proofs.lean CCFRaft/BootstrapExamples.lean; then
  echo "executable reconfiguration sources contain a proof placeholder" >&2
  exit 1
fi

if grep -n -E \
    'def INITIAL_CONFIGURATION_SIZE|newConfiguration\.card = ' \
    CCFRaft/Model.lean CCFRaft/Simulation.lean; then
  echo "ChangeConfiguration is restricted to the bootstrap cardinality" >&2
  exit 1
fi

grep -F "class Bootstrap (Node : Type) [DecidableEq Node] where" \
  CCFRaft/Model.lean >/dev/null
grep -F "structure State (Node TxId : Type) where" \
  CCFRaft/Model.lean >/dev/null
grep -F "structure NodeStore (Node TxId : Type) where" \
  CCFRaft/Model.lean >/dev/null
grep -F "entries : Finmap (fun _ : Node => NodeState Node TxId)" \
  CCFRaft/Model.lean >/dev/null
grep -F "def AllocatedNodesExactlyJoined (state : State Node TxId) : Prop :=" \
  CCFRaft/Properties.lean >/dev/null
grep -F "allocatedNodesExactlyJoined : AllocatedNodesExactlyJoined state" \
  CCFRaft/Properties.lean >/dev/null
grep -F "theorem changeConfiguration_addedNode_fresh" \
  CCFRaft/ReconfigurationPreservation.lean >/dev/null
if grep -n -F "Fintype Node" \
    CCFRaft/Model.lean CCFRaft/HandlerProofs.lean \
    CCFRaft/Properties.lean CCFRaft/ReconfigurationPreservation.lean; then
  echo "canonical reconfiguration semantics require a finite node universe" >&2
  exit 1
fi
python3 generalize_ccfraft_node_types.py --check
grep -F "SCHEDULER_CONFIGURATION_TARGET_WIDTH" \
  CCFRaft/Simulation.lean >/dev/null

check_hash \
  CCFRaft/Model.lean \
  9fac9537058dcbbb63ef2e42aece8eca3c69533655748c782fb6a4b572b97275
check_hash \
  CCFRaft/HandlerProofs.lean \
  0a3b3bcb5b216574034c51a8333123879a88a20a975a0c68335761cac53d2117
check_hash \
  CCFRaft/Simulation.lean \
  343a211ac0dd543e4532d97674ba76c3ced2c1b96c8768b7110492a23b673d03
check_hash \
  CCFRaft/BootstrapExamples.lean \
  362bcc5f1997503dac7b0314bade4c0f749d756423cac1e6d99e6f5c7c50ae71

nice -n 10 ionice -c 3 lake build \
  CCFRaft ccf-raft-simulator \
  >/dev/null

actual="$(
  .lake/build/bin/ccf-raft-simulator \
    replay CCFRaft/traces/reconfiguration-5-to-5.trace
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
    replay CCFRaft/traces/reconfiguration-5-to-5-to-5.trace
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

shrinking="$(
  .lake/build/bin/ccf-raft-simulator \
    replay CCFRaft/traces/reconfiguration-5-to-1.trace
)"
for expected in \
    "replayed 78 arbitrary-term Raft actions" \
    "max term=3" \
    "commit indices=[9, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0]" \
    "current configuration indices=[8, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0]" \
    "leader current configurations=[(0, [0, 5, 6])]" \
    "active configuration indices=[[8], [0, 1, 2, 3, 4], [0, 1, 2, 3, 4], [0], [0], [4, 8], [0], [0], [0], [0], [0], [0], [0], [0], [0]]" \
    "joined=[0, 1, 2, 3, 4, 5, 6]"; do
  if [[ "$shrinking" != *"$expected"* ]]; then
    echo "shrinking reconfiguration trace omitted expected state: $expected" >&2
    echo "$shrinking" >&2
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
  CCFRaft/traces/reconfiguration-old-quorum-only.trace \
  "disabled action: commit,0"
expect_disabled \
  CCFRaft/traces/reconfiguration-new-quorum-only.trace \
  "disabled action: commit,0"
expect_disabled \
  CCFRaft/traces/reconfiguration-rejoin.trace \
  "disabled action: reconfigure,0,0,5,6,7,8"

echo "$actual"
echo "$stacked"
echo "$shrinking"
echo "result=passed"
