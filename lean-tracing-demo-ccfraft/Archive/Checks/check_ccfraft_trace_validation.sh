#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

cd "$(dirname "$0")"

output_dir=".lake/build/trace-validation"
witness="$output_dir/accepted.trace"
accepted_log="$output_dir/accepted.log"
rejected_log="$output_dir/rejected.log"
timing_log="$output_dir/rejected-replicate-timing.log"
preprocessed_log="$output_dir/accepted-preprocessed.log"
undelivered_log="$output_dir/rejected-undelivered-send.log"
missing_log="$output_dir/rejected-missing-state.log"
bounded_log="$output_dir/inconclusive.log"
heartbeat_log="$output_dir/accepted-heartbeat.log"
nine_log="$output_dir/accepted-nine-replications.log"
packet_mismatch_log="$output_dir/rejected-heartbeat-packet-mismatch.log"
configuration_log="$output_dir/rejected-extra-configuration.log"
bootstrap_index_log="$output_dir/rejected-bootstrap-index.log"
duplicate_log="$output_dir/accepted-duplicate-heartbeat.log"
changed_configuration_log="$output_dir/rejected-changed-configuration.log"
arbitrary_bootstrap_log="$output_dir/accepted-arbitrary-bootstrap.log"
missing_bootstrap_leader_log="$output_dir/rejected-bootstrap-leader-missing.log"
capacity_log="$output_dir/inconclusive-transaction-capacity.log"
capacity_trace="$output_dir/transaction-capacity.ndjson"
minimum_witness="$output_dir/accepted-minimum-bounds.trace"
minimum_log="$output_dir/accepted-minimum-bounds.log"
minimum_depth_log="$output_dir/rejected-minimum-depth.log"
minimum_exact_states_log="$output_dir/rejected-exact-state-ceiling.log"
minimum_gap_log="$output_dir/rejected-minimum-gap.log"
minimum_states_log="$output_dir/inconclusive-minimum-states.log"

mkdir -p "$output_dir"

if grep -n -E '^import .*TLA|native_decide' \
    CCFRaft/TraceValidation.lean CCFRaftTraceValidator.lean; then
  echo "trace validator uses a forbidden TLA or native compiler dependency" >&2
  exit 1
fi

nice -n 10 ionice -c 3 lake build \
  CCFRaft.TraceValidation ccf-raft-trace-validator ccf-raft-simulator \
  >/dev/null

.lake/build/bin/ccf-raft-trace-validator \
  CCFRaft/traces/implementation/accepted.ndjson \
  "$witness" \
  >"$accepted_log"

grep -F "ACCEPT observations=12 ignored=0 actions=15 bootstrap_index=2" \
  "$accepted_log" >/dev/null
grep -F "observation_constraints=ok" "$accepted_log" >/dev/null
grep -F "canonical_replay=ok" "$accepted_log" >/dev/null
diff -u CCFRaft/traces/implementation/accepted.trace "$witness"

.lake/build/bin/ccf-raft-trace-validator \
  CCFRaft/traces/implementation/accepted.ndjson \
  "$minimum_witness" \
  --minimize-bounds \
  >"$minimum_log"
grep -F \
  "MINIMUM_BOUNDS max_depth=15 max_gap=1 max_states=38" \
  "$minimum_log" >/dev/null

set +e
.lake/build/bin/ccf-raft-trace-validator \
  CCFRaft/traces/implementation/accepted.ndjson \
  "$output_dir/minimum-depth.trace" \
  --minimize-bounds 14 6 50000 \
  >"$minimum_depth_log" 2>&1
minimum_depth_status=$?
.lake/build/bin/ccf-raft-trace-validator \
  CCFRaft/traces/implementation/accepted.ndjson \
  "$output_dir/minimum-exact-states.trace" \
  --minimize-bounds 14 6 68 \
  >"$minimum_exact_states_log" 2>&1
minimum_exact_states_status=$?
.lake/build/bin/ccf-raft-trace-validator \
  CCFRaft/traces/implementation/accepted.ndjson \
  "$output_dir/minimum-gap.trace" \
  --minimize-bounds 15 0 50000 \
  >"$minimum_gap_log" 2>&1
minimum_gap_status=$?
.lake/build/bin/ccf-raft-trace-validator \
  CCFRaft/traces/implementation/accepted.ndjson \
  "$output_dir/minimum-states.trace" \
  --minimize-bounds 15 1 37 \
  >"$minimum_states_log" 2>&1
minimum_states_status=$?
set -e
if [[
  "$minimum_depth_status" -ne 1 ||
  "$minimum_exact_states_status" -ne 1 ||
  "$minimum_gap_status" -ne 1
]]; then
  echo "lower depth or gap unexpectedly admitted the accepted trace" >&2
  exit 1
fi
if [[ "$minimum_states_status" -ne 4 ]]; then
  echo "lower state ceiling did not return inconclusive" >&2
  exit 1
fi
grep -F "REJECT no witness exists within the supplied ceilings" \
  "$minimum_depth_log" "$minimum_gap_log" >/dev/null
grep -F "limit_hit=true state_limit_hit=false" \
  "$minimum_depth_log" "$minimum_gap_log" >/dev/null
grep -F \
  "expanded=68" \
  "$minimum_exact_states_log" >/dev/null
grep -F \
  "limit_hit=true state_limit_hit=false" \
  "$minimum_exact_states_log" >/dev/null
grep -F "INCONCLUSIVE minimum_bounds" "$minimum_states_log" >/dev/null
grep -F "state_limit_hit=true" "$minimum_states_log" >/dev/null

.lake/build/bin/ccf-raft-trace-validator \
  CCFRaft/traces/implementation/accepted-preprocessed.ndjson \
  "$output_dir/accepted-preprocessed.trace" \
  >"$preprocessed_log"

grep -F "ACCEPT observations=4 ignored=3 actions=3 bootstrap_index=2" \
  "$preprocessed_log" >/dev/null
diff -u \
  CCFRaft/traces/implementation/accepted-preprocessed.trace \
  "$output_dir/accepted-preprocessed.trace"

.lake/build/bin/ccf-raft-trace-validator \
  CCFRaft/traces/implementation/accepted-heartbeat.ndjson \
  "$output_dir/accepted-heartbeat.trace" \
  >"$heartbeat_log"

grep -F "ACCEPT observations=3 ignored=0 actions=2 bootstrap_index=2" \
  "$heartbeat_log" >/dev/null
diff -u \
  CCFRaft/traces/implementation/accepted-heartbeat.trace \
  "$output_dir/accepted-heartbeat.trace"

.lake/build/bin/ccf-raft-trace-validator \
  CCFRaft/traces/implementation/accepted-nine-replications.ndjson \
  "$output_dir/accepted-nine-replications.trace" \
  >"$nine_log"

grep -F "ACCEPT observations=10 ignored=0 actions=9 bootstrap_index=2" \
  "$nine_log" >/dev/null
diff -u \
  CCFRaft/traces/implementation/accepted-nine-replications.trace \
  "$output_dir/accepted-nine-replications.trace"

.lake/build/bin/ccf-raft-trace-validator \
  CCFRaft/traces/implementation/accepted-duplicate-heartbeat.ndjson \
  "$output_dir/accepted-duplicate-heartbeat.trace" \
  >"$duplicate_log"

grep -F "ACCEPT observations=5 ignored=0 actions=3 bootstrap_index=2" \
  "$duplicate_log" >/dev/null
diff -u \
  CCFRaft/traces/implementation/accepted-duplicate-heartbeat.trace \
  "$output_dir/accepted-duplicate-heartbeat.trace"

.lake/build/bin/ccf-raft-trace-validator \
  CCFRaft/traces/implementation/accepted-arbitrary-bootstrap.ndjson \
  "$output_dir/accepted-arbitrary-bootstrap.trace" \
  >"$arbitrary_bootstrap_log"

grep -F "ACCEPT observations=3 ignored=0 actions=2 bootstrap_index=2" \
  "$arbitrary_bootstrap_log" >/dev/null
grep -F \
  "node_map node-7=0, node-2=1, node-3=2, node-4=3, node-5=4, node-6=5" \
  "$arbitrary_bootstrap_log" >/dev/null
grep -F "canonical_replay=ok max_term=1" \
  "$arbitrary_bootstrap_log" >/dev/null
head -n 1 "$output_dir/accepted-arbitrary-bootstrap.trace" |
  grep -Fx "bootstrap,0,0,1,2,3,4,5" >/dev/null
arbitrary_bootstrap_replay="$(
  .lake/build/bin/ccf-raft-simulator \
    replay "$output_dir/accepted-arbitrary-bootstrap.trace"
)"
for expected in \
    "replayed 2 arbitrary-term Raft actions" \
    "leaders=[0]" \
    "leader current configurations=[(0, [0, 1, 2, 3, 4, 5])]" \
    "joined=[0, 1, 2, 3, 4, 5]"; do
  if [[ "$arbitrary_bootstrap_replay" != *"$expected"* ]]; then
    echo "arbitrary-bootstrap replay omitted expected state: $expected" >&2
    echo "$arbitrary_bootstrap_replay" >&2
    exit 1
  fi
done

set +e
.lake/build/bin/ccf-raft-trace-validator \
  CCFRaft/traces/implementation/rejected-bootstrap-leader-missing.ndjson \
  "$output_dir/rejected-bootstrap-leader-missing.trace" \
  >"$missing_bootstrap_leader_log" 2>&1
missing_bootstrap_leader_status=$?
set -e
if [[ "$missing_bootstrap_leader_status" -ne 2 ]]; then
  echo "leaderless bootstrap returned $missing_bootstrap_leader_status" >&2
  exit 1
fi
grep -F \
  "bootstrap configuration must be nonempty and contain the observed leader" \
  "$missing_bootstrap_leader_log" >/dev/null

if .lake/build/bin/ccf-raft-trace-validator \
    CCFRaft/traces/implementation/rejected.ndjson \
    "$output_dir/rejected.trace" \
    >"$rejected_log" 2>&1; then
  echo "invalid implementation trace unexpectedly validated" >&2
  exit 1
fi

grep -F "REJECT observation_index=11 line=12 function=commit" \
  "$rejected_log" >/dev/null
grep -F "disabled canonical action: commit,0" "$rejected_log" >/dev/null

if .lake/build/bin/ccf-raft-trace-validator \
    CCFRaft/traces/implementation/rejected-replicate-timing.ndjson \
    "$output_dir/rejected-replicate-timing.trace" \
    >"$timing_log" 2>&1; then
  echo "post-action replicate state unexpectedly validated" >&2
  exit 1
fi

grep -F "REJECT observation_index=1 line=2 function=replicate" \
  "$timing_log" >/dev/null
grep -F "state.last_idx: observed 1, model has 0" "$timing_log" >/dev/null

if .lake/build/bin/ccf-raft-trace-validator \
    CCFRaft/traces/implementation/rejected-undelivered-send.ndjson \
    "$output_dir/rejected-undelivered-send.trace" \
    >"$undelivered_log" 2>&1; then
  echo "undelivered send unexpectedly validated" >&2
  exit 1
fi

grep -F "trace ended before every observed AppendEntries send was received" \
  "$undelivered_log" >/dev/null

set +e
.lake/build/bin/ccf-raft-trace-validator \
  CCFRaft/traces/implementation/rejected-missing-state.ndjson \
  "$output_dir/rejected-missing-state.trace" \
  >"$missing_log" 2>&1
missing_status=$?
set -e
if [[ "$missing_status" -ne 2 ]]; then
  echo "malformed state returned $missing_status instead of parse error 2" >&2
  exit 1
fi
grep -F \
  "state requires current_view, last_idx, commit_idx, and leadership_state" \
  "$missing_log" >/dev/null

if .lake/build/bin/ccf-raft-trace-validator \
    CCFRaft/traces/implementation/rejected-heartbeat-packet-mismatch.ndjson \
    "$output_dir/rejected-heartbeat-packet-mismatch.trace" \
    >"$packet_mismatch_log" 2>&1; then
  echo "mismatched wire packets unexpectedly validated" >&2
  exit 1
fi
grep -F "recv_append_entries has no preceding unmatched send observation" \
  "$packet_mismatch_log" >/dev/null

set +e
.lake/build/bin/ccf-raft-trace-validator \
  CCFRaft/traces/implementation/rejected-extra-configuration.ndjson \
  "$output_dir/rejected-extra-configuration.trace" \
  >"$configuration_log" 2>&1
configuration_status=$?
set -e
if [[ "$configuration_status" -ne 2 ]]; then
  echo "extra configuration returned $configuration_status instead of 2" >&2
  exit 1
fi
grep -F "requires exactly one active configuration" \
  "$configuration_log" >/dev/null

set +e
.lake/build/bin/ccf-raft-trace-validator \
  CCFRaft/traces/implementation/rejected-bootstrap-index.ndjson \
  "$output_dir/rejected-bootstrap-index.trace" \
  >"$bootstrap_index_log" 2>&1
bootstrap_index_status=$?
set -e
if [[ "$bootstrap_index_status" -ne 2 ]]; then
  echo "bad bootstrap returned $bootstrap_index_status instead of 2" >&2
  exit 1
fi
grep -F "bootstrap args.idx is 3, expected 2" \
  "$bootstrap_index_log" >/dev/null

set +e
.lake/build/bin/ccf-raft-trace-validator \
  CCFRaft/traces/implementation/rejected-changed-configuration.ndjson \
  "$output_dir/rejected-changed-configuration.trace" \
  >"$changed_configuration_log" 2>&1
changed_configuration_status=$?
set -e
if [[ "$changed_configuration_status" -ne 2 ]]; then
  echo "changed configuration returned $changed_configuration_status" >&2
  exit 1
fi
grep -F "commit configurations differ from the supported bootstrap configuration" \
  "$changed_configuration_log" >/dev/null

head -n 1 \
  CCFRaft/traces/implementation/accepted-nine-replications.ndjson \
  >"$capacity_trace"
for ((index = 0; index < 65; index++)); do
  seqno=$((index + 3))
  last_idx=$((index + 2))
  printf \
    '{"tag":"raft_trace","msg":{"function":"replicate","view":1,"seqno":%d,"globally_committable":false,"state":{"node_id":"node-0","current_view":1,"last_idx":%d,"commit_idx":2,"leadership_state":"Leader"}}}\n' \
    "$seqno" "$last_idx" \
    >>"$capacity_trace"
done

set +e
.lake/build/bin/ccf-raft-trace-validator \
  "$capacity_trace" \
  "$output_dir/transaction-capacity.trace" \
  >"$capacity_log" 2>&1
capacity_status=$?
set -e
if [[ "$capacity_status" -ne 4 ]]; then
  echo "transaction capacity returned $capacity_status instead of 4" >&2
  exit 1
fi
grep -F \
  "INCONCLUSIVE transaction_id_bound=64 ordinary_replications=65" \
  "$capacity_log" >/dev/null

set +e
.lake/build/bin/ccf-raft-trace-validator \
  CCFRaft/traces/implementation/accepted.ndjson \
  "$output_dir/inconclusive.trace" \
  10 2 50000 \
  >"$bounded_log" 2>&1
bounded_status=$?
set -e
if [[ "$bounded_status" -ne 4 ]]; then
  echo "bounded search returned $bounded_status instead of inconclusive 4" >&2
  exit 1
fi
grep -F "INCONCLUSIVE observation_index=" "$bounded_log" >/dev/null

.lake/build/bin/ccf-raft-simulator replay "$witness" >/dev/null

echo "result=passed"
