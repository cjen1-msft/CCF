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
capacity_log="$output_dir/inconclusive-transaction-capacity.log"
capacity_trace="$output_dir/transaction-capacity.ndjson"

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
