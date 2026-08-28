#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

cd "$(dirname "$0")"

output_dir=".lake/build/full-trace-prototype"
raw_trace="$output_dir/replicate.ndjson"
certificate="$output_dir/proposed-mapping-certificate-v2.json"
driver="../build/raft_driver"
scenario="../tests/raft_scenarios/replicate"
reducer="CCFRaft/full_trace_prototype.py"

if [[ ! -x "$driver" ]]; then
  echo "real raft driver is absent or not executable: $driver" >&2
  exit 2
fi

mkdir -p "$output_dir"

nice -n 10 python3 ../tests/raft_scenarios_runner.py \
  "$driver" \
  -o "$output_dir" \
  "$scenario" >/dev/null

python3 "$reducer" reduce \
  --raw "$raw_trace" \
  --certificate "$certificate" \
  --quiet

event_count="$(wc -l <"$raw_trace")"
if [[ "$event_count" -ne 53 ]]; then
  echo "unexpected real trace count: events=$event_count" >&2
  exit 1
fi

python3 "$reducer" validate \
  --raw "$raw_trace" \
  --certificate "$certificate"

echo "certificate=$certificate"
echo "result=passed"
