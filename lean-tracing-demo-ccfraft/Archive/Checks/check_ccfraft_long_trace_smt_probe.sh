#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

cd "$(dirname "$0")"

output_dir=".lake/build/long-trace-smt-probe"
runner_output="$output_dir/replicate.ndjson"
driver="../build/raft_driver"
scenario="../tests/raft_scenarios/replicate"
generator="CCFRaft/long_trace_smt_probe.py"
lean_checker="CCFRaft/LongTraceSmtProbe.lean"

if [[ ! -x "$driver" ]]; then
  echo "real raft driver is absent or not executable: $driver" >&2
  exit 2
fi

if command -v cvc5 >/dev/null 2>&1; then
  cvc5_command=(cvc5)
elif command -v nix >/dev/null 2>&1; then
  cvc5_store="$(nix build --no-link --print-out-paths nixpkgs#cvc5)"
  cvc5_command=("$cvc5_store/bin/cvc5")
else
  echo "cvc5 is unavailable; install it or provide nix" >&2
  exit 2
fi

mkdir -p "$output_dir"

scenario_start="$(date +%s%N)"
python3 ../tests/raft_scenarios_runner.py \
  "$driver" \
  -o "$output_dir" \
  "$scenario" >/dev/null
scenario_end="$(date +%s%N)"
scenario_ms="$(( (scenario_end - scenario_start) / 1000000 ))"

python3 "$generator" generate \
  --raw "$runner_output" \
  --output-dir "$output_dir"

solver_start="$(date +%s%N)"
"${cvc5_command[@]}" --lang smt2 "$output_dir/probe.smt2" \
  >"$output_dir/solver.out"
solver_end="$(date +%s%N)"
solver_ms="$(( (solver_end - solver_start) / 1000000 ))"

python3 "$generator" validate-solver --output-dir "$output_dir"

lean_start="$(date +%s%N)"
lean_summary="$(
  nice -n 10 lake env lean --run "$lean_checker" \
    "$output_dir/semantic.trace" \
    "$output_dir/model.values" \
    "$output_dir/observations.csv"
)"
lean_end="$(date +%s%N)"
lean_ms="$(( (lean_end - lean_start) / 1000000 ))"
echo "$lean_summary"

python3 "$generator" report \
  --output-dir "$output_dir" \
  --scenario-ms "$scenario_ms" \
  --solver-ms "$solver_ms" \
  --lean-ms "$lean_ms" \
  --lean-summary "$lean_summary"

event_count="$(wc -l <"$output_dir/raw.ndjson")"
suffix_count="$(wc -l <"$output_dir/suffix.ndjson")"
action_count="$(wc -l <"$output_dir/semantic.trace")"

if [[ "$event_count" -ne 53 || "$suffix_count" -ne 34 || "$action_count" -ne 26 ]]; then
  echo "unexpected output counts: events=$event_count suffix=$suffix_count actions=$action_count" >&2
  exit 1
fi

echo "events=$event_count suffix_events=$suffix_count actions=$action_count"
echo "timings_ms scenario=$scenario_ms solver=$solver_ms lean_compile_and_replay=$lean_ms"
echo "result=passed"
