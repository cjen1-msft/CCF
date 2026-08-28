#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

cd "$(dirname "$0")"

output_dir=".lake/build/naive-full-state-smt"
determinism_dir=".lake/build/naive-full-state-smt-determinism"
mutation_root=".lake/build/naive-full-state-smt-mutations"
certificate=".lake/build/full-trace-prototype/proposed-mapping-certificate-v2.json"
generator="CCFRaft/naive_full_state_smt.py"

./check_ccfraft_full_trace_prototype.sh

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

generation_start="$(date +%s%N)"
python3 "$generator" generate \
  --certificate "$certificate" \
  --output-dir "$output_dir"
generation_end="$(date +%s%N)"
generation_ms="$(( (generation_end - generation_start) / 1000000 ))"

python3 "$generator" generate \
  --certificate "$certificate" \
  --output-dir "$determinism_dir"
cmp "$output_dir/formula.smt2" "$determinism_dir/formula.smt2"
rm -rf .lake/build/naive-full-state-smt-determinism

solver_start="$(date +%s%N)"
nice -n 10 "${cvc5_command[@]}" --lang smt2 "$output_dir/formula.smt2" \
  >"$output_dir/solver.out"
solver_end="$(date +%s%N)"
solver_ms="$(( (solver_end - solver_start) / 1000000 ))"

decode_start="$(date +%s%N)"
set +e
python3 "$generator" decode \
  --certificate "$certificate" \
  --output-dir "$output_dir" \
  --generator-ms "$generation_ms" \
  --solver-ms "$solver_ms"
decode_status="$?"
set -e
decode_end="$(date +%s%N)"
decode_ms="$(( (decode_end - decode_start) / 1000000 ))"

if [[ "$decode_status" -eq 3 ]]; then
  echo "result=INCONCLUSIVE_ENCODING"
  exit 3
elif [[ "$decode_status" -ne 0 ]]; then
  exit "$decode_status"
fi

python3 "$generator" validate-witness \
  --certificate "$certificate" \
  --output-dir "$output_dir"

for mutation in conflicting-observed-commit wrong-destination-action-param; do
  mutation_dir="$mutation_root/$mutation"
  python3 "$generator" generate \
    --certificate "$certificate" \
    --output-dir "$mutation_dir" \
    --mutation "$mutation"
  nice -n 10 "${cvc5_command[@]}" --lang smt2 "$mutation_dir/formula.smt2" \
    >"$mutation_dir/solver.out"
  python3 "$generator" validate-mutation \
    --certificate "$certificate" \
    --output-dir "$mutation_dir" \
    --mutation "$mutation"
done
rm -rf .lake/build/naive-full-state-smt-mutations

if [[ "$solver_ms" -lt 60000 ]]; then
  under_target=yes
else
  under_target=no
fi

formula_bytes="$(wc -c <"$output_dir/formula.smt2")"
witness_bytes="$(wc -c <"$output_dir/witness-v1.json")"
echo "timings_ms formula_generation=$generation_ms direct_smt=$solver_ms decode=$decode_ms"
echo "prototype_target_under_60s=$under_target"
echo "output_bytes formula=$formula_bytes witness=$witness_bytes"
echo "result=passed"
