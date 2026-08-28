#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

script_path="$(realpath "$0")"
cd "$(dirname "$script_path")"

output_dir=".lake/build/cheap-full-state-smt"
certificate=".lake/build/full-trace-prototype/proposed-mapping-certificate-v2.json"
baseline_witness=".lake/build/naive-full-state-smt/witness-v1.json"
smt_generator="CCFRaft/cheap_full_state_smt.py"
lean_generator="CCFRaft/cheap_full_state_lean.py"
generated_source="$output_dir/CanonicalCheapFullStateWitness.lean"
benchmark_json="$output_dir/benchmark-v1.json"

now_ns() {
  python3 -c 'import time; print(time.monotonic_ns())'
}

elapsed_ms() {
  local start="$1"
  local end="$2"
  echo "$(( (end - start) / 1000000 ))"
}

resolve_nix_binary() {
  local package="$1"
  local executable="$2"
  local store_path
  local store_paths=()
  mapfile -t store_paths < <(
    nix build --no-link --print-out-paths "nixpkgs#$package"
  )
  for store_path in "${store_paths[@]}"; do
    if [[ -x "$store_path/bin/$executable" ]]; then
      printf '%s/bin/%s\n' "$store_path" "$executable"
      return
    fi
  done
  echo "Nix package $package does not contain $executable" >&2
  return 1
}

check_new_file_diff() {
  local path="$1"
  local status=0
  local output
  set +e
  output="$(git diff --no-index --check /dev/null "$path" 2>&1)"
  status="$?"
  set -e
  if [[ "$status" -gt 1 || -n "$output" ]]; then
    printf '%s\n' "$output" >&2
    echo "diff check failed for $path" >&2
    exit 1
  fi
}

check_ascii() {
  local path="$1"
  if LC_ALL=C grep -n '[^	 -~]' "$path" >"$output_dir/non-ascii.out"; then
    cat "$output_dir/non-ascii.out" >&2
    echo "non-ASCII content in $path" >&2
    exit 1
  fi
}

if [[ ! -f "$certificate" || ! -f "$baseline_witness" ]]; then
  echo "required v2 certificate or naive baseline witness is absent" >&2
  exit 2
fi

mkdir -p "$output_dir"

cvc5_bin="$(resolve_nix_binary cvc5 cvc5)"
cvc5_version="$("$cvc5_bin" --version | sed -n '1p')"

formula_start="$(now_ns)"
python3 "$smt_generator" generate \
  --certificate "$certificate" \
  --output-dir "$output_dir"
formula_end="$(now_ns)"
formula_ms="$(elapsed_ms "$formula_start" "$formula_end")"

smt_start="$(now_ns)"
nice -n 10 "$cvc5_bin" --lang smt2 "$output_dir/formula.smt2" \
  >"$output_dir/solver.out"
smt_end="$(now_ns)"
smt_ms="$(elapsed_ms "$smt_start" "$smt_end")"

decode_start="$(now_ns)"
set +e
python3 "$smt_generator" decode \
  --certificate "$certificate" \
  --output-dir "$output_dir" \
  --generator-ms "$formula_ms" \
  --solver-ms "$smt_ms"
decode_status="$?"
set -e
decode_end="$(now_ns)"
decode_wall_ms="$(elapsed_ms "$decode_start" "$decode_end")"
if [[ "$decode_status" -eq 3 ]]; then
  echo "classification=INCONCLUSIVE_ENCODING"
  exit 3
elif [[ "$decode_status" -ne 0 ]]; then
  exit "$decode_status"
fi

python3 "$smt_generator" validate-witness \
  --certificate "$certificate" \
  --output-dir "$output_dir"

if [[ "$smt_ms" -lt 10000 ]]; then
  solver_run_count=10
else
  solver_run_count=3
fi
solver_samples=()
for ((run = 1; run <= solver_run_count; run++)); do
  run_start="$(now_ns)"
  nice -n 10 "$cvc5_bin" --lang smt2 "$output_dir/formula.smt2" \
    >/dev/null
  run_end="$(now_ns)"
  solver_samples+=("$(elapsed_ms "$run_start" "$run_end")")
done

mkdir -p "$output_dir/mutations/conflicting-observed-commit"
mkdir -p "$output_dir/mutations/wrong-destination-action-param"
for mutation in conflicting-observed-commit wrong-destination-action-param; do
  mutation_dir="$output_dir/mutations/$mutation"
  python3 "$smt_generator" generate \
    --certificate "$certificate" \
    --output-dir "$mutation_dir" \
    --mutation "$mutation"
  nice -n 10 "$cvc5_bin" --lang smt2 "$mutation_dir/formula.smt2" \
    >"$mutation_dir/solver.out"
  python3 "$smt_generator" validate-mutation \
    --certificate "$certificate" \
    --output-dir "$mutation_dir" \
    --mutation "$mutation"
done

printf 'unknown\n' >"$output_dir/unknown-solver.out"
set +e
python3 "$smt_generator" classify-solver-output \
  --solver-output "$output_dir/unknown-solver.out" \
  >"$output_dir/unknown-classification.out"
unknown_status="$?"
set -e
if [[ "$unknown_status" -ne 3 ]]; then
  cat "$output_dir/unknown-classification.out" >&2
  echo "unknown status was not classified INCONCLUSIVE_ENCODING" >&2
  exit 1
fi
grep -Fxq \
  "solver_status=unknown classification=INCONCLUSIVE_ENCODING" \
  "$output_dir/unknown-classification.out"

lean_generation_start="$(now_ns)"
python3 "$lean_generator" generate \
  --witness "$output_dir/witness-v1.json" \
  --certificate "$certificate" \
  --output-dir "$output_dir"
python3 "$lean_generator" verify-source \
  --witness "$output_dir/witness-v1.json" \
  --certificate "$certificate" \
  --source "$generated_source"
lean_generation_end="$(now_ns)"
lean_generation_ms="$(elapsed_ms "$lean_generation_start" "$lean_generation_end")"

lean_threads="$(( ($(nproc) + 1) >> 1 ))"
lean_compile_start="$(now_ns)"
nice -n 10 lake env lean \
  -j "$lean_threads" \
  -o "$output_dir/CanonicalCheapFullStateWitness.olean" \
  "$generated_source"
lean_compile_end="$(now_ns)"
lean_compile_ms="$(elapsed_ms "$lean_compile_start" "$lean_compile_end")"

lean_check_start="$(now_ns)"
nice -n 10 lake env lean --run "$generated_source" \
  >"$output_dir/canonical-lean.out"
lean_check_end="$(now_ns)"
lean_compile_check_ms="$(elapsed_ms "$lean_check_start" "$lean_check_end")"
grep -Fxq "S0_STATE_CHECKS=passed" "$output_dir/canonical-lean.out"
grep -Fq \
  "completion smt_nodes=2 inert_nodes=13 inert_smt_discovered=false bootstrap=singleton-0" \
  "$output_dir/canonical-lean.out"
grep -Fq \
  "counts actions=43 observations=53 checkpoints=47 spans=6" \
  "$output_dir/canonical-lean.out"
grep -Fq "projected_unchecked=0" "$output_dir/canonical-lean.out"
grep -Fxq "VALID_SEGMENT" "$output_dir/canonical-lean.out"

pycache_dir="$output_dir/pycache"
mkdir -p "$pycache_dir"
PYTHONPYCACHEPREFIX="$pycache_dir" python3 -m py_compile \
  "$smt_generator" \
  "$lean_generator"

black_bin="$(resolve_nix_binary black black)"
"$black_bin" --check --quiet "$smt_generator" "$lean_generator"

shellcheck_bin="$(resolve_nix_binary shellcheck shellcheck)"
"$shellcheck_bin" "$script_path"

check_new_file_diff "$smt_generator"
check_new_file_diff "$lean_generator"
check_new_file_diff "$script_path"
check_ascii "$smt_generator"
check_ascii "$lean_generator"
check_ascii "$script_path"
check_ascii "$generated_source"

solver_samples_csv="$(IFS=,; echo "${solver_samples[*]}")"
python3 - \
  "$benchmark_json" \
  "$cvc5_bin" \
  "$cvc5_version" \
  "$formula_ms" \
  "$smt_ms" \
  "$decode_wall_ms" \
  "$lean_generation_ms" \
  "$lean_compile_ms" \
  "$lean_compile_check_ms" \
  "$solver_samples_csv" \
  "$output_dir/formula.smt2" \
  "$output_dir/solver.out" \
  "$output_dir/witness-v1.json" \
  "$generated_source" <<'PY'
import json
import sys
from pathlib import Path

(
    output,
    cvc5_binary,
    cvc5_version,
    formula_ms,
    smt_ms,
    decode_wall_ms,
    lean_generation_ms,
    lean_compile_ms,
    lean_compile_check_ms,
    solver_samples_csv,
    formula_path,
    solver_path,
    witness_path,
    source_path,
) = sys.argv[1:]
samples = [int(value) for value in solver_samples_csv.split(",")]
paths = {
    "formula": Path(formula_path),
    "solver_output": Path(solver_path),
    "witness": Path(witness_path),
    "generated_lean_source": Path(source_path),
}
value = {
    "schema_version": "ccfraft-cheap-full-state-benchmark/v1",
    "classification": "PENDING_REPORT",
    "cvc5": {
        "binary": cvc5_binary,
        "version": cvc5_version,
    },
    "timings_ms": {
        "formula_generation": int(formula_ms),
        "end_to_end_smt": int(smt_ms),
        "decode_wall": int(decode_wall_ms),
        "solver_only_runs": samples,
        "lean_generation": int(lean_generation_ms),
        "lean_compile": int(lean_compile_ms),
        "lean_compile_check": int(lean_compile_check_ms),
        "lean_runtime": None,
        "lean_runtime_separated": False,
    },
    "artifact_bytes": {
        name: path.stat().st_size for name, path in paths.items()
    },
    "canonical": {
        "result": "VALID_SEGMENT",
        "actions": 43,
        "observations": 53,
        "spans": 6,
        "projected_unchecked": 0,
        "inert_completion_nodes": list(range(2, 15)),
        "inert_completion_smt_discovered": False,
    },
    "mutations": {
        "conflicting_observed_commit": "UNSAT_INCONCLUSIVE_ENCODING",
        "wrong_in_domain_destination": "UNSAT_INCONCLUSIVE_ENCODING",
        "unknown": "INCONCLUSIVE_ENCODING",
    },
    "validation": {
        "deterministic_regeneration": True,
        "python_compile": True,
        "black": True,
        "shellcheck": True,
        "diff_check": True,
        "ascii": True,
    },
}
Path(output).write_text(
    json.dumps(value, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

python3 "$smt_generator" write-benchmark-report \
  --certificate "$certificate" \
  --output-dir "$output_dir" \
  --benchmark "$benchmark_json" \
  --baseline-witness "$baseline_witness"
check_ascii "$output_dir/report.md"

printf 'timings_ms formula=%s smt_end_to_end=%s decode_wall=%s lean_generation=%s lean_compile=%s lean_compile_check=%s\n' \
  "$formula_ms" \
  "$smt_ms" \
  "$decode_wall_ms" \
  "$lean_generation_ms" \
  "$lean_compile_ms" \
  "$lean_compile_check_ms"
printf 'solver_only_ms %s\n' "$solver_samples_csv"
echo "VALID_SEGMENT_CHEAP_FOOTPRINT"
