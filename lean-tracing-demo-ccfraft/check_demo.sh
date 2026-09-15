#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 BOUNDS.json" >&2
  exit 2
fi
bounds="$(realpath "$1")"
script_path="$(realpath "$0")"
demo_root="$(dirname "$script_path")"
cd "$demo_root"

python3 -c \
  'from pathlib import Path; import sys; from validate import read_bounds; read_bounds(Path(sys.argv[1]))' \
  "$bounds"

if ! cvc5="${CVC5:-$(command -v cvc5)}" || [[ ! -x "$cvc5" ]]; then
  echo "cvc5 is required; use nix shell nixpkgs#cvc5 or set CVC5 to its executable path" >&2
  exit 1
fi
export CVC5="$cvc5"

nix run nixpkgs#black -- --check --quiet \
  ./*.py \
  ./Shared/*.py \
  ./tests/*.py
nix run nixpkgs#shellcheck -- "$script_path"
python3 -m unittest -q \
  tests.test_trace_io \
  tests.test_reduction \
  tests.test_raw_normalization \
  tests.test_solver \
  tests.test_smt.SmtFormulaTests \
  tests.test_raw_orchestration \
  tests.test_pipeline_orchestration \
  tests.test_report_generation
./check_checked.sh

artifact_root="Artifacts/runs"

run_trace() {
  local trace="$1"
  local expected="$2"
  local stem
  local output
  local status

  stem="$(basename "$trace" .ndjson)"
  output="$artifact_root/$stem"
  status="$(
    python3 validate.py \
      --cvc5 "$cvc5" \
      --bounds "$bounds" \
      "$trace" \
      "$output"
  )"
  if [[ "$status" != "$expected" ]]; then
    echo "$trace: expected $expected, got $status" >&2
    exit 1
  fi
  diff -u \
    "Traces/Certificates/$stem.json" \
    "$output/reduced-certificate.json"
}

run_trace "Traces/Captured/bad_network.ndjson" sat
run_trace "Traces/Captured/soft_rollback.ndjson" sat
run_trace "Traces/Mutated/bad_network-direct.ndjson" unsat
run_trace "Traces/Mutated/bad_network-indirect.ndjson" unsat
run_trace "Traces/Mutated/soft_rollback-direct.ndjson" unsat
run_trace "Traces/Mutated/soft_rollback-indirect.ndjson" unsat

python3 generate_report.py --runs-dir "$artifact_root" --cvc5 "$cvc5"
nix run nixpkgs#html-tidy -- -errors -quiet Report/index.html

echo "result=passed"
echo "report=$demo_root/Report/index.html"
