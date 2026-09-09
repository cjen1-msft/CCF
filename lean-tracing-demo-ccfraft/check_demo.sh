#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

script_path="$(realpath "$0")"
demo_root="$(dirname "$script_path")"
cd "$demo_root"

artifact_root="Artifacts/runs"
mkdir -p "$artifact_root"

cvc5_store="$(nix build --no-link --print-out-paths nixpkgs#cvc5)"
cvc5="$cvc5_store/bin/cvc5"

nix run nixpkgs#black -- --check --quiet \
  ./*.py \
  ./Shared/*.py \
  ./tests/*.py
nix run nixpkgs#shellcheck -- "$script_path"
nice -n 10 lake build Demo EncoderAudit
CVC5="$cvc5" python3 -m unittest discover -s tests -q

run_trace() {
  local trace="$1"
  local expected="$2"
  local stem
  local output
  local status

  stem="$(basename "$trace" .ndjson)"
  output="$artifact_root/$stem"
  mkdir -p "$output"
  rm -f \
    "$output/certificate.canonical.json" \
    "$output/certificate.json" \
    "$output/cvc5-proof.stderr" \
    "$output/cvc5-proof.stdout" \
    "$output/cvc5-status.stderr" \
    "$output/cvc5-status.stdout" \
    "$output/cvc5-unsat-core.stderr" \
    "$output/cvc5-unsat-core.stdout" \
    "$output/diagnosis.json" \
    "$output/expected.canonical.json" \
    "$output/formula-reduced-proof.smt2" \
    "$output/formula-reduced.smt2" \
    "$output/formula-core-candidate.smt2" \
    "$output/formula-unsat-core.smt2" \
    "$output/formula.smt2" \
    "$output/proof.txt" \
    "$output/result.json" \
    "$output/unsat-core-original.txt" \
    "$output/unsat-core.txt"
  status="$(
    python3 validate.py \
      --cvc5 "$cvc5" \
      "$trace" \
      "$output"
  )"
  if [[ "$status" != "$expected" ]]; then
    echo "$trace: expected $expected, got $status" >&2
    exit 1
  fi
  jq -S . "$output/certificate.json" > "$output/certificate.canonical.json"
  jq -S . "Traces/Certificates/$stem.json" > "$output/expected.canonical.json"
  diff -u \
    "$output/expected.canonical.json" \
    "$output/certificate.canonical.json"
}

run_trace "Traces/Captured/bad_network.ndjson" sat
run_trace "Traces/Captured/soft_rollback.ndjson" sat
run_trace "Traces/Mutated/bad_network-direct.ndjson" unsat
run_trace "Traces/Mutated/bad_network-indirect.ndjson" unsat
run_trace "Traces/Mutated/soft_rollback-direct.ndjson" unsat
run_trace "Traces/Mutated/soft_rollback-indirect.ndjson" unsat

python3 generate_report.py
nix run nixpkgs#html-tidy -- -errors -quiet Report/index.html

echo "result=passed"
echo "report=$demo_root/Report/index.html"
