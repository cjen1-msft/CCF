#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

script_path="$(realpath "$0")"
cd "$(dirname "$script_path")"

output_dir=".lake/build/symbolic-sequence-prototype"
generator="CCFRaft/symbolic_sequence_prototype.py"
array_generator="CCFRaft/symbolic_array_prototype.py"
report="CCFRaft/symbolic-sequence-prototype.html"

if [[ ! -f ".lake/build/full-trace-prototype/proposed-mapping-certificate-v2.json" ]]; then
  ./check_ccfraft_full_trace_prototype.sh
fi

cvc5_bin=""
while IFS= read -r store_path; do
  if [[ -x "$store_path/bin/cvc5" ]]; then
    cvc5_bin="$store_path/bin/cvc5"
    break
  fi
done < <(nix build --no-link --print-out-paths nixpkgs#cvc5)
if [[ -z "$cvc5_bin" ]]; then
  echo "nixpkgs#cvc5 did not provide cvc5" >&2
  exit 2
fi

mkdir -p "$output_dir"
nice -n 10 python3 "$generator" \
  --cvc5 "$cvc5_bin" \
  --output-dir "$output_dir" \
  --report "$output_dir/native-sequence.html" \
  --prefix-lengths "0,15123,1000000" \
  --samples 1 \
  --time-limit-ms 10000 \
  --wall-timeout-seconds 15
nice -n 10 python3 "$array_generator" \
  --cvc5 "$cvc5_bin" \
  --output-dir "$output_dir/array" \
  --sequence-benchmark "$output_dir/benchmark.json" \
  --report "$report" \
  --prefix-lengths "0,15123,1000000" \
  --samples 5 \
  --time-limit-ms 10000 \
  --wall-timeout-seconds 15

PYTHONPYCACHEPREFIX="$output_dir/pycache" python3 -m py_compile \
  "$generator" \
  "$array_generator"

black_bin=""
while IFS= read -r store_path; do
  if [[ -x "$store_path/bin/black" ]]; then
    black_bin="$store_path/bin/black"
    break
  fi
done < <(nix build --no-link --print-out-paths nixpkgs#black)
"$black_bin" --check --quiet "$generator" "$array_generator"

shellcheck_bin=""
while IFS= read -r store_path; do
  if [[ -x "$store_path/bin/shellcheck" ]]; then
    shellcheck_bin="$store_path/bin/shellcheck"
    break
  fi
done < <(nix build --no-link --print-out-paths nixpkgs#shellcheck)
"$shellcheck_bin" "$script_path"

echo "result=passed"
