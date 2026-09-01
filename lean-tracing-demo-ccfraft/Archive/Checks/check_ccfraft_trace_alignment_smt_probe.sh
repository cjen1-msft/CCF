#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

cd "$(dirname "$0")"

if command -v cvc5 >/dev/null 2>&1; then
  cvc5_command=(cvc5)
elif command -v nix >/dev/null 2>&1; then
  cvc5_command=(nix run nixpkgs#cvc5 --)
else
  echo "cvc5 is unavailable; install it or run this script in a Nix environment" >&2
  exit 2
fi

output="$("${cvc5_command[@]}" \
  --lang smt2 \
  CCFRaft/trace_alignment_smt_probe.smt2)"

mapfile -t lines <<<"$output"
if [[ "${#lines[@]}" -ne 4 || "${lines[0]}" != "sat" || "${lines[2]}" != "unsat" ]]; then
  echo "expected one SAT and one UNSAT result" >&2
  echo "$output" >&2
  exit 1
fi

model="${lines[1]}"
core="${lines[3]}"

for expected in \
  "(term0 7)" \
  "(last0 119)" \
  "(commit0 116)" \
  "(pendingResponse0 true)" \
  "(action0 0)" \
  "(command0 0)" \
  "((select submitted0 command0) false)" \
  "((select submitted1 command0) true)" \
  "(responseSource0 1)" \
  "(responseDestination0 0)" \
  "(responseTerm0 7)" \
  "(responseIndex0 120)" \
  "(responseIndex1 120)" \
  "(highestCommittable2 120)" \
  "(commit3 120)" \
  ; do
  if [[ "$model" != *"$expected"* ]]; then
    echo "solver output omitted expected result: $expected" >&2
    echo "$output" >&2
    exit 1
  fi
done

for expected in mapAdvanceCommit406 event406 conflictingEvent407; do
  if [[ "$core" != *"$expected"* ]]; then
    echo "unsatisfiable assumptions omitted expected label: $expected" >&2
    echo "$output" >&2
    exit 1
  fi
done

echo "$output"
echo "result=passed"
