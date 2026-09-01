#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

cd "$(dirname "$0")"

mode=full
run_mutations=no
for argument in "$@"; do
  case "$argument" in
    --full)
      mode=full
      ;;
    --existing-witness)
      mode=existing
      ;;
    --mutations)
      run_mutations=yes
      ;;
    *)
      echo "unsupported argument: $argument" >&2
      echo "usage: $0 [--full|--existing-witness] [--mutations]" >&2
      exit 2
      ;;
  esac
done

output_dir=".lake/build/naive-full-state-smt"
certificate=".lake/build/full-trace-prototype/proposed-mapping-certificate-v2.json"
witness="$output_dir/witness-v1.json"
smt_generator="CCFRaft/naive_full_state_smt.py"
lean_generator="CCFRaft/naive_full_state_lean.py"
mutation_root=".lake/build/naive-full-state-canonical-mutations"

now_ns() {
  python3 -c 'import time; print(time.monotonic_ns())'
}

elapsed_ms() {
  local start="$1"
  local end="$2"
  echo "$(( (end - start) / 1000000 ))"
}

find_cvc5() {
  if command -v cvc5 >/dev/null 2>&1; then
    cvc5_command=(cvc5)
  elif command -v nix >/dev/null 2>&1; then
    local cvc5_store
    cvc5_store="$(nix build --no-link --print-out-paths nixpkgs#cvc5)"
    cvc5_command=("$cvc5_store/bin/cvc5")
  else
    echo "cvc5 is unavailable; install it or provide nix" >&2
    exit 2
  fi
}

generate_and_run_lean() {
  local input_witness="$1"
  local input_certificate="$2"
  local generated_dir="$3"
  local generated_source="$generated_dir/CanonicalNaiveFullStateWitness.lean"
  local generated_output="$generated_dir/canonical-lean.out"

  local generation_start generation_end
  generation_start="$(now_ns)"
  python3 "$lean_generator" generate \
    --witness "$input_witness" \
    --certificate "$input_certificate" \
    --output-dir "$generated_dir"
  python3 "$lean_generator" verify-source \
    --witness "$input_witness" \
    --certificate "$input_certificate" \
    --source "$generated_source"
  local witness_hash certificate_hash
  witness_hash="$(sha256sum "$input_witness" | cut -d' ' -f1)"
  certificate_hash="$(sha256sum "$input_certificate" | cut -d' ' -f1)"
  grep -Fqx -- "-- witness_sha256=$witness_hash" "$generated_source"
  grep -Fqx -- "-- certificate_sha256=$certificate_hash" "$generated_source"
  generation_end="$(now_ns)"
  lean_generation_ms="$(elapsed_ms "$generation_start" "$generation_end")"

  local lean_start lean_end lean_status
  lean_start="$(now_ns)"
  set +e
  nice -n 10 lake env lean --run "$generated_source" >"$generated_output" 2>&1
  lean_status="$?"
  set -e
  lean_end="$(now_ns)"
  lean_check_ms="$(elapsed_ms "$lean_start" "$lean_end")"
  if [[ "$lean_status" -ne 0 ]]; then
    cat "$generated_output"
    return "$lean_status"
  fi
  grep -Fxq "VALID_SEGMENT" "$generated_output"
  sed '/^VALID_SEGMENT$/d' "$generated_output"
}

run_negative_mutations() {
  rm -rf "$mutation_root"
  mkdir -p "$mutation_root"
  for mutation in initial-field projected-observation; do
    local mutation_dir="$mutation_root/$mutation"
    python3 "$lean_generator" mutate \
      --kind "$mutation" \
      --witness "$witness" \
      --certificate "$certificate" \
      --output-dir "$mutation_dir"
    python3 "$lean_generator" generate \
      --witness "$mutation_dir/$(basename "$witness")" \
      --certificate "$mutation_dir/$(basename "$certificate")" \
      --output-dir "$mutation_dir" >/dev/null
    python3 "$lean_generator" verify-source \
      --witness "$mutation_dir/$(basename "$witness")" \
      --certificate "$mutation_dir/$(basename "$certificate")" \
      --source "$mutation_dir/CanonicalNaiveFullStateWitness.lean" >/dev/null
    set +e
    nice -n 10 lake env lean --run \
      "$mutation_dir/CanonicalNaiveFullStateWitness.lean" \
      >"$mutation_dir/result.out" 2>&1
    local status="$?"
    set -e
    if [[ "$status" -eq 0 ]]; then
      cat "$mutation_dir/result.out"
      echo "mutation unexpectedly passed: $mutation" >&2
      exit 1
    fi
    if [[ "$mutation" == "initial-field" ]]; then
      grep -Fq "ENCODING_BUG S0.nodes[0].commitIndex" \
        "$mutation_dir/result.out"
    else
      grep -Fq \
        "ENCODING_BUG event 53 field msg.state.commit_idx" \
        "$mutation_dir/result.out"
    fi
    echo "mutation=$mutation result=ENCODING_BUG"
  done
  rm -rf "$mutation_root"
}

scenario_reduction_ms=skipped
formula_ms=skipped
smt_ms=skipped
decode_ms=skipped

if [[ "$mode" == "full" ]]; then
  mkdir -p .lake/build
  scenario_start="$(now_ns)"
  ./check_ccfraft_full_trace_prototype.sh \
    >"$output_dir-scenario-reduction.out"
  scenario_end="$(now_ns)"
  scenario_reduction_ms="$(elapsed_ms "$scenario_start" "$scenario_end")"

  find_cvc5
  mkdir -p "$output_dir"

  formula_start="$(now_ns)"
  python3 "$smt_generator" generate \
    --certificate "$certificate" \
    --output-dir "$output_dir"
  formula_end="$(now_ns)"
  formula_ms="$(elapsed_ms "$formula_start" "$formula_end")"

  smt_start="$(now_ns)"
  nice -n 10 "${cvc5_command[@]}" --lang smt2 "$output_dir/formula.smt2" \
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
  decode_ms="$(elapsed_ms "$decode_start" "$decode_end")"
  if [[ "$decode_status" -eq 3 ]]; then
    echo "result=INCONCLUSIVE_ENCODING"
    exit 3
  elif [[ "$decode_status" -ne 0 ]]; then
    exit "$decode_status"
  fi
  python3 "$smt_generator" validate-witness \
    --certificate "$certificate" \
    --output-dir "$output_dir"
else
  if [[ ! -f "$witness" || ! -f "$certificate" ]]; then
    echo "existing witness or certificate is absent" >&2
    exit 2
  fi
fi

generate_and_run_lean "$witness" "$certificate" "$output_dir"

if [[ "$run_mutations" == "yes" ]]; then
  run_negative_mutations
fi

echo "timings_ms scenario_reduction=$scenario_reduction_ms formula=$formula_ms smt=$smt_ms decode=$decode_ms lean_generation=$lean_generation_ms lean_compile_check=$lean_check_ms"
echo "VALID_SEGMENT"
