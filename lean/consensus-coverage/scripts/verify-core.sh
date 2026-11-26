#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
#
# Verification gate for ported coverage modules.
#
# Usage, from anywhere inside a checkout:
#
#     lean/consensus-coverage/scripts/verify-core.sh [MODULE ...]
#
# MODULE is a name under ConsensusCoverage (for example `StateCoverage`); with no
# argument every module of the library is checked. The gate:
#
# 1. scans the sources for forbidden words and hand-numbered `reach_N` references;
# 2. builds the modules out of tree with warnings as errors;
# 3. replays each module through the independent kernel checker `leanchecker`;
# 4. prints the axioms of every theorem of the modules and fails on any axiom other
#    than `propext`, `Classical.choice` and `Quot.sound`.
#
# The last line is `RESULT: PASS` or `RESULT: FAIL ...`; the exit code is 0 or 1.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
package=$(dirname "$here")
lean=$(dirname "$package")
src="$package/ConsensusCoverage"

if [ "$#" -eq 0 ]; then
  mapfile -t names < <(cd "$src" && ls ./*.lean | sed 's|^\./||; s|\.lean$||' | sort)
else
  names=("$@")
fi
modules=()
files=()
for name in "${names[@]}"; do
  modules+=("ConsensusCoverage.$name")
  files+=("$src/$name.lean")
done

fail() {
  echo "RESULT: FAIL $*"
  exit 1
}

# `Classes` and `PinnedClasses` only generate the numbered definitions; nothing may name one.
if grep -nE '\b(sorry|native_decide|implemented_by|unsafe)\b|^\s*axiom\b' "${files[@]}"; then
  fail "forbidden word"
fi
if grep -nE '\breach_[0-9]+' "${files[@]}"; then
  fail "hand-numbered reach reference (use reach% paths)"
fi

ws=$(python3 "$lean/relevance/scripts/workspace.py" consensus-coverage)
cd "$ws/consensus-coverage"
lake build --wfail "${modules[@]}" >"$ws/verify-build.log" 2>&1 ||
  { grep -E 'error' -A12 "$ws/verify-build.log" | head -150; fail "build"; }
# One process per module: replaying many modules in one process needs tens of gigabytes.
: >"$ws/verify-kernel.log"
for module in "${modules[@]}"; do
  lake env leanchecker "$module" >>"$ws/verify-kernel.log" 2>&1 ||
    { tail -20 "$ws/verify-kernel.log"; fail "leanchecker $module (exit $?)"; }
done

probe=$(mktemp "$ws/axioms-XXXXXX.lean")
trap 'rm -f "$probe"' EXIT
{
  echo "import Lean"
  for module in "${modules[@]}"; do echo "import $module"; done
  cat <<'LEAN'
open Lean in
#eval show CoreM Unit from do
  let env <- getEnv
  let wanted := (<- IO.getEnv "VERIFY_MODULES").getD "" |>.splitOn " " |>.map String.toName
  let allowed := [``propext, ``Classical.choice, ``Quot.sound]
  let mut bad := 0
  let mut checked := 0
  for (name, info) in env.constants.toList do
    let some index := env.getModuleIdxFor? name | continue
    unless wanted.contains env.header.moduleNames[index.toNat]! do continue
    unless info matches .thmInfo _ do continue
    checked := checked + 1
    let axioms <- collectAxioms name
    for used in axioms do
      unless allowed.contains used do
        bad := bad + 1
        IO.println s!"AXIOM {name}: {used}"
  IO.println s!"axioms: {checked} theorems checked, {bad} disallowed uses"
  if bad != 0 then throwError "disallowed axioms"
LEAN
} >"$probe"
VERIFY_MODULES="${modules[*]}" lake env lean "$probe" || fail "axioms"
echo "RESULT: PASS ${#modules[@]} modules"
