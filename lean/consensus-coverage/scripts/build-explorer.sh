#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
#
# Usage: LEAN_CC=/path/to/gcc16/bin/cc bash lean/consensus-coverage/scripts/build-explorer.sh
# Prints the executable path on stdout. Requires Python 3.11+ and the checkout's
# Lean/Lake toolchain on PATH. Use the toolchain's matching GCC wrapper: the
# Nix Lean 4.35.0 build uses GCC 16 libstdc++ wait/notify symbols absent in GCC 13.
# The compiler defaults to cc on PATH; build products go in the Lake workspace
# cache under ~/.cache/ccf-consensus-coverage, not in the checkout.

set -euo pipefail

source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
export LEAN_CC
LEAN_CC=$(command -v "${LEAN_CC:-cc}")
if [[ $("$LEAN_CC" -dumpfullversion) != 16.* ]]; then
  echo "Expected the GCC 16 wrapper matching Lean 4.35.0; set LEAN_CC." >&2
  exit 1
fi
workspace=$(python3 "$source_dir/../relevance/scripts/workspace.py" consensus-coverage)

nice python3 -I - "$source_dir" "$workspace" <<'PY'
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

source, workspace = map(Path, sys.argv[1:])
coverage = workspace / "consensus-coverage"
target = workspace / "native-explorer"
mirror = target / "src/scripts"
mirror.mkdir(parents=True, exist_ok=True)

# Lake's runtime target needs normal imports and definitions. Keep the
# interpreter script unchanged; only adjust its header and meta section here.
original = (source / "scripts/explore.lean").read_text()
assert original.count("\nmeta section\n") == 1 and original.endswith("\nend\n")
runtime = re.sub(r"(?m)^(?:public )?meta import ", "import ", original)
runtime = runtime.replace("\nmeta section\n", "", 1).removesuffix("\nend\n") + "\n"
for name in re.findall(r"(?m)^import all (.+)$", runtime):
    runtime = runtime.replace(f"\nimport {name}\n", "\n", 1)
(mirror / "explore.lean").write_text(runtime)

manifest = json.loads((coverage / "lake-manifest.json").read_text())
for package in manifest["packages"]:
    package["inherited"] = True
manifest["packages"].insert(0, dict(
    type="path", scope="", name=manifest["name"], manifestFile="lake-manifest.json",
    inherited=False, dir=str(coverage), copy=False, configFile="lakefile.toml",
))
manifest["name"] = "bounded_explorer"
(target / "lake-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
(target / "lean-toolchain").write_text((source / "lean-toolchain").read_text())
(target / "lakefile.toml").write_text(f'''name = "bounded_explorer"
srcDir = "src"
moreLeanArgs = ["-DwarningAsError=true"]

[[require]]
name = "consensus_coverage"
path = {json.dumps(str(coverage))}
copy = false

[[lean_exe]]
name = "bounded-explore"
root = "scripts.explore"
''')
subprocess.run(["lake", "-d", str(target), "--quiet", "build", "bounded-explore"],
               stdout=sys.stderr, check=True)

# The unused proof bound 2^(2^457) cannot be materialized. Check that
# generated C never reads it before omitting its eager initializer from a
# copied object. Leave all Lean sources and shared Lake objects alone.
exe = target / ".lake/build/bin/bounded-explore"
args = shlex.split(exe.with_suffix(".rsp").read_text())
objects = [Path(arg) for arg in args if arg.endswith(".c.o.export")]
(obj,) = [o for o in objects if o.name == "FullProfile.c.o.export"]
symbol = "lp_consensus__coverage_ConsensusCoverage_FullProfile_observationCapacity"
initialization = f"{symbol} = _init_{symbol}();\nlean_mark_persistent({symbol});\n"
for o in objects:
    code = o.with_suffix("").with_suffix("").read_text()
    assert len(re.findall(rf"\b{symbol}\b", code)) == (3 if o == obj else 0), o
    if o == obj:
        assert code.count(initialization) == 1
        overlay = target / "FullProfile-runtime.c"
        overlay.write_text(code.replace(initialization, ""))
cc = os.environ["LEAN_CC"]
prefix = subprocess.check_output(["lean", "--print-prefix"], text=True).strip()
replacement = target / "FullProfile-runtime.o"
subprocess.run([
    cc, "-I" + prefix + "/include", "-O3", "-DNDEBUG", "-DLEAN_EXPORTING",
    "-fdata-sections", "-ffunction-sections", "-fPIC", "-fvisibility=hidden",
    "-c", str(overlay), "-o", str(replacement),
], check=True)
rsp = target / "bounded-explore.rsp"
rsp.write_text("".join(json.dumps(str(replacement) if a == str(obj) else a) + "\n" for a in args))
result = target / "bounded-explore"
staged = target / "bounded-explore.new"
subprocess.run([cc, "-o", str(staged), "@" + str(rsp)], check=True)
staged.replace(result)
print(result)
PY
