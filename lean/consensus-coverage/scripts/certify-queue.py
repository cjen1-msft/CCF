#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Certify initialized Lean step labels from a TSV of question/run/queue choices/offset.

Build consensus-coverage first. Run this script with --regression to check the
25 published control coordinates. Use --input FILE for another manifest and
--only QUESTION to retry one row. The default output is outside the checkout;
each result names its generated Lean source and separately checked object.
"""

import argparse
import ast
import csv
import hashlib
import os
import re
import subprocess
import sys
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent
TOKENS = re.compile(r"[a-zA-Z_][a-zA-Z_0-9]*|[0-9]+|:=|[()[\]{},. \u27e8\u27e9\u2205]")
WORDS = set(
    "append checkQuorum configuration content deliver election flushes initAsBackup input "
    "nominateSuccessor none retirementConfirmations sendEntries signature some term timeout transaction".split()
)
HEADER = ["question", "offset", "input_sha256", "result", "detail", "source_seconds", "check_seconds"]


def parse(row):
    q = row["question"]
    run = row["run"]
    for char in "\u27e8\u27e9\u2205":
        run = run.replace(f"\\u{ord(char):04x}", char)
    tokens = TOKENS.findall(run)
    if "".join(tokens) != run or any((p[0].isalpha() or p[0] == "_") and p not in WORDS for p in tokens):
        raise ValueError("unexpected token in Run; input is data, not arbitrary Lean")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", q) or not re.fullmatch(r"[0-9]+", row["offset"]):
        raise ValueError("invalid question or schedule offset")
    choices = row.get("queue_choices")
    if choices is None:
        match = re.search(r"\bchoices\s*:=\s*(\[[^\]]*\]);", row.get("reason", ""))
        if not match:
            raise ValueError("no explicit sparse choices")
        choices = match[1]
    pairs = ast.literal_eval(choices)
    if not isinstance(pairs, list) or not all(
        isinstance(pair, tuple) and len(pair) == 2 and all(type(n) is int and n >= 0 for n in pair)
        for pair in pairs
    ):
        raise ValueError("invalid sparse choices")
    offset = int(row["offset"])
    fingerprint = hashlib.sha256(f"{run}\n{pairs}\n{offset}".encode()).hexdigest()
    return q, run, pairs, offset, fingerprint


def declarations(run, choices, offset):
    return f"""private def run : Run := {run}
private def selection := CensusQueueStep.selected run (by unfold Run.valid; decide) {choices} {offset}"""


def render(name, q, prefix):
    return f"""module
-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.CensusQueueHints
import all ConsensusCoverage.CensusQueueElection
import all ConsensusCoverage.CensusQueueSearch
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.CensusQueueStep
import all ConsensusCoverage.SolvedWitnesses
meta import ConsensusCoverage.CensusQueueCertificate

namespace CensusCertificates.{name}
open Consensus Consensus.Model Consensus.Model.Node ConsensusCoverage
open ActionProfile FrontierRows
set_option maxRecDepth 16384
set_option maxHeartbeats 35000
set_option Elab.async false

{prefix}
private theorem enabled : selection.isSome := by decide +kernel
private def step : Step := selection.get enabled
private theorem atStep : label step (.step .{q}) = true := by queue_certify step
public theorem occurs : \u2203 s : Step, label s (.step .{q}) = true := \u27e8step, atStep\u27e9
end CensusCertificates.{name}
"""


def timed(command, env, log):
    start = time.monotonic()
    with log.open("w") as out:
        process = subprocess.run(["nice", *command], stdout=out, stderr=subprocess.STDOUT, env=env, check=False)
    return process.returncode, round(time.monotonic() - start, 2)


def replay(prefix, files, digest, env):
    src = files / ("Prefix_" + digest + ".lean")
    src.write_text(
        "module\nimport all ConsensusCoverage.CensusQueueStep\n"
        "open Consensus Consensus.Model Consensus.Model.Node ConsensusCoverage\n"
        "open ActionProfile FrontierRows\n" + prefix + "\n#guard selection.isSome\n"
    )
    return timed(["lean", "-M", "7400", "-DwarningAsError=true", src], env, src.with_suffix(".log"))


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    group = cli.add_mutually_exclusive_group(required=True)
    group.add_argument("--input", type=Path)
    group.add_argument("--regression", action="store_true")
    cli.add_argument("--only", action="append", metavar="QUESTION")
    cli.add_argument("--workspace", type=Path, help="the workspace produced by relevance/scripts/workspace.py")
    cli.add_argument("--out", type=Path, help="dedicated directory for sources, objects, logs, and results.tsv")
    args = cli.parse_args()
    workspace = args.workspace or Path(
        subprocess.check_output(
            [sys.executable, HERE.parents[1] / "relevance/scripts/workspace.py", "consensus-coverage"], text=True
        ).strip()
    )
    out = (args.out or workspace / "queue-certificates").resolve()
    files = out / "CensusCertificates"
    files.mkdir(parents=True, exist_ok=True)
    base = subprocess.check_output(["lake", "-d", workspace / "consensus-coverage", "env", "printenv", "LEAN_PATH"], text=True).strip()
    env = os.environ | {"LEAN_PATH": str(out) + os.pathsep + base, "LEAN_NUM_THREADS": "1"}
    manifest = HERE / "queue-regression.tsv" if args.regression else args.input
    with manifest.open() as f:
        rows = list(csv.DictReader(f, delimiter="\t"))
    if len({r["question"] for r in rows}) != len(rows):
        cli.error("duplicate question in input")
    if args.regression and len(rows) != 25:
        cli.error("incomplete regression manifest")
    if args.only:
        rows = [r for r in rows if r["question"] in args.only]
        if len(rows) != len(set(args.only)):
            cli.error("unknown question in --only")
    success = True
    prefixes = {}
    with (out / "results.tsv").open("w") as result_file:
        results = csv.writer(result_file, delimiter="\t", lineterminator="\n")
        results.writerow(HEADER)
        for row in rows:
            try:
                q, run, choices, offset, digest = parse(row)
            except (KeyError, ValueError, SyntaxError, TypeError) as exc:
                results.writerow([row.get("question"), row.get("offset"), "", "stopped", f"invalid input: {exc}", "", ""])
                result_file.flush()
                success = False
                continue
            name = "Row_" + hashlib.sha256((q + digest).encode()).hexdigest()[:24]
            src = files / (name + ".lean")
            prefix = declarations(run, choices, offset)
            src.write_text(render(name, q, prefix))
            src.with_suffix(".olean").unlink(missing_ok=True)
            if digest not in prefixes:
                prefixes[digest] = replay(prefix, files, digest, env)
            rc, elapsed = prefixes[digest]
            if rc:
                results.writerow([q, offset, digest, "stopped", f"prefix replay failed; see Prefix_{digest}.log", elapsed, ""])
                result_file.flush()
                success = False
                continue
            log = files / (name + ".source.log")
            trace = files / (name + ".trace")
            trace.unlink(missing_ok=True)
            rc, src_time = timed(
                ["lean", "-M", "7400", "-DwarningAsError=true", "-R", out, "-o", src.with_suffix(".olean"), src],
                env | {"CCF_QUEUE_TRACE": str(trace)}, log,
            )
            check_time = ""
            if rc:
                status = "stopped"
                message = re.search(r": error(?:\([^)]*\))?: (.*?)(?:\n\n|\Z)", log.read_text(), flags=re.S)
                diagnostic = " ".join(message[1].split())[:800] if message else f"source exit {rc}"
                detail = diagnostic + ("; last formula: " + trace.read_text() if trace.exists() else "")
            else:
                rc, check_time = timed(["leanchecker", "CensusCertificates." + name], env, files / (name + ".kernel.log"))
                status = "checker-error" if rc else "kernel-certified"
                detail = f"{src.relative_to(out)}; leanchecker exit {rc}"
            results.writerow([q, offset, digest, status, detail, src_time, check_time])
            result_file.flush()
            success &= status == "kernel-certified"
    print(out / "results.tsv")
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
