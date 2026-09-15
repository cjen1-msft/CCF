#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Inspect state reads after explicit Z3 preprocessing, without a SAT search."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

import z3

from native_input import canonical_json, unique_object
from native_origin import validate_raw_origin
from native_run import validate_encoding
from Shared.solver import ValidationError

ROOT = Path(__file__).resolve().parent
PASSES = ("simplify", "propagate-values", "solve-eqs", "simplify")
PROBE_PREFIX = "ccf_diagnostic_probe_"


def walk(expressions):
    """Visit shared AST nodes once, including quantified bodies."""
    pending = list(expressions)
    seen = set()
    while pending:
        expression = pending.pop()
        if expression.get_id() in seen:
            continue
        seen.add(expression.get_id())
        yield expression
        if z3.is_quantifier(expression):
            pending.append(expression.body())
        elif z3.is_app(expression):
            pending.extend(expression.children())


def free_constants(expressions):
    return {
        str(expression.decl().name()): expression
        for expression in walk(expressions)
        if z3.is_const(expression)
        and expression.decl().kind() == z3.Z3_OP_UNINTERPRETED
    }


def metrics(goal):
    counts = Counter()
    for expression in walk(goal):
        counts["unique_ast_nodes"] += 1
        if z3.is_quantifier(expression):
            counts["quantifier_nodes"] += 1
        elif z3.is_app(expression):
            if expression.decl().kind() == z3.Z3_OP_SELECT:
                counts["array_select_nodes"] += 1
            if expression.decl().kind() == z3.Z3_OP_ITE:
                counts["ite_nodes"] += 1
    return {
        "assertions": len(goal),
        "free_constants": len(free_constants(goal)),
        **counts,
    }


def is_concrete(expression):
    """Recognise literal values, not arbitrary ground or model-completed terms."""
    for term in walk([expression]):
        if (
            z3.is_true(term)
            or z3.is_false(term)
            or z3.is_int_value(term)
            or z3.is_rational_value(term)
            or z3.is_bv_value(term)
        ):
            continue
        if z3.is_app(term) and term.decl().kind() in {
            z3.Z3_OP_DT_CONSTRUCTOR, z3.Z3_OP_CONST_ARRAY, z3.Z3_OP_STORE
        }:
            continue
        return False
    return True


def simplify_stages(goal, timeout_ms):
    stages = [{"pass": "parsed", **metrics(goal)}]
    for index, name in enumerate(PASSES):
        started = time.perf_counter()
        result = z3.TryFor(z3.Tactic(name), timeout_ms)(goal)
        if len(result) != 1:
            raise ValidationError(f"{name}: expected one subgoal, got {len(result)}")
        goal = result[0]
        stages.append({
            "pass": f"{index + 1}:{name}",
            "seconds": time.perf_counter() - started,
            **metrics(goal),
        })
    return goal, stages


def instrument(script, probes):
    """Fresh positive predicates expose reads without restricting original state."""
    if PROBE_PREFIX in script:
        raise ValidationError("diagnostic predicate prefix collides with input")
    declared = set(re.findall(r"^\(declare-const ([^ ]+) ", script, re.MULTILINE))
    symbols = {}
    for probe in probes:
        for symbol in probe["symbols"]:
            previous = symbols.setdefault(symbol["name"], symbol["sort"])
            if previous != symbol["sort"]:
                raise ValidationError("inconsistent diagnostic symbol sorts")
    additions = [
        f"(declare-const {name} {sort})"
        for name, sort in symbols.items() if name not in declared
    ]
    for index, probe in enumerate(probes):
        name = f"{PROBE_PREFIX}{index}"
        additions.extend([
            f"(declare-fun {name} ({probe['sort']}) Bool)",
            f"(assert ({name} {probe['expression']}))",
        ])
    goal = z3.Goal()
    goal.add(*z3.parse_smt2_string(script + "\n" + "\n".join(additions)))
    return goal


def read_probes(goal, probes):
    if any(z3.is_false(expression) for expression in goal):
        return [], "preprocessing_found_contradiction"
    values = {
        str(expression.decl().name()): expression.arg(0)
        for expression in goal
        if z3.is_app(expression)
        and str(expression.decl().name()).startswith(PROBE_PREFIX)
        and expression.num_args() == 1
    }
    rows = []
    for index, probe in enumerate(probes):
        expression = values.get(f"{PROBE_PREFIX}{index}")
        if expression is None:
            raise ValidationError(f"preprocessing removed probe {probe['label']}")
        text = expression.sexpr()
        rows.append({
            "label": probe["label"],
            "classification": "concrete" if is_concrete(expression) else "residual_symbolic",
            "expression": text[:600],
            "expression_characters": len(text),
            "free_constants": sorted(free_constants([expression])),
            "relevance": "state_read",
        })
    by_label = {row["label"]: row for row in rows}
    for row in rows:
        match = re.fullmatch(r"(node\[\d+\])\.log\[(\d+)\]", row["label"])
        if match:
            length = by_label[f"{match[1]}.logLength"]
            if length["classification"] == "concrete" and length["expression"].isdecimal():
                row["relevance"] = (
                    "live_log_cell" if int(match[2]) < int(length["expression"])
                    else "inactive_log_storage"
                )
            else:
                row["relevance"] = "log_liveness_not_resolved"
        if row["label"].endswith(".logStorage"):
            row["relevance"] = "whole_storage_including_unobserved_tails"
        if row["label"].endswith(".headPacket"):
            length = by_label[row["label"].removesuffix("headPacket") + "length"]
            if length["classification"] == "concrete" and length["expression"].isdecimal():
                row["relevance"] = (
                    "live_queue_head" if int(length["expression"]) > 0
                    else "inactive_queue_storage"
                )
            else:
                row["relevance"] = "queue_liveness_not_resolved"
    return rows, "residual_goal_not_solved"


def write_goal(path, goal):
    solver = z3.Solver()
    solver.add(*goal)
    path.write_text(solver.to_smt2(), encoding="utf-8")


def load_run(directory):
    def read(name):
        return json.loads((directory / name).read_text(), object_pairs_hook=unique_object)
    document = read("input.json")
    details = validate_encoding(document, read("encoding.json"))
    if (directory / "trace.smt2").read_text(encoding="ascii") != details["script"]:
        raise ValidationError("retained script does not match encoding.json")
    origin = None
    if (directory / "raw.ndjson").exists():
        origin = validate_raw_origin(
            (directory / "raw.ndjson").read_bytes(), read("reduction.json"), document
        )
    return document, details, origin


def diagnose(directory, output, *, after=None, indices=(), timeout_ms=10000):
    document, details, origin = load_run(directory)
    output.mkdir(parents=True, exist_ok=False)
    with (output / "snapshot.stderr").open("w") as errors:
        snapshot = subprocess.run(
            ["lake", "env", "lean", "--run", "Sparse/NativeStateDiagnosticMain.lean",
             "final" if after is None else str(after), *map(str, indices)],
            input=canonical_json(document), text=True, stdout=subprocess.PIPE, stderr=errors,
            cwd=ROOT, check=True,
        )
    state = json.loads(snapshot.stdout)
    if state["script"] != details["script"]:
        raise ValidationError("state diagnostic replay changed the original SMT script")
    state.pop("script")
    (output / "state-probes.json").write_text(json.dumps(state, indent=2) + "\n")
    assertions = z3.parse_smt2_string(details["script"])
    if len(assertions) != len(details["clauses"]):
        raise ValidationError("parsed assertions no longer match clause ownership")
    original = z3.Goal()
    original.add(*assertions)
    goal, stages = simplify_stages(original, timeout_ms)
    write_goal(output / "residual.smt2", goal)
    # Probes change preprocessing workload, so its metrics are kept separate.
    probed, probe_stages = simplify_stages(instrument(details["script"], state["probes"]), timeout_ms)
    write_goal(output / "residual-with-probes.smt2", probed)
    rows, status = read_probes(probed, state["probes"])
    needed = set(free_constants(goal)) | {name for row in rows for name in row["free_constants"]}
    first_uses = {}
    for group in details["groups"]:
        for position in range(group["start"], group["stop"]):
            for name in free_constants([assertions[position]]):
                if name not in needed or name in first_uses:
                    continue
                index = group["instruction"]
                first_uses[name] = {
                    "clause": details["clauses"][position]["name"],
                    "instruction": index,
                    "kind": document["instructions"][index]["kind"] if index is not None else "initial_domains",
                    "raw_lines": (
                        [entry["line"] for entry in origin.trace.steps[index]["provenance"]]
                        if origin is not None and index is not None else []
                    ),
                }
    report = {
        "schema": "ccfraft-native-residual/v1",
        "z3_version": z3.get_version_string(),
        "input_sha256": hashlib.sha256(details["script"].encode("ascii")).hexdigest(),
        "after_instructions": state["after_instructions"],
        "nodes": document["nodes"],
        "sampled_log_indices": list(indices),
        "status": status,
        "scope": (
            "Explicit preprocessing pipeline, not an exact dump of Z3's internal smt strategy. "
            "All trace assertions are retained, including those after the selected checkpoint. "
            "Residual symbolic means not resolved by these passes, not proven underdetermined. "
            "Fresh positive uninterpreted probe predicates can always be interpreted as true; "
            "they do not restrict the original state, but can affect preprocessing. "
            "Inactive storage and unobserved array tails need not be determined."
        ),
        "original_stages": stages,
        "instrumented_stages": probe_stages,
        "classifications": dict(Counter(row["classification"] for row in rows)),
        "probes": rows,
        "residual_constant_first_uses": first_uses,
    }
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    lines = [
        "# Residual state diagnostic", "",
        f"Z3 {report['z3_version']}; state after {report['after_instructions']} instructions.",
        "", report["scope"], "",
        "Node indices: " + ", ".join(f"{i}={name}" for i, name in enumerate(document["nodes"])),
        "", "| State read | Classification | Relevance | Simplified expression (preview) |",
        "| --- | --- | --- | --- |",
    ]
    for row in rows:
        preview = row["expression"][:120].replace("|", "\\|").replace("\n", " ")
        lines.append(f"| `{row['label']}` | {row['classification']} | {row['relevance']} | `{preview}` |")
    (output / "state.md").write_text("\n".join(lines) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--after", type=int, help="state after this many instructions; uses all trace constraints")
    parser.add_argument("--log-indices", type=int, nargs="*", default=list(range(8)))
    parser.add_argument("--pass-timeout-ms", type=int, default=10000)
    args = parser.parse_args()
    if args.pass_timeout_ms <= 0 or any(index < 0 for index in args.log_indices) or (
        args.after is not None and args.after < 0
    ):
        parser.error("timeout must be positive; checkpoint and log indices nonnegative")
    try:
        report = diagnose(
            args.run, args.output_dir, after=args.after, indices=args.log_indices,
            timeout_ms=args.pass_timeout_ms,
        )
    except (OSError, ValueError, ValidationError, z3.Z3Exception, subprocess.CalledProcessError) as error:
        parser.exit(2, f"residual diagnostic: {error}\n")
    print(json.dumps({
        "status": report["status"],
        "classifications": report["classifications"],
        "original_stages": report["original_stages"],
        "report": str(args.output_dir / "summary.json"),
    }, indent=2))


if __name__ == "__main__":
    main()
