#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Expose finite live log cells with stores, retaining arbitrary total-array tails."""

import argparse
import json
from pathlib import Path
import re

from encoding_study import PROJECT, digest, save
from study_flat_values import parse_sort, render, split_array, target_sort


def transform(script, width, bound):
    if "study_cell_" in script or "study_tail_" in script:
        raise ValueError("Finite-cell namespace is already used")
    lines = []
    changed = 0
    for line in script.splitlines(keepends=True):
        match = re.fullmatch(r"\(declare-const (c_[A-Za-z0-9_]+) (.+)\)\n", line)
        if not match:
            if line.lstrip().startswith(("(declare-const", "(declare-fun")):
                raise ValueError("Expected canonical native constant declarations")
            lines.append(line)
            continue
        name, raw_sort = match.groups()
        sort = parse_sort(raw_sort)
        indices, value = split_array(sort)
        if value != target_sort(width, "entry") or not indices:
            lines.append(line)
            continue
        if indices not in (["Int"], ["Int", "Int"]):
            raise ValueError("Unsupported log-array rank")
        tail = f"study_tail_{name}"
        lines.append(f"(declare-const {tail} {raw_sort})\n")
        expression = tail
        for node in range(width if len(indices) == 2 else 1):
            row = f"(select {tail} {node})" if len(indices) == 2 else tail
            for index in range(bound):
                cell = f"study_cell_{name}_{node}_{index}"
                lines.append(f"(declare-const {cell} {render(value)})\n")
                row = f"(store {row} {index} {cell})"
            expression = f"(store {expression} {node} {row})" if len(indices) == 2 else row
        lines.append(f"(define-fun {name} () {raw_sort} {expression})\n")
        changed += 1
    result = "".join(lines)
    if not changed or not result.endswith("(assert " + script.split("(assert ", 1)[1]):
        raise ValueError("Expected unchanged assertions and at least one log array")
    return result, changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--source-variant", required=True)
    parser.add_argument("--variant", required=True)
    parser.add_argument("--bound", type=int, required=True)
    args = parser.parse_args()
    if args.bound < 0:
        parser.error("Nonnegative bound required")
    manifest = json.loads((args.corpus / "manifest.json").read_text())
    preparation = json.loads(
        (args.corpus / "variants" / args.source_variant / "preparation.json").read_text()
    )
    if preparation.get("arguments") != ["finite", str(args.bound)]:
        raise ValueError("Cell exposure bound must match the finite source variant")
    root = args.corpus / "variants" / args.variant
    for case in manifest:
        details = json.loads(
            (args.corpus / "variants" / args.source_variant / case["name"] / "encoding.json").read_text()
        )
        script, count = transform(details["script"], len(details["input"]["nodes"]), args.bound)
        directory = root / case["name"]
        directory.mkdir(parents=True, exist_ok=False)
        save(directory / "encoding.json", {**details, "script": script})
        save(directory / "cells.json", {"bound": args.bound, "arrays_replaced": count})
        (directory / "original.smt2").write_text(script)
    source = Path(__file__).read_bytes()
    (root / "source.py").write_bytes(source)
    save(root / "preparation.json", {
        "source_path": str(Path(__file__).resolve().relative_to(PROJECT)),
        "source_sha256": digest(source), "source_variant": args.source_variant,
        "source_preparation": preparation,
        "dependencies": {"scripts/study_flat_values.py": digest(
            (PROJECT / "scripts/study_flat_values.py").read_bytes())},
        "bound": args.bound,
    })


if __name__ == "__main__":
    main()
